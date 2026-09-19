//! End-to-end runtime integration of gRPC logical streams and outer TLS.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::pki_types::ServerName};
use xray_core::{
    Config, Server,
    address::Destination,
    transport::{BoxStream, grpc, tls},
};

struct Echo {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn echo() -> Echo {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (mut stream, _) = result.unwrap();
                    sessions.spawn(async move {
                        let mut data = Vec::new();
                        if stream.read_to_end(&mut data).await.is_ok() {
                            let _ = stream.write_all(&data).await;
                            let _ = stream.shutdown().await;
                        }
                    });
                }
                _ = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
    });
    Echo { address, task }
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("gRPC runtime test timed out")
}

fn certificates() -> (Value, Value) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem: Vec<_> = certificate.cert.pem().lines().map(str::to_owned).collect();
    let key: Vec<_> = certificate
        .signing_key
        .serialize_pem()
        .lines()
        .map(str::to_owned)
        .collect();
    (
        json!({"certificates":[{"certificate":pem,"key":key}]}),
        json!({"serverName":"localhost","disableSystemRoot":true,"certificates":[{"certificate":pem,"usage":"verify"}]}),
    )
}

fn grpc_settings() -> Value {
    json!({"serviceName":"/runtime service/nested/tun!|multi!","user_agent":"golang"})
}

fn remote_config(target: SocketAddr, stream_settings: Value) -> Config {
    Config::from_json(&json!({
        "inbounds":[{"listen":"127.0.0.1","port":0,"protocol":"socks","tag":"grpc-in","settings":{},"streamSettings":stream_settings}],
        "outbounds":[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1"],"port":target.port()}]}}]
    }).to_string()).unwrap()
}

fn front_config(remote: SocketAddr, stream_settings: Value) -> Config {
    Config::from_json(&json!({
        "inbounds":[{"listen":"127.0.0.1","port":0,"protocol":"socks","tag":"front"}],
        "outbounds":[{"protocol":"socks","tag":"grpc-out","settings":{"address":"127.0.0.1","port":remote.port()},"streamSettings":stream_settings}]
    }).to_string()).unwrap()
}

async fn socks_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    destination: SocketAddr,
) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    stream.flush().await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    stream.write_all(&[5, 1, 0]).await.unwrap();
    Destination::from(destination)
        .write_socks(stream)
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 3];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0]);
    Destination::read_socks(stream).await.unwrap();
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, payload);
}

async fn pooled_runtime(secure: bool) {
    let echo = echo().await;
    let settings = grpc_settings();
    let mut inbound = json!({"network":"grpc","grpcSettings":settings});
    let (server_tls, mut client_tls) = certificates();
    if secure {
        inbound["security"] = json!("tls");
        inbound["tlsSettings"] = server_tls;
        client_tls["alpn"] = json!(["h2"]);
    }
    let server = Server::start(remote_config(echo.address, inbound))
        .await
        .unwrap();
    let mut transport: BoxStream = Box::new(
        TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap(),
    );
    if secure {
        let client = tls::TlsClient::new(&serde_json::from_value(client_tls).unwrap()).unwrap();
        transport = client
            .connect_with_alpn(transport, "localhost", b"h2")
            .await
            .unwrap();
    }
    let client = grpc::Client::handshake(
        transport,
        serde_json::from_value(settings).unwrap(),
        "authority.example",
    )
    .await
    .unwrap();
    let mut first = client.open_mode(grpc::Mode::Tun).await.unwrap();
    let mut second = client.open_mode(grpc::Mode::TunMulti).await.unwrap();
    // Both proxy handshakes must progress before either tunnel closes. A runtime
    // that only dispatches one stream per TCP connection deadlocks here.
    tokio::join!(
        socks_handshake(&mut first, echo.address),
        socks_handshake(&mut second, echo.address)
    );
    let mut canceled = client.open().await.unwrap();
    socks_handshake(&mut canceled, echo.address).await;
    drop(canceled);
    let a: Vec<u8> = (0..131_072).map(|i| (i % 251) as u8).collect();
    let b = vec![0xab; 65_537];
    tokio::join!(exchange(&mut first, &a), exchange(&mut second, &b));
    let mut after_cancel = client.open().await.unwrap();
    socks_handshake(&mut after_cancel, echo.address).await;
    exchange(
        &mut after_cancel,
        b"same HTTP/2 connection survives cancellation",
    )
    .await;

    // Retain half-written protocol handshakes while shutting down the runtime.
    // Its connection owner must cancel and drain all logical stream tasks.
    let mut pending = Vec::new();
    for _ in 0..8 {
        let mut stream = client.open().await.unwrap();
        stream.write_all(&[5]).await.unwrap();
        stream.flush().await.unwrap();
        pending.push(stream);
    }
    server.shutdown().await.unwrap();
    for mut stream in pending {
        assert!(stream.read(&mut [0u8; 1]).await.is_err());
    }
}

#[tokio::test]
async fn pooled_plain_runtime_dispatches_both_modes_half_closes_and_cancels() {
    bounded(pooled_runtime(false)).await;
}

#[tokio::test]
async fn pooled_tls_runtime_dispatches_both_modes_half_closes_and_cancels() {
    bounded(pooled_runtime(true)).await;
}

#[tokio::test]
async fn configured_outbound_grpc_chains_transfer_plain_and_tls() {
    bounded(async {
        let echo = echo().await;
        let (server_tls, client_tls) = certificates();
        for secure in [false, true] {
            for multi in [false, true] {
                let mut inbound = json!({"network":"grpc","grpcSettings":grpc_settings()});
                let mut outbound = inbound.clone();
                outbound["grpcSettings"]["multiMode"] = json!(multi);
                if secure {
                    inbound["security"] = json!("tls");
                    inbound["tlsSettings"] = server_tls.clone();
                    outbound["security"] = json!("tls");
                    outbound["tlsSettings"] = client_tls.clone();
                }
                let remote = Server::start(remote_config(echo.address, inbound))
                    .await
                    .unwrap();
                let front = Server::start(front_config(remote.local_addresses()[0], outbound))
                    .await
                    .unwrap();
                let mut socket = TcpStream::connect(front.local_addresses()[0])
                    .await
                    .unwrap();
                socks_handshake(&mut socket, echo.address).await;
                exchange(
                    &mut socket,
                    b"configured gRPC outbound retains its HTTP/2 driver",
                )
                .await;
                front.shutdown().await.unwrap();
                remote.shutdown().await.unwrap();
            }
        }
    })
    .await;
}

#[test]
fn rejects_misplaced_settings_keepalive_and_non_h2_alpn() {
    for stream in [
        json!({"network":"tcp","grpcSettings":{}}),
        json!({"network":"grpc","grpcSettings":{"idle_timeout":1}}),
        json!({"network":"grpc","grpcSettings":{"health_check_timeout":1}}),
        json!({"network":"grpc","grpcSettings":{"permit_without_stream":true}}),
        json!({"network":"grpc","grpcSettings":{"unknown_option":true}}),
        json!({"network":"grpc","security":"tls","tlsSettings":{"alpn":["http/1.1"]}}),
        json!({"network":"grpc","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"]}}),
    ] {
        let config = front_config("127.0.0.1:443".parse().unwrap(), stream.clone());
        assert!(config.validate().is_err(), "{stream}");
    }
}

#[tokio::test]
async fn remote_h2_connection_close_cancels_active_logical_upstreams() {
    bounded(async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let mut reads = JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                reads.spawn(async move {
                    let mut data = Vec::new();
                    let result = stream.read_to_end(&mut data).await;
                    assert!(matches!(result, Ok(0) | Err(_)));
                    assert!(data.is_empty());
                });
            }
            while let Some(result) = reads.join_next().await {
                result.unwrap();
            }
        });
        let server = Server::start(remote_config(
            destination,
            json!({
                "network":"grpc","grpcSettings":grpc_settings(),
            }),
        ))
        .await
        .unwrap();
        let socket = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap()
            .into_std()
            .unwrap();
        let close_handle = socket.try_clone().unwrap();
        let stream = TcpStream::from_std(socket).unwrap();
        let client = grpc::Client::handshake(
            Box::new(stream),
            serde_json::from_value(grpc_settings()).unwrap(),
            "example.test",
        )
        .await
        .unwrap();
        let mut first = client.open().await.unwrap();
        let mut second = client.open().await.unwrap();
        tokio::join!(
            socks_handshake(&mut first, destination),
            socks_handshake(&mut second, destination)
        );
        // Force physical connection loss while both logical proxy sessions and
        // their established upstream sockets remain live.
        close_handle.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(first.read(&mut [0u8; 1]).await.is_err());
        assert!(second.read(&mut [0u8; 1]).await.is_err());
        target_task.await.unwrap();
        server.shutdown().await.unwrap();
    })
    .await;
}

#[test]
fn grpc_preserves_explicit_native_reality_profile_validation() {
    let mut settings = json!({
        "network":"grpc","security":"reality","grpcSettings":grpc_settings(),
        "realitySettings":{"fingerprint":"native","serverName":"example.com","publicKey":URL_SAFE_NO_PAD.encode([7u8;32]),"shortId":"0102"}
    });
    front_config("127.0.0.1:443".parse().unwrap(), settings.clone())
        .validate()
        .unwrap();
    settings["realitySettings"]["fingerprint"] = json!("chrome");
    assert!(
        front_config("127.0.0.1:443".parse().unwrap(), settings)
            .validate()
            .is_err()
    );
}

#[tokio::test]
async fn grpc_inbound_rejects_missing_and_disjoint_actual_tls_alpn() {
    bounded(async {
        let echo = echo().await;
        let (server_tls, client_tls) = certificates();
        let inbound = json!({"network":"grpc","grpcSettings":grpc_settings(),"security":"tls","tlsSettings":server_tls});
        let server = Server::start(remote_config(echo.address, inbound)).await.unwrap();
        for alpn in [Vec::new(), vec![b"http/1.1".to_vec()]] {
            let settings: tls::TlsSettings = serde_json::from_value(client_tls.clone()).unwrap();
            let mut config = (*settings.build_client_config().unwrap()).clone();
            config.alpn_protocols = alpn;
            let connector = TlsConnector::from(Arc::new(config));
            let socket = TcpStream::connect(server.local_addresses()[0]).await.unwrap();
            if let Ok(stream) = connector.connect(ServerName::try_from("localhost").unwrap(), socket).await
                && let Ok(client) = grpc::Client::handshake(Box::new(stream), serde_json::from_value(grpc_settings()).unwrap(), "localhost").await
                && let Ok(mut tunnel) = client.open().await {
                    assert!(tunnel.read(&mut [0u8; 1]).await.is_err());
            }
        }
        server.shutdown().await.unwrap();
    }).await;
}

#[tokio::test]
async fn grpc_outbound_rejects_tls_server_omitting_alpn_before_sending_h2() {
    bounded(async {
        let (server_tls, client_tls) = certificates();
        let settings: tls::TlsSettings = serde_json::from_value(server_tls).unwrap();
        let mut tls_config = (*settings.build_server_config().unwrap()).clone();
        tls_config.alpn_protocols.clear();
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(socket).await.unwrap();
            assert!(stream.get_ref().1.alpn_protocol().is_none());
            // No H2 preface may be sent after the required ALPN was omitted.
            let result = stream.read(&mut [0u8; 1]).await;
            assert!(matches!(result, Ok(0) | Err(_)));
        });
        let front = Server::start(front_config(remote_address, json!({
            "network":"grpc","grpcSettings":grpc_settings(),"security":"tls","tlsSettings":client_tls,
        }))).await.unwrap();
        let mut client = TcpStream::connect(front.local_addresses()[0]).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2]; client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client.write_all(&[5, 1, 0]).await.unwrap();
        Destination::from("192.0.2.1:443".parse::<SocketAddr>().unwrap()).write_socks(&mut client).await.unwrap();
        let mut reply = [0; 3]; client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 5, 0]);
        front.shutdown().await.unwrap(); peer.await.unwrap();
    }).await;
}
