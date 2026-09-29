//! End-to-end hysteria runtime tests: a real QUIC endpoint on 127.0.0.1:0
//! serving the dispatch seam (a mock seam echoing every stream and datagram),
//! the outbound relaying a local downstream through the endpoint, and the
//! authentication rejection path (Go proxy/hysteria + transport/internet/
//! hysteria behavior over the tested codecs).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::rustls;

use xray_core::{
    address::Destination,
    protocol::hysteria_runtime::{
        HysteriaDispatch, HysteriaDispatchFuture, HysteriaInbound, HysteriaOutbound, HysteriaUser,
        TcpDispatch, UdpDispatch, client_dialer,
    },
    transport::{
        hysteria::NativeCongestion,
        hysteria_endpoint::{HysteriaEndpointListener, HysteriaServerOptions, Masquerade},
    },
};

/// Bounded waits (the whole test also runs inside an envelope).
const WAIT: Duration = Duration::from_secs(5);
const ENVELOPE: Duration = Duration::from_secs(10);

/// A self-signed loopback certificate pair, exactly like the codec tests:
/// TLS 1.3 with the ring provider; the endpoint forces the h3 ALPN itself.
fn loopback_tls() -> (rustls::ServerConfig, rustls::ClientConfig) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, client)
}

/// The mock seam: every dispatched TCP stream and UDP datagram is echoed
/// back, so the tests observe the whole inbound path.
struct EchoSeam;

impl HysteriaDispatch for EchoSeam {
    fn dispatch_stream(&self, connection: TcpDispatch) -> HysteriaDispatchFuture {
        Box::pin(async move {
            let mut stream = connection.stream;
            let mut buffer = vec![0u8; 4096];
            loop {
                let size = stream.read(&mut buffer).await?;
                if size == 0 {
                    break;
                }
                stream.write_all(&buffer[..size]).await?;
            }
            Ok(())
        })
    }

    fn dispatch_udp(&self, session: UdpDispatch) -> HysteriaDispatchFuture {
        Box::pin(async move {
            let mut packets = session.packets;
            let responses = session.responses;
            while let Some((_destination, payload)) = packets.recv().await {
                responses.send(payload).await?;
            }
            Ok(())
        })
    }
}

/// One inbound-bound user (Go's validator), matching the client secret.
fn user() -> HysteriaUser {
    HysteriaUser {
        auth: "secret".into(),
        level: 0,
        email: "echo@example.net".into(),
    }
}

fn server_options() -> HysteriaServerOptions {
    HysteriaServerOptions {
        users: vec![user()],
        auth: String::new(),
        masquerade: Masquerade::NotFound,
        udp_idle_timeout: Duration::from_secs(60),
        receive_bytes_per_second: 100_000,
        congestion: NativeCongestion::QuinnNewReno,
        quic: Default::default(),
    }
}

/// Bind the endpoint and serve every accepted connection through the echo
/// seam. Returns the bound loopback address and the client TLS config that
/// trusts the endpoint's certificate (one pair per test, no shared state).
async fn spawn_echo_server() -> (SocketAddr, rustls::ClientConfig) {
    let (server_tls, client_tls) = loopback_tls();
    let mut listener = HysteriaEndpointListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        server_tls,
        server_options(),
    )
    .expect("bind the hysteria endpoint");
    let address = listener.local_addr();
    let inbound = Arc::new(HysteriaInbound::new(Arc::new(EchoSeam)));
    tokio::spawn(async move {
        while let Some(connection) = listener.accept().await {
            let inbound = inbound.clone();
            tokio::spawn(async move {
                let _ = inbound.serve_connection(connection).await;
            });
        }
    });
    (address, client_tls)
}

fn dialer(
    address: SocketAddr,
    client_tls: rustls::ClientConfig,
    auth: &str,
) -> xray_core::transport::hysteria_endpoint::HysteriaClientDialer {
    client_dialer(
        &Destination::new("127.0.0.1", address.port()).unwrap(),
        "localhost",
        client_tls,
        auth,
        0,
        NativeCongestion::QuinnNewReno,
    )
}

#[tokio::test]
async fn inbound_tcp_streams_echo_through_the_dispatch_seam() {
    timeout(ENVELOPE, async {
        let (address, client_tls) = spawn_echo_server().await;
        let connection = dialer(address, client_tls, "secret")
            .connect()
            .await
            .expect("authenticate");
        // The negotiated capabilities come from the server's options.
        assert!(connection.peer_capabilities().udp_enabled);
        assert_eq!(
            connection.peer_capabilities().receive_bytes_per_second,
            100_000
        );
        let mut stream = connection
            .open_tcp("echo.example.net:443")
            .await
            .expect("open a proxy stream");
        stream.write_all(b"hello seam").await.unwrap();
        let mut echoed = [0u8; 10];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello seam");
        connection.close();
    })
    .await
    .expect("the inbound echo test timed out");
}

#[tokio::test]
async fn outbound_relays_a_local_downstream_to_the_endpoint() {
    timeout(ENVELOPE, async {
        let (address, client_tls) = spawn_echo_server().await;
        let outbound = HysteriaOutbound::new(dialer(address, client_tls, "secret"));
        // The duplex plays the local connection the runtime would relay.
        let (mut local, mut remote) = duplex(64 * 1024);
        let target = Destination::new("echo.example.net", 443).unwrap();
        let relay = tokio::spawn(async move { outbound.process_tcp(&target, &mut remote).await });
        local.write_all(b"ping relay").await.unwrap();
        let mut echoed = [0u8; 10];
        local.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping relay");
        // Closing the downstream ends the relay exactly like Go's task.Run.
        drop(local);
        timeout(WAIT, relay)
            .await
            .expect("the relay task timed out")
            .expect("the relay task panicked")
            .expect("the relay ended cleanly");
    })
    .await
    .expect("the outbound relay test timed out");
}

#[tokio::test]
async fn wrong_password_is_refused_with_the_masquerade() {
    timeout(ENVELOPE, async {
        let (address, client_tls) = spawn_echo_server().await;
        let result = dialer(address, client_tls, "wrong").connect().await;
        let message = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("authentication with the wrong password must fail"),
        };
        assert!(
            message.contains("HTTP status 404"),
            "the masquerade answer must surface, got: {message}"
        );
    })
    .await
    .expect("the rejection test timed out");
}

#[tokio::test]
async fn outbound_udp_sessions_echo_back_through_the_seam() {
    timeout(ENVELOPE, async {
        let (address, client_tls) = spawn_echo_server().await;
        let outbound = Arc::new(HysteriaOutbound::new(dialer(address, client_tls, "secret")));
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(8);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(8);
        let target = Destination::new("dns.example.net", 53).unwrap();
        let relay = {
            let outbound = outbound.clone();
            tokio::spawn(
                async move { outbound.process_udp(&target, outbound_rx, inbound_tx).await },
            )
        };
        outbound_tx.send(b"query".to_vec()).await.unwrap();
        let reply = timeout(WAIT, inbound_rx.recv())
            .await
            .expect("the UDP echo timed out")
            .expect("the UDP session stayed alive");
        assert_eq!(reply, b"query");
        // Dropping the outbound side ends the session like Go's Process.
        drop(outbound_tx);
        timeout(WAIT, relay)
            .await
            .expect("the UDP relay task timed out")
            .expect("the UDP relay task panicked")
            .expect("the UDP relay ended cleanly");
    })
    .await
    .expect("the outbound UDP test timed out");
}

#[tokio::test]
async fn transport_auth_without_users_disables_udp() {
    timeout(ENVELOPE, async {
        // Go: a transport `auth` secret without proxy users authenticates,
        // but `ResponseHeaderUDPEnabled` is false (validator == nil).
        let (server_tls, client_tls) = loopback_tls();
        let options = HysteriaServerOptions {
            users: Vec::new(),
            auth: "transport-secret".into(),
            ..server_options()
        };
        let mut listener =
            HysteriaEndpointListener::bind("127.0.0.1:0".parse().unwrap(), server_tls, options)
                .expect("bind the auth-only endpoint");
        let address = listener.local_addr();
        let inbound = Arc::new(HysteriaInbound::new(Arc::new(EchoSeam)));
        tokio::spawn(async move {
            while let Some(connection) = listener.accept().await {
                let inbound = inbound.clone();
                tokio::spawn(async move {
                    let _ = inbound.serve_connection(connection).await;
                });
            }
        });
        let connection = dialer(address, client_tls, "transport-secret")
            .connect()
            .await
            .expect("the transport secret authenticates");
        assert!(!connection.peer_capabilities().udp_enabled);
        // TCP still works through the seam.
        let mut stream = connection
            .open_tcp("echo.example.net:443")
            .await
            .expect("open a proxy stream");
        stream.write_all(b"auth only").await.unwrap();
        let mut echoed = [0u8; 9];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"auth only");
        connection.close();
    })
    .await
    .expect("the auth-only test timed out");
}

// ---------------------------------------------------------------------------
// Full-runtime wiring: the config surface, the inbound seam, the outbound
// pool (Config/Server from JSON, exactly like the other runtime suites).
// ---------------------------------------------------------------------------

use serde_json::json;
use xray_core::{Config, Server, transport::tls as config_tls};

/// A loopback TCP echo server whose accept loop aborts on drop (the masque
/// suite's shape; the runtime tests relay through it).
struct TcpEcho {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TcpEcho {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TcpEcho {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(size) => {
                                if stream.write_all(&buffer[..size]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        TcpEcho { address, task }
    }
}

/// The PEM certificate pair the JSON configs carry (masque suite's shape:
/// the server holds the key, the client trusts only the pinned certificate).
fn json_tls_pair() -> (serde_json::Value, serde_json::Value) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).unwrap();
    let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
    let server = json!({
        "certificates": [{
            "certificate": certificate.clone(),
            "key": signing_key.serialize_pem().lines().map(str::to_owned).collect::<Vec<_>>(),
        }]
    });
    let client = json!({
        "disableSystemRoot": true,
        "certificates": [{"certificate": certificate, "usage": "verify"}]
    });
    (server, client)
}

/// The hysteria stream settings both sides use (Go's spellings; reno is the
/// one congestion controller the port runs, the others are named rejections).
fn hysteria_stream(server_tls: serde_json::Value, quic: serde_json::Value) -> serde_json::Value {
    json!({
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": server_tls,
        "hysteriaSettings": {"version": 2, "auth": "", "udpIdleTimeout": 60},
        "finalmask": {"tcp": [], "udp": [], "quicParams": quic}
    })
}

fn reno() -> serde_json::Value {
    json!({"congestion": "reno"})
}

#[tokio::test]
async fn config_rejects_unsupported_hysteria_shapes() {
    // The Go default congestion (BBR) is a named rejection, as are Brutal
    // modes and mask chains; reno compiles.
    let (server_tls, _) = json_tls_pair();
    let stream = hysteria_stream(server_tls.clone(), json!({}));
    let base = json!({
        "inbounds": [{
            "listen": "127.0.0.1", "port": 0, "tag": "hy-in", "protocol": "hysteria",
            "settings": {"version": 2, "users": [{"auth": "secret", "level": 0, "email": "u@example"}]},
            "streamSettings": stream
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}]
    });
    let error = Config::from_json(&base.to_string())
        .and_then(|config| config.validate())
        .err()
        .map(|e| format!("{e:#}"));
    assert!(
        error.as_deref().is_some_and(|e| e.contains("BBR")),
        "the default congestion must fail with the BBR named rejection, got {error:?}"
    );
    let mut reno_config = base.clone();
    reno_config["inbounds"][0]["streamSettings"]["finalmask"]["quicParams"] = reno();
    Config::from_json(&reno_config.to_string())
        .and_then(|config| config.validate())
        .expect("reno compiles");
    let mut masks = reno_config.clone();
    masks["inbounds"][0]["streamSettings"]["finalmask"]["tcp"] = json!([{"type": "noise"}]);
    assert!(
        Config::from_json(&masks.to_string())
            .and_then(|config| config.validate())
            .is_err()
    );
    // A non-hysteria network or missing hysteriaSettings fails like Go's
    // "not hysteria transport".
    let mut wrong_network = reno_config.clone();
    wrong_network["inbounds"][0]["streamSettings"]["network"] = json!("tcp");
    assert!(
        Config::from_json(&wrong_network.to_string())
            .and_then(|config| config.validate())
            .is_err()
    );
    let mut missing_settings = reno_config.clone();
    missing_settings["inbounds"][0]["streamSettings"]["hysteriaSettings"] = json!(null);
    assert!(
        Config::from_json(&missing_settings.to_string())
            .and_then(|config| config.validate())
            .is_err()
    );
    let _ = server_tls;
}

#[tokio::test]
async fn hysteria_inbound_relays_through_the_runtime() {
    timeout(ENVELOPE, async {
        let echo = TcpEcho::start().await;
        let (server_tls, client_tls) = json_tls_pair();
        let config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "hy-in", "protocol": "hysteria",
                    "settings": {"version": 2, "users": [{"auth": "secret", "level": 0, "email": "runtime@example"}]},
                    "streamSettings": hysteria_stream(server_tls, reno())
                }],
                "outbounds": [{
                    "tag": "direct", "protocol": "freedom",
                    "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo.address.port()}
                    ]}
                }]
            })
            .to_string(),
        )
        .unwrap();
        let server = Server::start(config).await.unwrap();
        let address = server.local_addresses()[0];
        // A direct client dialer against the runtime's endpoint: the TLS
        // client config mirrors the JSON pair.
        let settings: config_tls::TlsSettings =
            serde_json::from_value(client_tls).unwrap();
        let client_config = settings.build_client_config().unwrap();
        let dialer = client_dialer(
            &Destination::new("127.0.0.1", address.port()).unwrap(),
            "hysteria.test",
            (*client_config).clone(),
            "secret",
            0,
            NativeCongestion::QuinnNewReno,
        );
        let connection = dialer.connect().await.expect("authenticate");
        let mut stream = connection
            .open_tcp(&format!("127.0.0.1:{}", echo.address.port()))
            .await
            .expect("open a proxy stream");
        stream.write_all(b"runtime seam").await.unwrap();
        let mut echoed = [0u8; 12];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"runtime seam");
        connection.close();
        server.shutdown().await.unwrap();
    })
    .await
    .expect("the runtime inbound test timed out");
}

#[tokio::test]
async fn hysteria_outbound_relays_through_two_runtimes() {
    timeout(ENVELOPE, async {
        let echo = TcpEcho::start().await;
        let (server_tls, client_tls) = json_tls_pair();
        // The upstream server: hysteria inbound + freedom to the echo.
        let upstream = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "hy-in", "protocol": "hysteria",
                    "settings": {"version": 2, "users": [{"auth": "secret", "level": 0, "email": "upstream@example"}]},
                    "streamSettings": hysteria_stream(server_tls, reno())
                }],
                "outbounds": [{
                    "tag": "direct", "protocol": "freedom",
                    "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo.address.port()}
                    ]}
                }]
            })
            .to_string(),
        )
        .unwrap();
        let upstream = Server::start(upstream).await.unwrap();
        let upstream_address = upstream.local_addresses()[0];
        // The client proxy: SOCKS inbound + the hysteria outbound (Go's
        // proxy/hysteria client over the same JSON pair).
        let client = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "socks-in", "protocol": "socks",
                    "settings": {"auth": "noauth"}
                }],
                "outbounds": [{
                    "tag": "proxy", "protocol": "hysteria",
                    "settings": {"version": 2, "address": "127.0.0.1", "port": upstream_address.port()},
                    "streamSettings": {
                        "network": "hysteria", "security": "tls",
                        "tlsSettings": {"serverName": "hysteria.test", "disableSystemRoot": true,
                            "certificates": client_tls["certificates"].clone()},
                        "hysteriaSettings": {"version": 2, "auth": "secret", "udpIdleTimeout": 60},
                        "finalmask": {"tcp": [], "udp": [], "quicParams": reno()}
                    }
                }]
            })
            .to_string(),
        )
        .unwrap();
        let client = Server::start(client).await.unwrap();
        // SOCKS CONNECT through both hops to the echo target.
        let mut proxy = tokio::net::TcpStream::connect(client.local_addresses()[0])
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        proxy.write_all(&[5, 1, 0]).await.unwrap();
        let mut methods = [0; 2];
        proxy.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [5, 0]);
        proxy.write_all(&[5, 1, 0]).await.unwrap();
        xray_core::address::Destination::from(echo.address)
            .write_socks(&mut proxy)
            .await
            .unwrap();
        let mut reply = [0; 3];
        proxy.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0]);
        xray_core::address::Destination::read_socks(&mut proxy)
            .await
            .unwrap();
        proxy.write_all(b"two hops").await.unwrap();
        let mut echoed = [0u8; 8];
        proxy.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"two hops");
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
    })
    .await
    .expect("the two-runtime outbound test timed out");
}
