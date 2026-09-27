//! Runtime KCP integration over UDP, including outer TLS and listener cleanup.
//! KCP close is full-conversation close, so data exchanges do not depend on TCP
//! half-close semantics. Every network operation is loopback and time bounded.
use std::{net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
};
use xray_core::{Config, Server, address::Destination, transport::kcp};

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
                accepted=listener.accept()=>{
                    let (mut stream,_)=accepted.unwrap();
                    sessions.spawn(async move {
                        let mut bytes=[0;8192];
                        while let Ok(count)=stream.read(&mut bytes).await {
                            if count==0 { break; }
                            for byte in &mut bytes[..count] { *byte=byte.rotate_left(1)^0xa5; }
                            if stream.write_all(&bytes[..count]).await.is_err() { break; }
                        }
                    });
                }
                _=sessions.join_next(),if !sessions.is_empty()=>{},
            }
        }
    });
    Echo { address, task }
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("KCP runtime test deadline exceeded")
}

fn kcp_settings() -> Value {
    json!({"mtu":1200,"tti":10,"uplinkCapacity":5,"downlinkCapacity":20,"cwndMultiplier":1,"maxSendingWindow":65536})
}
fn inbound_config(port: u16, stream: Value) -> Config {
    Config::from_json(&json!({
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","tag":"kcp-in","settings":{},"streamSettings":stream}],
        "outbounds":[{"protocol":"freedom","settings":{}}]
    }).to_string()).unwrap()
}
fn front_config(remote: SocketAddr, stream: Value) -> Config {
    Config::from_json(&json!({
        "inbounds":[{"listen":"127.0.0.1","port":0,"protocol":"socks","tag":"front"}],
        "outbounds":[{"protocol":"socks","tag":"kcp-out","settings":{"address":"127.0.0.1","port":remote.port()},"streamSettings":stream}]
    }).to_string()).unwrap()
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
async fn socks_connect(front: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(front).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    stream.write_all(&[5, 1, 0]).await.unwrap();
    Destination::from(target)
        .write_socks(&mut stream)
        .await
        .unwrap();
    let mut reply = [0; 3];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0]);
    Destination::read_socks(&mut stream).await.unwrap();
    stream
}
async fn exchange(mut stream: TcpStream, seed: u8) {
    let payload: Vec<_> = (0..131_073)
        .map(|offset| (offset % 251) as u8 ^ seed)
        .collect();
    let expected: Vec<_> = payload
        .iter()
        .map(|byte| byte.rotate_left(1) ^ 0xa5)
        .collect();
    let (mut read, mut write) = tokio::io::split(&mut stream);
    let sending = async {
        write.write_all(&payload).await.unwrap();
        write.flush().await.unwrap();
    };
    let receiving = async {
        let mut actual = vec![0; expected.len()];
        read.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    };
    tokio::join!(sending, receiving);
}

async fn configured_chain(secure: bool) {
    let echo = echo().await;
    let mut inbound = json!({"network":"mkcp","kcpSettings":kcp_settings()});
    let mut outbound = json!({"network":"kcp","kcpSettings":kcp_settings()});
    if secure {
        let (server_tls, client_tls) = certificates();
        inbound["security"] = json!("tls");
        inbound["tlsSettings"] = server_tls;
        outbound["security"] = json!("tls");
        outbound["tlsSettings"] = client_tls;
    }
    let remote = Server::start(inbound_config(0, inbound)).await.unwrap();
    let front = Server::start(front_config(remote.local_addresses()[0], outbound))
        .await
        .unwrap();
    // Two independent UDP conversations must progress concurrently through the
    // same configured listener. Payloads exceed both adapter and send buffers.
    let (first, second) = tokio::join!(
        socks_connect(front.local_addresses()[0], echo.address),
        socks_connect(front.local_addresses()[0], echo.address)
    );
    tokio::join!(exchange(first, 0x17), exchange(second, 0x93));
    front.shutdown().await.unwrap();
    remote.shutdown().await.unwrap();
}

#[tokio::test]
async fn configured_plain_kcp_chains_transfer_multiple_conversations() {
    bounded(configured_chain(false)).await;
}
#[tokio::test]
async fn configured_tls_over_kcp_chains_transfer_multiple_conversations() {
    bounded(configured_chain(true)).await;
}

#[tokio::test]
async fn kcp_uses_udp_and_shutdown_releases_pending_protocol_sessions() {
    bounded(async {
        // A held TCP port must not prevent the KCP runtime binding UDP there.
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let server = Server::start(inbound_config(
            address.port(),
            json!({"network":"mkcp","kcpSettings":kcp_settings()}),
        ))
        .await
        .unwrap();
        assert_eq!(server.local_addresses(), &[address]);
        let settings = kcp::Config::from_json(&kcp_settings()).unwrap();
        let mut client = kcp::connect(address, settings, kcp::StreamOptions::default())
            .await
            .unwrap();
        client.write_all(&[5]).await.unwrap();
        client.flush().await.unwrap();
        // Retain an incomplete SOCKS handshake during shutdown. Both the runtime
        // session and KCP's UDP driver must be cancelled before shutdown returns.
        server.shutdown().await.unwrap();
        let rebound = UdpSocket::bind(address).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap(), address);
        client.cancel();
        drop(client);
        drop(rebound);
        drop(tcp);
    })
    .await;
}

#[tokio::test]
async fn later_bind_failure_releases_previously_bound_kcp_socket() {
    bounded(async {
        let first=UdpSocket::bind("127.0.0.1:0").await.unwrap(); let first_address=first.local_addr().unwrap();
        let occupied=UdpSocket::bind("127.0.0.1:0").await.unwrap(); let occupied_address=occupied.local_addr().unwrap();
        let config=Config::from_json(&json!({
            "inbounds":[
                {"listen":"127.0.0.1","port":first_address.port(),"protocol":"socks","tag":"first","streamSettings":{"network":"kcp"}},
                {"listen":"127.0.0.1","port":occupied_address.port(),"protocol":"socks","tag":"occupied","streamSettings":{"network":"kcp"}}
            ],"outbounds":[{"protocol":"freedom"}]
        }).to_string()).unwrap();
        drop(first); assert!(Server::start(config).await.is_err());
        // Startup rollback must join already-bound KCP listeners before returning
        // its error, so retrying immediately does not depend on a scheduler yield.
        let rebound=UdpSocket::bind(first_address).await.expect("failed startup returned before releasing an earlier KCP UDP socket");
        drop(rebound); drop(occupied);
    }).await;
}

#[test]
fn rejects_misplaced_legacy_and_incompatible_runtime_settings() {
    for stream in [
        json!({"network":"tcp","kcpSettings":{}}),
        json!({"network":"kcp","grpcSettings":{}}),
        json!({"network":"kcp","wsSettings":{}}),
        json!({"network":"kcp","xhttpSettings":{}}),
        json!({"network":"kcp","security":"reality","realitySettings":{}}),
        json!({"network":"mkcp","security":"reality","realitySettings":{}}),
        json!({"network":"kcp","kcpSettings":{"congestion":false}}),
        json!({"network":"kcp","kcpSettings":{"readBufferSize":2}}),
        json!({"network":"kcp","kcpSettings":{"writeBufferSize":2}}),
        json!({"network":"kcp","kcpSettings":{"seed":""}}),
        json!({"network":"kcp","kcpSettings":{"header":{"type":"srtp"}}}),
        json!({"network":"kcp","kcpSettings":{"tti":1}}),
        json!({"network":"kcp","sockopt":{"mark":1}}),
        json!({"network":"kcp","udpmaskSettings":[{"type":"srtp"}]}),
    ] {
        let raw=json!({"inbounds":[],"outbounds":[{"protocol":"socks","settings":{"address":"127.0.0.1","port":443},"streamSettings":stream}]}).to_string();
        let result = Config::from_json(&raw).and_then(|config| config.validate());
        assert!(result.is_err(), "unexpectedly accepted {stream}");
    }
}
