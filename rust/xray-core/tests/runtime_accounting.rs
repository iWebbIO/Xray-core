//! Runtime boundaries: protocol framing, session setup, and API stream ownership.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::oneshot,
    time::{Instant, sleep, timeout},
};
use xray_core::{
    Config, Server, address::Destination, features::StatsManager, protocol::vmess,
    transport::BoxStream,
};

const USER_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const EMAIL: &str = "accounting@example.test";

fn policy(idle: u32) -> Value {
    json!({
        "levels":{"0":{"connIdle":idle,"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}},
        "system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}
    })
}

fn config(value: Value) -> Config {
    Config::from_json(&value.to_string()).unwrap()
}

fn traffic(stats: &StatsManager, identity: &str, direction: &str) -> i64 {
    stats
        .stat(&format!("{identity}>>>traffic>>>{direction}"), false)
        .unwrap()
        .value
}

fn online(stats: &StatsManager) -> usize {
    stats
        .get_online_map(&format!("user>>>{EMAIL}>>>online"))
        .map_or(0, |map| map.count())
}

async fn wait_online(stats: &StatsManager, expected: usize) {
    timeout(Duration::from_secs(2), async {
        while online(stats) != expected {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("online-user ownership did not reach the expected state");
}

async fn http_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 32 * 1024);
    }
    bytes
}

async fn socks_client(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    stream
        .write_all(&[5, 1, 0, 1, 198, 51, 100, 1, 1, 187])
        .await
        .unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    stream
}

async fn vmess_client(address: SocketAddr) -> BoxStream {
    // Go's online tracker deliberately excludes 127.0.0.1. A second loopback
    // address exercises a real, included source without external networking.
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from(([127, 0, 0, 2], 0))).unwrap();
    let stream = socket.connect(address).await.unwrap();
    vmess::stream::connect(
        Box::new(stream),
        &vmess::Account::from_user_id(USER_ID, "").unwrap(),
        &Destination::new("management.test", 80).unwrap(),
    )
    .await
    .unwrap()
}

fn vmess_inbound() -> Value {
    json!({"tag":"in","listen":"127.0.0.1","port":0,"protocol":"vmess","settings":{"clients":[{"id":USER_ID,"email":EMAIL}]}})
}

#[tokio::test]
async fn system_counters_include_each_proxys_distinct_framing() {
    timeout(Duration::from_secs(8), async {
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote.local_addr().unwrap();
        let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
        let remote_task = tokio::spawn(async move {
            let (mut stream, _) = remote.accept().await.unwrap();
            let header = http_head(&mut stream).await;
            assert!(header.starts_with(b"CONNECT 198.51.100.1:443 HTTP/1.1\r\n"));
            stream.write_all(response).await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            header.len()
        });
        let server = Server::start(config(json!({
            "stats":{},"policy":policy(5),
            "inbounds":[{"tag":"in","listen":"127.0.0.1","port":0,"protocol":"socks"}],
            "outbounds":[{"tag":"out","protocol":"http","settings":{"address":"127.0.0.1","port":remote_address.port()}}]
        }))).await.unwrap();
        let stats = server.stats().unwrap();
        // Proxyman registers enabled counters even before a connection exists.
        for identity in ["inbound>>>in", "outbound>>>out"] {
            for direction in ["uplink", "downlink"] {
                assert_eq!(traffic(&stats, identity, direction), 0);
            }
        }
        let mut client = socks_client(server.local_addresses()[0]).await;
        let payload = b"system accounting payload";
        client.write_all(payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        let header_length = remote_task.await.unwrap();
        server.shutdown().await.unwrap();
        let payload_length = payload.len() as i64;
        assert_eq!(traffic(&stats, "inbound>>>in", "uplink"), 13 + payload_length);
        assert_eq!(traffic(&stats, "inbound>>>in", "downlink"), 12 + payload_length);
        assert_eq!(traffic(&stats, "outbound>>>out", "uplink"), header_length as i64 + payload_length);
        assert_eq!(traffic(&stats, "outbound>>>out", "downlink"), response.len() as i64 + payload_length);
    }).await.unwrap();
}

#[tokio::test]
async fn rejected_handshake_still_counts_transport_bytes() {
    timeout(Duration::from_secs(5), async {
        let server = Server::start(config(json!({
            "stats":{},"policy":policy(3),
            "inbounds":[{"tag":"in","listen":"127.0.0.1","port":0,"protocol":"socks"}],
            "outbounds":[{"tag":"out","protocol":"freedom"}]
        })))
        .await
        .unwrap();
        let stats = server.stats().unwrap();
        let mut stream = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        stream.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 255]);
        server.shutdown().await.unwrap();
        assert_eq!(traffic(&stats, "inbound>>>in", "uplink"), 3);
        assert_eq!(traffic(&stats, "inbound>>>in", "downlink"), 2);
        assert_eq!(traffic(&stats, "outbound>>>out", "uplink"), 0);
        assert_eq!(traffic(&stats, "outbound>>>out", "downlink"), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vmess_inactivity_cancels_stalled_outbound_handshake_and_releases_user() {
    timeout(Duration::from_secs(5), async {
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote.local_addr().unwrap();
        let (started, waiting) = oneshot::channel();
        let remote_task = tokio::spawn(async move {
            let (mut stream, _) = remote.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            started.send(()).unwrap();
            // Deliberately never answer the outbound SOCKS negotiation.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        });
        let server = Server::start(config(json!({
            "stats":{},"policy":policy(1),"inbounds":[vmess_inbound()],
            "outbounds":[{"tag":"out","protocol":"socks","settings":{"address":"127.0.0.1","port":remote_address.port()}}]
        }))).await.unwrap();
        let stats = server.stats().unwrap();
        let began = Instant::now();
        let mut stream = vmess_client(server.local_addresses()[0]).await;
        waiting.await.unwrap();
        assert_eq!(online(&stats), 1, "user must be online during dialing");
        assert_eq!(traffic(&stats, "outbound>>>out", "uplink"), 3);
        assert!(timeout(Duration::from_millis(2500), stream.read_u8()).await.unwrap().is_err());
        assert!(began.elapsed() < Duration::from_millis(2500));
        wait_online(&stats, 0).await;
        remote_task.await.unwrap();
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

async fn routed_api(
    idle: u32,
) -> (
    Server,
    Arc<StatsManager>,
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let server = Server::start(config(json!({
        "stats":{},"policy":policy(idle),"inbounds":[vmess_inbound()],
        "outbounds":[{"tag":"unused","protocol":"blackhole"}],
        "api":{"tag":"management","services":["StatsService"]},
        "routing":{"rules":[{"inboundTag":["in"],"outboundTag":"management"}]}
    })))
    .await
    .unwrap();
    let stats = server.stats().unwrap();
    let stream = vmess_client(server.local_addresses()[0]).await;
    let (sender, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);
    (server, stats, sender, driver)
}

async fn query_stats(sender: &mut h2::client::SendRequest<Bytes>) {
    std::future::poll_fn(|cx| sender.poll_ready(cx))
        .await
        .unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("http://management.test/xray.app.stats.command.StatsService/QueryStats")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, mut request_body) = sender.send_request(request, false).unwrap();
    request_body
        .send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), true)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        bytes.extend_from_slice(&chunk);
    }
    assert!(bytes.len() > 5, "StatsService returned no counters");
    assert_eq!(body.trailers().await.unwrap().unwrap()["grpc-status"], "0");
}

#[tokio::test]
async fn routed_api_keeps_vmess_user_accounting_and_expires_when_idle() {
    timeout(Duration::from_secs(5), async {
        let (server, stats, mut sender, driver) = routed_api(1).await;
        query_stats(&mut sender).await;
        assert_eq!(online(&stats), 1);
        let user = format!("user>>>{EMAIL}");
        assert!(traffic(&stats, &user, "uplink") > 0);
        assert!(traffic(&stats, &user, "downlink") > 0);
        assert!(traffic(&stats, "inbound>>>in", "uplink") > traffic(&stats, &user, "uplink"));
        assert!(traffic(&stats, "inbound>>>in", "downlink") > traffic(&stats, &user, "downlink"));
        let _ = timeout(Duration::from_millis(2500), driver)
            .await
            .expect("routed API bypassed connIdle")
            .unwrap();
        wait_online(&stats, 0).await;
        drop(sender);
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shutdown_releases_live_routed_api_user_and_closes_stream() {
    timeout(Duration::from_secs(5), async {
        let (server, stats, mut sender, driver) = routed_api(60).await;
        query_stats(&mut sender).await;
        assert_eq!(online(&stats), 1);
        timeout(Duration::from_secs(2), server.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(online(&stats), 0);
        let _ = timeout(Duration::from_secs(2), driver)
            .await
            .unwrap()
            .unwrap();
        drop(sender);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pipelined_http_payload_is_relayed_and_counted_once() {
    timeout(Duration::from_secs(5), async {
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = remote.local_addr().unwrap();
        let remote_task = tokio::spawn(async move {
            let (mut stream, _) = remote.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let server = Server::start(config(json!({
            "stats":{},"policy":policy(3),
            "inbounds":[{"tag":"in","listen":"127.0.0.1","port":0,"protocol":"http","settings":{"accounts":[{"user":"user","pass":"pass"}]}}],
            "outbounds":[{"tag":"out","protocol":"freedom"}]
        }))).await.unwrap();
        let stats = server.stats().unwrap();
        let mut stream = TcpStream::connect(server.local_addresses()[0]).await.unwrap();
        let payload = b"already buffered payload";
        let header = format!("CONNECT {address} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
        let mut wire = header.as_bytes().to_vec();
        wire.extend_from_slice(payload);
        stream.write_all(&wire).await.unwrap();
        stream.shutdown().await.unwrap();
        let response_header = http_head(&mut stream).await;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        remote_task.await.unwrap();
        server.shutdown().await.unwrap();
        assert_eq!(traffic(&stats, "inbound>>>in", "uplink"), wire.len() as i64);
        assert_eq!(traffic(&stats, "inbound>>>in", "downlink"), (response_header.len() + payload.len()) as i64);
        for identity in ["user>>>user", "outbound>>>out"] {
            for direction in ["uplink", "downlink"] {
                assert_eq!(traffic(&stats, identity, direction), payload.len() as i64);
            }
        }
    }).await.unwrap();
}
