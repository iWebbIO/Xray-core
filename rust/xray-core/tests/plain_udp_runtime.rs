//! End-to-end: legacy Shadowsocks UDP and dokodemo UDP through a real server.

use std::{net::SocketAddr, time::Duration};

use serde_json::json;
use tokio::{net::UdpSocket, time::timeout};
use xray_core::{Config, Server, protocol::shadowsocks_udp};

/// Bind an ephemeral TCP port, release it, and return the port so the
/// inbound's TCP and UDP listeners share one explicit port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// A UDP echo service.
async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((size, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..size], from).await;
        }
    });
    (address, task)
}

#[tokio::test]
async fn legacy_shadowsocks_udp_relays_datagrams() {
    timeout(Duration::from_secs(15), async {
        let (echo, echo_task) = udp_echo().await;
        let config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": free_port().await, "tag": "ss-in", "protocol": "shadowsocks",
                    "settings": {"method": "aes-256-gcm", "password": "legacy-test-password", "network": "tcp,udp"}
                }],
                "outbounds": [{
                    "tag": "direct", "protocol": "freedom",
                    "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo.port()}
                    ]}
                }]
            })
            .to_string(),
        )
        .unwrap();
        let server = Server::start(config).await.unwrap();
        let listener = server.local_addresses()[0];
        let cipher = shadowsocks_udp::LegacyCipher::from_password(
            xray_core::protocol::shadowsocks::CipherKind::Aes256Gcm,
            b"legacy-test-password",
        );
        let mut client = shadowsocks_udp::LegacyUdp::new(cipher);
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire = client
            .encode(
                &echo.into(),
                b"legacy udp payload",
                std::time::Instant::now(),
                &mut rand::rngs::OsRng,
            )
            .unwrap();
        sender.send_to(&wire, listener).await.unwrap();
        let mut buffer = vec![0u8; 65_535];
        let (size, _) = timeout(Duration::from_secs(5), sender.recv_from(&mut buffer))
            .await
            .expect("legacy SS UDP reply timeout")
            .unwrap();
        let reply = client.decode(&buffer[..size], std::time::Instant::now()).unwrap();
        assert_eq!(reply.payload, b"legacy udp payload");
        assert_eq!(reply.destination, xray_core::address::Destination::from(echo));
        server.shutdown().await.unwrap();
        echo_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dokodemo_udp_relays_datagrams_to_the_fixed_destination() {
    timeout(Duration::from_secs(15), async {
        let (echo, echo_task) = udp_echo().await;
        let config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": free_port().await, "tag": "doko-in", "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1", "port": echo.port(), "network": "tcp,udp"}
                }],
                "outbounds": [{
                    "tag": "direct", "protocol": "freedom",
                    "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo.port()}
                    ]}
                }]
            })
            .to_string(),
        )
        .unwrap();
        let server = Server::start(config).await.unwrap();
        let listener = server.local_addresses()[0];
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"dokodemo payload", listener).await.unwrap();
        let mut buffer = [0u8; 2048];
        let (size, _) = timeout(Duration::from_secs(5), sender.recv_from(&mut buffer))
            .await
            .expect("dokodemo UDP reply timeout")
            .unwrap();
        assert_eq!(&buffer[..size], b"dokodemo payload");
        server.shutdown().await.unwrap();
        echo_task.abort();
    })
    .await
    .unwrap();
}
