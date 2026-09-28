//! Mux.Cool outbound end-to-end tests: carrier sharing against a manual
//! peer, the full runtime chain through a real server, and XUDP.

use std::{net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time::timeout,
};
use xray_core::{
    Config, Server, address::Destination, mux::Connection, mux::Options, protocol::vless,
    user::parse_id,
};

/// One TCP echo connection-serving listener, counting accepted connections.
struct Echo {
    address: SocketAddr,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        let Ok(size) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                            let _ = stream.shutdown().await;
                            return;
                        }
                    }
                });
            }
        });
        Echo { address, accepted }
    }
}

/// A SOCKS5 noauth CONNECT client.
async fn socks_connect(proxy: SocketAddr, destination: SocketAddr) -> std::io::Result<TcpStream> {
    let mut client = TcpStream::connect(proxy).await?;
    client.write_all(&[5, 1, 0]).await?;
    let mut methods = [0; 2];
    client.read_exact(&mut methods).await?;
    if methods != [5, 0] {
        return Err(std::io::Error::other("SOCKS server rejected noauth"));
    }
    client.write_all(&[5, 1, 0]).await?;
    Destination::from(destination)
        .write_socks(&mut client)
        .await
        .map_err(std::io::Error::other)?;
    let mut reply = [0; 3];
    client.read_exact(&mut reply).await?;
    if reply != [5, 0, 0] {
        return Err(std::io::Error::other("SOCKS CONNECT rejected"));
    }
    Destination::read_socks(&mut client)
        .await
        .map_err(std::io::Error::other)?;
    Ok(client)
}

/// The client proxy: SOCKS inbound, one VLESS outbound with mux enabled.
fn mux_client_config(remote: SocketAddr, mux: Value) -> Config {
    Config::from_json(
        &json!({
            "inbounds": [{
                "listen": "127.0.0.1", "port": 0, "tag": "socks-in", "protocol": "socks",
                "settings": {"auth": "noauth", "udp": true}
            }],
            "outbounds": [{
                "tag": "proxy", "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1", "port": remote.port(),
                    "id": "mux-user", "encryption": "none"
                },
                "mux": mux
            }]
        })
        .to_string(),
    )
    .unwrap()
}

/// The server proxy: VLESS inbound, freedom to the echo target (the scoped
/// allow defeats the private-IP default delay, exactly like the interop
/// tests' Go configs).
fn vless_server_config(echo_port: u16) -> Config {
    Config::from_json(
        &json!({
            "inbounds": [{
                "listen": "127.0.0.1", "port": 0, "tag": "vless-in", "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": "mux-user"}]}
            }],
            "outbounds": [{
                "tag": "direct", "protocol": "freedom",
                "settings": {"finalRules": [
                    {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo_port}
                ]}
            }]
        })
        .to_string(),
    )
    .unwrap()
}

fn account() -> vless::Account {
    vless::Account {
        id: *parse_id("mux-user").unwrap().as_bytes(),
        email: String::new(),
        flow: String::new(),
        level: 0,
    }
}

#[tokio::test]
async fn mux_enabled_outbound_relays_through_a_real_server() {
    timeout(Duration::from_secs(20), async {
        let echo = Echo::start().await;
        let server = Server::start(vless_server_config(echo.address.port()))
            .await
            .unwrap();
        let client = Server::start(mux_client_config(
            server.local_addresses()[0],
            json!({"enabled": true}),
        ))
        .await
        .unwrap();

        // Two logical connections through the same proxy outbound.
        for payload in ["first mux payload", "second mux payload"] {
            let mut stream = socks_connect(client.local_addresses()[0], echo.address)
                .await
                .unwrap();
            stream.write_all(payload.as_bytes()).await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload.as_bytes());
        }
        // Both logical connections reached the echo service.
        assert_eq!(
            echo.accepted.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "both mux streams must dispatch to the target"
        );
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn two_mux_streams_share_one_carrier_connection() {
    timeout(Duration::from_secs(20), async {
        let echo = Echo::start().await;
        // A manual VLESS peer: accepts the carrier, answers the VLESS
        // handshake, then serves every Mux.Cool session with an echo stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_address = listener.local_addr().unwrap();
        let (carrier_tx, mut carrier_rx) = mpsc::channel::<usize>(4);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            carrier_tx.send(1).await.unwrap();
            let accepted = vless::read_request(&mut stream, &[account()])
                .await
                .unwrap();
            assert_eq!(accepted.request.destination.to_string(), "v1.mux.cool:9527");
            vless::write_response(&mut stream).await.unwrap();
            let (connection, mut incoming) =
                Connection::server(Box::new(stream), Options::default()).unwrap();
            while let Some(session) = incoming.recv().await {
                let mut stream = session.into_stream().unwrap();
                let echo_address = echo.address;
                tokio::spawn(async move {
                    let mut upstream = TcpStream::connect(echo_address).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                });
            }
            let _ = connection;
        });

        let client = Server::start(mux_client_config(
            peer_address,
            json!({"enabled": true, "concurrency": 8}),
        ))
        .await
        .unwrap();

        for payload in ["shared carrier one", "shared carrier two"] {
            let mut stream = socks_connect(client.local_addresses()[0], echo.address)
                .await
                .unwrap();
            stream.write_all(payload.as_bytes()).await.unwrap();
            let mut echoed = [0u8; 18];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, payload.as_bytes());
        }

        // Exactly one carrier connection carried both streams.
        assert_eq!(carrier_rx.recv().await, Some(1));
        assert!(
            timeout(Duration::from_millis(300), carrier_rx.recv())
                .await
                .is_err(),
            "a second carrier connection must not be dialed"
        );
        client.shutdown().await.unwrap();
        peer.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn xudp_enabled_outbound_relays_udp_associations() {
    timeout(Duration::from_secs(20), async {
        // A UDP echo service.
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_socket.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let Ok((size, from)) = echo_socket.recv_from(&mut buffer).await else {
                    return;
                };
                let _ = echo_socket.send_to(&buffer[..size], from).await;
            }
        });

        let server = Server::start(vless_server_config(echo_address.port()))
            .await
            .unwrap();
        let client = Server::start(mux_client_config(
            server.local_addresses()[0],
            json!({"enabled": true, "xudpConcurrency": 8}),
        ))
        .await
        .unwrap();

        // A SOCKS UDP association through the mux-enabled outbound. The
        // associate reply carries the relay address.
        let mut associate = TcpStream::connect(client.local_addresses()[0])
            .await
            .unwrap();
        associate.write_all(&[5, 1, 0]).await.unwrap();
        let mut methods = [0; 2];
        associate.read_exact(&mut methods).await.unwrap();
        associate
            .write_all(&[5, 3, 0, 1, 0x7f, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut reply = [0; 3];
        associate.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0], "SOCKS UDP associate failed");
        let relay = Destination::read_socks(&mut associate)
            .await
            .map_err(std::io::Error::other)
            .unwrap();
        let relay = match relay.address {
            xray_core::address::Address::Ip(ip) => SocketAddr::new(ip, relay.port),
            _ => panic!("relay address must be numeric"),
        };

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // One SOCKS-framed datagram to the echo service.
        let mut packet = vec![0, 0, 0, 1, 0x7f, 0, 0, 1];
        let port = echo_address.port().to_be_bytes();
        packet.extend_from_slice(&port);
        packet.extend_from_slice(b"xudp payload");
        sender.send_to(&packet, relay).await.unwrap();

        let mut buffer = [0u8; 1500];
        let (size, _) = timeout(Duration::from_secs(5), sender.recv_from(&mut buffer))
            .await
            .expect("xudp reply timeout")
            .unwrap();
        // The reply is a SOCKS packet from the echo service.
        let reply = xray_core::protocol::udp::decode_socks5_packet(&buffer[..size]).unwrap();
        assert_eq!(reply.payload, b"xudp payload");

        echo.abort();
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn mux_settings_follow_go_build_semantics() {
    // The defaults: enabled off means no mux at all.
    let config = mux_client_config(
        SocketAddr::from(([127, 0, 0, 1], 1)),
        json!({"enabled": false}),
    );
    config.validate().unwrap();
    // xudpProxyUDP443 must name a known policy.
    let config = mux_client_config(
        SocketAddr::from(([127, 0, 0, 1], 1)),
        json!({"enabled": true, "xudpProxyUDP443": "nope"}),
    );
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("xudpProxyUDP443")
    );
    // The masque outbound rejects mux, like Go.
    let config = Config::from_json(
        &json!({
            "outbounds": [{
                "tag": "m", "protocol": "masque",
                "settings": {"address": "127.0.0.1", "port": 443},
                "streamSettings": {"network": "masque", "security": "tls"},
                "mux": {"enabled": true}
            }]
        })
        .to_string(),
    )
    .unwrap();
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not support")
    );
}
