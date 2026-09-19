//! Root SOCKS UDP wiring: routing, policy admission, counters and owned lifetime.
use std::{net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
use xray_core::{
    Config, Server,
    address::Destination,
    protocol::udp::{decode_socks5_packet, encode_socks5_packet},
};

fn config(outbounds: Value, routing: Value, password: bool, idle: u32) -> Config {
    let mut settings = json!({"udp":true,"ip":"127.0.0.1"});
    if password {
        settings["auth"] = json!("password");
        settings["accounts"] = json!([{"user":"alice","pass":"pw"}]);
    }
    Config::from_json(&json!({
        "stats":{},
        "policy":{"levels":{"0":{"connIdle":idle,"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}},
            "system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}},
        "inbounds":[{"tag":"udp-in","listen":"127.0.0.1","port":0,"protocol":"socks","settings":settings}],
        "outbounds":outbounds,"routing":routing
    }).to_string()).unwrap()
}

async fn associate(server: &Server, password: bool) -> (TcpStream, SocketAddr, UdpSocket) {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from(([127, 0, 0, 2], 0))).unwrap();
    let mut control = socket.connect(server.local_addresses()[0]).await.unwrap();
    let method = if password { 2 } else { 0 };
    control.write_all(&[5, 1, method]).await.unwrap();
    let mut reply = [0; 2];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, method]);
    if password {
        control.write_all(b"\x01\x05alice\x02pw").await.unwrap();
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
    }
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut status = [0; 3];
    control.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [5, 0, 0]);
    let relay = Destination::read_socks(&mut control).await.unwrap();
    let xray_core::address::Address::Ip(ip) = relay.address else {
        panic!("UDP relay must be numeric")
    };
    let socket = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    (control, SocketAddr::new(ip, relay.port), socket)
}

async fn exchange(socket: &UdpSocket, relay: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let packet = encode_socks5_packet(&Destination::from(target), payload).unwrap();
    socket.send_to(&packet, relay).await.unwrap();
    let mut bytes = [0; 8192];
    let (count, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, relay);
    let response = decode_socks5_packet(&bytes[..count]).unwrap();
    assert_eq!(response.destination, Destination::from(target));
    assert_eq!(response.payload, payload);
}

#[tokio::test]
async fn authenticated_association_routes_udp_and_preserves_accounting_boundaries() {
    timeout(Duration::from_secs(6), async {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut bytes = [0; 8192];
            let (length, from) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..length], from).await.unwrap();
        });
        let server = Server::start(config(
            json!([{"tag":"default-drop","protocol":"blackhole"},{"tag":"udp-direct","protocol":"freedom"}]),
            json!({"rules":[{"inboundTag":["udp-in"],"network":"udp","port":target.port(),"outboundTag":"udp-direct"}]}),
            true, 5,
        )).await.unwrap();
        let stats = server.stats().unwrap();
        let (mut control, relay, socket) = associate(&server, true).await;
        let online = stats.get_online_map("user>>>alice>>>online").unwrap();
        assert_eq!(online.count(), 1);
        let payload = b"accounted UDP body";
        exchange(&socket, relay, target, payload).await;
        peer.await.unwrap();
        control.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        control.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        assert_eq!(online.count(), 0);
        // Control-close cleanup joins the UDP workers before closing TCP.
        let rebound = UdpSocket::bind(relay).await.unwrap();
        drop(rebound);
        server.shutdown().await.unwrap();
        for scope in ["user>>>alice", "outbound>>>udp-direct"] {
            for direction in ["uplink", "downlink"] {
                assert_eq!(stats.stat(&format!("{scope}>>>traffic>>>{direction}"), false).unwrap().value, payload.len() as i64);
            }
        }
        assert_eq!(stats.stat("inbound>>>udp-in>>>traffic>>>uplink", false).unwrap().value, 23);
        assert_eq!(stats.stat("inbound>>>udp-in>>>traffic>>>downlink", false).unwrap().value, 14);
        assert_eq!(stats.stat("outbound>>>default-drop>>>traffic>>>uplink", false).unwrap().value, 0);
    }).await.unwrap();
}

#[tokio::test]
async fn every_packet_obeys_udp_routing_and_final_admission_without_proxy_fallback() {
    timeout(Duration::from_secs(6), async {
        let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blocked_target = blocked.local_addr().unwrap();
        let unsupported = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unsupported_target = unsupported.local_addr().unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut bytes = [0; 8192];
            let (length, from) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..length], from).await.unwrap();
        });
        let server = Server::start(config(
            json!([
                {"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"block","network":"udp","ip":["127.0.0.1"],"port":blocked_target.port()}]}},
                {"tag":"tcp-only","protocol":"socks","settings":{"address":"127.0.0.1","port":proxy_address.port()}}
            ]),
            json!({"rules":[{"network":"udp","port":unsupported_target.port(),"outboundTag":"tcp-only"}]}),
            false, 5,
        )).await.unwrap();
        let (control, relay, socket) = associate(&server, false).await;
        for target in [blocked_target, unsupported_target] {
            let packet = encode_socks5_packet(&Destination::from(target), b"must not arrive").unwrap();
            socket.send_to(&packet, relay).await.unwrap();
        }
        exchange(&socket, relay, target, b"allowed packet").await;
        peer.await.unwrap();
        let mut bytes = [0; 8192];
        assert!(timeout(Duration::from_millis(50), blocked.recv_from(&mut bytes)).await.is_err());
        assert!(timeout(Duration::from_millis(50), unsupported.recv_from(&mut bytes)).await.is_err());
        assert!(timeout(Duration::from_millis(50), proxy.accept()).await.is_err());
        drop(control);
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn idle_and_server_shutdown_release_udp_associations() {
    timeout(Duration::from_secs(6), async {
        for (idle, stop_server) in [(1, false), (60, true)] {
            let server = Server::start(config(
                json!([{"tag":"direct","protocol":"freedom"}]),
                json!({}),
                true,
                idle,
            ))
            .await
            .unwrap();
            let stats = server.stats().unwrap();
            let (mut control, relay, _socket) = associate(&server, true).await;
            assert_eq!(
                stats
                    .get_online_map("user>>>alice>>>online")
                    .unwrap()
                    .count(),
                1
            );
            if stop_server {
                timeout(Duration::from_secs(2), server.shutdown())
                    .await
                    .unwrap()
                    .unwrap();
            } else {
                assert_eq!(
                    timeout(Duration::from_millis(2500), control.read(&mut [0]))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
                server.shutdown().await.unwrap();
            }
            assert_eq!(
                stats
                    .get_online_map("user>>>alice>>>online")
                    .unwrap()
                    .count(),
                0
            );
            let rebound = UdpSocket::bind(relay).await.unwrap();
            drop(rebound);
        }
    })
    .await
    .unwrap();
}
