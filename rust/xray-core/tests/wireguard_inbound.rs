//! WireGuard inbound integration tests over the crate's public surface: the
//! infra/conf/wireguard.go JSON shape compiled for the server role (exact
//! keys, defaults, and named rejections), and a real loopback session — a
//! server-role engine bound on 127.0.0.1:0 with a client-role engine (the
//! existing engine in client role, like the outbound tests) connecting and
//! relaying TCP sessions plus a UDP exchange through the userspace
//! netstack. The dispatcher handoff itself (hysteria_seam's
//! `dispatch_request`/UDP dispatch path) is crate-private and covered by the
//! in-crate `runtime::wireguard_inbound` tests with an echo seam; here the
//! echo relay stands in for the dispatcher, exactly like the hysteria
//! endpoint tests' mock seam.
//!
//! Fixtures: testing/scenarios/wireguard_test.go's key material (pairing
//! corrected the way the netstack and outbound tests did).

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

use xray_core::protocol::wireguard::{
    DEFAULT_MTU, DeviceConfig, Role, WireGuardConfig, WireGuardPeerConfig, parse_key,
};
use xray_core::protocol::wireguard_netstack::{WgNet, WgUdpSocket};

const SERVER_PRIVATE: &str = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=";
const SERVER_PUBLIC: &str = "MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=";
const CLIENT_PRIVATE: &str = "CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=";
const CLIENT_PUBLIC: &str = "osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=";

const WAIT: Duration = Duration::from_secs(5);

fn tunnel_v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// infra/conf/wireguard.go's JSON surface for the inbound (the `IsClient`
/// flag is set by registration, not JSON: the inbound compiles Role::Server).
fn inbound_settings(peers: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "secretKey": SERVER_PRIVATE,
        "address": ["10.0.0.1"],
        "mtu": 1420,
        "peers": peers,
    })
}

fn peer_settings(public_key: &str) -> serde_json::Value {
    serde_json::json!({
        "publicKey": public_key,
        "preSharedKey": "",
        "keepAlive": 25,
        "allowedIPs": ["10.0.0.2/32"],
        "email": "wg-peer@example.test",
        "level": 2,
    })
}

fn server_device() -> DeviceConfig {
    let raw: WireGuardConfig =
        serde_json::from_value(inbound_settings(serde_json::json!([peer_settings(
            CLIENT_PUBLIC
        ),])))
        .unwrap();
    raw.build(Role::Server).unwrap()
}

fn client_config(endpoint: SocketAddr) -> DeviceConfig {
    WireGuardConfig {
        secret_key: CLIENT_PRIVATE.to_owned(),
        // Go's client scenario: the client's tunnel address is the source the
        // server's user allowed-IPs must authorize.
        address: Some(vec!["10.0.0.2".to_owned()]),
        peers: vec![WireGuardPeerConfig {
            public_key: SERVER_PUBLIC.to_owned(),
            endpoint: endpoint.to_string(),
            allowed_ips: Some(vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()]),
            ..Default::default()
        }],
        ..Default::default()
    }
    .build(Role::Client)
    .unwrap()
}

/// Aborts a task on unwind or scope exit so no engine survives a test.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn pump_error(role: &str, result: anyhow::Result<()>) -> anyhow::Error {
    match result {
        Ok(()) => anyhow::anyhow!("the {role} engine pumps stopped unexpectedly"),
        Err(error) => error,
    }
}

/// One loopback-bound engine (server or client role) with its bound endpoint
/// and its pumps guarded for the test's lifetime, like the outbound runtime
/// tests' engines.
type LoopbackEngine = (
    SocketAddr,
    Arc<WgNet<WgUdpSocket>>,
    AbortOnDrop<anyhow::Result<()>>,
);

fn loopback_engine(config: DeviceConfig) -> anyhow::Result<LoopbackEngine> {
    let transport = WgUdpSocket::bind(SocketAddr::new(tunnel_v4(127, 0, 0, 1), 0))?;
    let endpoint = transport.local_addr()?;
    let engine = Arc::new(WgNet::new(config, transport)?);
    let runner = {
        let engine = Arc::clone(&engine);
        AbortOnDrop(tokio::spawn(async move { engine.run().await }))
    };
    Ok((endpoint, engine, runner))
}

#[test]
fn server_settings_match_the_go_json_surface() {
    let config = server_device();
    // infra/conf/wireguard.go's exact mappings for the server role.
    assert_eq!(config.role, Role::Server);
    assert_eq!(config.mtu, DEFAULT_MTU);
    assert_eq!(config.addresses, vec![tunnel_v4(10, 0, 0, 1)]);
    // Inbound peers become users: level and email are kept, the endpoint is
    // dropped (Go's MemoryAccount carries no endpoint), keepAlive is the
    // formatted seconds interval, and the preshared key is optional.
    let peer = &config.peers[0];
    assert_eq!(peer.level, 2);
    assert_eq!(peer.email, "wg-peer@example.test");
    assert_eq!(peer.persistent_keepalive, Some(25));
    assert!(peer.preshared_key.is_none());
    assert_eq!(peer.endpoint, None);
    assert_eq!(
        peer.allowed_ips,
        vec!["10.0.0.2/32".parse::<ipnet::IpNet>().unwrap()]
    );
    // The server zeroes the reserved marker (Go's server bind has none).
    assert_eq!(config.reserved, [0; 3]);

    // Defaults with an empty object: Go's bogon addresses, the 1420 MTU, and
    // the 0.0.0.0/0 + ::0/0 allowed-IP defaults. A server with no peers
    // compiles (Go's NewServer imposes no peer requirement; the users list
    // is simply empty).
    let empty: WireGuardConfig =
        serde_json::from_value(serde_json::json!({"secretKey": SERVER_PRIVATE})).unwrap();
    let config = empty.build(Role::Server).unwrap();
    assert_eq!(
        config.addresses,
        vec![
            tunnel_v4(10, 0, 0, 1),
            "fd59:7153:2388:b5fd::1".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(config.mtu, 1420);
    assert!(config.peers.is_empty());

    let raw: WireGuardConfig = serde_json::from_value(serde_json::json!({
        "secretKey": SERVER_PRIVATE,
        "peers": [{"publicKey": CLIENT_PUBLIC}],
    }))
    .unwrap();
    let config = raw.build(Role::Server).unwrap();
    assert_eq!(
        config.peers[0].allowed_ips,
        vec![
            "0.0.0.0/0".parse::<ipnet::IpNet>().unwrap(),
            "::/0".parse::<ipnet::IpNet>().unwrap(),
        ]
    );

    // Go's ParseWireGuardKey accepts hex, standard Base64, and URL-safe
    // Base64 encodings of the 32 device key bytes.
    let hexed: String = (0..32).map(|byte| format!("{byte:02x}")).collect();
    let url_safe = SERVER_PUBLIC.replace('+', "-");
    for encoded in [hexed, url_safe] {
        parse_key(&encoded).unwrap();
    }
}

#[test]
fn server_settings_reject_go_error_cases_with_named_errors() {
    // infra/conf/wireguard.go Build + server.go NewServer rejections.
    for bad in [
        serde_json::json!({}),                         // empty secret key
        serde_json::json!({"secretKey": "not-a-key"}), // undecodable key
    ] {
        let raw: WireGuardConfig = serde_json::from_value(bad).unwrap();
        let error = raw.build(Role::Server).unwrap_err();
        assert!(
            format!("{error:#}").contains("key"),
            "unexpected error: {error:#}"
        );
    }
    // `"reserved" should be empty or 3 bytes`.
    let raw: WireGuardConfig = serde_json::from_value(serde_json::json!({
        "secretKey": SERVER_PRIVATE,
        "reserved": [1, 2],
    }))
    .unwrap();
    let error = raw.build(Role::Server).unwrap_err();
    assert!(
        format!("{error:#}").contains("reserved"),
        "unexpected error: {error:#}"
    );
    // allowedIPs entries must be prefixes (Go's netip.ParsePrefix).
    let raw: WireGuardConfig = serde_json::from_value(inbound_settings(serde_json::json!([{
        "publicKey": CLIENT_PUBLIC,
        "allowedIPs": ["10.0.0.1"],
    }])))
    .unwrap();
    let error = raw.build(Role::Server).unwrap_err();
    assert!(
        format!("{error:#}").contains("allowed IP"),
        "unexpected error: {error:#}"
    );
    // A peer using the server's own public key (Go's AddUser "invalid
    // public key") is rejected when the engine is built.
    let own_public = xray_core::protocol::wireguard::SecretKey::parse(SERVER_PRIVATE)
        .unwrap()
        .public_key();
    let encoded = STANDARD.encode(own_public);
    let raw: WireGuardConfig = serde_json::from_value(inbound_settings(serde_json::json!([
        {"publicKey": encoded},
    ])))
    .unwrap();
    // `WireGuardDevice` carries no Debug, so match instead of unwrap_err.
    let error = match xray_core::protocol::wireguard::WireGuardDevice::new(
        raw.build(Role::Server).unwrap(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a peer using the server's own public key must be rejected"),
    };
    assert!(
        format!("{error:#}").contains("local public key"),
        "unexpected error: {error:#}"
    );
}

/// The catch-all listener bind the inbound's forwarder uses: the unspecified
/// address makes the netstack listener match every destination address and
/// family on the port, so the served destination is fully arbitrary (Go's
/// promiscuous + spoofing forwarder).
fn catch_all(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
}

#[tokio::test]
async fn server_accepts_sessions_to_arbitrary_destinations() {
    const SESSION_PORT: u16 = 4747;
    let (endpoint, server, mut server_runner) = loopback_engine(server_device()).unwrap();
    let (_client_endpoint, client, mut client_runner) =
        loopback_engine(client_config(endpoint)).unwrap();
    let work = async {
        // The listener is installed before the client dials, so the first
        // SYN meets a listening socket (the inbound runtime bootstraps it
        // by peeking SYNs; the public adapter has no such hook, so the test
        // installs it up front for the fixed session port).
        let mut listener = server
            .netstack()
            .listen_tcp(catch_all(SESSION_PORT))
            .await?;
        let first_remote = SocketAddr::new(tunnel_v4(192, 0, 2, 10), SESSION_PORT);
        let mut first = client
            .netstack()
            .dial_tcp(
                SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_101),
                first_remote,
            )
            .await?;
        let (conn, source) = listener.accept().await?;
        // The dispatch handoff's semantics: the source is the peer's tunnel
        // address, the local endpoint is the original requested destination.
        assert_eq!(source.ip(), tunnel_v4(10, 0, 0, 2));
        assert_eq!(source.port(), 40_101);
        assert_eq!(conn.local_addr(), first_remote);
        assert_eq!(conn.remote_addr().ip(), tunnel_v4(10, 0, 0, 2));
        let echo = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(conn);
            tokio::io::copy(&mut reader, &mut writer).await
        });
        let payload: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
        first.write_all(&payload).await?;
        let mut echoed = vec![0u8; payload.len()];
        first.read_exact(&mut echoed).await?;
        assert_eq!(echoed, payload);
        drop(first);
        timeout(Duration::from_secs(2), echo)
            .await
            .expect("echo finished")
            .expect("echo task alive")?;

        // A second destination on the same port through the same listener:
        // the transparency the single Go forwarder provides.
        let second_remote = SocketAddr::new(tunnel_v4(198, 51, 100, 7), SESSION_PORT);
        let mut second = client
            .netstack()
            .dial_tcp(
                SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_102),
                second_remote,
            )
            .await?;
        let (conn, source) = listener.accept().await?;
        assert_eq!(source.port(), 40_102);
        assert_eq!(conn.local_addr(), second_remote);
        let echo = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(conn);
            tokio::io::copy(&mut reader, &mut writer).await
        });
        second.write_all(b"second destination").await?;
        let mut echoed = vec![0u8; b"second destination".len()];
        second.read_exact(&mut echoed).await?;
        assert_eq!(echoed, b"second destination");
        drop(second);
        timeout(Duration::from_secs(2), echo)
            .await
            .expect("echo finished")
            .expect("echo task alive")?;
        anyhow::Ok(())
    };
    timeout(WAIT, async {
        tokio::select! {
            result = &mut client_runner.0 => Err(pump_error("client", result.unwrap())),
            result = &mut server_runner.0 => Err(pump_error("server", result.unwrap())),
            result = work => result,
        }
    })
    .await
    .expect("session test finished within the deadline")
    .unwrap();
}

#[tokio::test]
async fn server_relays_udp_datagrams_with_spoofed_reply_sources() {
    let (endpoint, server, mut server_runner) = loopback_engine(server_device()).unwrap();
    let (_client_endpoint, client, mut client_runner) =
        loopback_engine(client_config(endpoint)).unwrap();
    let work = async {
        // The UDP path the inbound's udpManager drives: inbound datagrams on
        // any destination, replies written back with the queried destination
        // as the source address (Go's writeRawUDPPacket spoofing).
        let source = SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_202);
        let target = SocketAddr::new(tunnel_v4(192, 0, 2, 53), 53);
        client.netstack().udp_send(source, target, b"query").await?;
        let datagram = server.netstack().udp_recv().await?;
        assert_eq!(datagram.payload, b"query");
        assert_eq!(datagram.source, source);
        assert_eq!(datagram.destination, target);
        server
            .netstack()
            .udp_send(target, source, b"answer")
            .await?;
        let reply = client.netstack().udp_recv().await?;
        assert_eq!(reply.payload, b"answer");
        assert_eq!(reply.source, target);
        assert_eq!(reply.destination, source);
        anyhow::Ok(())
    };
    timeout(WAIT, async {
        tokio::select! {
            result = &mut client_runner.0 => Err(pump_error("client", result.unwrap())),
            result = &mut server_runner.0 => Err(pump_error("server", result.unwrap())),
            result = work => result,
        }
    })
    .await
    .expect("UDP test finished within the deadline")
    .unwrap();
}
