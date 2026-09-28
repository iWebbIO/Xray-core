//! sockopt settings matrix, real-socket application of the applicable
//! options, and the acceptProxyProtocol accept flow. Everything runs on
//! loopback sockets with bounded waits; the settings assertions mirror
//! Go's infra/conf/transport_sockopt.go and the per-platform
//! transport/internet/sockopt_*.go files.

use std::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::Duration,
};

use serde_json::json;
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_core::transport::{
    proxy_protocol_runtime::accept_proxy_protocol,
    sockopt::{CompiledSockopt, SockoptSettings},
};

fn compile(value: serde_json::Value) -> anyhow::Result<CompiledSockopt> {
    SockoptSettings::from_value(&value)?.compile()
}

// ---------------------------------------------------------------------------
// Settings matrix (public config surface)
// ---------------------------------------------------------------------------

#[test]
fn settings_matrix_parses_every_go_key() {
    let settings = SockoptSettings::from_value(&json!({
        "mark": 5,
        "tcpFastOpen": true,
        "tproxy": "redirect",
        "acceptProxyProtocol": true,
        "domainStrategy": "ForceIPv4",
        "dialerProxy": "tag",
        "tcpKeepAliveInterval": 15,
        "tcpKeepAliveIdle": 30,
        "tcpCongestion": "bbr",
        "tcpWindowClamp": 1024,
        "tcpMaxSeg": 536,
        "penetrate": true,
        "tcpUserTimeout": 3000,
        "v6only": true,
        "interface": "eth0",
        "tcpMptcp": true,
        "customSockopt": [{
            "system": "", "network": "tcp", "level": "6",
            "opt": "1", "value": "1", "type": "int"
        }],
        "addressPortStrategy": "TxtPortOnly",
        "happyEyeballs": {
            "prioritizeIPv6": true, "tryDelayMs": 100,
            "interleave": 2, "maxConcurrentTry": 8
        },
        "trustedXForwardedFor": ["127.0.0.1"]
    }))
    .expect("every Go key must parse");
    assert_eq!(settings.mark, 5);
    assert!(settings.accept_proxy_protocol);
    assert_eq!(settings.tcp_keep_alive_interval, 15);
    assert_eq!(settings.happy_eyeballs.unwrap().max_concurrent_try, 8);
    assert_eq!(settings.trusted_x_forwarded_for, vec!["127.0.0.1"]);
}

#[test]
fn settings_matrix_denies_unknown_keys() {
    let error = SockoptSettings::from_value(&json!({"sockoptExtra": 1}))
        .expect_err("unknown keys must fail");
    assert!(error.to_string().contains("sockoptExtra"), "{error}");
}

#[test]
fn settings_matrix_names_each_unsupported_option() {
    for (key, option) in [
        (json!({"mark": 5}), "mark"),
        (json!({"tcpFastOpen": true}), "tcpFastOpen"),
        (json!({"tproxy": "tproxy"}), "tproxy"),
        (json!({"dialerProxy": "wg"}), "dialerProxy"),
        (json!({"tcpCongestion": "bbr"}), "tcpCongestion"),
        (json!({"tcpWindowClamp": 1024}), "tcpWindowClamp"),
        (json!({"tcpMaxSeg": 536}), "tcpMaxSeg"),
        (json!({"tcpUserTimeout": 3000}), "tcpUserTimeout"),
        (json!({"interface": "eth0"}), "interface"),
        (json!({"tcpMptcp": true}), "tcpMptcp"),
        (
            json!({"customSockopt": [{"opt": "1", "value": "1", "type": "int"}]}),
            "customSockopt[0]",
        ),
    ] {
        let message = compile(key.clone())
            .expect_err("unsupported option must fail compile")
            .to_string();
        assert!(message.contains(&format!("`{option}`")), "{key}: {message}");
    }
}

#[test]
fn settings_matrix_compiles_the_applicable_surface() {
    let compiled = compile(json!({
        "acceptProxyProtocol": true,
        "domainStrategy": "UseIPv4v6",
        "addressPortStrategy": "SrvPortAndAddress",
        "happyEyeballs": {"tryDelayMs": 250},
        "trustedXForwardedFor": ["10.0.0.0/8"],
        "tcpKeepAliveIdle": 30,
        "tcpKeepAliveInterval": 15,
        "v6only": true,
        "penetrate": true
    }))
    .expect("the applicable options must compile");
    assert!(compiled.accept_proxy_protocol);
    assert!(compiled.penetrate);
    assert!(compiled.v6only);
    assert_eq!(
        compiled.keepalive,
        xray_core::transport::sockopt::KeepalivePlan {
            time: Some(Duration::from_secs(30)),
            interval: Some(Duration::from_secs(15)),
            disable: false,
        }
    );
    assert_eq!(
        compiled.happy_eyeballs,
        xray_core::transport::sockopt::HappyEyeballs {
            try_delay_ms: 250,
            ..xray_core::transport::sockopt::HappyEyeballs::default()
        }
    );
    assert_eq!(compiled.trusted_x_forwarded_for, vec!["10.0.0.0/8"]);
    // Defaults compile too and keep Go's happy-eyeballs fallback values.
    let empty = compile(json!({})).unwrap();
    assert_eq!(empty.happy_eyeballs.interleave, 1);
    assert_eq!(empty.happy_eyeballs.max_concurrent_try, 4);
    assert_eq!(
        empty.keepalive,
        xray_core::transport::sockopt::KeepalivePlan::default()
    );
}

// ---------------------------------------------------------------------------
// Applicable socket options on real loopback sockets
// ---------------------------------------------------------------------------

fn loopback_pair() -> (TcpListener, TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let address = listener.local_addr().unwrap();
    let dialer = TcpStream::connect(address).expect("connect loopback");
    let (accepted, _) = listener.accept().expect("accept loopback");
    (listener, dialer, accepted)
}

#[test]
fn outbound_keepalive_enables_like_go_chrome_defaults() {
    let (_listener, dialer, accepted) = loopback_pair();
    // Unconfigured keepalive still enables 45s/45s: Go's DefaultSystemDialer
    // always dials with the "Chrome defaults" unless the sockopt overrides
    // or disables them. Observable as SO_KEEPALIVE flipping on.
    let compiled = compile(json!({})).unwrap();
    let reference = SockRef::from(&dialer);
    if reference.keepalive().unwrap() {
        panic!("test precondition: a fresh socket must not have keepalive on");
    }
    compiled
        .apply_outbound(xray_core::transport::sockopt::SocketNet::Tcp4, &reference)
        .unwrap();
    assert!(reference.keepalive().unwrap());
    // apply_keepalive replays a CONFIGURED plan on any socket, e.g. on each
    // accepted connection of an inbound (Go's KeepAliveConfig on accept).
    let configured = compile(json!({
        "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15
    }))
    .unwrap();
    let accepted_socket = SockRef::from(&accepted);
    assert!(!accepted_socket.keepalive().unwrap());
    configured.apply_keepalive(&accepted_socket).unwrap();
    assert!(accepted_socket.keepalive().unwrap());
}

#[test]
fn outbound_keepalive_honors_explicit_values_and_disable() {
    let (_listener, dialer, _accepted) = loopback_pair();
    let compiled = compile(json!({
        "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15
    }))
    .unwrap();
    let socket = SockRef::from(&dialer);
    compiled
        .apply_outbound(xray_core::transport::sockopt::SocketNet::Tcp4, &socket)
        .unwrap();
    assert!(socket.keepalive().unwrap());

    // A negative value disables keepalive explicitly (Go: KeepAlive = -1).
    let disabled = compile(json!({"tcpKeepAliveIdle": -1})).unwrap();
    disabled
        .apply_outbound(xray_core::transport::sockopt::SocketNet::Tcp4, &socket)
        .unwrap();
    assert!(!socket.keepalive().unwrap());
    disabled.apply_keepalive(&socket).unwrap();
    assert!(!socket.keepalive().unwrap());
}

#[test]
fn udp_dials_skip_the_tcp_only_options() {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let compiled = compile(json!({"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15})).unwrap();
    // Go guards every TCP option behind isTCPSocket(network); keepalive is
    // simply not attempted on a UDP socket.
    compiled
        .apply_outbound(
            xray_core::transport::sockopt::SocketNet::Udp4,
            &SockRef::from(&socket),
        )
        .unwrap();
    compiled
        .apply_inbound(
            xray_core::transport::sockopt::SocketNet::Udp4,
            &SockRef::from(&socket),
        )
        .unwrap();
    // (SO_KEEPALIVE itself is a TCP-only option on Windows — 10042 on a UDP
    // socket — so there is nothing further to observe here.)
}

#[test]
fn inbound_v6only_sets_the_dualstack_flag_before_bind() {
    // Go applies IPV6_V6ONLY in the listener's Control hook, which runs on
    // the fd AFTER socket creation but BEFORE bind(); on Windows the option
    // is only settable pre-bind (WSAEINVAL after). Mirror that order: an
    // unbound socket2 socket, apply, then bind and listen on [::1].
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("create ipv6 stream socket");
    let compiled = compile(json!({"v6only": true})).unwrap();
    let reference = SockRef::from(&socket);
    compiled
        .apply_inbound(xray_core::transport::sockopt::SocketNet::Tcp6, &reference)
        .unwrap();
    assert!(reference.only_v6().unwrap());
    let bound = "[::1]:0".parse::<std::net::SocketAddr>().unwrap();
    socket.bind(&bound.into()).expect("bind ipv6 loopback");
    socket.listen(16).expect("listen ipv6 loopback");
    // The flag survives bind+listen, and the whole Go Control-hook shape
    // (create -> apply -> bind -> listen) is exercised on a real socket.
    assert!(SockRef::from(&socket).only_v6().unwrap());
}

#[test]
fn inbound_v6only_on_an_ipv4_socket_fails_explicitly() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let compiled = compile(json!({"v6only": true})).unwrap();
    let error = compiled
        .apply_inbound(
            xray_core::transport::sockopt::SocketNet::Tcp4,
            &SockRef::from(&listener),
        )
        .expect_err("v6only on an IPv4 socket must fail explicitly");
    assert!(
        error.to_string().contains("v6only"),
        "the error must name the option: {error}"
    );
}

#[test]
fn inbound_keepalive_follows_the_listener_defaults() {
    // Configured idle/interval: SO_KEEPALIVE flips on (Go's
    // applyInboundSocketOptions + the listener KeepAliveConfig).
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let compiled = compile(json!({"tcpKeepAliveIdle": 30})).unwrap();
    let socket = SockRef::from(&listener);
    assert!(!socket.keepalive().unwrap());
    compiled
        .apply_inbound(xray_core::transport::sockopt::SocketNet::Tcp4, &socket)
        .unwrap();
    assert!(socket.keepalive().unwrap());
    // No keepalive configured: Go's listener defaults to disabled
    // (net.ListenConfig.KeepAlive = -1).
    let plain = compile(json!({})).unwrap();
    plain
        .apply_inbound(xray_core::transport::sockopt::SocketNet::Tcp4, &socket)
        .unwrap();
    assert!(!socket.keepalive().unwrap());
}

// ---------------------------------------------------------------------------
// acceptProxyProtocol accept flow over a duplex
// ---------------------------------------------------------------------------

const V1: &[u8] = b"PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n";

#[tokio::test]
async fn proxy_protocol_v1_accept_flow_over_duplex() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut wire = V1.to_vec();
        wire.extend_from_slice(b"socks request bytes");
        writer.write_all(&wire).await.unwrap();
        writer.shutdown().await.unwrap();
        let mut accepted = accept_proxy_protocol(reader).await.unwrap();
        assert_eq!(
            accepted.source_addr(),
            Some("192.0.2.1:12345".parse().unwrap())
        );
        assert_eq!(
            accepted.destination_addr(),
            Some("198.51.100.2:443".parse().unwrap())
        );
        accepted.stream().write_all(b"reply").await.unwrap();
        let mut echoed = [0u8; 5];
        writer.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"reply");
        let mut replayed = Vec::new();
        accepted.stream().read_to_end(&mut replayed).await.unwrap();
        assert_eq!(replayed, b"socks request bytes");
    })
    .await
    .expect("proxy protocol v1 flow timed out");
}

#[tokio::test]
async fn proxy_protocol_malformed_header_drops_the_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut writer, reader) = tokio::io::duplex(1024);
        // A plain SOCKS greeting is not a PROXY header; under Go's REQUIRE
        // policy the accept fails and the hub drops the connection.
        writer.write_all(b"\x05\x01\x00").await.unwrap();
        writer.shutdown().await.unwrap();
        let error = match accept_proxy_protocol(reader).await {
            Ok(_) => panic!("absent header must be rejected under REQUIRE"),
            Err(error) => error,
        };
        assert!(
            error.to_string().to_lowercase().contains("proxy"),
            "{error}"
        );
        assert_eq!(writer.read(&mut [0u8; 1]).await.unwrap(), 0);
    })
    .await
    .expect("proxy protocol malformed flow timed out");
}

#[tokio::test]
async fn proxy_protocol_accept_flow_on_a_real_loopback_listener() {
    // The exact runtime call shape: TCP accept -> acceptProxyProtocol ->
    // the transport accept chain sees only the replayed application bytes.
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let ((), ()) = tokio::join!(
            async {
                let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
                let mut wire = V1.to_vec();
                wire.extend_from_slice(b"application");
                client.write_all(&wire).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"ack");
            },
            async {
                let (stream, _real_peer) = listener.accept().await.unwrap();
                let mut accepted = accept_proxy_protocol(stream).await.unwrap();
                assert_eq!(
                    accepted.source_addr(),
                    Some("192.0.2.1:12345".parse().unwrap())
                );
                let mut application = Vec::new();
                accepted
                    .stream()
                    .read_to_end(&mut application)
                    .await
                    .unwrap();
                assert_eq!(application, b"application");
                accepted.stream().write_all(b"ack").await.unwrap();
                accepted.stream().shutdown().await.unwrap();
            }
        );
    })
    .await
    .expect("proxy protocol loopback flow timed out");
}
