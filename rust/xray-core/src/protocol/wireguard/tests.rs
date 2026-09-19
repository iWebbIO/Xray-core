use std::{net::SocketAddr, str::FromStr};

use base64::{Engine as _, engine::general_purpose};

use super::*;

// Independent key fixtures from testing/scenarios/wireguard_test.go. Its
// serverPublic/clientPublic variables name the configured REMOTE peer, so the
// local public identity below uses the opposite source variable's value.
const SERVER_PRIVATE: &str = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=";
const SERVER_PUBLIC: &str = "MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=";
const CLIENT_PRIVATE: &str = "CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=";
const CLIENT_PUBLIC: &str = "osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=";

fn client_address() -> SocketAddr {
    "127.0.0.1:51001".parse().unwrap()
}

fn server_address() -> SocketAddr {
    "127.0.0.1:51002".parse().unwrap()
}

fn settings(private: &str, public: &str, endpoint: &str) -> WireGuardConfig {
    WireGuardConfig {
        secret_key: private.to_owned(),
        peers: vec![WireGuardPeerConfig {
            public_key: public.to_owned(),
            endpoint: endpoint.to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn pair() -> (WireGuardDevice, WireGuardDevice) {
    let client = settings(CLIENT_PRIVATE, SERVER_PUBLIC, &server_address().to_string());
    let server = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    (
        WireGuardDevice::new(client.build(Role::Client).unwrap()).unwrap(),
        WireGuardDevice::new(server.build(Role::Server).unwrap()).unwrap(),
    )
}

fn network(actions: Vec<PacketAction>) -> Vec<Vec<u8>> {
    actions
        .into_iter()
        .map(|action| match action {
            PacketAction::Network { packet, .. } => packet,
            PacketAction::Tunnel { .. } => panic!("expected encrypted UDP output"),
        })
        .collect()
}

fn establish_from(
    client: &mut WireGuardDevice,
    server: &mut WireGuardDevice,
    client_addr: SocketAddr,
) {
    let first = network(client.initiate_handshake(0, false).unwrap());
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].len(), 148);
    assert_eq!(first[0][0], 1);
    let response = network(server.decapsulate(client_addr, &first[0]).unwrap());
    assert_eq!(response.len(), 1);
    assert_eq!(response[0].len(), 92);
    assert_eq!(response[0][0], 2);
    let confirmation = network(client.decapsulate(server_address(), &response[0]).unwrap());
    assert_eq!(confirmation.len(), 1);
    assert_eq!(confirmation[0].len(), DATA_OVERHEAD);
    assert_eq!(confirmation[0][0], 4);
    assert!(
        server
            .decapsulate(client_addr, &confirmation[0])
            .unwrap()
            .is_empty()
    );
}

fn establish(client: &mut WireGuardDevice, server: &mut WireGuardDevice) {
    establish_from(client, server, client_address());
}

fn ipv4(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    // A complete IPv4 protocol-253 test datagram with a valid header checksum.
    let mut packet = vec![0; 20 + payload.len()];
    packet[0] = 0x45;
    let length = (packet.len() as u16).to_be_bytes();
    packet[2..4].copy_from_slice(&length);
    packet[8] = 64;
    packet[9] = 253;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    let folded = (sum & 0xffff) + (sum >> 16);
    let checksum = !((folded & 0xffff) + (folded >> 16)) as u16;
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(payload);
    packet
}

fn ipv6(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40 + payload.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = 253;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&std::net::Ipv6Addr::from_str("fd00::2").unwrap().octets());
    packet[24..40].copy_from_slice(&std::net::Ipv6Addr::from_str("fd00::1").unwrap().octets());
    packet[40..].copy_from_slice(payload);
    packet
}

#[test]
fn go_scenario_keypairs_match_and_all_source_encodings_work() {
    for (private, public) in [
        (CLIENT_PRIVATE, CLIENT_PUBLIC),
        (SERVER_PRIVATE, SERVER_PUBLIC),
    ] {
        let secret = SecretKey::parse(private).unwrap();
        let expected = parse_key(public).unwrap();
        assert_eq!(secret.public_key(), expected);
        let hex = expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for encoded in [
            hex.clone(),
            hex.to_uppercase(),
            general_purpose::STANDARD.encode(expected),
            general_purpose::STANDARD_NO_PAD.encode(expected),
            general_purpose::URL_SAFE.encode(expected),
            general_purpose::URL_SAFE_NO_PAD.encode(expected),
        ] {
            assert_eq!(parse_key(&encoded).unwrap(), expected);
        }
        assert_eq!(format!("{secret:?}"), "SecretKey([REDACTED])");
    }
    for bad in ["", "AAAA", "not-a-key", &"z".repeat(64)] {
        assert!(parse_key(bad).is_err());
    }
}

#[test]
fn omitted_null_and_empty_lists_preserve_source_distinctions() {
    for value in [
        serde_json::json!({}),
        serde_json::json!({"address":null,"peers":[{"allowedIPs":null}]}),
    ] {
        let mut raw: WireGuardConfig = serde_json::from_value(value).unwrap();
        raw.secret_key = SERVER_PRIVATE.to_owned();
        if raw.peers.is_empty() {
            raw.peers.push(WireGuardPeerConfig::default());
        }
        raw.peers[0].public_key = CLIENT_PUBLIC.to_owned();
        let config = raw.build(Role::Server).unwrap();
        assert_eq!(
            config.addresses,
            vec![
                "10.0.0.1".parse::<std::net::IpAddr>().unwrap(),
                "fd59:7153:2388:b5fd::1".parse().unwrap()
            ]
        );
        assert_eq!(config.peers[0].allowed_ips.len(), 2);
        assert_eq!(config.mtu, 1420);
        assert!(matches!(config.remote_dns, RemoteDns::Servers(ref servers) if servers.len() == 4));
    }
    let mut raw = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    raw.address = Some(Vec::new());
    raw.peers[0].allowed_ips = Some(Vec::new());
    let config = raw.build(Role::Server).unwrap();
    assert!(config.addresses.is_empty());
    assert!(config.peers[0].allowed_ips.is_empty());
}

#[test]
fn address_prefix_keeps_host_and_route_prefix_is_normalized() {
    let mut raw = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    raw.address = Some(vec!["10.1.2.3/24".into(), "fd00::9/64".into()]);
    raw.peers[0].allowed_ips = Some(vec!["10.1.2.3/24".into()]);
    let config = raw.build(Role::Server).unwrap();
    assert_eq!(config.addresses[0].to_string(), "10.1.2.3");
    assert_eq!(config.addresses[1].to_string(), "fd00::9");
    assert_eq!(config.peers[0].allowed_ips[0].to_string(), "10.1.2.0/24");
}

#[test]
fn json_reserved_accepts_go_byte_array_and_base64_forms() {
    for encoded in [serde_json::json!([1, 2, 255]), serde_json::json!("AQL/")] {
        let raw: WireGuardConfig =
            serde_json::from_value(serde_json::json!({"reserved":encoded})).unwrap();
        assert_eq!(raw.reserved, [1, 2, 255]);
    }
    for encoded in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!(""),
    ] {
        let raw: WireGuardConfig =
            serde_json::from_value(serde_json::json!({"reserved":encoded})).unwrap();
        assert!(raw.reserved.is_empty());
    }
    assert!(
        serde_json::from_value::<WireGuardConfig>(serde_json::json!({"reserved":[256]})).is_err()
    );
}

#[test]
fn configuration_validation_and_server_user_metadata() {
    let mut raw = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    raw.peers[0].level = 5;
    raw.peers[0].email = "peer@example.test".into();
    assert!(raw.build(Role::Client).is_err());
    let server = raw.build(Role::Server).unwrap();
    assert_eq!(server.peers[0].level, 5);
    assert_eq!(server.peers[0].email, "peer@example.test");
    raw.peers[0].endpoint = "example.test:51820".into();
    assert!(raw.build(Role::Client).unwrap().peers[0].email.is_empty());
    raw.peers[0].keep_alive = 65_536;
    assert!(raw.build(Role::Server).is_err());
    raw.peers[0].keep_alive = 25;
    assert_eq!(
        raw.build(Role::Server).unwrap().peers[0].persistent_keepalive,
        Some(25)
    );
    raw.reserved = vec![1, 2];
    assert!(raw.build(Role::Server).is_err());
    raw.reserved.clear();
    raw.mtu = -1;
    assert!(raw.build(Role::Server).is_err());
    raw.mtu = 65_535;
    assert!(raw.build(Role::Server).is_err());
    raw.mtu = 0;
    raw.remote_dns = vec!["local".into()];
    assert_eq!(
        raw.build(Role::Server).unwrap().remote_dns,
        RemoteDns::Local
    );
    raw.remote_dns = vec!["dns.example.test".into()];
    assert!(raw.build(Role::Server).is_err());
}

#[test]
fn endpoint_and_domain_strategy_parsing() {
    assert_eq!(
        Endpoint::parse("[::1]:51820").unwrap().socket_addr(),
        Some("[::1]:51820".parse().unwrap())
    );
    assert!(
        Endpoint::parse("example.test:51820")
            .unwrap()
            .socket_addr()
            .is_none()
    );
    for value in [
        "",
        "example.test",
        "host:0",
        "host:65536",
        "::1:51820",
        "bad host:1",
    ] {
        assert!(Endpoint::parse(value).is_err(), "accepted {value}");
    }
    let addresses = vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()];
    assert_eq!(
        DomainStrategy::parse("ForceIPv4v6")
            .unwrap()
            .select_addresses(&addresses),
        vec![addresses[1]]
    );
    assert_eq!(
        DomainStrategy::ForceIpv6.select_addresses(&addresses),
        vec![addresses[0]]
    );
    assert!(DomainStrategy::parse("AsIs").is_err());
}

#[test]
fn longest_prefix_owner_and_exact_replacement() {
    let mut routes = RouteTable::default();
    routes.insert("0.0.0.0/0".parse().unwrap(), 0);
    routes.insert("10.0.0.0/8".parse().unwrap(), 1);
    routes.insert("10.1.2.3/32".parse().unwrap(), 2);
    routes.insert("::/0".parse().unwrap(), 3);
    assert_eq!(routes.lookup("8.8.8.8".parse().unwrap()), Some(0));
    assert_eq!(routes.lookup("10.9.8.7".parse().unwrap()), Some(1));
    assert_eq!(routes.lookup("10.1.2.3".parse().unwrap()), Some(2));
    assert_eq!(routes.lookup("fd00::1".parse().unwrap()), Some(3));
    routes.insert("10.0.0.1/8".parse().unwrap(), 4);
    assert_eq!(routes.lookup("10.9.8.7".parse().unwrap()), Some(4));
    assert_eq!(routes.lookup("10.1.2.3".parse().unwrap()), Some(2));
}

#[test]
fn real_noise_handshake_and_bidirectional_ipv4_ipv6_transport() {
    let (mut client, mut server) = pair();
    establish(&mut client, &mut server);
    assert!(
        client
            .peer_stats(0)
            .unwrap()
            .time_since_last_handshake
            .is_some()
    );
    assert!(
        server
            .peer_stats(0)
            .unwrap()
            .time_since_last_handshake
            .is_some()
    );
    for packet in [
        ipv4([10, 0, 0, 2], [10, 0, 0, 1], b"secret v4 payload"),
        ipv6(b"secret v6 payload"),
    ] {
        let encrypted = network(client.encapsulate(&packet).unwrap());
        assert_eq!(encrypted.len(), 1);
        assert_eq!((encrypted[0].len() - DATA_OVERHEAD) % 16, 0);
        let payload = if packet[0] >> 4 == 4 {
            &packet[20..]
        } else {
            &packet[40..]
        };
        assert!(
            !encrypted[0]
                .windows(payload.len())
                .any(|window| window == payload)
        );
        assert_eq!(
            server.decapsulate(client_address(), &encrypted[0]).unwrap(),
            vec![PacketAction::Tunnel {
                peer: 0,
                packet: packet.clone()
            }]
        );
        let back = network(server.encapsulate(&packet).unwrap());
        assert_eq!(
            client.decapsulate(server_address(), &back[0]).unwrap(),
            vec![PacketAction::Tunnel { peer: 0, packet }]
        );
    }
    assert!(client.peer_stats(0).unwrap().transmitted_bytes > 0);
    assert!(server.peer_stats(0).unwrap().received_bytes > 0);
    assert!(client.update_timers().errors.is_empty());
}

#[test]
fn first_packet_queues_until_handshake_then_is_delivered() {
    let (mut client, mut server) = pair();
    let packet = ipv4([10, 0, 0, 2], [10, 0, 0, 1], b"queued before handshake");
    let init = network(client.encapsulate(&packet).unwrap());
    assert_eq!(init[0][0], 1);
    let response = network(server.decapsulate(client_address(), &init[0]).unwrap());
    let queued = network(client.decapsulate(server_address(), &response[0]).unwrap());
    assert_eq!(queued.len(), 2); // confirmation keepalive, then queued IP packet
    let mut delivered = Vec::new();
    for encrypted in queued {
        delivered.extend(server.decapsulate(client_address(), &encrypted).unwrap());
    }
    assert_eq!(delivered, vec![PacketAction::Tunnel { peer: 0, packet }]);
}

#[test]
fn reserved_bytes_are_applied_and_normalized_like_go_bind() {
    let mut c = settings(CLIENT_PRIVATE, SERVER_PUBLIC, &server_address().to_string());
    let mut s = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    c.reserved = vec![1, 2, 3];
    s.reserved = vec![4, 5, 6];
    let mut client = WireGuardDevice::new(c.build(Role::Client).unwrap()).unwrap();
    let mut server_config = s.build(Role::Server).unwrap();
    assert_eq!(server_config.reserved, [0; 3]);
    // Direct engine callers can supply markers; source JSON inbound ignores it.
    server_config.reserved = [4, 5, 6];
    let mut server = WireGuardDevice::new(server_config).unwrap();
    let init = network(client.initiate_handshake(0, false).unwrap());
    assert_eq!(&init[0][1..4], &[1, 2, 3]);
    let response = network(server.decapsulate(client_address(), &init[0]).unwrap());
    assert_eq!(&response[0][1..4], &[4, 5, 6]);
    let mut ack = network(client.decapsulate(server_address(), &response[0]).unwrap());
    ack[0][1..4].copy_from_slice(&[91, 92, 93]);
    assert!(
        server
            .decapsulate(client_address(), &ack[0])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn tampering_replay_and_failed_authentication_do_not_roam() {
    let (mut client, mut server) = pair();
    establish(&mut client, &mut server);
    let packet = ipv4(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        b"authenticated endpoint migration",
    );
    let mut encrypted = network(client.encapsulate(&packet).unwrap()).remove(0);
    let roamed = "127.0.0.2:59999".parse().unwrap();
    let final_byte = encrypted.len() - 1;
    encrypted[final_byte] ^= 1;
    assert!(server.decapsulate(roamed, &encrypted).is_err());
    assert_eq!(
        server.peer_stats(0).unwrap().endpoint,
        Some(client_address())
    );
    encrypted[final_byte] ^= 1;
    assert_eq!(
        server.decapsulate(roamed, &encrypted).unwrap(),
        vec![PacketAction::Tunnel { peer: 0, packet }]
    );
    assert_eq!(server.peer_stats(0).unwrap().endpoint, Some(roamed));
    assert!(server.decapsulate(client_address(), &encrypted).is_err());
    assert_eq!(server.peer_stats(0).unwrap().endpoint, Some(roamed));
}

#[test]
fn mismatched_preshared_key_prevents_handshake_completion() {
    let mut c = settings(CLIENT_PRIVATE, SERVER_PUBLIC, &server_address().to_string());
    let mut s = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    c.peers[0].pre_shared_key = general_purpose::STANDARD.encode([1; 32]);
    s.peers[0].pre_shared_key = general_purpose::STANDARD.encode([2; 32]);
    let mut client = WireGuardDevice::new(c.build(Role::Client).unwrap()).unwrap();
    let mut server = WireGuardDevice::new(s.build(Role::Server).unwrap()).unwrap();
    let init = network(client.initiate_handshake(0, false).unwrap());
    let response = network(server.decapsulate(client_address(), &init[0]).unwrap());
    assert!(client.decapsulate(server_address(), &response[0]).is_err());
    assert!(
        client
            .peer_stats(0)
            .unwrap()
            .time_since_last_handshake
            .is_none()
    );
}

#[test]
fn overlapping_allowed_ips_use_source_owner_and_second_peer_demux() {
    let second_private = general_purpose::STANDARD.encode([77; 32]);
    let second_public =
        general_purpose::STANDARD.encode(SecretKey::parse(&second_private).unwrap().public_key());
    let mut server_config = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    server_config.peers.push(WireGuardPeerConfig {
        public_key: second_public,
        allowed_ips: Some(vec!["10.0.0.2/32".into()]),
        ..Default::default()
    });
    let mut server = WireGuardDevice::new(server_config.build(Role::Server).unwrap()).unwrap();
    let mut first = pair().0;
    establish(&mut first, &mut server);
    let spoofed = ipv4(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        b"another peer owns this source",
    );
    let encrypted = network(first.encapsulate(&spoofed).unwrap());
    assert!(
        server
            .decapsulate("127.0.0.9:55555".parse().unwrap(), &encrypted[0])
            .is_err()
    );
    assert_eq!(
        server.peer_stats(0).unwrap().endpoint,
        Some(client_address())
    );
    let mut second = WireGuardDevice::new(
        settings(
            &second_private,
            SERVER_PUBLIC,
            &server_address().to_string(),
        )
        .build(Role::Client)
        .unwrap(),
    )
    .unwrap();
    let second_address = "127.0.0.1:51003".parse().unwrap();
    establish_from(&mut second, &mut server, second_address);
    let encrypted = network(second.encapsulate(&spoofed).unwrap());
    assert_eq!(
        server.decapsulate(second_address, &encrypted[0]).unwrap(),
        vec![PacketAction::Tunnel {
            peer: 1,
            packet: spoofed
        }]
    );
    let reply = ipv4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        b"second peer selected by destination",
    );
    let actions = server.encapsulate(&reply).unwrap();
    assert!(
        matches!(&actions[0], PacketAction::Network { peer: Some(1), endpoint, .. } if *endpoint == second_address)
    );
    let encrypted = network(actions);
    assert_eq!(
        second.decapsulate(server_address(), &encrypted[0]).unwrap(),
        vec![PacketAction::Tunnel {
            peer: 0,
            packet: reply
        }]
    );
}

#[test]
fn bad_ip_frames_and_unresolved_endpoints_are_explicit_errors() {
    let (mut client, _) = pair();
    for packet in [
        vec![],
        vec![0x45; 19],
        vec![0x60; 39],
        vec![0x75; 40],
        vec![0x40; 40],
    ] {
        assert!(client.encapsulate(&packet).is_err());
    }
    let oversized = ipv4([10, 0, 0, 2], [10, 0, 0, 1], &vec![1; 1420]);
    assert!(client.encapsulate(&oversized).is_err());
    let mut raw = settings(CLIENT_PRIVATE, SERVER_PUBLIC, "vpn.example.test:51820");
    let mut unresolved = WireGuardDevice::new(raw.build(Role::Client).unwrap()).unwrap();
    assert!(unresolved.initiate_handshake(0, false).is_err());
    unresolved.set_peer_endpoint(0, server_address()).unwrap();
    assert_eq!(
        network(unresolved.initiate_handshake(0, false).unwrap())[0].len(),
        148
    );
    raw.peers[0].allowed_ips = Some(Vec::new());
    let mut no_routes = WireGuardDevice::new(raw.build(Role::Client).unwrap()).unwrap();
    assert!(no_routes.encapsulate(&ipv6(b"no route")).is_err());
}

#[test]
fn duplicate_self_and_low_order_peers_are_rejected() {
    let mut raw = settings(SERVER_PRIVATE, CLIENT_PUBLIC, "");
    raw.peers.push(raw.peers[0].clone());
    assert!(WireGuardDevice::new(raw.build(Role::Server).unwrap()).is_err());
    raw.peers.truncate(1);
    raw.peers[0].public_key = SERVER_PUBLIC.into();
    assert!(WireGuardDevice::new(raw.build(Role::Server).unwrap()).is_err());
    raw.peers[0].public_key = general_purpose::STANDARD.encode([0; 32]);
    assert!(WireGuardDevice::new(raw.build(Role::Server).unwrap()).is_err());
}
