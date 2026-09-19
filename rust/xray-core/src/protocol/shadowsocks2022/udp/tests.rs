use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{SeedableRng, rngs::StdRng};

const UNIX_NOW: u64 = 1_700_000_000;

fn account(kind: CipherKind) -> Account {
    let key: Vec<u8> = (0..kind.key_len() as u8).collect();
    Account::from_key(kind, &key, "udp@example.org".to_owned()).unwrap()
}

fn peer(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn target() -> Destination {
    Destination::new("example.org", 443).unwrap()
}

fn request(account: &Account, session_id: u64, packet_id: u64, timestamp: u64) -> Vec<u8> {
    cipher(account)
        .unwrap()
        .seal_with_nonce(
            &Packet {
                direction: Direction::Client,
                session_id,
                packet_id,
                timestamp,
                client_session_id: None,
                datagram: Datagram {
                    destination: target(),
                    payload: b"request".to_vec(),
                },
            },
            b"pad",
            [0; 24],
        )
        .unwrap()
}

fn reply(account: &Account, client_session_id: u64) -> Vec<u8> {
    cipher(account)
        .unwrap()
        .seal_with_nonce(
            &Packet {
                direction: Direction::Server,
                session_id: 73,
                packet_id: 0,
                timestamp: UNIX_NOW,
                client_session_id: Some(client_session_id),
                datagram: Datagram {
                    destination: target(),
                    payload: b"response".to_vec(),
                },
            },
            b"",
            [0; 24],
        )
        .unwrap()
}

fn unhex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn account_backed_codec_matches_existing_independent_aes_fixtures() {
    // Reuse the independently generated Python AES/BLAKE3 fixtures that validate
    // shadowsocks_udp; this checks the new Account adapter rather than creating
    // a second cryptographic implementation or self-derived reference vectors.
    let cases = [
        (
            CipherKind::Aes128Gcm,
            false,
            "12f250371f475aa71c3ab38e1308b5b8e33d719e15cf7e1746399d1d83807145a026233bfc9cccf925c70106bf1f7aa6920b99c49db6074e4c74",
        ),
        (
            CipherKind::Aes128Gcm,
            true,
            "ce8b012cf8173186af83e7dab1f0d99ac447a48189229d20e446498e795cb088e861fac99ffe606aeb41b1411252d3a9dc27dbf641a66cb6344c518456b0a7c49ac8",
        ),
        (
            CipherKind::Aes256Gcm,
            false,
            "43af1bac10ead1bba3120598a2ea4edd06fab6b6129cc084c977125f89c6d5e32af6dc90cb1ea34dcb083f02efbc3540f64da752a6dcc52e1522",
        ),
        (
            CipherKind::Aes256Gcm,
            true,
            "09a24bf73f92dc1a22496481611e7ace803efb5f3cce77d0cef7e7a6c4482690512902706d0c4def9c925edbb9ffd9195f755d53ebcb309cf0dc35ac46371803f409",
        ),
    ];
    for (kind, server, expected) in cases {
        let codec = cipher(&account(kind)).unwrap();
        let packet = Packet {
            direction: if server {
                Direction::Server
            } else {
                Direction::Client
            },
            session_id: if server {
                0x1112131415161718
            } else {
                0x0102030405060708
            },
            packet_id: if server { 9 } else { 7 },
            timestamp: UNIX_NOW,
            client_session_id: server.then_some(0x0102030405060708),
            datagram: Datagram {
                destination: Destination::new("8.8.8.8", 53).unwrap(),
                payload: b"\x12\x34dns".to_vec(),
            },
        };
        let wire = unhex(expected);
        assert_eq!(
            codec.seal_with_nonce(&packet, b"pad", [0; 24]).unwrap(),
            wire
        );
        assert_eq!(
            codec.open(&wire, packet.direction, UNIX_NOW).unwrap(),
            packet
        );
    }
}

#[test]
fn account_normalization_is_shared_with_tcp_including_base64_line_breaks() {
    for kind in [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm] {
        let key: Vec<u8> = (0..70).collect();
        let password = STANDARD.encode(&key);
        let wrapped = format!("{}\r\n{}", &password[..16], &password[16..]);
        let raw = Account::from_key(kind, &key, String::new()).unwrap();
        let parsed = Account::new(kind, &wrapped, String::new()).unwrap();
        assert_eq!(
            request(&raw, 11, 4, UNIX_NOW),
            request(&parsed, 11, 4, UNIX_NOW)
        );
        assert_eq!(
            cipher(&raw).unwrap().session_key(11).as_slice(),
            cipher(&parsed).unwrap().session_key(11).as_slice()
        );
    }
}

#[test]
fn both_ciphers_round_trip_all_address_forms_and_empty_payloads() {
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(1);
    for kind in [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm] {
        let account = account(kind);
        let mut client = Client::new(&account, peer(9000), &mut rng).unwrap();
        let mut server = Server::new(&account).unwrap();
        assert_eq!(client.server(), peer(9000));
        for host in ["203.0.113.7", "2001:db8::7", "example.org"] {
            for payload in [b"".as_slice(), b"application bytes".as_slice()] {
                let destination = Destination::new(host, 53).unwrap();
                let sent = client
                    .encode_request(&destination, payload, UNIX_NOW, &mut rng)
                    .unwrap();
                assert_eq!(sent.peer, peer(9000));
                let received = server
                    .accept_from(peer(1000), &sent.wire, UNIX_NOW, now, &mut rng)
                    .unwrap();
                assert_eq!(received.session.session_id(), client.session_id());
                assert_eq!(received.peer, peer(1000));
                assert_eq!(
                    received.datagram,
                    Datagram {
                        destination: destination.clone(),
                        payload: payload.to_vec()
                    }
                );
                let reply = server
                    .encode_reply(
                        &received.session,
                        &destination,
                        payload,
                        UNIX_NOW,
                        now,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(reply.peer, peer(1000));
                assert_eq!(
                    client
                        .accept_from(peer(9000), &reply.wire, UNIX_NOW)
                        .unwrap(),
                    received.datagram
                );
                assert!(
                    client
                        .accept_from(peer(9000), &reply.wire, UNIX_NOW)
                        .is_err()
                );
            }
        }
        assert_eq!(server.session_count(), 1);
    }
}

#[test]
fn authenticated_rebinding_updates_outstanding_reply_tokens() {
    let account = account(CipherKind::Aes128Gcm);
    let mut server = Server::new(&account).unwrap();
    let mut rng = StdRng::seed_from_u64(2);
    let now = Instant::now();
    let first = server
        .accept_from(
            peer(1000),
            &request(&account, 9, 0, UNIX_NOW),
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    let second_wire = request(&account, 9, 1, UNIX_NOW);
    server
        .accept_from(peer(2000), &second_wire, UNIX_NOW, now, &mut rng)
        .unwrap();
    assert!(
        server
            .accept_from(peer(3000), &second_wire, UNIX_NOW, now, &mut rng)
            .is_err()
    );
    let reply = server
        .encode_reply(
            &first.session,
            &target(),
            b"delayed",
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    assert_eq!(reply.peer, peer(2000));
    let third_wire = request(&account, 9, 2, UNIX_NOW);
    let mut corrupted = third_wire.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(
        server
            .accept_from(peer(3000), &corrupted, UNIX_NOW, now, &mut rng)
            .is_err()
    );
    assert_eq!(
        server
            .encode_reply(&first.session, &target(), b"still", UNIX_NOW, now, &mut rng)
            .unwrap()
            .peer,
        peer(2000)
    );
    server
        .accept_from(peer(3000), &third_wire, UNIX_NOW, now, &mut rng)
        .unwrap();
    assert_eq!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"rebound",
                UNIX_NOW,
                now,
                &mut rng
            )
            .unwrap()
            .peer,
        peer(3000)
    );
    assert_eq!(server.session_count(), 1);
}

#[test]
fn endpoint_and_client_binding_rejections_do_not_poison_client_state() {
    let account = account(CipherKind::Aes256Gcm);
    let mut rng = StdRng::seed_from_u64(3);
    let mut client = Client::new(&account, peer(9000), &mut rng).unwrap();
    let wire = reply(&account, client.session_id());
    assert!(client.accept_from(peer(9001), &wire, UNIX_NOW).is_err());
    let wrong_binding = reply(&account, client.session_id().wrapping_add(1));
    assert!(
        client
            .accept_from(peer(9000), &wrong_binding, UNIX_NOW)
            .is_err()
    );
    assert_eq!(
        client
            .accept_from(peer(9000), &wire, UNIX_NOW)
            .unwrap()
            .payload,
        b"response"
    );
    assert!(client.accept_from(peer(9000), &wire, UNIX_NOW).is_err());
}

#[test]
fn unauthenticated_or_truncated_packets_never_allocate_routes() {
    let account = account(CipherKind::Aes256Gcm);
    let wire = request(&account, 9, 0, UNIX_NOW);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(4);
    let mut server = Server::new(&account).unwrap();
    for length in 0..wire.len() {
        assert!(
            server
                .accept_from(peer(1000), &wire[..length], UNIX_NOW, now, &mut rng)
                .is_err()
        );
        assert_eq!(server.session_count(), 0);
    }
    for index in 0..wire.len() {
        let mut corrupted = wire.clone();
        corrupted[index] ^= 1;
        assert!(
            server
                .accept_from(peer(1000), &corrupted, UNIX_NOW, now, &mut rng)
                .is_err()
        );
        assert_eq!(server.session_count(), 0);
    }
    assert!(
        server
            .accept_from(peer(1000), &wire, UNIX_NOW, now, &mut rng)
            .is_ok()
    );
    assert_eq!(server.session_count(), 1);
}

#[test]
fn invalid_authenticated_metadata_does_not_consume_replay_ids_or_rebind() {
    let account = account(CipherKind::Aes128Gcm);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(5);
    let mut server = Server::new(&account).unwrap();
    let first = server
        .accept_from(
            peer(1000),
            &request(&account, 9, 0, UNIX_NOW),
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    for timestamp in [UNIX_NOW - 31, UNIX_NOW + 31] {
        assert!(
            server
                .accept_from(
                    peer(2000),
                    &request(&account, 9, 9000, timestamp),
                    UNIX_NOW,
                    now,
                    &mut rng
                )
                .is_err()
        );
    }
    assert!(
        server
            .accept_from(peer(2000), &reply(&account, 9), UNIX_NOW, now, &mut rng)
            .is_err()
    );
    assert_eq!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"response",
                UNIX_NOW,
                now,
                &mut rng
            )
            .unwrap()
            .peer,
        peer(1000)
    );
    // If rejected counter 9000 had advanced the replay window, counter 1 would
    // be outside its 8128-packet span and could no longer be admitted.
    assert!(
        server
            .accept_from(
                peer(1000),
                &request(&account, 9, 1, UNIX_NOW - 30),
                UNIX_NOW,
                now,
                &mut rng
            )
            .is_ok()
    );
    assert!(
        server
            .accept_from(
                peer(1000),
                &request(&account, 9, 2, UNIX_NOW + 30),
                UNIX_NOW,
                now,
                &mut rng
            )
            .is_ok()
    );
}

#[test]
fn bounded_capacity_preserves_live_routes_and_replay_history() {
    let account = account(CipherKind::Aes128Gcm);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(6);
    let mut server = Server::with_limits(&account, Duration::from_secs(61), 1).unwrap();
    let first_wire = request(&account, 9, 0, UNIX_NOW);
    let first = server
        .accept_from(peer(1000), &first_wire, UNIX_NOW, now, &mut rng)
        .unwrap();
    assert!(
        server
            .accept_from(
                peer(2000),
                &request(&account, 10, 0, UNIX_NOW),
                UNIX_NOW,
                now,
                &mut rng
            )
            .is_err()
    );
    assert!(
        server
            .accept_from(peer(2000), &first_wire, UNIX_NOW, now, &mut rng)
            .is_err()
    );
    assert_eq!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"response",
                UNIX_NOW,
                now,
                &mut rng
            )
            .unwrap()
            .peer,
        peer(1000)
    );
    assert_eq!(server.session_count(), 1);
    let later = now + Duration::from_secs(61);
    let second = server
        .accept_from(
            peer(2000),
            &request(&account, 10, 0, UNIX_NOW + 61),
            UNIX_NOW + 61,
            later,
            &mut rng,
        )
        .unwrap();
    assert_eq!(second.session.session_id(), 10);
    assert_eq!(server.session_count(), 1);
    assert!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"old",
                UNIX_NOW + 61,
                later,
                &mut rng
            )
            .is_err()
    );
}

#[test]
fn expired_or_foreign_tokens_cannot_target_recreated_sessions() {
    let account = account(CipherKind::Aes256Gcm);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(7);
    let mut server = Server::with_limits(&account, Duration::from_secs(61), 1).unwrap();
    let old = server
        .accept_from(
            peer(1000),
            &request(&account, 9, 0, UNIX_NOW),
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    let later = now + Duration::from_secs(61);
    let fresh_wire = request(&account, 9, 1, UNIX_NOW + 61);
    let fresh = server
        .accept_from(peer(2000), &fresh_wire, UNIX_NOW + 61, later, &mut rng)
        .unwrap();
    assert_eq!(old.session.session_id(), fresh.session.session_id());
    assert!(
        server
            .encode_reply(
                &old.session,
                &target(),
                b"old",
                UNIX_NOW + 61,
                later,
                &mut rng
            )
            .is_err()
    );
    let mut other = Server::new(&account).unwrap();
    let foreign = other
        .accept_from(peer(3000), &fresh_wire, UNIX_NOW + 61, later, &mut rng)
        .unwrap();
    assert!(
        server
            .encode_reply(
                &foreign.session,
                &target(),
                b"foreign",
                UNIX_NOW + 61,
                later,
                &mut rng
            )
            .is_err()
    );
    assert!(
        other
            .encode_reply(
                &fresh.session,
                &target(),
                b"foreign",
                UNIX_NOW + 61,
                later,
                &mut rng
            )
            .is_err()
    );
    assert_eq!(
        server
            .encode_reply(
                &fresh.session,
                &target(),
                b"fresh",
                UNIX_NOW + 61,
                later,
                &mut rng
            )
            .unwrap()
            .peer,
        peer(2000)
    );
}

#[test]
fn invalid_requests_and_failed_replies_do_not_refresh_inactivity() {
    let account = account(CipherKind::Aes128Gcm);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(8);
    let mut server = Server::with_limits(&account, Duration::from_secs(61), 1).unwrap();
    let first = server
        .accept_from(
            peer(1000),
            &request(&account, 9, 0, UNIX_NOW),
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    let later = now + Duration::from_secs(60);
    // Timestamp is fresh but the counter was already used, so a replay cannot
    // refresh the session's inactivity timeout or change its return address.
    assert!(
        server
            .accept_from(
                peer(2000),
                &request(&account, 9, 0, UNIX_NOW + 60),
                UNIX_NOW + 60,
                later,
                &mut rng
            )
            .is_err()
    );
    assert!(
        server
            .encode_reply(
                &first.session,
                &target(),
                &vec![0; MAX_PACKET_SIZE + 1],
                UNIX_NOW + 60,
                later,
                &mut rng
            )
            .is_err()
    );
    server.expire(now + Duration::from_secs(61));
    assert_eq!(server.session_count(), 0);
    assert!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"late",
                UNIX_NOW + 61,
                now + Duration::from_secs(61),
                &mut rng
            )
            .is_err()
    );
}

#[test]
fn successful_replies_refresh_both_session_tables_to_exact_expiry() {
    let account = account(CipherKind::Aes256Gcm);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(9);
    let mut server = Server::with_limits(&account, Duration::from_secs(61), 1).unwrap();
    let first = server
        .accept_from(
            peer(1000),
            &request(&account, 9, 0, UNIX_NOW),
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    assert!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"active",
                UNIX_NOW + 60,
                now + Duration::from_secs(60),
                &mut rng
            )
            .is_ok()
    );
    server.expire(now + Duration::from_secs(120));
    assert_eq!(server.session_count(), 1);
    server.expire(now + Duration::from_secs(121));
    assert_eq!(server.session_count(), 0);
    assert!(
        server
            .encode_reply(
                &first.session,
                &target(),
                b"late",
                UNIX_NOW + 121,
                now + Duration::from_secs(121),
                &mut rng
            )
            .is_err()
    );
}

#[test]
fn sessions_sharing_a_source_keep_their_reply_routes_and_destinations_separate() {
    let account = account(CipherKind::Aes256Gcm);
    let now = Instant::now();
    let mut rng = StdRng::seed_from_u64(10);
    let mut first_client = Client::new(&account, peer(9000), &mut rng).unwrap();
    let mut second_client = Client::new(&account, peer(9000), &mut rng).unwrap();
    let mut server = Server::new(&account).unwrap();
    let first_target = Destination::new("203.0.113.1", 53).unwrap();
    let second_target = Destination::new("example.net", 443).unwrap();
    let first_wire = first_client
        .encode_request(&first_target, b"first", UNIX_NOW, &mut rng)
        .unwrap();
    let second_wire = second_client
        .encode_request(&second_target, b"second", UNIX_NOW, &mut rng)
        .unwrap();
    let first = server
        .accept_from(peer(1000), &first_wire.wire, UNIX_NOW, now, &mut rng)
        .unwrap();
    let second = server
        .accept_from(peer(1000), &second_wire.wire, UNIX_NOW, now, &mut rng)
        .unwrap();
    let moved = first_client
        .encode_request(&first_target, b"moved", UNIX_NOW, &mut rng)
        .unwrap();
    server
        .accept_from(peer(2000), &moved.wire, UNIX_NOW, now, &mut rng)
        .unwrap();
    let first_reply = server
        .encode_reply(
            &first.session,
            &first_target,
            b"one",
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    let second_reply = server
        .encode_reply(
            &second.session,
            &second_target,
            b"two",
            UNIX_NOW,
            now,
            &mut rng,
        )
        .unwrap();
    assert_eq!(first_reply.peer, peer(2000));
    assert_eq!(second_reply.peer, peer(1000));
    assert!(
        second_client
            .accept_from(peer(9000), &first_reply.wire, UNIX_NOW)
            .is_err()
    );
    assert_eq!(
        first_client
            .accept_from(peer(9000), &first_reply.wire, UNIX_NOW)
            .unwrap(),
        Datagram {
            destination: first_target,
            payload: b"one".to_vec()
        }
    );
    assert_eq!(
        second_client
            .accept_from(peer(9000), &second_reply.wire, UNIX_NOW)
            .unwrap(),
        Datagram {
            destination: second_target,
            payload: b"two".to_vec()
        }
    );
    assert_eq!(server.session_count(), 2);
}

#[test]
fn replay_retention_and_capacity_limits_are_validated() {
    let account = account(CipherKind::Aes128Gcm);
    assert!(Server::with_limits(&account, Duration::from_secs(60), 1).is_err());
    assert!(Server::with_limits(&account, Duration::from_secs(61), 0).is_err());
    assert!(Server::with_limits(&account, Duration::from_secs(61), 1).is_ok());
}
