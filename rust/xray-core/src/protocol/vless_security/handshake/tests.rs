use std::{io, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{CryptoRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::wire::{CLIENT_PFS_CIPHERTEXT_LEN, LENGTH_LEN, SERVER_PREFIX_LEN};
use super::*;

// Reproducible test entropy only; production entry points always use OsRng.
// The independent Python/OpenSSL oracle reproduces these exact byte offsets.
struct CounterRng(u8);

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(output);
        Ok(())
    }
}
impl CryptoRng for CounterRng {}

fn take<'a>(wire: &'a [u8], offset: &mut usize, count: usize) -> io::Result<&'a [u8]> {
    let result = wire
        .get(*offset..*offset + count)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    *offset += count;
    Ok(result)
}

fn accept_server(
    config: &ServerConfig,
    wire: &[u8],
    rng: &mut CounterRng,
) -> io::Result<(Session, Vec<u8>, usize)> {
    let mut offset = 0;
    let mut state = ServerState::start(
        config,
        take(wire, &mut offset, config.prefix_len() + LENGTH_LEN)?,
    )?;
    state.receive_pfs(take(wire, &mut offset, CLIENT_PFS_CIPHERTEXT_LEN)?)?;
    let length = state.receive_padding_length(take(wire, &mut offset, LENGTH_LEN)?)?;
    let (session, reply) = state.finish(config, take(wire, &mut offset, length)?, rng)?;
    Ok((session, reply, offset))
}

fn accept_client(state: ClientState, wire: &[u8]) -> io::Result<(Session, usize)> {
    let mut offset = 0;
    let finish = state.receive_prefix(take(wire, &mut offset, SERVER_PREFIX_LEN)?)?;
    let padding = take(wire, &mut offset, finish.padding_len())?;
    Ok((finish.finish(padding)?, offset))
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn configuration_accepts_pinned_one_key_profile_and_rejects_unsupported_modes() {
    for seed in [vec![0x11; 32], vec![0x22; 64]] {
        let server_text = format!(
            "mlkem768x25519plus.native.0s.{}",
            URL_SAFE_NO_PAD.encode(&seed)
        );
        let server = ServerConfig::parse(&server_text).unwrap();
        let public = URL_SAFE_NO_PAD.encode(server.public_key_bytes());
        let client_text = format!("mlkem768x25519plus.native.1rtt.{public}");
        ClientConfig::parse(&client_text).unwrap();
        for mode in ["xorpub", "random"] {
            assert_eq!(
                ClientConfig::parse(&client_text.replace("native", mode))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
        }
        assert_eq!(
            ClientConfig::parse(&client_text.replace("1rtt", "0rtt"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert!(ClientConfig::parse(&format!("{client_text}.{public}")).is_ok());
        assert!(ClientConfig::parse(&client_text.replace(".1rtt.", ".1rtt.100-111-111.")).is_err());
        assert!(ServerConfig::parse(&server_text.replace(".0s.", ".600s.")).is_err());
        assert!(!format!("{server:?}").contains(&URL_SAFE_NO_PAD.encode(&seed)));
    }
    assert!(ServerConfig::from_private_key(&[0; 63]).is_err());
    assert!(ClientConfig::from_public_key(&[0xff; 1184]).is_err());
    assert!(ClientConfig::from_public_key(&[0; 31]).is_err());
    assert!(ClientConfig::parse("none").is_err());
    assert!(ServerConfig::parse("mlkem768x25519plus.native.0s.!invalid!").is_err());
}

#[test]
fn both_static_key_types_and_both_aeads_establish_hybrid_directional_sessions() {
    for seed in [vec![0x11; 32], vec![0x22; 64]] {
        for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
            let server = ServerConfig::from_private_key(&seed).unwrap();
            let client = ClientConfig::from_public_key(&server.public_key_bytes())
                .unwrap()
                .with_algorithm(algorithm);
            let (state, mut hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
            let hello_len = hello.len();
            hello.extend_from_slice(b"unconsumed client bytes");
            let (mut server_session, mut reply, consumed) =
                accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
            assert_eq!(consumed, hello_len);
            let reply_len = reply.len();
            reply.extend_from_slice(b"unconsumed server bytes");
            let (mut client_session, consumed) = accept_client(state, &reply).unwrap();
            assert_eq!(consumed, reply_len);
            assert_eq!(client_session.algorithm(), algorithm);
            assert_eq!(server_session.algorithm(), algorithm);
            let uplink = client_session.outbound.seal_record(b"request").unwrap();
            assert_eq!(
                server_session.inbound.open_record(&uplink).unwrap(),
                b"request"
            );
            let downlink = server_session.outbound.seal_record(b"response").unwrap();
            assert_eq!(
                client_session.inbound.open_record(&downlink).unwrap(),
                b"response"
            );
            assert!(server_session.inbound.open_record(&uplink).is_err());
            assert!(client_session.inbound.open_record(&downlink).is_err());
        }
    }
}

#[test]
fn server_record_nonce_continues_after_three_handshake_operations() {
    for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
        let mut aead = super::super::encryption::SessionAead::new(b"context", b"key", algorithm);
        for payload in [b"ticket".as_slice(), b"length", b"padding"] {
            aead.seal(payload, &[]).unwrap();
        }
        let mut records = RecordCipher::from_aead(aead, b"key");
        let wire = records.seal_record(b"first application record").unwrap();
        let expected = super::super::encryption::SessionAead::new(b"context", b"key", algorithm)
            .seal_at(
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
                b"first application record",
                &wire[..5],
            )
            .unwrap();
        assert_eq!(&wire[5..], expected);
    }
}

#[test]
fn client_hello_tampering_truncation_wrong_keys_and_replay_are_rejected() {
    let server = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
    let client = ClientConfig::from_public_key(&server.public_key_bytes()).unwrap();
    let (_, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
    for length in 0..hello.len() {
        assert!(
            accept_server(&server, &hello[..length], &mut CounterRng(160)).is_err(),
            "prefix {length}"
        );
    }
    for index in [
        0,
        15,
        16,
        47,
        48,
        49,
        65,
        66,
        1249,
        1297,
        1298,
        1315,
        1316,
        hello.len() - 1,
    ] {
        let mut damaged = hello.clone();
        damaged[index] ^= 1;
        assert!(
            accept_server(&server, &damaged, &mut CounterRng(160)).is_err(),
            "byte {index}"
        );
    }
    let wrong_server = ServerConfig::from_private_key(&[0x12; 32]).unwrap();
    assert!(accept_server(&wrong_server, &hello, &mut CounterRng(160)).is_err());
    accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
    assert!(accept_server(&server, &hello, &mut CounterRng(160)).is_err());
}

#[test]
fn server_hello_authentication_precedes_decapsulation_and_covers_ticket_and_padding() {
    let server = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
    let client = ClientConfig::from_public_key(&server.public_key_bytes()).unwrap();
    let (_, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
    let (_, reply, _) = accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
    for index in [
        0,
        1087,
        1088,
        1119,
        1120,
        1135,
        1136,
        1167,
        1168,
        1185,
        1186,
        reply.len() - 1,
    ] {
        let mut damaged = reply.clone();
        damaged[index] ^= 1;
        let (state, _) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
        assert!(accept_client(state, &damaged).is_err(), "byte {index}");
    }
    for length in [0, 1135, 1136, 1167, 1168, 1185, 1186, reply.len() - 1] {
        let (state, _) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
        assert!(
            accept_client(state, &reply[..length]).is_err(),
            "prefix {length}"
        );
    }
}

#[test]
fn noncanonical_and_low_order_nfs_shares_are_rejected() {
    let server = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
    let client = ClientConfig::from_public_key(&server.public_key_bytes()).unwrap();
    let (_, mut hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
    hello[47] |= 0x80;
    assert!(ServerState::start(&server, &hello[..66]).is_err());
    hello[16..48].fill(0);
    assert!(ServerState::start(&server, &hello[..66]).is_err());
    let client = ClientConfig::from_public_key(&[0; 32]).unwrap();
    assert!(ClientState::start(&client, &mut CounterRng(0)).is_err());
}

#[test]
fn authenticated_malformed_hybrid_shares_do_not_fill_replay_history() {
    let server = ServerConfig::from_private_key(&[0x11; 32])
        .unwrap()
        .with_replay_limits(1, Duration::from_secs(180))
        .unwrap();
    let client = ClientConfig::from_public_key(&server.public_key_bytes()).unwrap();
    for bad_mlkem in [false, true] {
        let mut rng = CounterRng(9);
        let iv = keys::random_bytes::<16>(&mut rng).unwrap();
        let (share, nfs) = client.keys[0].exchange(&mut rng).unwrap();
        let mut hybrid = keys::Ephemeral::generate(&mut rng).unwrap().public_bytes();
        if bad_mlkem {
            hybrid[..1184].fill(0xff);
        } else {
            hybrid[1184..].fill(0);
        }
        let mut aead =
            super::super::encryption::SessionAead::new(&iv, nfs.as_ref(), Algorithm::Aes256Gcm);
        let mut hello = iv.to_vec();
        hello.extend(share);
        hello.extend(
            aead.seal(&(CLIENT_PFS_CIPHERTEXT_LEN as u16).to_be_bytes(), &[])
                .unwrap(),
        );
        hello.extend(aead.seal(&hybrid, &[]).unwrap());
        hello.extend(aead.seal(&17u16.to_be_bytes(), &[]).unwrap());
        hello.extend(aead.seal(&[0], &[]).unwrap());
        assert!(accept_server(&server, &hello, &mut CounterRng(160)).is_err());
    }
    let (_, valid) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
    accept_server(&server, &valid, &mut CounterRng(160)).unwrap();
}

#[test]
fn noncanonical_nfs_field_alias_cannot_bypass_authenticated_hello_replay_history() {
    let private = [0x11; 32];
    let server = ServerConfig::from_private_key(&private).unwrap();
    let nfs_key = server.public_key_bytes();
    let iv = [0x37; 16];
    let mut basepoint = [0; 32];
    basepoint[0] = 9;
    let hybrid = keys::Ephemeral::generate(&mut CounterRng(33))
        .unwrap()
        .public_bytes();
    let mut aead = super::super::encryption::SessionAead::new(&iv, &nfs_key, Algorithm::Aes256Gcm);
    let mut hello = iv.to_vec();
    hello.extend_from_slice(&basepoint);
    hello.extend(
        aead.seal(&(CLIENT_PFS_CIPHERTEXT_LEN as u16).to_be_bytes(), &[])
            .unwrap(),
    );
    hello.extend(aead.seal(&hybrid, &[]).unwrap());
    hello.extend(aead.seal(&17u16.to_be_bytes(), &[]).unwrap());
    hello.extend(aead.seal(&[0], &[]).unwrap());
    accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
    assert!(accept_server(&server, &hello, &mut CounterRng(160)).is_err());

    // A canonical reciprocal is a different point with the same X25519 NFS
    // secret. It remains valid input, but its authenticated flight is a replay.
    let reciprocal = hex("12c7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711c47");
    assert_eq!(
        keys::ecdh(&private, &reciprocal).unwrap().as_slice(),
        nfs_key
    );
    let mut equivalent = hello.clone();
    equivalent[16..48].copy_from_slice(&reciprocal);
    let fresh = ServerConfig::from_private_key(&private).unwrap();
    accept_server(&fresh, &equivalent, &mut CounterRng(160)).unwrap();
    assert!(accept_server(&server, &equivalent, &mut CounterRng(160)).is_err());
    assert!(accept_server(&fresh, &hello, &mut CounterRng(160)).is_err());

    // p + 9 = 2^255 - 10 reduces to the same accepted basepoint, without its
    // high bit set. The IV and every authenticated ciphertext byte stay equal.
    let mut alias = [0xff; 32];
    alias[0] = 0xf6;
    alias[31] = 0x7f;
    assert_eq!(keys::ecdh(&private, &alias).unwrap().as_slice(), nfs_key);
    hello[16..48].copy_from_slice(&alias);
    assert!(ServerState::start(&server, &hello[..66]).is_err());
    let key = keys::PrivateKey::parse(&private).unwrap();
    for low in 0xed..=0xff {
        alias[0] = low;
        assert!(key.exchange(&alias).is_err(), "noncanonical low byte {low}");
    }
}

#[test]
fn canonical_reciprocal_aliases_at_every_relay_hop_share_replay_identity() {
    // Independently generated with Python cryptography/OpenSSL: CounterRng(0)
    // supplies X25519 secrets 16..47, 48..79, and 80..111 after the 16-byte IV.
    // The second encoding in each pair is 1/u mod (2^255 - 19).
    let shares = [
        (
            "d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66",
            "0c8a5e16affd5a824a0e12e714da170f442962fba56440f789d25eecfa733b70",
        ),
        (
            "34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847",
            "baea1c3e8a39f491e8664c690cae2ad828835f36dfad2f1a7d2cb304e1803c08",
        ),
        (
            "392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c",
            "c9533d22824fbefd8cc5b72c5ae33cafb56ba48f1b65e12951415dab5e544401",
        ),
    ];
    for count in [1, 3] {
        let chain: Vec<Vec<u8>> = (0..count).map(|i| vec![0x11 * (i + 1) as u8; 32]).collect();
        for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
            let server = ServerConfig::from_private_keys(&chain).unwrap();
            let client = ClientConfig::from_public_keys(&server.public_keys_bytes())
                .unwrap()
                .with_algorithm(algorithm);
            let (_, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
            accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
            for (hop, (original, alias)) in shares.iter().take(count).enumerate() {
                let original = hex(original);
                let alias = hex(alias);
                assert_eq!(
                    server.keys[hop].exchange(&original).unwrap().as_ref(),
                    server.keys[hop].exchange(&alias).unwrap().as_ref(),
                );
                let mut equivalent = hello.clone();
                let start = 16 + 64 * hop;
                // XOR the plaintext difference through the preceding relay's
                // mask; every key-hash link and authenticated record is intact.
                for index in 0..32 {
                    equivalent[start + index] ^= original[index] ^ alias[index];
                }
                assert_eq!(
                    &equivalent[server.prefix_len()..],
                    &hello[server.prefix_len()..]
                );
                let fresh = ServerConfig::from_private_keys(&chain).unwrap();
                accept_server(&fresh, &equivalent, &mut CounterRng(160)).unwrap();
                assert!(
                    accept_server(&server, &equivalent, &mut CounterRng(160)).is_err(),
                    "hop {hop}"
                );
                assert!(
                    accept_server(&fresh, &hello, &mut CounterRng(160)).is_err(),
                    "reverse hop {hop}"
                );
            }
        }
    }
}

#[test]
fn independent_openssl_mlkem_x25519_and_aead_wire_fixtures() {
    for (algorithm, fixture) in [
        (
            Algorithm::Aes256Gcm,
            include_str!("fixtures/native_aes.json"),
        ),
        (
            Algorithm::ChaCha20Poly1305,
            include_str!("fixtures/native_chacha.json"),
        ),
    ] {
        let vector: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let bytes = |name: &str| hex(vector[name].as_str().unwrap());
        let server = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
        let client = ClientConfig::from_public_key(&server.public_key_bytes())
            .unwrap()
            .with_algorithm(algorithm);
        let (state, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
        assert_eq!(hello, bytes("client_hello"));
        let (mut session, consumed) = accept_client(state, &bytes("server_hello")).unwrap();
        assert_eq!(consumed, bytes("server_hello").len());
        assert_eq!(
            session.outbound.seal_record(b"fixture uplink").unwrap(),
            bytes("uplink")
        );
        assert_eq!(
            session.inbound.open_record(&bytes("downlink")).unwrap(),
            b"fixture downlink"
        );
        accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
    }
}

#[test]
fn native_relay_chains_preserve_hybrid_sessions_for_mixed_key_types() {
    let chains = [
        vec![vec![0x11; 32], vec![0x22; 32]],
        vec![vec![0x11; 32], vec![0x22; 64], vec![0x33; 32]],
        vec![vec![0x11; 64], vec![0x22; 32], vec![0x33; 64]],
        (0..8).map(|i| vec![0x31 + i; 32]).collect(),
    ];
    for chain in chains {
        for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
            let server = ServerConfig::from_private_keys(&chain).unwrap();
            let public = server.public_keys_bytes();
            let client = ClientConfig::from_public_keys(&public)
                .unwrap()
                .with_algorithm(algorithm);
            assert_eq!(
                server.prefix_len(),
                16 + chain
                    .iter()
                    .map(|key| if key.len() == 32 { 32 } else { 1088 })
                    .sum::<usize>()
                    + 32 * (chain.len() - 1)
            );
            let (state, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
            let (mut server_session, reply, consumed) =
                accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
            assert_eq!(consumed, hello.len());
            let (mut client_session, consumed) = accept_client(state, &reply).unwrap();
            assert_eq!(consumed, reply.len());
            let up = client_session
                .outbound
                .seal_record(b"mixed relay upload")
                .unwrap();
            assert_eq!(
                server_session.inbound.open_record(&up).unwrap(),
                b"mixed relay upload"
            );
            let down = server_session
                .outbound
                .seal_record(b"mixed relay download")
                .unwrap();
            assert_eq!(
                client_session.inbound.open_record(&down).unwrap(),
                b"mixed relay download"
            );
        }
    }
}

#[test]
fn relay_binding_rejects_reordered_keys_tampering_and_all_prefix_truncations() {
    let private = vec![vec![0x11; 32], vec![0x22; 32]];
    let server = ServerConfig::from_private_keys(&private).unwrap();
    let client = ClientConfig::from_public_keys(&server.public_keys_bytes()).unwrap();
    let (_, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
    let prefix_len = server.prefix_len() + LENGTH_LEN;
    for length in 0..prefix_len {
        assert!(
            ServerState::start(&server, &hello[..length]).is_err(),
            "prefix {length}"
        );
    }
    for index in 16..server.prefix_len() {
        let mut damaged = hello[..prefix_len].to_vec();
        damaged[index] ^= 1;
        assert!(
            ServerState::start(&server, &damaged).is_err(),
            "relay byte {index}"
        );
    }
    let reversed =
        ServerConfig::from_private_keys(&[private[1].clone(), private[0].clone()]).unwrap();
    assert!(ServerState::start(&reversed, &hello[..prefix_len]).is_err());
    accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
    assert!(accept_server(&server, &hello, &mut CounterRng(160)).is_err());
}

#[test]
fn relay_configuration_has_explicit_key_count_bounds() {
    assert!(ClientConfig::from_public_keys(&[]).is_err());
    assert!(ServerConfig::from_private_keys(&[]).is_err());
    assert!(ServerConfig::from_private_keys(&vec![vec![1; 32]; 9]).is_err());
    let server = ServerConfig::from_private_keys(&vec![vec![1; 32]; 8]).unwrap();
    let public = server.public_keys_bytes();
    assert!(
        ClientConfig::from_public_keys(&[public.clone(), vec![public[0].clone()]].concat())
            .is_err()
    );
    let encoded = public
        .iter()
        .map(|key| URL_SAFE_NO_PAD.encode(key))
        .collect::<Vec<_>>()
        .join(".");
    assert!(ClientConfig::parse(&format!("mlkem768x25519plus.native.1rtt.{encoded}")).is_ok());
    assert!(
        ClientConfig::parse(&format!(
            "mlkem768x25519plus.native.1rtt.{encoded}.{}",
            URL_SAFE_NO_PAD.encode(&public[0])
        ))
        .is_err()
    );
}

#[test]
fn independent_relay_wire_fixture_checks_hash_and_continuous_ctr_binding() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/relay_aes.json")).unwrap();
    let bytes = |name: &str| hex(vector[name].as_str().unwrap());
    let server = ServerConfig::from_private_keys(&[vec![0x11; 32], vec![0x22; 32]]).unwrap();
    let client = ClientConfig::from_public_keys(&server.public_keys_bytes()).unwrap();
    let (state, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
    assert_eq!(hello, bytes("client_hello"));
    let (mut session, consumed) = accept_client(state, &bytes("server_hello")).unwrap();
    assert_eq!(consumed, bytes("server_hello").len());
    assert_eq!(
        session.outbound.seal_record(b"fixture uplink").unwrap(),
        bytes("uplink")
    );
    assert_eq!(
        session.inbound.open_record(&bytes("downlink")).unwrap(),
        b"fixture downlink"
    );
    accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
}

#[tokio::test]
async fn async_handshake_and_large_bidirectional_transfer_over_fragmented_transport() {
    for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
        let server_config = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
        let client_config = ClientConfig::from_public_key(&server_config.public_key_bytes())
            .unwrap()
            .with_algorithm(algorithm);
        let (client_io, server_io) = tokio::io::duplex(37);
        let payload: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let client = async {
            let mut stream = client_handshake(client_io, &client_config).await.unwrap();
            assert_eq!(stream.algorithm(), algorithm);
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
        };
        let server = async {
            let mut stream = server_handshake(server_io, &server_config).await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, payload);
            stream.write_all(&request).await.unwrap();
            stream.shutdown().await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(client, server);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn simultaneous_write_then_read_progresses_under_backpressure_without_explicit_flush() {
    let server_config = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
    let client_config = ClientConfig::from_public_key(&server_config.public_key_bytes()).unwrap();
    let (client_io, server_io) = tokio::io::duplex(37);
    let client = async {
        let mut stream = client_handshake(client_io, &client_config).await.unwrap();
        stream.write_all(&[1; 500]).await.unwrap();
        let mut reply = [0; 500];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [2; 500]);
    };
    let server = async {
        let mut stream = server_handshake(server_io, &server_config).await.unwrap();
        stream.write_all(&[2; 500]).await.unwrap();
        let mut request = [0; 500];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [1; 500]);
    };
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_and_tampered_application_records_never_release_plaintext() {
    for tamper in [false, true] {
        let server = ServerConfig::from_private_key(&[0x11; 32]).unwrap();
        let client = ClientConfig::from_public_key(&server.public_key_bytes()).unwrap();
        let (state, hello) = ClientState::start(&client, &mut CounterRng(0)).unwrap();
        let (mut server_session, reply, _) =
            accept_server(&server, &hello, &mut CounterRng(160)).unwrap();
        let (client_session, _) = accept_client(state, &reply).unwrap();
        let mut wire = server_session
            .outbound
            .seal_record(b"must remain secret")
            .unwrap();
        if tamper {
            *wire.last_mut().unwrap() ^= 1;
        } else {
            wire.pop();
        }
        let (mut peer, local) = tokio::io::duplex(128);
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut stream = EncryptedStream::new(local, client_session);
        let mut plaintext = Vec::new();
        assert!(stream.read_to_end(&mut plaintext).await.is_err());
        assert!(plaintext.is_empty());
        assert!(stream.read_u8().await.is_err());
    }
}
