use std::time::UNIX_EPOCH;

use super::super::{self as client_side, ClientConfig, EphemeralKeys};
use super::*;
use crate::transport::reality::{RealityAuthKey, authenticated_client_hello};

fn config() -> ServerConfig {
    ServerConfig::new(
        [7; 32],
        ServerPolicy {
            server_names: vec!["example.test".into()],
            short_ids: vec![[1; 8]],
            min_client_version: Some([26, 1, 1]),
            max_client_version: Some([27, 0, 0]),
            max_time_diff: Duration::from_secs(120),
        },
    )
}

fn client_config() -> ClientConfig {
    ClientConfig::new(
        "example.test".into(),
        config().public_key(),
        [1; 8],
        [26, 9, 19],
    )
}

fn hello_with_identity(
    client: &ClientConfig,
    seconds: u32,
) -> (Vec<u8>, EphemeralKeys, RealityAuthKey) {
    let keys = EphemeralKeys::generate().unwrap();
    let standalone = x25519(*keys.standalone_x25519, X25519_BASEPOINT_BYTES);
    let mut hello =
        wire::client_hello(client, &[51; 32], &keys.hybrid_public(), &standalone).unwrap();
    let private = if client.hybrid_only {
        &keys.hybrid_x25519
    } else {
        &keys.standalone_x25519
    };
    let auth = authenticated_client_hello(
        &mut hello,
        private,
        &client.server_public_key,
        ClientIdentity::new(client.client_version, seconds, client.short_id),
    )
    .unwrap();
    (hello, keys, auth)
}

fn current_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn replace_extensions(hello: &[u8], edit: impl FnOnce(&mut Vec<(u16, Vec<u8>)>)) -> Vec<u8> {
    let mut cursor = wire::Cursor::new(&hello[4..]);
    cursor.take(34).unwrap();
    cursor.vec8().unwrap();
    cursor.vec16().unwrap();
    cursor.vec8().unwrap();
    let offset = hello.len() - cursor.rest.len();
    let mut extensions = wire::Cursor::new(cursor.vec16().unwrap());
    let mut items = Vec::new();
    while !extensions.rest.is_empty() {
        items.push((
            extensions.u16().unwrap(),
            extensions.vec16().unwrap().to_vec(),
        ));
    }
    edit(&mut items);
    let mut encoded = Vec::new();
    for (id, value) in items {
        wire::extension(&mut encoded, id, &value).unwrap();
    }
    let mut body = hello[4..offset].to_vec();
    body.extend(wire::vector16(&encoded).unwrap());
    wire::handshake(1, &body).unwrap()
}

#[test]
fn server_config_requires_explicit_fresh_admission_and_valid_negotiation() {
    config().validate().unwrap();
    let mut value = config();
    value.policy.server_names.clear();
    assert!(value.validate().is_err());
    let mut value = config();
    value.policy.short_ids.clear();
    assert!(value.validate().is_err());
    let mut value = config();
    value.policy.max_time_diff = Duration::ZERO;
    assert!(value.validate().is_err());
    let mut value = config();
    value.policy.min_client_version = Some([28, 0, 0]);
    assert!(value.validate().is_err());
    let mut value = config();
    value.key_exchange_groups.push(KeyExchangeGroup::X25519);
    assert!(value.validate().is_err());
    let mut value = config();
    value.cipher_suites.clear();
    assert!(value.validate().is_err());
    let mut value = config();
    value.alpn = vec![vec![]];
    assert!(value.validate().is_err());
    let mut value = config();
    value.handshake_timeout = Duration::ZERO;
    assert!(value.validate().is_err());
    let mut value = config();
    value.max_handshake_bytes = usize::MAX;
    assert!(value.validate().is_err());
}

#[test]
fn hello_parser_rejects_truncation_duplicate_extensions_and_missing_requirements() {
    let (hello, _, _) = hello_with_identity(&client_config(), current_seconds());
    hello::Offer::parse(&hello).unwrap();
    for end in 0..hello.len() {
        assert!(hello::Offer::parse(&hello[..end]).is_err(), "prefix {end}");
    }
    let duplicate = replace_extensions(&hello, |items| items.push(items[0].clone()));
    assert!(hello::Offer::parse(&duplicate).is_err());
    for id in [0, 10, 43] {
        let missing = replace_extensions(&hello, |items| items.retain(|(kind, _)| *kind != id));
        assert!(hello::Offer::parse(&missing).is_err(), "missing {id}");
    }
    // The pinned Go REALITY server forces Ed25519 for its synthetic
    // certificate and never consults signature_algorithms, so a hello without
    // extension 13 (like every browser fingerprint) must stay acceptable.
    let no_signatures = replace_extensions(&hello, |items| items.retain(|(k, _)| *k != 13));
    hello::Offer::parse(&no_signatures).unwrap();
    for id in [41, 42] {
        let unsupported = replace_extensions(&hello, |items| items.push((id, vec![])));
        assert_eq!(
            hello::Offer::parse(&unsupported).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
    }
}

#[test]
fn hello_parser_rejects_bad_shares_and_negotiation_mismatch() {
    let (hello, _, _) = hello_with_identity(&client_config(), current_seconds());
    let duplicate = replace_extensions(&hello, |items| {
        let (_, value) = items.iter_mut().find(|(id, _)| *id == 51).unwrap();
        let duplicate = value[2..].to_vec();
        let mut shares = duplicate.clone();
        shares.extend(duplicate);
        *value = wire::vector16(&shares).unwrap();
    });
    assert!(hello::Offer::parse(&duplicate).is_err());
    let missing_group = replace_extensions(&hello, |items| {
        items.iter_mut().find(|(id, _)| *id == 10).unwrap().1 = wire::vector16(&[0, 29]).unwrap();
    });
    assert!(hello::Offer::parse(&missing_group).is_err());
    let short_share = replace_extensions(&hello, |items| {
        items.iter_mut().find(|(id, _)| *id == 51).unwrap().1 = vec![0, 5, 0x11, 0xec, 0, 1, 0];
    });
    assert!(
        hello::Offer::parse(&short_share)
            .unwrap()
            .select(&config())
            .is_err()
    );
    let mut no_suite = hello.clone();
    no_suite[73..79].fill(0);
    assert!(
        hello::Offer::parse(&no_suite)
            .unwrap()
            .select(&config())
            .is_err()
    );
    let mut no_alpn = config();
    no_alpn.alpn = vec![b"unsupported".to_vec()];
    assert!(
        hello::Offer::parse(&hello)
            .unwrap()
            .select(&no_alpn)
            .is_err()
    );
    let no_shares = replace_extensions(&hello, |items| items.retain(|(id, _)| *id != 51));
    assert!(
        hello::Offer::parse(&no_shares)
            .unwrap()
            .select(&config())
            .is_err()
    );
}

#[test]
fn exchange_agrees_with_client_for_both_groups_and_rejects_low_order_or_bad_mlkem() {
    let keys = EphemeralKeys::generate().unwrap();
    for group in [KeyExchangeGroup::X25519MlKem768, KeyExchangeGroup::X25519] {
        let share = match group {
            KeyExchangeGroup::X25519MlKem768 => keys.hybrid_public(),
            KeyExchangeGroup::X25519 => {
                x25519(*keys.standalone_x25519, X25519_BASEPOINT_BYTES).to_vec()
            }
        };
        let (response, shared) = hello::exchange(group, &share).unwrap();
        assert_eq!(*shared, *keys.shared_secret(group.id(), &response).unwrap());
        let mut low_order = share.clone();
        let offset = low_order.len() - 32;
        low_order[offset..].fill(0);
        assert!(hello::exchange(group, &low_order).is_err());
        assert!(hello::exchange(group, &share[..share.len() - 1]).is_err());
    }
    let mut malformed = keys.hybrid_public();
    malformed[..1184].fill(255);
    assert!(hello::exchange(KeyExchangeGroup::X25519MlKem768, &malformed).is_err());
}

#[test]
fn certificate_contains_authenticated_ed25519_marker_and_matching_signer() {
    let (hello, _, auth) = hello_with_identity(&client_config(), current_seconds());
    let (message, signer) = certificate::create("example.test", &auth).unwrap();
    let key = client_side::verify_certificate(&message[4..], &auth, None, &hello, &[]).unwrap();
    assert_eq!(key, signer.verifying_key());
    let mut changed = message;
    let end = changed.len();
    changed[end - 3] ^= 1;
    assert!(client_side::verify_certificate(&changed[4..], &auth, None, &hello, &[]).is_err());
}

#[tokio::test]
async fn all_suites_and_groups_complete_authenticated_application_io_and_half_close() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        for group in [KeyExchangeGroup::X25519MlKem768, KeyExchangeGroup::X25519] {
            let mut server = config();
            server.cipher_suites = vec![suite];
            server.key_exchange_groups = vec![group];
            let (left, right) = tokio::io::duplex(4096);
            let server_task = async move {
                let (mut stream, info) = accept(Box::new(left), server).await.unwrap();
                assert_eq!(info.tls.cipher_suite, suite);
                assert_eq!(info.tls.key_exchange_group, group.id());
                assert_eq!(info.server_name, "example.test");
                assert_eq!(info.identity.short_id, [1; 8]);
                let mut input = Vec::new();
                stream.read_to_end(&mut input).await.unwrap();
                assert_eq!(input, vec![0x5a; 40000]);
                stream.write_all(b"authenticated reply").await.unwrap();
                stream.shutdown().await.unwrap();
            };
            let client_task = async move {
                let mut client = client_config();
                client.hybrid_only = group == KeyExchangeGroup::X25519MlKem768;
                let (mut stream, info) =
                    client_side::client(Box::new(right), client).await.unwrap();
                assert_eq!(info.alpn, Some(b"h2".to_vec()));
                stream.write_all(&vec![0x5a; 40000]).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"authenticated reply");
            };
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server_task, client_task);
            })
            .await
            .unwrap();
        }
    }
}

async fn send_hello(stream: &mut BoxStream, hello: &[u8], fragment_size: usize) {
    for (index, chunk) in hello.chunks(fragment_size).enumerate() {
        let mut record = vec![22, 3, if index == 0 { 1 } else { 3 }];
        record.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        record.extend_from_slice(chunk);
        stream.write_all(&record).await.unwrap();
    }
    stream.flush().await.unwrap();
}

struct PendingClient {
    stream: BoxStream,
    finished: Vec<u8>,
    write: RecordCipher,
    app_write: RecordCipher,
    server_hello: Vec<u8>,
    encrypted_lengths: Vec<usize>,
}

async fn pending_client(mut stream: BoxStream, fragment_size: usize) -> PendingClient {
    let (hello, keys, auth) = hello_with_identity(&client_config(), current_seconds());
    send_hello(&mut stream, &hello, fragment_size).await;
    let mut reader = RecordReader::default();
    let server_hello = poll_fn(|cx| reader.poll_read(&mut stream, cx))
        .await
        .unwrap()
        .payload;
    let parsed = wire::parse_server_hello(&server_hello, &hello[39..71], false).unwrap();
    let shared = keys.shared_secret(parsed.group, parsed.share).unwrap();
    let suite = parsed.suite;
    let mut transcript = Transcript::new(suite);
    transcript.update(&hello);
    transcript.update(&server_hello);
    let secrets = HandshakeSecrets::new(suite, &shared, &transcript.hash()).unwrap();
    let mut read = RecordCipher::new(suite, secrets.server.clone()).unwrap();
    let write = RecordCipher::new(suite, secrets.client.clone()).unwrap();
    let mut messages = HandshakeBuffer::new(1 << 20);
    let mut stage = 0;
    let mut encrypted_lengths = Vec::new();
    let mut key = None;
    loop {
        if let Some(message) = messages.take().unwrap() {
            match (stage, message[0]) {
                (0, 8) => {
                    wire::encrypted_extensions(&message[4..], &client_config().alpn).unwrap();
                }
                (1, 11) => {
                    key = Some(
                        client_side::verify_certificate(
                            &message[4..],
                            &auth,
                            None,
                            &hello,
                            &server_hello,
                        )
                        .unwrap(),
                    )
                }
                (2, 15) => client_side::verify_certificate_verify(
                    &message[4..],
                    key.as_ref().unwrap(),
                    &transcript.hash(),
                )
                .unwrap(),
                (3, 20) => {
                    verify_finished(
                        &suite.finished(&secrets.server, &transcript.hash()).unwrap(),
                        &message[4..],
                    )
                    .unwrap();
                    transcript.update(&message);
                    break;
                }
                other => panic!("unexpected server message {other:?}"),
            }
            transcript.update(&message);
            stage += 1;
            continue;
        }
        let record = poll_fn(|cx| reader.poll_read(&mut stream, cx))
            .await
            .unwrap();
        if record.header[0] == 20 {
            assert_eq!(record.payload, [1]);
            continue;
        }
        encrypted_lengths.push(record.payload.len() + 5);
        let (kind, plain) = read.open(&record.header, record.payload).unwrap();
        assert_eq!(kind, 22);
        messages.push(&plain).unwrap();
    }
    let finished = wire::handshake(
        20,
        &suite.finished(&secrets.client, &transcript.hash()).unwrap(),
    )
    .unwrap();
    let (app_write, _) = secrets.application(&transcript.hash()).unwrap();
    PendingClient {
        stream,
        finished,
        write,
        app_write,
        server_hello,
        encrypted_lengths,
    }
}

#[tokio::test]
async fn fragmented_hello_and_finished_are_accepted_only_after_finished_verification() {
    let (left, right) = tokio::io::duplex(8192);
    let task = tokio::spawn(accept(Box::new(left), config()));
    let mut client = pending_client(Box::new(right), 7).await;
    assert!(!task.is_finished());
    for fragment in client.finished.chunks(3) {
        client
            .stream
            .write_all(&client.write.seal(22, fragment).unwrap())
            .await
            .unwrap();
    }
    client.stream.flush().await.unwrap();
    let (_, info) = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(info.tls.key_exchange_group, 0x11ec);
}

#[tokio::test]
async fn wrong_finished_or_application_data_before_finished_never_returns_a_stream() {
    for early_application in [false, true] {
        let (left, right) = tokio::io::duplex(8192);
        let task = tokio::spawn(accept(Box::new(left), config()));
        let mut client = pending_client(Box::new(right), 16384).await;
        let record = if early_application {
            client.app_write.seal(23, b"too early").unwrap()
        } else {
            let end = client.finished.len();
            client.finished[end - 1] ^= 1;
            client.write.seal(22, &client.finished).unwrap()
        };
        client.stream.write_all(&record).await.unwrap();
        client.stream.flush().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test]
async fn server_rejects_client_sent_session_ticket_after_valid_handshake() {
    let (left, right) = tokio::io::duplex(8192);
    let task = tokio::spawn(accept(Box::new(left), config()));
    let mut client = pending_client(Box::new(right), 16384).await;
    client
        .stream
        .write_all(&client.write.seal(22, &client.finished).unwrap())
        .await
        .unwrap();
    client.stream.flush().await.unwrap();
    let (mut server, _) = task.await.unwrap().unwrap();
    // A syntactically valid NewSessionTicket may only be sent by a server.
    let ticket = wire::handshake(4, &[0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 1, 42, 0, 0]).unwrap();
    client
        .stream
        .write_all(&client.app_write.seal(22, &ticket).unwrap())
        .await
        .unwrap();
    client.stream.flush().await.unwrap();
    let error = server.read(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn policy_rejections_send_no_server_flight() {
    for case in 0..4 {
        let mut client = client_config();
        let seconds = if case == 0 {
            current_seconds() - 600
        } else {
            current_seconds()
        };
        if case == 1 {
            client.server_name = "wrong.test".into();
        }
        if case == 2 {
            client.short_id = [2; 8];
        }
        if case == 3 {
            client.client_version = [25, 0, 0];
        }
        let (hello, _, _) = hello_with_identity(&client, seconds);
        let (left, right) = tokio::io::duplex(8192);
        let task = tokio::spawn(accept(Box::new(left), config()));
        let mut right: BoxStream = Box::new(right);
        send_hello(&mut right, &hello, 16384).await;
        assert!(task.await.unwrap().is_err());
        assert_eq!(right.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn server_timeout_and_cancellation_drop_the_owned_transport() {
    let mut server = config();
    server.handshake_timeout = Duration::from_millis(10);
    let (left, mut right) = tokio::io::duplex(8192);
    let error = accept(Box::new(left), server).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(right.read(&mut [0; 1]).await.unwrap(), 0);
    let (left, mut right) = tokio::io::duplex(8192);
    let task = tokio::spawn(accept(Box::new(left), config()));
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert_eq!(right.read(&mut [0; 1]).await.unwrap(), 0);
}

struct GoClient(std::process::Child);

fn plaintext_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![kind, 3, 3];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

fn opaque_target_record(size: usize) -> Vec<u8> {
    assert!((22..=16406).contains(&size));
    plaintext_record(23, &vec![0x67; size - 5])
}

fn target_server_hello(client: &[u8], suite: CipherSuite, group: KeyExchangeGroup) -> Vec<u8> {
    let share = vec![
        55;
        if group == KeyExchangeGroup::X25519MlKem768 {
            1120
        } else {
            32
        }
    ];
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x69; 32]);
    body.push(32);
    body.extend_from_slice(&client[39..71]);
    body.extend_from_slice(&suite.id().to_be_bytes());
    body.push(0);
    let mut extensions = Vec::new();
    let mut key = group.id().to_be_bytes().to_vec();
    key.extend(wire::vector16(&share).unwrap());
    // Reverse the native serializer's extension order to catch reconstruction
    // that would accidentally erase the target's observable ServerHello layout.
    wire::extension(&mut extensions, 51, &key).unwrap();
    wire::extension(&mut extensions, 43, &[3, 4]).unwrap();
    body.extend(wire::vector16(&extensions).unwrap());
    wire::handshake(2, &body).unwrap()
}

#[tokio::test]
async fn target_mirrors_server_hello_and_combined_or_split_record_sizes_for_all_negotiations() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        for group in [KeyExchangeGroup::X25519MlKem768, KeyExchangeGroup::X25519] {
            for split in [false, true] {
                let (server_io, client_io) = tokio::io::duplex(8192);
                let (target_io, mut target_peer) = tokio::io::duplex(8192);
                let lengths = if split {
                    vec![50, 1800, 160, 100]
                } else {
                    vec![2400]
                };
                let target_lengths = lengths.clone();
                let target_task = tokio::spawn(async move {
                    let client_hello = read_client_hello(&mut target_peer, 1 << 20).await.unwrap();
                    let hello = target_server_hello(&client_hello, suite, group);
                    target_peer
                        .write_all(&plaintext_record(22, &hello))
                        .await
                        .unwrap();
                    target_peer.write_all(&[20, 3, 3, 0, 1, 1]).await.unwrap();
                    for size in target_lengths {
                        target_peer
                            .write_all(&opaque_target_record(size))
                            .await
                            .unwrap();
                    }
                    target_peer.flush().await.unwrap();
                    let mut unexpected = Vec::new();
                    target_peer.read_to_end(&mut unexpected).await.unwrap();
                    assert!(
                        unexpected.is_empty(),
                        "native Finished/application traffic leaked to the target"
                    );
                    hello
                });
                let server_task = tokio::spawn(accept_with_target(
                    Box::new(server_io),
                    Box::new(target_io),
                    config(),
                ));
                let mut client = pending_client(Box::new(client_io), 11).await;
                assert_eq!(client.encrypted_lengths, lengths);
                client
                    .stream
                    .write_all(&client.write.seal(22, &client.finished).unwrap())
                    .await
                    .unwrap();
                client.stream.flush().await.unwrap();
                let outcome = tokio::time::timeout(Duration::from_secs(3), server_task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let (mut server, info) = match outcome {
                    TargetOutcome::Authenticated { stream, info } => (stream, info),
                    TargetOutcome::Forwarded { reason, .. } => {
                        panic!("unexpected target fallback: {reason}")
                    }
                };
                assert_eq!(info.tls.cipher_suite, suite);
                assert_eq!(info.tls.key_exchange_group, group.id());
                assert_eq!(info.tls.alpn, None);
                let expected_hello = target_task.await.unwrap();
                let share_len = if group == KeyExchangeGroup::X25519MlKem768 {
                    1120
                } else {
                    32
                };
                let end = client.server_hello.len() - 6;
                assert_ne!(
                    client.server_hello[end - share_len..end],
                    expected_hello[end - share_len..end]
                );
                client.server_hello[end - share_len..end].fill(55);
                assert_eq!(client.server_hello, expected_hello);
                client
                    .stream
                    .write_all(
                        &client
                            .app_write
                            .seal(23, b"target-shaped authenticated bytes")
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                client.stream.flush().await.unwrap();
                let mut payload = [0; 33];
                server.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"target-shaped authenticated bytes");
            }
        }
    }
}

#[tokio::test]
async fn rejected_client_forwarding_preserves_original_records_tail_and_half_closes() {
    let mut client = client_config();
    client.short_id = [2; 8];
    let (hello, _, _) = hello_with_identity(&client, current_seconds());
    let mut upload = Vec::new();
    for chunk in hello.chunks(7) {
        upload.extend(plaintext_record(22, chunk));
    }
    upload.extend_from_slice(b"opaque pipelined bytes after ClientHello");
    let expected = upload.clone();
    let (server_io, mut client_io) = tokio::io::duplex(37);
    let (target_io, mut target_peer) = tokio::io::duplex(37);
    let server = accept_with_target(Box::new(server_io), Box::new(target_io), config());
    let client = async {
        client_io.write_all(&upload).await.unwrap();
        client_io.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client_io.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, upload);
    };
    let target = async {
        let mut received = Vec::new();
        target_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
        target_peer.write_all(&received).await.unwrap();
        target_peer.shutdown().await.unwrap();
    };
    let outcome = tokio::time::timeout(Duration::from_secs(3), async {
        let (result, _, _) = tokio::join!(server, client, target);
        result.unwrap()
    })
    .await
    .unwrap();
    match outcome {
        TargetOutcome::Forwarded {
            client_to_target,
            target_to_client,
            ..
        } => {
            assert_eq!(client_to_target, upload.len() as u64);
            assert_eq!(target_to_client, upload.len() as u64);
        }
        _ => panic!("rejected identity returned an authenticated stream"),
    }
}

#[tokio::test]
async fn unsupported_target_prefix_is_forwarded_exactly_without_a_forged_flight() {
    for insufficient_padding in [false, true] {
        let (hello, _, _) = hello_with_identity(&client_config(), current_seconds());
        let upload = plaintext_record(22, &hello);
        let mut response = if insufficient_padding {
            let mut response = plaintext_record(
                22,
                &target_server_hello(
                    &hello,
                    CipherSuite::Aes128GcmSha256,
                    KeyExchangeGroup::X25519,
                ),
            );
            response.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
            for size in [28, 22, 100, 58] {
                response.extend(opaque_target_record(size));
            }
            response
        } else {
            b"HTTP/1.1 400 Target reply\r\n\r\n".to_vec()
        };
        response.extend_from_slice(b"post-observation target bytes");
        let expected = response.clone();
        let (server_io, mut client_io) = tokio::io::duplex(8192);
        let (target_io, mut target_peer) = tokio::io::duplex(8192);
        let server = accept_with_target(Box::new(server_io), Box::new(target_io), config());
        let client = async {
            client_io.write_all(&upload).await.unwrap();
            client_io.shutdown().await.unwrap();
            let mut received = Vec::new();
            client_io.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
        };
        let target = async {
            let received = read_client_hello(&mut target_peer, 1 << 20).await.unwrap();
            assert_eq!(received, hello);
            target_peer.write_all(&response).await.unwrap();
            target_peer.shutdown().await.unwrap();
            let mut rest = Vec::new();
            target_peer.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        };
        let outcome = tokio::time::timeout(Duration::from_secs(3), async {
            let (result, _, _) = tokio::join!(server, client, target);
            result.unwrap()
        })
        .await
        .unwrap();
        assert!(matches!(outcome, TargetOutcome::Forwarded { .. }));
    }
}

#[tokio::test]
async fn cancelled_target_observation_replays_partial_record_and_forwarding_outlives_deadline() {
    let (hello, _, _) = hello_with_identity(&client_config(), current_seconds());
    let response = plaintext_record(
        22,
        &target_server_hello(
            &hello,
            CipherSuite::Aes128GcmSha256,
            KeyExchangeGroup::X25519,
        ),
    );
    let mut server_config = config();
    server_config.handshake_timeout = Duration::from_millis(40);
    let (server_io, mut client_io) = tokio::io::duplex(8192);
    let (target_io, mut target_peer) = tokio::io::duplex(8192);
    let server = accept_with_target(Box::new(server_io), Box::new(target_io), server_config);
    let client = async {
        client_io
            .write_all(&plaintext_record(22, &hello))
            .await
            .unwrap();
        client_io.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_io.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, response);
    };
    let target = async {
        read_client_hello(&mut target_peer, 1 << 20).await.unwrap();
        target_peer.write_all(&response[..12]).await.unwrap();
        target_peer.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        target_peer.write_all(&response[12..]).await.unwrap();
        target_peer.shutdown().await.unwrap();
        let mut rest = Vec::new();
        target_peer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    };
    let outcome = tokio::time::timeout(Duration::from_secs(3), async {
        let (result, _, _) = tokio::join!(server, client, target);
        result.unwrap()
    })
    .await
    .unwrap();
    assert!(matches!(outcome, TargetOutcome::Forwarded { .. }));
}

#[tokio::test]
async fn malformed_client_and_capture_budget_fall_back_with_no_prefix_loss() {
    for upload in [b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(), {
        let mut bytes = vec![22, 3, 3, 0x40, 0];
        bytes.resize(16389, 0x5a);
        bytes
    }] {
        let mut server_config = config();
        server_config.max_handshake_bytes = 4096;
        let (server_io, mut client_io) = tokio::io::duplex(37);
        let (target_io, mut target_peer) = tokio::io::duplex(37);
        let server = accept_with_target(Box::new(server_io), Box::new(target_io), server_config);
        let client = async {
            client_io.write_all(&upload).await.unwrap();
            client_io.shutdown().await.unwrap();
            let mut received = Vec::new();
            client_io.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"target accepted bytes");
        };
        let target = async {
            let mut received = Vec::new();
            target_peer.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, upload);
            target_peer
                .write_all(b"target accepted bytes")
                .await
                .unwrap();
            target_peer.shutdown().await.unwrap();
        };
        let outcome = tokio::time::timeout(Duration::from_secs(3), async {
            let (result, _, _) = tokio::join!(server, client, target);
            result.unwrap()
        })
        .await
        .unwrap();
        assert!(matches!(outcome, TargetOutcome::Forwarded { .. }));
    }
}

#[tokio::test]
async fn cancelled_partial_target_write_is_resumed_without_duplicating_client_bytes() {
    let (hello, _, _) = hello_with_identity(&client_config(), current_seconds());
    let upload = plaintext_record(22, &hello);
    let mut cfg = config();
    cfg.handshake_timeout = Duration::from_millis(40);
    let (server_io, mut client_io) = tokio::io::duplex(8192);
    let (target_io, mut target_peer) = tokio::io::duplex(37);
    let server = accept_with_target(Box::new(server_io), Box::new(target_io), cfg);
    let client = async {
        client_io.write_all(&upload).await.unwrap();
        client_io.shutdown().await.unwrap();
        let mut response = Vec::new();
        client_io.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"resumed target");
    };
    let target = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut received = Vec::new();
        target_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, upload);
        target_peer.write_all(b"resumed target").await.unwrap();
        target_peer.shutdown().await.unwrap();
    };
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let (result, _, _) = tokio::join!(server, client, target);
        result.unwrap()
    })
    .await
    .unwrap();
    assert!(
        matches!(result, TargetOutcome::Forwarded { client_to_target, .. } if client_to_target == upload.len() as u64)
    );
}

#[tokio::test]
async fn bad_finished_after_target_shaping_closes_without_fallback() {
    let (server_io, client_io) = tokio::io::duplex(8192);
    let (target_io, mut target_peer) = tokio::io::duplex(8192);
    let target_task = tokio::spawn(async move {
        let hello = read_client_hello(&mut target_peer, 1 << 20).await.unwrap();
        target_peer
            .write_all(&plaintext_record(
                22,
                &target_server_hello(
                    &hello,
                    CipherSuite::Aes128GcmSha256,
                    KeyExchangeGroup::X25519,
                ),
            ))
            .await
            .unwrap();
        target_peer.write_all(&[20, 3, 3, 0, 1, 1]).await.unwrap();
        target_peer
            .write_all(&opaque_target_record(2000))
            .await
            .unwrap();
        target_peer.flush().await.unwrap();
        let mut unexpected = Vec::new();
        target_peer.read_to_end(&mut unexpected).await.unwrap();
        assert!(unexpected.is_empty());
    });
    let task = tokio::spawn(accept_with_target(
        Box::new(server_io),
        Box::new(target_io),
        config(),
    ));
    let mut client = pending_client(Box::new(client_io), 16384).await;
    let end = client.finished.len();
    client.finished[end - 1] ^= 1;
    client
        .stream
        .write_all(&client.write.seal(22, &client.finished).unwrap())
        .await
        .unwrap();
    client.stream.flush().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    target_task.await.unwrap();
    assert_eq!(client.stream.read(&mut [0; 1]).await.unwrap(), 0);
}

impl Drop for GoClient {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires XRAY_REALITY_GO_CLIENT pointing to compiled server/interop/main.go"]
async fn pinned_go_reality_client_interoperability() {
    use std::process::{Command, Stdio};
    let executable = std::env::var_os("XRAY_REALITY_GO_CLIENT")
        .expect("build server/interop/main.go and set XRAY_REALITY_GO_CLIENT");
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        for group in [KeyExchangeGroup::X25519MlKem768, KeyExchangeGroup::X25519] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut server = config();
            server.cipher_suites = vec![suite];
            server.key_exchange_groups = vec![group];
            let public_key = server
                .public_key()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let mut command = Command::new(&executable);
            command
                .arg(listener.local_addr().unwrap().to_string())
                .arg(public_key)
                .arg("0101010101010101")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x0800_0000);
            }
            let mut process = GoClient(command.spawn().unwrap());
            tokio::time::timeout(Duration::from_secs(12), async {
                let (socket, _) = listener.accept().await.unwrap();
                let (mut stream, info) = accept(Box::new(socket), server).await.unwrap();
                assert_eq!(info.tls.cipher_suite, suite);
                assert_eq!(info.tls.key_exchange_group, group.id());
                let payload = b"pinned Go REALITY client to native Rust server";
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload);
                stream.write_all(&received).await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
            })
            .await
            .unwrap();
            assert!(process.0.wait().unwrap().success());
        }
    }
}

#[tokio::test]
#[ignore = "requires XRAY_REALITY_GO_CLIENT with target mode; checks genuine Go target and uTLS client"]
async fn pinned_go_target_and_reality_client_interoperability() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
    };
    let executable = std::env::var_os("XRAY_REALITY_GO_CLIENT")
        .expect("build server/interop/main.go and set XRAY_REALITY_GO_CLIENT");
    for (name, group) in [
        ("hybrid", KeyExchangeGroup::X25519MlKem768),
        ("x25519", KeyExchangeGroup::X25519),
    ] {
        let mut target_command = Command::new(&executable);
        target_command
            .args(["target", name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            target_command.creation_flags(0x0800_0000);
        }
        let mut target_process = GoClient(target_command.spawn().unwrap());
        let mut line = String::new();
        BufReader::new(target_process.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let endpoint: serde_json::Value = serde_json::from_str(&line).unwrap();
        let target_address = endpoint["address"].as_str().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = config();
        let public = server
            .public_key()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut client_command = Command::new(&executable);
        client_command
            .arg(listener.local_addr().unwrap().to_string())
            .arg(public)
            .arg("0101010101010101")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            client_command.creation_flags(0x0800_0000);
        }
        let mut client_process = GoClient(client_command.spawn().unwrap());
        tokio::time::timeout(Duration::from_secs(12), async {
            let (client, _) = listener.accept().await.unwrap();
            let target = tokio::net::TcpStream::connect(target_address)
                .await
                .unwrap();
            let outcome = accept_with_target(Box::new(client), Box::new(target), server)
                .await
                .unwrap();
            let (mut stream, info) = match outcome {
                TargetOutcome::Authenticated { stream, info } => (stream, info),
                TargetOutcome::Forwarded { reason, .. } => {
                    panic!("genuine Go target unexpectedly fell back: {reason}")
                }
            };
            assert_eq!(info.tls.key_exchange_group, group.id());
            assert_eq!(info.tls.alpn, None);
            let payload = b"pinned Go REALITY client to native Rust server";
            let mut received = vec![0; payload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            stream.write_all(&received).await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await
        .unwrap();
        assert!(client_process.0.wait().unwrap().success());
    }
}
