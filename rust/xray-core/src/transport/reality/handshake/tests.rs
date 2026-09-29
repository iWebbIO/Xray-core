use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};

use ed25519_dalek::{Signer, SigningKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn config() -> ClientConfig {
    ClientConfig::new(
        "example.test".into(),
        x25519([7; 32], X25519_BASEPOINT_BYTES),
        [1; 8],
        [26, 9, 19],
    )
}

#[test]
fn rfc8448_handshake_traffic_secrets_and_record_keys() {
    let suite = CipherSuite::Aes128GcmSha256;
    let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let hello_hash = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    let secrets = HandshakeSecrets::new(suite, &shared, &hello_hash).unwrap();
    assert_eq!(
        &*secrets.client,
        &hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    );
    assert_eq!(
        &*secrets.server,
        &hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    );
    assert_eq!(
        &*suite
            .expand_label(&secrets.server, b"key", b"", 16)
            .unwrap(),
        &hex("3fce516009c21727d0f2e4e86ee403bc")
    );
    assert_eq!(
        &*suite.expand_label(&secrets.server, b"iv", b"", 12).unwrap(),
        &hex("5d313eb2671276ee13000b30")
    );
}

#[test]
fn record_protection_matches_independent_openssl_vectors_at_two_sequences() {
    let fixtures = [
        (
            CipherSuite::Aes128GcmSha256,
            "170303001a4d6d8b52c4161bf1952a64e689d38a7080ae3b43833ee1abcf46",
            "170303001a3d985273c2425dfff9a727ea3de88d877e1d2351e4fa8b6fe482",
        ),
        (
            CipherSuite::Aes256GcmSha384,
            "170303001a205213507a2dc2e9e2d36a51f110168157f198a9c751b8aca575",
            "170303001af574159cab6e7945274b2783c96c8b3aaeac4249e61179557be5",
        ),
        (
            CipherSuite::ChaCha20Poly1305Sha256,
            "170303001adacb07926855ce8d9c7a9a865a5442d282cc803412f46a71b641",
            "170303001a63d059b6e80cb7bffd1c8425b990a6d9139da545862feefcf374",
        ),
    ];
    for (suite, first, second) in fixtures {
        let secret = Zeroizing::new((0..suite.hash_len() as u8).collect::<Vec<_>>());
        let mut writer = RecordCipher::new(suite, secret.clone()).unwrap();
        let mut reader = RecordCipher::new(suite, secret).unwrap();
        for vector in [first, second] {
            let record = writer.seal(23, b"hello tls").unwrap();
            assert_eq!(record, hex(vector));
            assert_eq!(
                reader
                    .open(record[..5].try_into().unwrap(), record[5..].to_vec())
                    .unwrap(),
                (23, b"hello tls".to_vec())
            );
        }
    }
}

#[test]
fn encrypted_record_tampering_replay_and_wrong_sequence_fail_authentication() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let secret = Zeroizing::new(vec![9; suite.hash_len()]);
        let mut writer = RecordCipher::new(suite, secret.clone()).unwrap();
        let record = writer.seal(23, b"secret payload").unwrap();
        for index in 0..record.len() {
            let mut changed = record.clone();
            changed[index] ^= 1;
            let mut reader = RecordCipher::new(suite, secret.clone()).unwrap();
            assert!(
                reader
                    .open(changed[..5].try_into().unwrap(), changed[5..].to_vec())
                    .is_err(),
                "accepted tampering at {index}"
            );
        }
        let mut reader = RecordCipher::new(suite, secret).unwrap();
        reader
            .open(record[..5].try_into().unwrap(), record[5..].to_vec())
            .unwrap();
        assert!(
            reader
                .open(record[..5].try_into().unwrap(), record[5..].to_vec())
                .is_err()
        );
    }
}

fn encrypted_inner_plaintext(inner: &[u8]) -> Vec<u8> {
    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInPlace, KeyInit},
    };
    let suite = CipherSuite::Aes128GcmSha256;
    let secret = [47; 32];
    let key = suite.expand_label(&secret, b"key", b"", 16).unwrap();
    let iv = suite.expand_label(&secret, b"iv", b"", 12).unwrap();
    let len = inner.len() + 16;
    let header = [23, 3, 3, (len >> 8) as u8, len as u8];
    let mut encrypted = inner.to_vec();
    Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt_in_place(aes_gcm::Nonce::from_slice(&iv), &header, &mut encrypted)
        .unwrap();
    let mut record = header.to_vec();
    record.extend(encrypted);
    record
}

#[test]
fn authenticated_padding_counts_toward_inner_plaintext_limit_and_control_content_is_nonempty() {
    for (kind, content, padding, allowed) in [
        (23, b"x".as_slice(), 16383, true),
        (23, b"x".as_slice(), 16384, false),
        (23, b"".as_slice(), 16384, true),
        (22, b"".as_slice(), 0, false),
        (22, b"".as_slice(), 8, false),
        (21, b"".as_slice(), 0, false),
        (21, b"".as_slice(), 8, false),
    ] {
        let mut inner = content.to_vec();
        inner.push(kind);
        inner.resize(inner.len() + padding, 0);
        let record = encrypted_inner_plaintext(&inner);
        let mut reader =
            RecordCipher::new(CipherSuite::Aes128GcmSha256, Zeroizing::new(vec![47; 32])).unwrap();
        let result = reader.open(record[..5].try_into().unwrap(), record[5..].to_vec());
        assert_eq!(result.is_ok(), allowed, "kind={kind}, padding={padding}");
        if let Ok((actual_kind, actual_content)) = result {
            assert_eq!(actual_kind, kind);
            assert_eq!(actual_content, content);
        }
    }
}

#[test]
fn padded_records_bound_length_and_preserve_content_and_sequence() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let secret = Zeroizing::new(vec![47; suite.hash_len()]);
        let mut writer = RecordCipher::new(suite, secret.clone()).unwrap();
        let mut reader = RecordCipher::new(suite, secret).unwrap();
        assert!(writer.seal_padded(23, b"x", usize::MAX).is_err());
        assert!(writer.seal_padded(23, b"x", 16384).is_err());
        assert!(writer.seal_padded(22, b"", 1).is_err());
        for (kind, content, padding) in [
            (22, b"handshake".as_slice(), 100),
            (23, b"x".as_slice(), 16383),
            (23, b"".as_slice(), 16384),
            (23, b"next record".as_slice(), 0),
        ] {
            let record = writer.seal_padded(kind, content, padding).unwrap();
            assert_eq!(record.len(), 5 + content.len() + 1 + padding + 16);
            let opened = reader
                .open(record[..5].try_into().unwrap(), record[5..].to_vec())
                .unwrap();
            assert_eq!(opened, (kind, content.to_vec()));
        }
    }
}

#[test]
fn genuine_hybrid_key_share_decapsulates_mlkem_before_ecdh() {
    let keys = EphemeralKeys::generate().unwrap();
    let peer_secret = [42; 32];
    let peer_public = x25519(peer_secret, X25519_BASEPOINT_BYTES);
    let (ciphertext, kem_secret) = keys
        .mlkem
        .encapsulation_key()
        .encapsulate_deterministic(&[3; 32].into());
    let mut share = ciphertext.to_vec();
    share.extend_from_slice(&peer_public);
    let actual = keys.shared_secret(0x11ec, &share).unwrap();
    let expected_ecdh = x25519(
        peer_secret,
        x25519(*keys.hybrid_x25519, X25519_BASEPOINT_BYTES),
    );
    assert_eq!(&actual[..32], kem_secret.as_slice());
    assert_eq!(&actual[32..], &expected_ecdh);
    assert!(keys.shared_secret(0x001d, &[0; 32]).is_err());
    assert!(keys.shared_secret(0x11ec, &share[..1119]).is_err());
}

#[test]
fn both_client_profiles_authenticate_against_existing_reality_primitives() {
    for hybrid_only in [false, true] {
        let keys = EphemeralKeys::generate().unwrap();
        let mut config = config();
        config.hybrid_only = hybrid_only;
        let random = [11; 32];
        let standalone = x25519(*keys.standalone_x25519, X25519_BASEPOINT_BYTES);
        let mut hello =
            wire::client_hello(&config, &random, &keys.hybrid_public(), &standalone).unwrap();
        let selected = if hybrid_only {
            &keys.hybrid_x25519
        } else {
            &keys.standalone_x25519
        };
        let identity = ClientIdentity::new(config.client_version, 12345, config.short_id);
        authenticated_client_hello(&mut hello, selected, &config.server_public_key, identity)
            .unwrap();
        let parsed = super::super::ClientHello::parse(&hello).unwrap();
        let server_auth =
            RealityAuthKey::derive(&[7; 32], parsed.auth_public_key, &random).unwrap();
        assert_eq!(server_auth.open_client_hello(&hello).unwrap(), identity);
        assert_eq!(parsed.server_name, b"example.test");
    }
}

fn server_hello(session: &[u8], group: u16, share: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[23; 32]);
    body.push(session.len() as u8);
    body.extend_from_slice(session);
    body.extend_from_slice(&[0x13, 1, 0]);
    let mut extensions = Vec::new();
    wire::extension(&mut extensions, 43, &[3, 4]).unwrap();
    let mut key = group.to_be_bytes().to_vec();
    key.extend(wire::vector16(share).unwrap());
    wire::extension(&mut extensions, 51, &key).unwrap();
    body.extend(wire::vector16(&extensions).unwrap());
    wire::handshake(2, &body).unwrap()
}

#[test]
fn server_hello_validates_echo_group_and_every_truncated_prefix() {
    let session = [9; 32];
    let hello = server_hello(&session, 0x001d, &[1; 32]);
    assert!(wire::parse_server_hello(&hello, &session, false).is_ok());
    assert!(wire::parse_server_hello(&hello, &session, true).is_err());
    assert!(wire::parse_server_hello(&hello, &[8; 32], false).is_err());
    for len in 0..hello.len() {
        assert!(wire::parse_server_hello(&hello[..len], &session, false).is_err());
    }
    let mut appended = hello.clone();
    appended.push(0);
    assert!(wire::parse_server_hello(&appended, &session, false).is_err());
    assert!(
        wire::parse_server_hello(&server_hello(&session, 0x0017, &[1; 65]), &session, false)
            .is_err()
    );
}

fn vector24(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_be_bytes()[1..].to_vec();
    result.extend_from_slice(bytes);
    result
}

fn certificate(auth: &RealityAuthKey, marker: bool) -> (Vec<u8>, SigningKey) {
    let seed = [29; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let mut pkcs8 = hex("302e020100300506032b657004220420");
    pkcs8.extend_from_slice(&seed);
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8),
        &rcgen::PKCS_ED25519,
    )
    .unwrap();
    let mut der = rcgen::CertificateParams::new(vec!["example.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec();
    if marker {
        let end = der.len();
        der[end - 64..]
            .copy_from_slice(&auth.certificate_marker(signing_key.verifying_key().as_bytes()));
    }
    let mut entry = vector24(&der);
    entry.extend_from_slice(&[0, 0]);
    let mut body = vec![0];
    body.extend(vector24(&entry));
    (body, signing_key)
}

#[test]
fn certificate_marker_never_replaces_tls_certificate_verify_or_finished() {
    let auth = RealityAuthKey::from_shared_secret(&[5; 32], &[6; 32]).unwrap();
    let (body, signer) = certificate(&auth, true);
    let key = verify_certificate(&body, &auth, None, b"", b"").unwrap();
    let transcript_hash = [7; 32];
    let mut input = vec![32; 64];
    input.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    input.extend_from_slice(&transcript_hash);
    let mut proof = vec![8, 7];
    proof.extend(wire::vector16(&signer.sign(&input).to_bytes()).unwrap());
    verify_certificate_verify(&proof, &key, &transcript_hash).unwrap();
    assert!(verify_certificate_verify(&proof, &key, &[8; 32]).is_err());
    proof[5] ^= 1;
    assert!(verify_certificate_verify(&proof, &key, &transcript_hash).is_err());
    let mut changed = body.clone();
    let index = changed.len() - 3;
    changed[index] ^= 1;
    assert!(verify_certificate(&changed, &auth, None, b"", b"").is_err());
    assert!(
        verify_certificate(&certificate(&auth, false).0, &auth, None, b"", b"").is_err(),
        "ordinary certificate must not authenticate REALITY"
    );
    assert!(verify_finished(&[1; 32], &[2; 32]).is_err());
    assert!(verify_certificate(&body, &auth, Some(&[0; 1952]), b"client", b"server").is_err());
}

#[test]
fn mldsa65_verification_binds_message_public_key_and_signature() {
    let signer = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[19; 32].into());
    let public = ml_dsa::Keypair::verifying_key(&signer).encode();
    let signature: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::Signer::sign(&signer, b"reality original hello transcript");
    let encoded = signature.encode();
    verify_mldsa65(
        public.as_slice(),
        encoded.as_slice(),
        b"reality original hello transcript",
    )
    .unwrap();
    assert!(
        verify_mldsa65(
            public.as_slice(),
            encoded.as_slice(),
            b"changed hello transcript"
        )
        .is_err()
    );
    assert!(
        verify_mldsa65(
            &[0; 1952],
            encoded.as_slice(),
            b"reality original hello transcript"
        )
        .is_err()
    );
    let mut corrupted = encoded.to_vec();
    corrupted[0] ^= 1;
    assert!(
        verify_mldsa65(
            public.as_slice(),
            &corrupted,
            b"reality original hello transcript"
        )
        .is_err()
    );
}

#[test]
fn bounded_handshake_parser_reassembles_fragments_and_rejects_declared_oversize() {
    let mut buffer = HandshakeBuffer::new(32);
    let message = wire::handshake(8, &[1; 29]).unwrap();
    for byte in &message[..message.len() - 1] {
        buffer.push(&[*byte]).unwrap();
        assert!(buffer.take().unwrap().is_none());
    }
    buffer.push(&message[message.len() - 1..]).unwrap();
    assert_eq!(buffer.take().unwrap().unwrap(), message);
    buffer.push(&[11, 0, 1, 0]).unwrap();
    assert!(buffer.take().is_err());
}

fn traffic_pair(suite: CipherSuite) -> (ClientStream, ClientStream) {
    let (a, b) = tokio::io::duplex(65536);
    let c = Zeroizing::new(vec![1; suite.hash_len()]);
    let s = Zeroizing::new(vec![2; suite.hash_len()]);
    let a = ClientStream::new(
        Box::new(a),
        RecordCipher::new(suite, s.clone()).unwrap(),
        RecordCipher::new(suite, c.clone()).unwrap(),
        65536,
    );
    let b = ClientStream::new(
        Box::new(b),
        RecordCipher::new(suite, c).unwrap(),
        RecordCipher::new(suite, s).unwrap(),
        65536,
    );
    (a, b)
}

#[tokio::test]
async fn application_stream_preserves_large_payloads_and_bidirectional_half_close() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let (mut a, mut b) = traffic_pair(suite);
        let payload = vec![61; 131_077];
        let expected = payload.clone();
        let sending = async move {
            a.write_all(&payload).await.unwrap();
            a.shutdown().await.unwrap();
            let mut response = Vec::new();
            a.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"after client half-close");
        };
        let receiving = async move {
            let mut received = Vec::new();
            b.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
            b.write_all(b"after client half-close").await.unwrap();
            b.shutdown().await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(sending, receiving);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn incoming_key_update_rekeys_before_data_and_replies_with_old_write_key() {
    let suite = CipherSuite::Aes128GcmSha256;
    let secret = Zeroizing::new(vec![4; 32]);
    let (a, mut peer) = tokio::io::duplex(4096);
    let mut stream = ClientStream::new(
        Box::new(a),
        RecordCipher::new(suite, secret.clone()).unwrap(),
        RecordCipher::new(suite, secret.clone()).unwrap(),
        65536,
    );
    let mut sender = RecordCipher::new(suite, secret.clone()).unwrap();
    peer.write_all(&sender.seal(22, &[24, 0, 0, 1, 1]).unwrap())
        .await
        .unwrap();
    sender.update().unwrap();
    peer.write_all(&sender.seal(23, b"updated").unwrap())
        .await
        .unwrap();
    let mut plain = [0; 7];
    stream.read_exact(&mut plain).await.unwrap();
    assert_eq!(&plain, b"updated");
    let mut record_reader = RecordReader::default();
    let reply = poll_fn(|cx| record_reader.poll_read(&mut peer, cx))
        .await
        .unwrap();
    let mut receiver = RecordCipher::new(suite, secret).unwrap();
    assert_eq!(
        receiver.open(&reply.header, reply.payload).unwrap(),
        (22, vec![24, 0, 0, 1, 0])
    );
    receiver.update().unwrap();
    stream.write_all(b"reply").await.unwrap();
    stream.flush().await.unwrap();
    let record = poll_fn(|cx| record_reader.poll_read(&mut peer, cx))
        .await
        .unwrap();
    assert_eq!(
        receiver.open(&record.header, record.payload).unwrap(),
        (23, b"reply".to_vec())
    );
}

#[tokio::test]
async fn key_update_may_span_old_key_records_or_follow_a_ticket_at_record_end() {
    let mut ticket_body = vec![0; 8];
    ticket_body.push(0);
    ticket_body.extend(wire::vector16(&[42]).unwrap());
    ticket_body.extend_from_slice(&[0, 0]);
    let mut ticket_and_update = wire::handshake(4, &ticket_body).unwrap();
    ticket_and_update.extend_from_slice(&[24, 0, 0, 1, 0]);
    for fragments in [vec![vec![24, 0], vec![0, 1, 0]], vec![ticket_and_update]] {
        let (a, mut peer) = tokio::io::duplex(4096);
        let secret = Zeroizing::new(vec![18; 32]);
        let suite = CipherSuite::Aes128GcmSha256;
        let mut stream = ClientStream::new(
            Box::new(a),
            RecordCipher::new(suite, secret.clone()).unwrap(),
            RecordCipher::new(suite, secret.clone()).unwrap(),
            65536,
        );
        let mut sender = RecordCipher::new(suite, secret).unwrap();
        for fragment in fragments {
            peer.write_all(&sender.seal(22, &fragment).unwrap())
                .await
                .unwrap();
        }
        sender.update().unwrap();
        peer.write_all(&sender.seal(23, b"new-key data").unwrap())
            .await
            .unwrap();
        let mut payload = [0; 12];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"new-key data");
    }
}

#[tokio::test]
async fn key_update_rejects_trailing_old_key_handshake_bytes_and_invalid_request_values() {
    for message in [&[24, 0, 0, 1, 0, 4, 0, 0, 0][..], &[24, 0, 0, 1, 2][..]] {
        let (a, mut peer) = tokio::io::duplex(4096);
        let secret = Zeroizing::new(vec![18; 32]);
        let suite = CipherSuite::Aes128GcmSha256;
        let mut stream = ClientStream::new(
            Box::new(a),
            RecordCipher::new(suite, secret.clone()).unwrap(),
            RecordCipher::new(suite, secret.clone()).unwrap(),
            65536,
        );
        let mut sender = RecordCipher::new(suite, secret).unwrap();
        peer.write_all(&sender.seal(22, message).unwrap())
            .await
            .unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn abrupt_eof_is_not_reported_as_authenticated_close() {
    let (a, b) = tokio::io::duplex(1024);
    drop(b);
    let suite = CipherSuite::Aes128GcmSha256;
    let secret = Zeroizing::new(vec![0; 32]);
    let mut stream = ClientStream::new(
        Box::new(a),
        RecordCipher::new(suite, secret.clone()).unwrap(),
        RecordCipher::new(suite, secret).unwrap(),
        65536,
    );
    assert_eq!(
        stream.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn close_notify_cannot_complete_a_truncated_post_handshake_message() {
    let (a, mut peer) = tokio::io::duplex(4096);
    let secret = Zeroizing::new(vec![18; 32]);
    let suite = CipherSuite::Aes128GcmSha256;
    let mut stream = ClientStream::new(
        Box::new(a),
        RecordCipher::new(suite, secret.clone()).unwrap(),
        RecordCipher::new(suite, secret.clone()).unwrap(),
        65536,
    );
    let mut sender = RecordCipher::new(suite, secret).unwrap();
    peer.write_all(&sender.seal(22, &[4, 0, 0, 100, 1, 2, 3]).unwrap())
        .await
        .unwrap();
    peer.write_all(&sender.seal(21, &[1, 0]).unwrap())
        .await
        .unwrap();
    assert_eq!(
        stream.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn malformed_mldsa_configuration_is_rejected_before_any_network_write() {
    let (a, mut peer) = tokio::io::duplex(4096);
    let mut config = config();
    config.mldsa65_verify = Some(vec![0; 1951]);
    assert!(
        matches!(client(Box::new(a), config).await, Err(error) if error.kind() == io::ErrorKind::InvalidInput)
    );
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

struct GoFixture(Child);
impl Drop for GoFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires XRAY_REALITY_GO_SERVER pointing to the fixture built from the pre-removal git history"]
async fn pinned_go_reality_server_interoperability() {
    let executable = std::env::var_os("XRAY_REALITY_GO_SERVER")
        .expect(
            "build handshake/interop/main.go from the pre-removal git history and set XRAY_REALITY_GO_SERVER",
        );
    for (group, use_mldsa) in [("hybrid", false), ("x25519", false), ("hybrid", true)] {
        let mut command = Command::new(&executable);
        command
            .arg(group)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if use_mldsa {
            command.arg("mldsa");
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut process = GoFixture(command.spawn().unwrap());
        let mut line = String::new();
        BufReader::new(process.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let endpoint: serde_json::Value = serde_json::from_str(&line).unwrap();
        let address = endpoint["address"].as_str().unwrap();
        let public_key: [u8; 32] = hex(endpoint["public_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        for hybrid_only in if group == "hybrid" {
            vec![false, true]
        } else {
            vec![false]
        } {
            let mut cfg = ClientConfig::new("example.test".into(), public_key, [1; 8], [26, 9, 19]);
            cfg.hybrid_only = hybrid_only;
            if use_mldsa {
                cfg.mldsa65_verify = Some(hex(endpoint["mldsa65_public_key"].as_str().unwrap()));
            }
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut stream, info) = client(Box::new(socket), cfg).await.unwrap();
            assert_eq!(
                info.key_exchange_group,
                if group == "hybrid" { 0x11ec } else { 0x001d }
            );
            let payload: Vec<_> = (0..65539).map(|index| (index % 251) as u8).collect();
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let mut echoed = vec![0; payload.len()];
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::try_join!(
                    async {
                        writer.write_all(&payload).await?;
                        writer.flush().await
                    },
                    async { reader.read_exact(&mut echoed).await.map(|_| ()) }
                )
                .unwrap();
            })
            .await
            .unwrap();
            assert_eq!(echoed, payload);
            stream.shutdown().await.unwrap();
        }
        // Wrong credentials must never yield an authenticated application stream.
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let bad = ClientConfig::new("example.test".into(), public_key, [2; 8], [26, 9, 19]);
        assert!(client(Box::new(socket), bad).await.is_err());
        if use_mldsa {
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut wrong_key =
                ClientConfig::new("example.test".into(), public_key, [1; 8], [26, 9, 19]);
            wrong_key.mldsa65_verify = Some(vec![0; 1952]);
            assert!(client(Box::new(socket), wrong_key).await.is_err());
        }
    }
}
