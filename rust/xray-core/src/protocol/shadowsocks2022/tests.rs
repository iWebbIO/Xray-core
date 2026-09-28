use super::*;
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, duplex};

fn account(kind: CipherKind) -> Account {
    Account::from_key(
        kind,
        &(0..kind.key_len() as u8).collect::<Vec<_>>(),
        "ss2022@example.test".into(),
    )
    .unwrap()
}
fn target() -> Destination {
    Destination::new("example.org", 443).unwrap()
}
fn salt(kind: CipherKind) -> Vec<u8> {
    (32..32 + kind.key_len() as u8).collect()
}
fn response_salt(kind: CipherKind) -> Vec<u8> {
    (80..80 + kind.key_len() as u8).collect()
}
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// Independent Python blake3 derive_key_context + cryptography AESGCM fixtures,
// following pinned sing-shadowsocks v0.2.7 record order, not Rust round trips.
#[tokio::test]
async fn independent_aes128_aes256_handshake_and_record_vectors() {
    for (
        kind,
        expected_key,
        request_hex,
        request_body,
        response_hex,
        response_body,
        empty_response,
    ) in [
        (
            CipherKind::Aes128Gcm,
            "8180421f8f56092ca7544a64ff852536",
            "202122232425262728292a2b2c2d2e2fced439ccd5cb58003297446921804afb67de65f51e5f0147c5ec0c1dd6f7900b8f2ce61fcee866c3b49c4da589a8f797a10c49511796896b5357ac47ef33d82b33147b",
            "bd2d8d1bdf58ebc0ce5d5364f34e1e99941c0f4d2bb2873b464680bbd756673c900fed266b1a92",
            "505152535455565758595a5b5c5d5e5f394917bdb1a55f4bd6937c93c8deef277cc29f4ccca00278a55012335afd52996033638d084426ece81e5198d30b2b91688af2c1b7079f973bf5cdb0f8a524d5",
            "07cbaaf84dd0879b215e0680b58252822ef90d96f5de68b5a5313dd8d4352a81cf5ae756312715",
            "505152535455565758595a5b5c5d5e5f394917bdb1a55f4bd6937c93c8deef277cc29f4ccca00278a550175a0eb4eef0ba254131f4bfc742a5963fa2fa2a6480ab6465a816b93aa3e51f59",
        ),
        (
            CipherKind::Aes256Gcm,
            "374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3faa4efbd2198e0f750c826221b588f16540662cf549ac176b89f4f1e906b5d46f86e2a0c6ab7795392a973b32dbd751b76f6e3f0b591220d5273abf7372f58c94549566",
            "1e830a086555683257980dbbed6a135fd3d4f1f206e413dc631864eb34e0aafea75c991c999b3a",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7d8430f92c1487481cc10bbcfe5e00d711b1bc4be8e859668e77f62cd05f757627a248608a0274092d167d097ecc988d3de250ee1ea68258ddabc7c7d1ef68b2dcb74097b38eee29b3461b1b269b3263",
            "d67089142bd7f0c4b4afbe8623370c88ad5ebc6f9abf1ab9535e0e997f5a2c09f443f85cd7ed55",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7d8430f92c1487481cc10bbcfe5e00d711b1bc4be8e859668e77f62cd05f757627a248608a0274092d16789a00fef6f2a6a8fc98d5495538009f6e8ec282ab87dc6ec99abb5130a65f5f00",
        ),
    ] {
        let account = account(kind);
        let salt = salt(kind);
        let rsalt = response_salt(kind);
        let now = 1_700_000_000;
        assert_eq!(
            &*codec::subkey(&account, &salt).unwrap(),
            &hex(expected_key)
        );
        let (wire, mut writer) =
            codec::request(&account, &salt, &target(), &[0xaa, 0xbb], b"hello", now)
                .await
                .unwrap();
        assert_eq!(wire, hex(request_hex));
        assert_eq!(writer.frame(b"later").unwrap(), hex(request_body));
        let mut reader = codec::Cipher::new(&account, &salt).unwrap();
        let fixed_end = salt.len() + 27;
        let fixed = reader.open(&wire[salt.len()..fixed_end]).unwrap();
        assert_eq!(
            codec::parse_request_fixed(&fixed, now).unwrap() + 16,
            wire.len() - fixed_end
        );
        let variable = reader.open(&wire[fixed_end..]).unwrap();
        assert_eq!(
            codec::parse_request_variable(&variable).await.unwrap(),
            (target(), b"hello".to_vec())
        );
        let body = hex(request_body);
        assert_eq!(reader.open(&body[..18]).unwrap(), [0, 5]);
        assert_eq!(reader.open(&body[18..]).unwrap(), b"later");
        let (wire, mut writer) = codec::response(&account, &rsalt, &salt, b"world", now).unwrap();
        assert_eq!(wire, hex(response_hex));
        assert_eq!(writer.frame(b"later").unwrap(), hex(response_body));
        assert_eq!(
            codec::response(&account, &rsalt, &salt, &[], now)
                .unwrap()
                .0,
            hex(empty_response)
        );
        let mut reader = codec::Cipher::new(&account, &rsalt).unwrap();
        let end = rsalt.len() + 11 + salt.len() + 16;
        assert_eq!(
            codec::parse_response_fixed(&reader.open(&wire[rsalt.len()..end]).unwrap(), &salt, now)
                .unwrap(),
            5
        );
        assert_eq!(reader.open(&wire[end..]).unwrap(), b"world");
    }
}

#[test]
fn account_modes_key_normalization_and_timestamp_edges() {
    for kind in [
        CipherKind::Aes128Gcm,
        CipherKind::Aes256Gcm,
        CipherKind::ChaCha20Poly1305,
    ] {
        let key = vec![0xa5; kind.key_len()];
        let password = STANDARD.encode(&key);
        assert_eq!(
            Account::new(kind, &password, String::new())
                .unwrap()
                .cipher(),
            kind
        );
        let wrapped = format!("{}\r\n{}", &password[..4], &password[4..]);
        assert_eq!(
            Account::new(kind, &wrapped, String::new())
                .unwrap()
                .cipher(),
            kind
        );
        assert!(Account::new(kind, &format!("{password}:{password}"), String::new()).is_err());
        assert!(Account::new(kind, "not base64", String::new()).is_err());
        assert!(Account::from_key(kind, &key[..key.len() - 1], String::new()).is_err());
        let long = vec![0x5a; 64];
        let normalized = Account::from_key(kind, &long, String::new()).unwrap();
        assert_eq!(
            normalized.key.as_slice(),
            &Sha256::digest(&long)[..kind.key_len()]
        );
        let debug = format!("{normalized:?}");
        assert!(!debug.contains("90, 90"));
        assert_eq!(kind.name().parse::<CipherKind>().unwrap(), kind);
    }
    // The single-key XChaCha method parses like every other method; its
    // cipher arms are exercised by the codec round trips below.
    assert_eq!(
        "2022-blake3-chacha20-poly1305"
            .parse::<CipherKind>()
            .unwrap(),
        CipherKind::ChaCha20Poly1305
    );
    let now = 1_700_000_000;
    for epoch in [now - 30, now, now + 30] {
        codec::check_timestamp(epoch, now).unwrap();
    }
    for epoch in [0, now - 31, now + 31, u64::MAX] {
        assert!(codec::check_timestamp(epoch, now).is_err());
    }
}

#[test]
fn replay_retention_and_capacity_do_not_evict_live_salts() {
    let now = Instant::now();
    let mut cache = ReplayCache::default();
    cache.admit(b"salt", now).unwrap();
    assert!(cache.admit(b"salt", now + REPLAY_LIFETIME).is_err());
    cache
        .admit(b"salt", now + REPLAY_LIFETIME + Duration::from_nanos(1))
        .unwrap();
    for i in 0..REPLAY_CAPACITY - 1 {
        cache
            .admit(
                &i.to_le_bytes(),
                now + REPLAY_LIFETIME + Duration::from_nanos(1),
            )
            .unwrap();
    }
    assert!(
        cache
            .admit(b"new", now + REPLAY_LIFETIME + Duration::from_nanos(1))
            .is_err()
    );
}

async fn raw_accept(wire: &[u8], account: &Account) -> Result<(BoxStream, Request)> {
    let (mut client, server) = duplex(wire.len().max(1) + 1);
    client.write_all(wire).await.unwrap();
    client.shutdown().await.unwrap();
    accept(Box::new(server), account).await
}

#[tokio::test]
async fn request_authentication_replay_and_initial_payload_boundaries() {
    for kind in [
        CipherKind::Aes128Gcm,
        CipherKind::Aes256Gcm,
        CipherKind::ChaCha20Poly1305,
    ] {
        let account = account(kind);
        let salt = salt(kind);
        let now = unix_time().unwrap();
        let (mut wire, mut cipher) =
            codec::request(&account, &salt, &target(), &[1], b"initial", now)
                .await
                .unwrap();
        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(raw_accept(&tampered, &account).await.is_err());
        assert!(account.received.lock().unwrap().salts.is_empty());
        wire.extend(cipher.frame(b"later").unwrap());
        let (mut stream, request) = raw_accept(&wire, &account).await.unwrap();
        assert_eq!(request.destination, target());
        assert_eq!(request.user, "ss2022@example.test");
        assert!(request.initial_payload.is_empty());
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"initiallater");
        assert!(raw_accept(&wire, &account.clone()).await.is_err());
        for count in 0..kind.key_len() + 27 {
            assert!(
                raw_accept(&wire[..count], &super::tests::account(kind))
                    .await
                    .is_err()
            );
        }
        let (old, _) = codec::request(&account, &salt, &target(), &[1], &[], now - 31)
            .await
            .unwrap();
        assert!(
            raw_accept(&old, &super::tests::account(kind))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn malformed_variable_headers_and_response_binding_are_rejected() {
    let account = account(CipherKind::Aes128Gcm);
    let salt = salt(account.kind);
    let now = unix_time().unwrap();
    let mut addr = Vec::new();
    target().write_socks(&mut addr).await.unwrap();
    for suffix in [vec![], vec![0], vec![0, 0], vec![0, 2, 1]] {
        let mut variable = addr.clone();
        variable.extend(suffix);
        assert!(codec::parse_request_variable(&variable).await.is_err());
    }
    let (wire, _) = codec::response(
        &account,
        &response_salt(account.kind),
        &salt,
        b"secret",
        now,
    )
    .unwrap();
    for request_salt in [vec![0; 16], salt.clone()] {
        let (_, writer) = codec::request(&account, &request_salt, &target(), &[1], &[], now)
            .await
            .unwrap();
        let (mut peer, client) = duplex(4096);
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut client = Shadowsocks2022Stream::client(
            Box::new(client),
            account.clone(),
            request_salt.clone(),
            writer,
        );
        let mut output = [0; 6];
        if request_salt != salt {
            assert!(client.read(&mut output).await.is_err());
            assert_eq!(output, [0; 6]);
            assert!(client.write_all(b"bad").await.is_err());
        } else {
            client.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"secret");
        }
    }
    // Reusing a correctly bound, authenticated response salt is still rejected.
    let (_, writer) = codec::request(&account, &salt, &target(), &[1], &[], now)
        .await
        .unwrap();
    let (mut peer, client) = duplex(4096);
    peer.write_all(&wire).await.unwrap();
    let mut client = Shadowsocks2022Stream::client(Box::new(client), account, salt, writer);
    assert!(client.read(&mut [0; 16]).await.is_err());
}

#[tokio::test]
async fn forged_record_tags_and_response_type_time_never_release_plaintext() {
    let kind = CipherKind::Aes128Gcm;
    let now = unix_time().unwrap();
    let request_salt = salt(kind);
    let rsalt = response_salt(kind);
    for case in 0..4 {
        let account = account(kind);
        let mut cipher = codec::Cipher::new(&account, &rsalt).unwrap();
        let mut fixed = vec![if case == 0 { 0 } else { 1 }];
        fixed.extend_from_slice(&(if case == 1 { now - 31 } else { now }).to_be_bytes());
        fixed.extend_from_slice(&request_salt);
        fixed.extend_from_slice(&6u16.to_be_bytes());
        let mut wire = rsalt.clone();
        wire.extend(cipher.seal(&fixed).unwrap());
        let mut payload = cipher.seal(b"secret").unwrap();
        if case == 2 {
            payload[0] ^= 1;
        }
        wire.extend(payload);
        if case == 3 {
            wire[rsalt.len()] ^= 1;
        }
        let (_, writer) = codec::request(&account, &request_salt, &target(), &[1], &[], now)
            .await
            .unwrap();
        let (mut peer, client) = duplex(4096);
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut client = Shadowsocks2022Stream::client(
            Box::new(client),
            account.clone(),
            request_salt.clone(),
            writer,
        );
        let mut plaintext = [0; 6];
        assert!(client.read(&mut plaintext).await.is_err());
        assert_eq!(plaintext, [0; 6]);
        assert!(client.read(&mut plaintext).await.is_err());
        assert!(client.write_all(b"after failure").await.is_err());
        assert!(account.received.lock().unwrap().salts.is_empty());
    }
    let account = account(kind);
    let (mut wire, mut writer) = codec::request(&account, &request_salt, &target(), &[1], &[], now)
        .await
        .unwrap();
    let mut frame = writer.frame(b"body secret").unwrap();
    *frame.last_mut().unwrap() ^= 1;
    wire.extend(frame);
    let (mut server, _) = raw_accept(&wire, &account).await.unwrap();
    let mut output = [0; 32];
    assert!(server.read(&mut output).await.is_err());
    assert_eq!(output, [0; 32]);
    assert!(server.flush().await.is_err());
}

#[tokio::test]
async fn domain_literal_normalization_and_payloadless_padding_constraints() {
    for (domain, expected) in [
        ("[::1]", "::1"),
        ("[::ffff:192.0.2.1]", "192.0.2.1"),
        ("192.0.2.1", "192.0.2.1"),
    ] {
        let mut raw = vec![3, domain.len() as u8];
        raw.extend_from_slice(domain.as_bytes());
        raw.extend_from_slice(&[1, 187, 0, 1, 0]);
        assert_eq!(
            codec::parse_request_variable(&raw).await.unwrap(),
            (Destination::new(expected, 443).unwrap(), Vec::new())
        );
    }
    let account = account(CipherKind::Aes128Gcm);
    assert!(
        codec::request(
            &account,
            &salt(account.kind),
            &target(),
            &[],
            &[],
            unix_time().unwrap()
        )
        .await
        .is_err()
    );
    assert!(
        codec::request(
            &account,
            &salt(account.kind),
            &target(),
            &vec![0; 901],
            &[],
            unix_time().unwrap()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn every_partial_response_and_ordinary_record_is_truncation_not_eof() {
    let kind = CipherKind::Aes128Gcm;
    let now = unix_time().unwrap();
    let salt = salt(kind);
    let (response, _) =
        codec::response(&account(kind), &response_salt(kind), &salt, b"hello", now).unwrap();
    for count in 0..response.len() {
        let account = account(kind);
        let (_, writer) = codec::request(&account, &salt, &target(), &[1], &[], now)
            .await
            .unwrap();
        let (mut peer, client) = duplex(4096);
        peer.write_all(&response[..count]).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut client =
            Shadowsocks2022Stream::client(Box::new(client), account, salt.clone(), writer);
        let error = client.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "cut {count}");
    }
    let base = account(kind);
    let (request, mut writer) = codec::request(&base, &salt, &target(), &[1], &[], now)
        .await
        .unwrap();
    let frame = writer.frame(b"hello").unwrap();
    for count in 1..frame.len() {
        let mut wire = request.clone();
        wire.extend_from_slice(&frame[..count]);
        let (mut server, _) = raw_accept(&wire, &account(kind)).await.unwrap();
        assert_eq!(
            server.read(&mut [0; 16]).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "cut {count}"
        );
    }
}

#[tokio::test]
async fn complete_tcp_sessions_support_maximum_records_and_half_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for kind in [
            CipherKind::Aes128Gcm,
            CipherKind::Aes256Gcm,
            CipherKind::ChaCha20Poly1305,
        ] {
            // Enough space for the complete first fixed header, preserving its
            // source single-read gate; the body exceeds the duplex buffer.
            let (client, server) = duplex(2048);
            let server_account = account(kind);
            let task = tokio::spawn(async move {
                let (mut server, _) = accept(Box::new(server), &server_account).await.unwrap();
                let mut request = Vec::new();
                server.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, vec![0xa5; MAX_PAYLOAD_LENGTH + 123]);
                server.write_all(&request).await.unwrap();
                server.shutdown().await.unwrap();
            });
            let mut client = connect(Box::new(client), &account(kind), &target())
                .await
                .unwrap();
            client
                .write_all(&vec![0xa5; MAX_PAYLOAD_LENGTH + 123])
                .await
                .unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, vec![0xa5; MAX_PAYLOAD_LENGTH + 123]);
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

struct OneByte<S> {
    inner: S,
    read: bool,
    write: bool,
}
impl<S> OneByte<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            read: false,
            write: false,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for OneByte<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.read {
            this.read = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.read = false;
        let mut b = [0];
        let mut rb = ReadBuf::new(&mut b);
        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                output.put_slice(rb.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for OneByte<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write {
            this.write = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.write = false;
        Pin::new(&mut this.inner).poll_write(cx, &input[..1])
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn one_byte_io_cancelled_operations_and_empty_flush_preserve_records() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let account = account(CipherKind::Aes128Gcm);
        let salt = salt(account.kind);
        let (_, writer) =
            codec::request(&account, &salt, &target(), &[1], &[], unix_time().unwrap())
                .await
                .unwrap();
        let mut reader = codec::Cipher::new(&account, &salt).unwrap();
        // Position the server's request reader after the two handshake chunks.
        let (wire, _) = codec::request(&account, &salt, &target(), &[1], &[], unix_time().unwrap())
            .await
            .unwrap();
        reader.open(&wire[16..43]).unwrap();
        reader.open(&wire[43..]).unwrap();
        let (client, server) = duplex(4096);
        let mut client = Shadowsocks2022Stream::client(
            Box::new(OneByte::new(client)),
            account.clone(),
            salt.clone(),
            writer,
        );
        let mut server = Shadowsocks2022Stream::server(
            Box::new(OneByte::new(server)),
            account,
            salt,
            reader,
            Vec::new(),
        );
        // Empty flush sends one authenticated empty first-response record, not EOF.
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_flush(cx)))
                .await
                .is_pending()
        );
        server.flush().await.unwrap();
        server.write_all(b"first").await.unwrap();
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_write(cx, b"discard")))
                .await
                .is_pending()
        );
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_flush(cx)))
                .await
                .is_pending()
        );
        server.write_all(b"second").await.unwrap();
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_shutdown(cx)))
                .await
                .is_pending()
        );
        assert!(server.write_all(b"late").await.is_err());
        server.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        let mut byte = [0];
        let mut rb = ReadBuf::new(&mut byte);
        for _ in 0..8 {
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut client).poll_read(cx, &mut rb)))
                    .await
                    .is_pending()
            );
        }
        let mut data = Vec::new();
        client.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"firstsecond");
    })
    .await
    .unwrap();
}

// This subprocess is a test peer only. Production code never invokes Go.
struct GoPeer(std::process::Child);
impl Drop for GoPeer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn interop_data(size: usize, response: bool) -> Vec<u8> {
    (0..size)
        .map(|i| {
            if response {
                255 - (i % 251) as u8
            } else {
                (i % 251) as u8
            }
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires XRAY_SS2022_GO_PEER pointing to the separately built pinned Go test peer"]
async fn pinned_go_tcp_interoperability_both_directions_and_ciphers() {
    use std::{
        io::BufRead,
        process::{Command, Stdio},
    };
    let binary = std::env::var_os("XRAY_SS2022_GO_PEER")
        .expect("set XRAY_SS2022_GO_PEER to the built fixtures/go-peer executable");
    tokio::time::timeout(Duration::from_secs(60), async {
        for kind in [
            CipherKind::Aes128Gcm,
            CipherKind::Aes256Gcm,
            CipherKind::ChaCha20Poly1305,
        ] {
            let account = account(kind);
            let password = STANDARD.encode(account.key.as_slice());
            let mut peer = GoPeer(
                Command::new(&binary)
                    .args(["server", kind.name(), &password])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let stdout = peer.0.stdout.take().unwrap();
            let mut address = String::new();
            std::io::BufReader::new(stdout)
                .read_line(&mut address)
                .unwrap();
            let socket = tokio::net::TcpStream::connect(address.trim())
                .await
                .unwrap();
            let mut client = connect(Box::new(socket), &account, &target())
                .await
                .unwrap();
            client.write_all(&interop_data(70017, false)).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = vec![0; 73031];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, interop_data(response.len(), true));
            drop(client);
            assert!(peer.0.wait().unwrap().success());
            drop(peer);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let mut peer = GoPeer(
                Command::new(&binary)
                    .args(["client", kind.name(), &password, &address])
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let (socket, _) = listener.accept().await.unwrap();
            let (mut server, request) = accept(Box::new(socket), &account).await.unwrap();
            assert_eq!(request.destination, target());
            let mut received = vec![0; 70017];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, interop_data(received.len(), false));
            server.write_all(&interop_data(73031, true)).await.unwrap();
            server.shutdown().await.unwrap();
            drop(server);
            assert!(peer.0.wait().unwrap().success());
        }
    })
    .await
    .unwrap();
}
