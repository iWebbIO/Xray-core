//! Legacy Shadowsocks SIP004 AEAD TCP framing.
//!
//! The wire stream is a random salt followed by authenticated length/payload
//! pairs. Each direction needs its own salt, subkey, and nonce counter. These
//! adapters retain partial I/O across polls, authenticate complete records before
//! releasing plaintext, and bound allocations to the maximum record size.
//!
//! This module does not implement destination headers, account selection, replay
//! protection, UDP, or Shadowsocks 2022. A server must reject reused salts at the
//! account/session layer. A salt obtained from an untrusted connection is not an
//! authenticated identity until at least one record has been verified.

use std::{
    io,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll, ready},
};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::{RngCore, rngs::OsRng};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PAYLOAD_LEN: usize = 0x3fff;
pub const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const LENGTH_RECORD_LEN: usize = 2 + TAG_LEN;

/// The legacy AEAD methods supported by this TCP codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub const fn salt_len(self) -> usize {
        self.key_len()
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-ietf-poly1305",
        }
    }
}

impl FromStr for CipherKind {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aes_128_gcm" | "aead_aes_128_gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" | "aes_256_gcm" | "aead_aes_256_gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305"
            | "chacha20-ietf-poly1305"
            | "chacha20_poly1305"
            | "aead_chacha20_poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported legacy Shadowsocks AEAD TCP method",
            )),
        }
    }
}

/// The unsalted, single-iteration OpenSSL EVP_BytesToKey MD5 expansion used by
/// legacy Shadowsocks. This is protocol compatibility, not a general password KDF.
pub fn password_to_key(kind: CipherKind, password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(Vec::with_capacity(kind.key_len()));
    let mut previous = Zeroizing::new(Vec::<u8>::new());
    while key.len() < kind.key_len() {
        let mut digest = Md5::new();
        digest.update(previous.as_slice());
        digest.update(password);
        let mut block = digest.finalize();
        previous.clear();
        previous.extend_from_slice(&block);
        let remaining = kind.key_len() - key.len();
        key.extend_from_slice(&block[..remaining.min(block.len())]);
        block.as_mut_slice().zeroize();
    }
    key
}

/// HKDF-SHA1(master_key, salt, "ss-subkey"), as specified by SIP004.
pub fn derive_subkey(
    kind: CipherKind,
    master_key: &[u8],
    salt: &[u8],
) -> io::Result<Zeroizing<Vec<u8>>> {
    check_key(kind, master_key)?;
    if salt.len() != kind.salt_len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Shadowsocks salt length",
        ));
    }
    let mut key = Zeroizing::new(vec![0; kind.key_len()]);
    Hkdf::<Sha1>::new(Some(salt), master_key)
        .expand(b"ss-subkey", key.as_mut_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid subkey length"))?;
    Ok(key)
}

fn check_key(kind: CipherKind, key: &[u8]) -> io::Result<()> {
    if key.len() == kind.key_len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Shadowsocks master key length",
        ))
    }
}

#[derive(Default)]
struct NonceSequence {
    bytes: [u8; NONCE_LEN],
    exhausted: bool,
}

impl NonceSequence {
    fn next(&mut self) -> io::Result<[u8; NONCE_LEN]> {
        if self.exhausted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Shadowsocks nonce counter exhausted",
            ));
        }
        let current = self.bytes;
        for byte in &mut self.bytes {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return Ok(current);
            }
        }
        // The final nonce is usable once. Subsequent operations must fail rather
        // than wrap around and repeat the all-zero nonce with the same key.
        self.exhausted = true;
        Ok(current)
    }
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

struct SessionCipher {
    cipher: Cipher,
    nonce: NonceSequence,
}

impl SessionCipher {
    fn new(kind: CipherKind, key: &[u8], salt: &[u8]) -> io::Result<Self> {
        let subkey = derive_subkey(kind, key, salt)?;
        let invalid_key =
            |_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Shadowsocks AEAD key");
        let cipher = match kind {
            CipherKind::Aes128Gcm => Cipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&subkey).map_err(invalid_key)?,
            )),
            CipherKind::Aes256Gcm => Cipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&subkey).map_err(invalid_key)?,
            )),
            CipherKind::ChaCha20Poly1305 => Cipher::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&subkey).map_err(invalid_key)?,
            )),
        };
        Ok(Self {
            cipher,
            nonce: NonceSequence::default(),
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.nonce.next()?;
        let mut buffer = plaintext.to_vec();
        let result = match &self.cipher {
            Cipher::Aes128(cipher) => {
                cipher.encrypt_in_place(aes_gcm::Nonce::from_slice(&nonce), b"", &mut buffer)
            }
            Cipher::Aes256(cipher) => {
                cipher.encrypt_in_place(aes_gcm::Nonce::from_slice(&nonce), b"", &mut buffer)
            }
            Cipher::ChaCha(cipher) => cipher.encrypt_in_place(
                chacha20poly1305::Nonce::from_slice(&nonce),
                b"",
                &mut buffer,
            ),
        };
        if result.is_err() {
            buffer.zeroize();
            return Err(io::Error::other("Shadowsocks encryption failed"));
        }
        Ok(buffer)
    }

    fn open(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.nonce.next()?;
        let result = match &self.cipher {
            Cipher::Aes128(cipher) => {
                cipher.decrypt_in_place(aes_gcm::Nonce::from_slice(&nonce), b"", buffer)
            }
            Cipher::Aes256(cipher) => {
                cipher.decrypt_in_place(aes_gcm::Nonce::from_slice(&nonce), b"", buffer)
            }
            Cipher::ChaCha(cipher) => {
                cipher.decrypt_in_place(chacha20poly1305::Nonce::from_slice(&nonce), b"", buffer)
            }
        };
        result.map_err(|_| {
            buffer.zeroize();
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Shadowsocks record authentication failed",
            )
        })
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks payload exceeds the maximum record length",
            ));
        }
        let mut record = self.seal(&(payload.len() as u16).to_be_bytes())?;
        record.extend_from_slice(&self.seal(payload)?);
        Ok(record)
    }
}

#[derive(Clone, Copy)]
enum ReadPhase {
    Salt,
    Length,
    Payload,
    Eof,
    Failed(io::ErrorKind),
}

/// A byte-stream reader which verifies each entire AEAD record before exposing
/// its plaintext. Empty authenticated records are skipped, not treated as EOF.
/// Dropping a pending read future preserves the internal wire framing state.
pub struct AeadReader<R> {
    inner: R,
    kind: CipherKind,
    master_key: Zeroizing<Vec<u8>>,
    cipher: Option<SessionCipher>,
    salt: Option<Vec<u8>>,
    phase: ReadPhase,
    encrypted: Vec<u8>,
    received: usize,
    plaintext: Zeroizing<Vec<u8>>,
    consumed: usize,
}

impl<R> AeadReader<R> {
    pub fn new(inner: R, kind: CipherKind, password: &[u8]) -> io::Result<Self> {
        Self::from_key(inner, kind, &password_to_key(kind, password))
    }

    /// Consume the remote salt from `inner` before reading records.
    pub fn from_key(inner: R, kind: CipherKind, master_key: &[u8]) -> io::Result<Self> {
        check_key(kind, master_key)?;
        Ok(Self {
            inner,
            kind,
            master_key: Zeroizing::new(master_key.to_vec()),
            cipher: None,
            salt: None,
            phase: ReadPhase::Salt,
            encrypted: vec![0; kind.salt_len()],
            received: 0,
            plaintext: Zeroizing::new(Vec::new()),
            consumed: 0,
        })
    }

    /// Construct a reader after the caller has already consumed the remote salt.
    /// The first bytes in `inner` must be the first encrypted length record.
    pub fn with_salt(
        inner: R,
        kind: CipherKind,
        master_key: &[u8],
        salt: &[u8],
    ) -> io::Result<Self> {
        let cipher = SessionCipher::new(kind, master_key, salt)?;
        Ok(Self {
            inner,
            kind,
            master_key: Zeroizing::new(Vec::new()),
            cipher: Some(cipher),
            salt: Some(salt.to_vec()),
            phase: ReadPhase::Length,
            encrypted: vec![0; LENGTH_RECORD_LEN],
            received: 0,
            plaintext: Zeroizing::new(Vec::new()),
            consumed: 0,
        })
    }

    /// The received salt, if it has been fully read. See the module-level replay
    /// protection requirement; merely receiving a salt does not authenticate it.
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Return the underlying reader, discarding any buffered decrypted bytes.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn fail(&mut self, error: io::Error) -> Poll<io::Result<()>> {
        self.phase = ReadPhase::Failed(error.kind());
        self.encrypted.zeroize();
        self.plaintext.zeroize();
        self.master_key.zeroize();
        self.cipher = None;
        Poll::Ready(Err(error))
    }

    fn next_record(&mut self, phase: ReadPhase, length: usize) {
        self.encrypted.zeroize();
        self.encrypted.resize(length, 0);
        self.received = 0;
        self.phase = phase;
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AeadReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Bound work even when a peer sends many authenticated empty records.
        for _ in 0..32 {
            if this.consumed < this.plaintext.len() {
                let count = output.remaining().min(this.plaintext.len() - this.consumed);
                output.put_slice(&this.plaintext[this.consumed..this.consumed + count]);
                this.consumed += count;
                if this.consumed == this.plaintext.len() {
                    this.plaintext.zeroize();
                    this.consumed = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.phase {
                ReadPhase::Eof => return Poll::Ready(Ok(())),
                ReadPhase::Failed(kind) => {
                    return Poll::Ready(Err(io::Error::new(
                        kind,
                        "Shadowsocks reader cannot continue after a stream error",
                    )));
                }
                _ => {}
            }
            let mut input = ReadBuf::new(&mut this.encrypted[this.received..]);
            match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input)) {
                Err(error) => return this.fail(error),
                Ok(()) => {
                    let count = input.filled().len();
                    if count == 0 {
                        if matches!(this.phase, ReadPhase::Length) && this.received == 0 {
                            this.phase = ReadPhase::Eof;
                            return Poll::Ready(Ok(()));
                        }
                        return this.fail(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Shadowsocks salt or record",
                        ));
                    }
                    this.received += count;
                }
            }
            if this.received < this.encrypted.len() {
                continue;
            }
            match this.phase {
                ReadPhase::Salt => {
                    let cipher =
                        match SessionCipher::new(this.kind, &this.master_key, &this.encrypted) {
                            Ok(cipher) => cipher,
                            Err(error) => return this.fail(error),
                        };
                    this.salt = Some(this.encrypted.clone());
                    this.master_key.zeroize();
                    this.cipher = Some(cipher);
                    this.next_record(ReadPhase::Length, LENGTH_RECORD_LEN);
                }
                ReadPhase::Length => {
                    let Some(cipher) = this.cipher.as_mut() else {
                        return this.fail(io::Error::other("missing Shadowsocks session cipher"));
                    };
                    if let Err(error) = cipher.open(&mut this.encrypted) {
                        return this.fail(error);
                    }
                    let length =
                        u16::from_be_bytes([this.encrypted[0], this.encrypted[1]]) as usize;
                    if length > MAX_PAYLOAD_LEN {
                        return this.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks payload exceeds the maximum record length",
                        ));
                    }
                    this.next_record(ReadPhase::Payload, length + TAG_LEN);
                }
                ReadPhase::Payload => {
                    let Some(cipher) = this.cipher.as_mut() else {
                        return this.fail(io::Error::other("missing Shadowsocks session cipher"));
                    };
                    if let Err(error) = cipher.open(&mut this.encrypted) {
                        return this.fail(error);
                    }
                    this.plaintext.extend_from_slice(&this.encrypted);
                    this.consumed = 0;
                    this.next_record(ReadPhase::Length, LENGTH_RECORD_LEN);
                }
                ReadPhase::Eof | ReadPhase::Failed(_) => unreachable!(),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// A bounded-buffer AEAD writer. Each successful nonempty write accepts at most
/// `MAX_PAYLOAD_LEN` bytes. Call `flush` or `shutdown` to drain the final record;
/// dropping the writer does not perform asynchronous I/O.
pub struct AeadWriter<W> {
    inner: W,
    cipher: SessionCipher,
    salt: Vec<u8>,
    pending: Vec<u8>,
    written: usize,
    failed: Option<io::ErrorKind>,
    shutdown: bool,
}

impl<W> AeadWriter<W> {
    pub fn new(inner: W, kind: CipherKind, password: &[u8]) -> io::Result<Self> {
        Self::from_key(inner, kind, &password_to_key(kind, password))
    }

    pub fn from_key(inner: W, kind: CipherKind, master_key: &[u8]) -> io::Result<Self> {
        check_key(kind, master_key)?;
        let mut salt = vec![0; kind.salt_len()];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| io::Error::other("could not generate a Shadowsocks session salt"))?;
        Self::with_salt(inner, kind, master_key, &salt)
    }

    /// Emit a caller-supplied salt before the first record. The caller MUST ensure
    /// this salt is never reused with the same master key, in either direction.
    /// Prefer `new` or `from_key`, which obtain salts from the operating system.
    pub fn with_salt(
        inner: W,
        kind: CipherKind,
        master_key: &[u8],
        salt: &[u8],
    ) -> io::Result<Self> {
        Ok(Self {
            inner,
            cipher: SessionCipher::new(kind, master_key, salt)?,
            salt: salt.to_vec(),
            pending: salt.to_vec(),
            written: 0,
            failed: None,
            shutdown: false,
        })
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Return the underlying writer. Flush first to avoid discarding queued data.
    pub fn into_inner(self) -> W {
        self.inner
    }

    fn check_open(&self) -> io::Result<()> {
        if let Some(kind) = self.failed {
            Err(io::Error::new(
                kind,
                "Shadowsocks writer cannot continue after a stream error",
            ))
        } else if self.shutdown {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Shadowsocks writer has been shut down",
            ))
        } else {
            Ok(())
        }
    }
}

impl<W: AsyncWrite + Unpin> AeadWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..32 {
            if self.written == self.pending.len() {
                self.pending.clear();
                self.written = 0;
                return Poll::Ready(Ok(()));
            }
            let result =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]));
            match result {
                Ok(0) => {
                    self.failed = Some(io::ErrorKind::WriteZero);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "could not write Shadowsocks salt or record",
                    )));
                }
                Ok(count) => self.written += count,
                Err(error) => {
                    self.failed = Some(error.kind());
                    return Poll::Ready(Err(error));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AeadWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_open()?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.poll_drain(cx))?;
        let length = buffer.len().min(MAX_PAYLOAD_LEN);
        match this.cipher.seal_chunk(&buffer[..length]) {
            Ok(record) => {
                this.pending = record;
                Poll::Ready(Ok(length))
            }
            Err(error) => {
                this.failed = Some(error.kind());
                Poll::Ready(Err(error))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_open()?;
        ready!(this.poll_drain(cx))?;
        let result = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        if let Err(error) = &result {
            this.failed = Some(error.kind());
        }
        Poll::Ready(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        this.check_open()?;
        ready!(this.poll_drain(cx))?;
        match ready!(Pin::new(&mut this.inner).poll_shutdown(cx)) {
            Ok(()) => {
                this.shutdown = true;
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                this.failed = Some(error.kind());
                Poll::Ready(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Waker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const FIRST_PAYLOAD: &[u8] = b"\x03\x0bexample.com\x01\xbbhello";
    const SECOND_PAYLOAD: &[u8] = b"world";

    struct Vector {
        kind: CipherKind,
        key: &'static str,
        subkey: &'static str,
        wire: &'static str,
    }

    // Independently generated with Python cryptography 50.0.1 (OpenSSL-backed
    // AESGCM/ChaCha20Poly1305 and HKDF), hashlib.md5, and explicit byte-order
    // encoding. Password: "password"; salt: bytes(range(key_len)); payloads above.
    // These constants deliberately cover multiple records and nonces 0..=3.
    const VECTORS: &[Vector] = &[
        Vector {
            kind: CipherKind::Aes128Gcm,
            key: "5f4dcc3b5aa765d61d8327deb882cf99",
            subkey: "ed2a618d9490d1701de885d82aa80616",
            wire: concat!(
                "000102030405060708090a0b0c0d0e0f",
                "5c3a018ad5a3dade7192a2cad7061ed12e91",
                "ff1a7ea18456ee41050a92f7f43411191163cd183dff3587a265a1dcb76b7f6d040d98b4f",
                "7d21e1c0c17caadfde232c6e55dc00f4c2ce",
                "1bc576a8639a278fe7655803c1942dc4b962947b1",
            ),
        },
        Vector {
            kind: CipherKind::Aes256Gcm,
            key: "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08",
            subkey: "ee187aed3f87574907a39db98606f60a526114831288097cac66054b33a9464f",
            wire: concat!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "7eb1e74651876cca50979731faf962d1e5da",
                "f62bba0d4b25261b49e432d754ab992e6a6965fd986126f72fb16be3ffd1b63199d0682c",
                "8e9592365e698bac22ab920558367a0bf5ad",
                "68980e9ba1ae489815576f928e6847469749f0995b",
            ),
        },
        Vector {
            kind: CipherKind::ChaCha20Poly1305,
            key: "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08",
            subkey: "ee187aed3f87574907a39db98606f60a526114831288097cac66054b33a9464f",
            wire: concat!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "ad5c1efb7fdec9f4b41c2dacded86e7d7e87",
                "83c3ce5d825d5be9428b2bc98d00058b7c47fd9a372be54bdce10e3d9c5c2cb932930c78",
                "ef962715abb8903234d772356c9e91ccfcc8",
                "d0f628e250c5bdaa65fc92ad03412a0e5ec979f6e1",
            ),
        },
    ];

    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| (byte as char).to_digit(16).unwrap() as u8;
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn independent_password_and_hkdf_vectors() {
        for vector in VECTORS {
            let key = password_to_key(vector.kind, b"password");
            assert_eq!(key.as_slice(), hex(vector.key));
            let salt = &hex(vector.wire)[..vector.kind.salt_len()];
            assert_eq!(
                derive_subkey(vector.kind, &key, salt).unwrap().as_slice(),
                hex(vector.subkey)
            );
        }
    }

    #[tokio::test]
    async fn independent_wire_vectors_encrypt_and_decrypt() {
        for vector in VECTORS {
            let wire = hex(vector.wire);
            let key = hex(vector.key);
            let salt = &wire[..vector.kind.salt_len()];
            let mut writer = AeadWriter::with_salt(Vec::new(), vector.kind, &key, salt).unwrap();
            writer.write_all(FIRST_PAYLOAD).await.unwrap();
            writer.write_all(SECOND_PAYLOAD).await.unwrap();
            writer.flush().await.unwrap();
            assert_eq!(writer.get_ref(), &wire, "{}", vector.kind.name());

            let mut reader = AeadReader::new(wire.as_slice(), vector.kind, b"password").unwrap();
            let mut plaintext = Vec::new();
            reader.read_to_end(&mut plaintext).await.unwrap();
            assert_eq!(plaintext, [FIRST_PAYLOAD, SECOND_PAYLOAD].concat());
            assert_eq!(reader.salt(), Some(salt));

            let mut reader =
                AeadReader::with_salt(&wire[salt.len()..], vector.kind, &key, salt).unwrap();
            plaintext.clear();
            reader.read_to_end(&mut plaintext).await.unwrap();
            assert_eq!(plaintext, [FIRST_PAYLOAD, SECOND_PAYLOAD].concat());
        }
    }

    #[tokio::test]
    async fn authenticates_every_byte_before_releasing_plaintext() {
        for vector in VECTORS {
            let length = vector.kind.salt_len() + LENGTH_RECORD_LEN + FIRST_PAYLOAD.len() + TAG_LEN;
            let original = &hex(vector.wire)[..length];
            for index in 0..length {
                let mut wire = original.to_vec();
                wire[index] ^= 1;
                let mut reader =
                    AeadReader::new(wire.as_slice(), vector.kind, b"password").unwrap();
                let mut plaintext = Vec::new();
                let error = reader.read_to_end(&mut plaintext).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData, "byte {index}");
                assert!(plaintext.is_empty(), "released unauthenticated plaintext");
                assert_eq!(
                    reader.read_u8().await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData,
                    "authentication failure must poison the reader"
                );
            }
        }
    }

    #[tokio::test]
    async fn rejects_every_truncated_salt_or_record() {
        for vector in VECTORS {
            let wire = hex(vector.wire);
            let first_end =
                vector.kind.salt_len() + LENGTH_RECORD_LEN + FIRST_PAYLOAD.len() + TAG_LEN;
            for cut in 0..first_end {
                if cut == vector.kind.salt_len() {
                    // EOF between records is valid; a salt-only stream is empty.
                    continue;
                }
                let mut reader = AeadReader::new(&wire[..cut], vector.kind, b"password").unwrap();
                let mut plaintext = Vec::new();
                assert_eq!(
                    reader.read_to_end(&mut plaintext).await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof,
                    "{} cut at {cut}",
                    vector.kind.name()
                );
                assert!(plaintext.is_empty());
            }
            let mut reader = AeadReader::new(&wire[..first_end], vector.kind, b"password").unwrap();
            let mut plaintext = Vec::new();
            reader.read_to_end(&mut plaintext).await.unwrap();
            assert_eq!(plaintext, FIRST_PAYLOAD);
        }
    }

    #[test]
    fn nonce_is_little_endian_and_never_wraps() {
        let mut nonce = NonceSequence::default();
        assert_eq!(nonce.next().unwrap(), [0; NONCE_LEN]);
        for _ in 1..255 {
            nonce.next().unwrap();
        }
        let mut expected = [0; NONCE_LEN];
        expected[0] = 255;
        assert_eq!(nonce.next().unwrap(), expected);
        expected[0] = 0;
        expected[1] = 1;
        assert_eq!(nonce.next().unwrap(), expected);
        nonce.bytes = [255; NONCE_LEN];
        assert_eq!(nonce.next().unwrap(), [255; NONCE_LEN]);
        assert!(nonce.next().is_err());
        assert!(nonce.next().is_err());
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        for vector in VECTORS {
            let key = hex(vector.key);
            let salt = vec![0; vector.kind.salt_len()];
            assert!(AeadReader::from_key(&b""[..], vector.kind, &key[..key.len() - 1]).is_err());
            assert!(derive_subkey(vector.kind, &key, &salt[..salt.len() - 1]).is_err());
            assert!(derive_subkey(vector.kind, &key[..key.len() - 1], &salt).is_err());
        }
        assert_eq!(
            "AES-128-GCM".parse::<CipherKind>().unwrap(),
            CipherKind::Aes128Gcm
        );
        assert_eq!(
            "chacha20-poly1305".parse::<CipherKind>().unwrap(),
            CipherKind::ChaCha20Poly1305
        );
        assert!("2022-blake3-aes-128-gcm".parse::<CipherKind>().is_err());
        assert!("xchacha20-poly1305".parse::<CipherKind>().is_err());
        assert!("none".parse::<CipherKind>().is_err());
    }

    #[tokio::test]
    async fn chunk_boundary_lengths_and_shutdown() {
        for vector in VECTORS {
            for length in [1, MAX_PAYLOAD_LEN - 1, MAX_PAYLOAD_LEN, MAX_PAYLOAD_LEN + 1] {
                let key = hex(vector.key);
                let salt = vec![9; vector.kind.salt_len()];
                let payload = vec![0x5a; length];
                let mut writer =
                    AeadWriter::with_salt(Vec::new(), vector.kind, &key, &salt).unwrap();
                writer.write_all(&payload).await.unwrap();
                writer.shutdown().await.unwrap();
                writer.shutdown().await.unwrap();
                assert_eq!(
                    writer.write_u8(1).await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                let wire = writer.into_inner();
                let count = length.div_ceil(MAX_PAYLOAD_LEN);
                assert_eq!(
                    wire.len(),
                    salt.len() + length + count * (LENGTH_RECORD_LEN + TAG_LEN)
                );
                let mut verifier = SessionCipher::new(vector.kind, &key, &salt).unwrap();
                let mut offset = salt.len();
                let mut remaining = length;
                while remaining > 0 {
                    let mut encrypted_length = wire[offset..offset + LENGTH_RECORD_LEN].to_vec();
                    offset += LENGTH_RECORD_LEN;
                    verifier.open(&mut encrypted_length).unwrap();
                    let chunk_len =
                        u16::from_be_bytes(encrypted_length.try_into().unwrap()) as usize;
                    assert_eq!(chunk_len, remaining.min(MAX_PAYLOAD_LEN));
                    let mut chunk = wire[offset..offset + chunk_len + TAG_LEN].to_vec();
                    offset += chunk_len + TAG_LEN;
                    verifier.open(&mut chunk).unwrap();
                    assert_eq!(chunk, vec![0x5a; chunk_len]);
                    remaining -= chunk_len;
                }
                let mut reader =
                    AeadReader::new(wire.as_slice(), vector.kind, b"password").unwrap();
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, payload);
            }
        }
    }

    #[tokio::test]
    async fn rejects_oversized_authenticated_length() {
        let kind = CipherKind::Aes128Gcm;
        let key = password_to_key(kind, b"password");
        let salt = vec![0; kind.salt_len()];
        let mut cipher = SessionCipher::new(kind, &key, &salt).unwrap();
        let mut wire = salt;
        wire.extend_from_slice(&cipher.seal(&0x4000u16.to_be_bytes()).unwrap());
        let mut reader = AeadReader::new(wire.as_slice(), kind, b"password").unwrap();
        assert_eq!(
            reader.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // A rejected length must not cause an allocation for its alleged body.
        // Vec may round the small salt/header allocation up when growing.
        assert!(reader.encrypted.capacity() < 0x4000);
    }

    #[tokio::test]
    async fn empty_records_do_not_end_the_stream_and_empty_writes_do_not_add_records() {
        let kind = CipherKind::Aes128Gcm;
        let key = password_to_key(kind, b"password");
        let salt = vec![0; kind.salt_len()];
        let mut cipher = SessionCipher::new(kind, &key, &salt).unwrap();
        let mut wire = salt.clone();
        // Enough records to exercise the cooperative polling budget.
        for _ in 0..100 {
            wire.extend_from_slice(&cipher.seal_chunk(b"").unwrap());
        }
        wire.extend_from_slice(&cipher.seal_chunk(b"hello").unwrap());
        let mut reader = AeadReader::new(wire.as_slice(), kind, b"password").unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).await.unwrap();
        assert_eq!(plaintext, b"hello");

        let mut writer = AeadWriter::with_salt(Vec::new(), kind, &key, &salt).unwrap();
        assert_eq!(writer.write(b"").await.unwrap(), 0);
        writer.flush().await.unwrap();
        assert_eq!(writer.get_ref(), &salt);
        let mut reader = AeadReader::new(writer.get_ref().as_slice(), kind, b"password").unwrap();
        assert_eq!(reader.read(&mut [0; 1]).await.unwrap(), 0);
    }

    struct FragmentedReader {
        wire: Vec<u8>,
        offset: usize,
        block_next: bool,
    }

    impl AsyncRead for FragmentedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.block_next {
                this.block_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if this.offset < this.wire.len() && buffer.remaining() > 0 {
                buffer.put_slice(&this.wire[this.offset..this.offset + 1]);
                this.offset += 1;
                this.block_next = true;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn fragmented_read_survives_cancelled_future() {
        let vector = &VECTORS[0];
        let inner = FragmentedReader {
            wire: hex(vector.wire),
            offset: 0,
            block_next: false,
        };
        let mut reader = AeadReader::new(inner, vector.kind, b"password").unwrap();
        let mut byte = [0; 1];
        let mut future = Box::pin(reader.read_exact(&mut byte));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        drop(future);
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).await.unwrap();
        assert_eq!(plaintext, [FIRST_PAYLOAD, SECOND_PAYLOAD].concat());
    }

    #[derive(Default)]
    struct FragmentedWriter {
        wire: Vec<u8>,
        block_next: bool,
        shutdown: bool,
    }

    impl AsyncWrite for FragmentedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.block_next {
                this.block_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let count = buffer.len().min(3);
            this.wire.extend_from_slice(&buffer[..count]);
            this.block_next = true;
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn fragmented_write_survives_cancelled_flush() {
        for vector in VECTORS {
            let wire = hex(vector.wire);
            let mut writer = AeadWriter::with_salt(
                FragmentedWriter::default(),
                vector.kind,
                &hex(vector.key),
                &wire[..vector.kind.salt_len()],
            )
            .unwrap();
            writer.write_all(FIRST_PAYLOAD).await.unwrap();
            let mut future = Box::pin(writer.flush());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            drop(future);
            writer.write_all(SECOND_PAYLOAD).await.unwrap();
            writer.shutdown().await.unwrap();
            assert_eq!(writer.get_ref().wire, wire);
            assert!(writer.get_ref().shutdown);
        }
    }

    struct BrokenWriter;

    impl AsyncWrite for BrokenWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn failed_write_cannot_be_retried_with_new_plaintext() {
        let mut writer = AeadWriter::new(BrokenWriter, CipherKind::Aes128Gcm, b"password").unwrap();
        assert_eq!(
            writer.write_u8(1).await.unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(
            writer.flush().await.unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(
            writer.write_u8(2).await.unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
}
