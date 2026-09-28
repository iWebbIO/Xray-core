//! Single-account Shadowsocks 2022 TCP and UDP, pinned to sing-shadowsocks v0.2.7.
//!
//! Supports 2022-blake3-aes-128-gcm and 2022-blake3-aes-256-gcm. Extended
//! identity headers, relay/multi-user key chains, and ChaCha2022 are not
//! supported here. Account clones share replay state. The caller supplies
//! handshake deadlines and socket-level close/drain policy.

mod codec;
mod stream;
pub mod udp;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{
    address::Destination,
    protocol::{Reply, Request},
    transport::BoxStream,
};
pub use stream::Shadowsocks2022Stream;

pub const MAX_PAYLOAD_LENGTH: usize = u16::MAX as usize;
pub const MAX_PADDING_LENGTH: usize = 900;
pub const TIMESTAMP_TOLERANCE_SECONDS: u64 = 30;
// Inclusive +/-30-second timestamps can remain valid for almost 61 wall-clock
// seconds because the timestamp is truncated to seconds. Keep salts that long.
const REPLAY_LIFETIME: Duration = Duration::from_secs(61);
const REPLAY_CAPACITY: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    /// Single-key XChaCha20-Poly1305 (32-byte PSK and salt); the UDP layout
    /// uses the PSK directly and TCP derives session subkeys.
    ChaCha20Poly1305,
}
impl CipherKind {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }
}
impl FromStr for CipherKind {
    type Err = anyhow::Error;
    fn from_str(name: &str) -> Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => anyhow::bail!("unsupported Shadowsocks2022 cipher"),
        }
    }
}

#[derive(Default)]
struct ReplayCache {
    salts: HashSet<Vec<u8>>,
    order: VecDeque<(Instant, Vec<u8>)>,
}
impl ReplayCache {
    fn admit(&mut self, salt: &[u8], now: Instant) -> Result<()> {
        while self
            .order
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > REPLAY_LIFETIME)
        {
            let (_, expired) = self.order.pop_front().expect("front checked");
            self.salts.remove(&expired);
        }
        ensure!(!self.salts.contains(salt), "replayed Shadowsocks2022 salt");
        ensure!(
            self.salts.len() < REPLAY_CAPACITY,
            "Shadowsocks2022 replay capacity exhausted"
        );
        self.salts.insert(salt.to_vec());
        self.order.push_back((now, salt.to_vec()));
        Ok(())
    }
}

/// One shared account per listener/remote. Constructing one per accepted stream
/// would defeat replay protection. Secrets are omitted from Debug output.
#[derive(Clone)]
pub struct Account {
    kind: CipherKind,
    key: Arc<Zeroizing<Vec<u8>>>,
    email: String,
    received: Arc<Mutex<ReplayCache>>,
    generated: Arc<Mutex<ReplayCache>>,
}
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shadowsocks2022Account")
            .field("cipher", &self.kind)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}
impl Account {
    pub fn new(kind: CipherKind, password: &str, email: String) -> Result<Self> {
        ensure!(
            !password.contains(':'),
            "Shadowsocks2022 EIH/multi-user relay key chains are unsupported"
        );
        // Go's base64.StdEncoding ignores CR/LF inside encoded key strings.
        let encoded = Zeroizing::new(
            password
                .bytes()
                .filter(|byte| !matches!(*byte, b'\r' | b'\n'))
                .collect::<Vec<_>>(),
        );
        let key = Zeroizing::new(
            STANDARD
                .decode(encoded.as_slice())
                .context("invalid Shadowsocks2022 base64 PSK")?,
        );
        Self::from_key(kind, &key, email)
    }
    /// Like the pinned Go constructor, longer decoded keys use SHA256 truncated
    /// to the cipher key size; shorter keys are rejected. This is not EVP_BytesToKey.
    pub fn from_key(kind: CipherKind, key: &[u8], email: String) -> Result<Self> {
        ensure!(
            key.len() >= kind.key_len(),
            "Shadowsocks2022 PSK is too short"
        );
        let key = if key.len() == kind.key_len() {
            key.to_vec()
        } else {
            Sha256::digest(key)[..kind.key_len()].to_vec()
        };
        Ok(Self {
            kind,
            key: Arc::new(Zeroizing::new(key)),
            email,
            received: Arc::default(),
            generated: Arc::default(),
        })
    }
    pub fn cipher(&self) -> CipherKind {
        self.kind
    }
    pub fn email(&self) -> &str {
        &self.email
    }
    fn admit_received(&self, salt: &[u8]) -> Result<()> {
        self.received
            .lock()
            .map_err(|_| anyhow::anyhow!("Shadowsocks2022 replay mutex poisoned"))?
            .admit(salt, Instant::now())
    }
    fn fresh_salt(&self) -> Result<Vec<u8>> {
        let mut salt = vec![0; self.kind.key_len()];
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .context("generate Shadowsocks2022 salt")?;
        self.generated
            .lock()
            .map_err(|_| anyhow::anyhow!("Shadowsocks2022 salt mutex poisoned"))?
            .admit(&salt, Instant::now())?;
        Ok(salt)
    }
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Authenticate the complete request before routing. Preserve the source's
/// single-read fixed-header gate: a short first transport read is rejected.
/// Cancellation owns/drops the stream. Later records tolerate arbitrary partial I/O.
pub async fn accept(mut stream: BoxStream, account: &Account) -> Result<(BoxStream, Request)> {
    let salt_length = account.kind.key_len();
    let mut prefix = vec![0; salt_length + codec::REQUEST_FIXED_LENGTH + codec::TAG_LENGTH];
    let count = stream
        .read(&mut prefix)
        .await
        .context("read Shadowsocks2022 request prefix")?;
    ensure!(
        count == prefix.len(),
        "short Shadowsocks2022 initial fixed header"
    );
    let salt = prefix[..salt_length].to_vec();
    let mut cipher = codec::Cipher::new(account, &salt)?;
    let fixed = cipher
        .open(&prefix[salt_length..])
        .context("authenticate single-account Shadowsocks2022 header (EIH unsupported)")?;
    let length = codec::parse_request_fixed(&fixed, unix_time()?)?;
    let mut variable = vec![0; length + codec::TAG_LENGTH];
    stream
        .read_exact(&mut variable)
        .await
        .context("read Shadowsocks2022 variable header")?;
    let variable = cipher.open(&variable)?;
    let (destination, initial) = codec::parse_request_variable(&variable).await?;
    account.admit_received(&salt)?; // Unauthenticated salts cannot poison the cache.
    let request = Request {
        destination,
        user: account.email.clone(),
        initial_payload: Vec::new(),
        reply: Reply::None,
    };
    let stream = Shadowsocks2022Stream::server(stream, account.clone(), salt, cipher, initial);
    Ok((Box::new(stream), request))
}

/// Emit the request without waiting for a response. Application writes can
/// proceed immediately; response authentication occurs on the first read.
pub async fn connect(
    mut stream: BoxStream,
    account: &Account,
    target: &Destination,
) -> Result<BoxStream> {
    let salt = account.fresh_salt()?;
    let padding_length = rand::rngs::OsRng.gen_range(1..=MAX_PADDING_LENGTH);
    let mut padding = vec![0; padding_length];
    rand::rngs::OsRng
        .try_fill_bytes(&mut padding)
        .context("generate Shadowsocks2022 padding")?;
    let (wire, cipher) =
        codec::request(account, &salt, target, &padding, &[], unix_time()?).await?;
    stream
        .write_all(&wire)
        .await
        .context("write Shadowsocks2022 request")?;
    stream.flush().await?;
    Ok(Box::new(Shadowsocks2022Stream::client(
        stream,
        account.clone(),
        salt,
        cipher,
    )))
}

#[cfg(test)]
mod tests;
