use std::{
    collections::HashMap,
    fmt, io,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use super::super::encryption::Algorithm;
use super::{
    invalid,
    keys::{PrivateKey, PublicKey},
    unsupported,
};

const DEFAULT_PADDING_PLAINTEXT: usize = 77;
const MAX_PADDING_PLAINTEXT: usize = u16::MAX as usize - 16;
pub const MAX_RELAY_KEYS: usize = 8;

fn parse_text(text: &str, server: bool) -> io::Result<Vec<&str>> {
    if text.len() > MAX_RELAY_KEYS * 1600 + 128 {
        return Err(invalid("VLESS encryption configuration is too long"));
    }
    let fields: Vec<_> = text.split('.').collect();
    if fields.first() != Some(&"mlkem768x25519plus") {
        return Err(unsupported("expected mlkem768x25519plus VLESS encryption"));
    }
    if fields.get(1) != Some(&"native") {
        return Err(unsupported(
            "VLESS XOR encryption modes are not supported by this handshake profile",
        ));
    }
    let valid_round_trip = if server {
        matches!(fields.get(2), Some(&"0") | Some(&"0s") | Some(&"0-0s"))
    } else {
        fields.get(2) == Some(&"1rtt")
    };
    if !valid_round_trip {
        return Err(unsupported(
            "VLESS ticket resumption and nonzero ticket lifetimes are not supported",
        ));
    }
    if fields.len() < 4 || fields[3..].iter().any(|field| field.len() < 20) {
        return Err(unsupported(
            "VLESS configured padding schedules are not supported",
        ));
    }
    if fields.len() - 3 > MAX_RELAY_KEYS {
        return Err(unsupported("VLESS native relay chain exceeds eight keys"));
    }
    Ok(fields[3..].to_vec())
}

fn padding_len(length: usize) -> io::Result<usize> {
    if !(1..=MAX_PADDING_PLAINTEXT).contains(&length) {
        return Err(invalid(
            "VLESS handshake padding must contain 1..65519 plaintext bytes",
        ));
    }
    Ok(length)
}

/// An ordered chain of configured public keys and client-side 1-RTT options.
pub struct ClientConfig {
    pub(super) keys: Vec<PublicKey>,
    pub(super) algorithm: Algorithm,
    pub(super) padding: usize,
}

impl ClientConfig {
    pub fn parse(text: &str) -> io::Result<Self> {
        let keys = parse_text(text, false)?
            .into_iter()
            .map(|field| {
                URL_SAFE_NO_PAD
                    .decode(field)
                    .map_err(|_| invalid("invalid VLESS public key base64url"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::from_public_keys(&keys)
    }

    pub fn from_public_key(key: &[u8]) -> io::Result<Self> {
        Ok(Self {
            keys: vec![PublicKey::parse(key)?],
            algorithm: Algorithm::Aes256Gcm,
            padding: DEFAULT_PADDING_PLAINTEXT,
        })
    }

    pub fn from_public_keys(keys: &[Vec<u8>]) -> io::Result<Self> {
        if keys.is_empty() || keys.len() > MAX_RELAY_KEYS {
            return Err(invalid(
                "VLESS native relay chain requires one to eight public keys",
            ));
        }
        Ok(Self {
            keys: keys
                .iter()
                .map(|key| PublicKey::parse(key))
                .collect::<io::Result<_>>()?,
            algorithm: Algorithm::Aes256Gcm,
            padding: DEFAULT_PADDING_PLAINTEXT,
        })
    }

    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set fixed authenticated padding. This changes lengths, not send timing.
    pub fn with_padding_length(mut self, length: usize) -> io::Result<Self> {
        self.padding = padding_len(length)?;
        Ok(self)
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("relay_keys", &self.keys.len())
            .field("algorithm", &self.algorithm)
            .field("padding", &self.padding)
            .finish_non_exhaustive()
    }
}

/// Server key plus process-local replay protection. Share this value across
/// connections. Keys, remembered transcript hashes, and key-derived values are
/// deliberately excluded from Debug output.
pub struct ServerConfig {
    pub(super) keys: Vec<PrivateKey>,
    pub(super) padding: usize,
    replay: Mutex<ReplayCache>,
}

impl ServerConfig {
    pub fn parse(text: &str) -> io::Result<Self> {
        let keys = parse_text(text, true)?
            .into_iter()
            .map(|field| {
                let key = Zeroizing::new(
                    URL_SAFE_NO_PAD
                        .decode(field)
                        .map_err(|_| invalid("invalid VLESS private key base64url"))?,
                );
                PrivateKey::parse(&key)
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::from_parsed_keys(keys)
    }

    pub fn from_private_key(key: &[u8]) -> io::Result<Self> {
        Self::from_parsed_keys(vec![PrivateKey::parse(key)?])
    }

    pub fn from_private_keys(keys: &[Vec<u8>]) -> io::Result<Self> {
        if keys.is_empty() || keys.len() > MAX_RELAY_KEYS {
            return Err(invalid(
                "VLESS native relay chain requires one to eight private keys",
            ));
        }
        Self::from_parsed_keys(
            keys.iter()
                .map(|key| PrivateKey::parse(key))
                .collect::<io::Result<_>>()?,
        )
    }

    fn from_parsed_keys(keys: Vec<PrivateKey>) -> io::Result<Self> {
        Ok(Self {
            keys,
            padding: DEFAULT_PADDING_PLAINTEXT,
            replay: Mutex::new(ReplayCache::new(4096, Duration::from_secs(180))),
        })
    }

    /// First configured public key; use `public_keys_bytes` for a relay chain.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keys[0].public_bytes()
    }

    pub fn public_keys_bytes(&self) -> Vec<Vec<u8>> {
        self.keys.iter().map(PrivateKey::public_bytes).collect()
    }

    pub fn with_padding_length(mut self, length: usize) -> io::Result<Self> {
        self.padding = padding_len(length)?;
        Ok(self)
    }

    /// Change the bounded, additional authenticated-flight replay defense. Existing live
    /// entries are never evicted to make room for unauthenticated connections.
    pub fn with_replay_limits(mut self, capacity: usize, retention: Duration) -> io::Result<Self> {
        if capacity == 0 || retention.is_zero() {
            return Err(invalid("VLESS replay limits must be nonzero"));
        }
        self.replay = Mutex::new(ReplayCache::new(capacity, retention));
        Ok(self)
    }

    pub(super) fn prefix_len(&self) -> usize {
        16 + self.keys.iter().map(PrivateKey::share_len).sum::<usize>() + (self.keys.len() - 1) * 32
    }

    pub(super) fn reserve(&self, transcript: [u8; 32], now: Instant) -> io::Result<()> {
        self.replay
            .lock()
            .map_err(|_| invalid("VLESS replay cache lock is poisoned"))?
            .reserve(transcript, now)
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("relay_keys", &self.keys.len())
            .field("padding", &self.padding)
            .finish_non_exhaustive()
    }
}

struct ReplayCache {
    entries: HashMap<[u8; 32], Instant>,
    capacity: usize,
    retention: Duration,
}

impl ReplayCache {
    fn new(capacity: usize, retention: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            retention,
        }
    }

    fn reserve(&mut self, transcript: [u8; 32], now: Instant) -> io::Result<()> {
        self.entries
            .retain(|_, inserted| now.saturating_duration_since(*inserted) < self.retention);
        if self.entries.contains_key(&transcript) {
            return Err(invalid("replayed VLESS encrypted handshake"));
        }
        if self.entries.len() >= self.capacity {
            return Err(invalid("VLESS encrypted handshake replay cache is full"));
        }
        self.entries.insert(transcript, now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_capacity_and_expiration_fail_closed() {
        let mut cache = ReplayCache::new(1, Duration::from_secs(180));
        let now = Instant::now();
        cache.reserve([1; 32], now).unwrap();
        assert!(
            cache
                .reserve([1; 32], now + Duration::from_secs(179))
                .is_err()
        );
        assert!(
            cache
                .reserve([2; 32], now + Duration::from_secs(179))
                .is_err()
        );
        cache
            .reserve([2; 32], now + Duration::from_secs(180))
            .unwrap();
    }
}
