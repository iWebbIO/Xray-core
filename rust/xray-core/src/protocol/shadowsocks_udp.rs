//! Native legacy AEAD and single-key Shadowsocks 2022 UDP codecs and sessions.
//!
//! Sources: `proxy/shadowsocks/{config,protocol}.go` and the pinned
//! `github.com/sagernet/sing-shadowsocks@v0.2.7/shadowaead_2022` package.
//! No sockets are opened here. One server/client state belongs to one account;
//! callers must serialize access and route only successfully admitted packets.
//! Multi-user extended identity headers and relay chains are not implemented.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
    aes::{
        Aes128, Aes256,
        cipher::{BlockDecrypt, BlockEncrypt},
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::shadowsocks::{CipherKind, derive_subkey, password_to_key};
pub use super::udp::Datagram;
use crate::address::{Address, Destination};

pub const TAG_SIZE: usize = 16;
pub const MAX_PACKET_SIZE: usize = 65_535;
pub const MAX_CLOCK_SKEW: u64 = 30;
pub const MAX_DNS_PADDING: usize = 900;
pub const REPLAY_WINDOW_SIZE: u64 = 8128;
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(500);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> io::Result<&'a [u8]> {
    if input.len() < len {
        return Err(invalid("truncated Shadowsocks UDP packet"));
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn read_u64(input: &mut &[u8]) -> io::Result<u64> {
    Ok(u64::from_be_bytes(take(input, 8)?.try_into().unwrap()))
}

fn encode_destination(destination: &Destination, out: &mut Vec<u8>) -> io::Result<()> {
    if destination.port == 0 {
        return Err(invalid("Shadowsocks UDP destination port is zero"));
    }
    match &destination.address {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            Address::parse(name).map_err(|e| invalid(e.to_string()))?;
            if name.is_empty() || name.len() > 255 {
                return Err(invalid("invalid UDP domain length"));
            }
            out.extend_from_slice(&[3, name.len() as u8]);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn decode_destination(input: &mut &[u8], legacy: bool) -> io::Result<Destination> {
    let mut family = take(input, 1)?[0];
    // Xray legacy UDP explicitly masks the high four bits after authentication.
    if legacy {
        family &= 0x0f;
    }
    let address = match family {
        1 => Address::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(take(input, 4)?).unwrap()).into()),
        4 => Address::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(take(input, 16)?).unwrap()).into()),
        3 => {
            let len = usize::from(take(input, 1)?[0]);
            let name = std::str::from_utf8(take(input, len)?)
                .map_err(|_| invalid("UDP domain is not UTF-8"))?;
            Address::parse(name).map_err(|e| invalid(e.to_string()))?
        }
        _ => return Err(invalid("unsupported Shadowsocks UDP address family")),
    };
    let port = u16::from_be_bytes(take(input, 2)?.try_into().unwrap());
    if port == 0 {
        return Err(invalid("Shadowsocks UDP destination port is zero"));
    }
    Ok(Destination { address, port })
}

fn crypt_aead(
    kind: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    input: &[u8],
    encrypt: bool,
) -> io::Result<Vec<u8>> {
    let mut out = input.to_vec();
    let result = match kind {
        CipherKind::Aes128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|_| invalid("invalid AES-128 key"))?;
            if encrypt {
                cipher.encrypt_in_place(nonce.into(), b"", &mut out)
            } else {
                cipher.decrypt_in_place(nonce.into(), b"", &mut out)
            }
        }
        CipherKind::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| invalid("invalid AES-256 key"))?;
            if encrypt {
                cipher.encrypt_in_place(nonce.into(), b"", &mut out)
            } else {
                cipher.decrypt_in_place(nonce.into(), b"", &mut out)
            }
        }
        CipherKind::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| invalid("invalid ChaCha20 key"))?;
            if encrypt {
                cipher.encrypt_in_place(nonce.into(), b"", &mut out)
            } else {
                cipher.decrypt_in_place(nonce.into(), b"", &mut out)
            }
        }
    };
    if result.is_err() {
        out.zeroize();
        return Err(invalid("Shadowsocks UDP authentication/encryption failed"));
    }
    Ok(out)
}

/// Stateless SIP004 AEAD UDP: salt || AEAD(address || payload), nonce all zero.
/// Unlike TCP, every datagram has a new salt and just one authentication tag.
pub struct LegacyCipher {
    kind: CipherKind,
    key: Zeroizing<Vec<u8>>,
}

impl LegacyCipher {
    pub fn from_key(kind: CipherKind, key: &[u8]) -> io::Result<Self> {
        if key.len() != kind.key_len() {
            return Err(invalid("invalid legacy Shadowsocks key length"));
        }
        Ok(Self {
            kind,
            key: Zeroizing::new(key.to_vec()),
        })
    }

    pub fn from_password(kind: CipherKind, password: &[u8]) -> Self {
        Self {
            kind,
            key: password_to_key(kind, password),
        }
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    /// The caller must supply a fresh cryptographically random salt per packet.
    pub fn seal_with_salt(
        &self,
        destination: &Destination,
        payload: &[u8],
        salt: &[u8],
    ) -> io::Result<Vec<u8>> {
        let subkey = derive_subkey(self.kind, &self.key, salt)?;
        let mut plain = Vec::new();
        encode_destination(destination, &mut plain)?;
        let overhead = salt.len() + TAG_SIZE + plain.len();
        if payload.len() > MAX_PACKET_SIZE - overhead {
            return Err(invalid("legacy UDP packet too large"));
        }
        plain.extend_from_slice(payload);
        let body = crypt_aead(self.kind, &subkey, &[0; 12], &plain, true)?;
        plain.zeroize();
        let mut out = salt.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn seal<R: RngCore + CryptoRng + ?Sized>(
        &self,
        destination: &Destination,
        payload: &[u8],
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        let mut salt = vec![0; self.kind.salt_len()];
        rng.fill_bytes(&mut salt);
        self.seal_with_salt(destination, payload, &salt)
    }

    /// Authenticates and parses one datagram, without a replay cache. Use
    /// `LegacyUdp` for account-scoped salt admission.
    pub fn open(&self, packet: &[u8]) -> io::Result<Datagram> {
        let salt_len = self.kind.salt_len();
        if packet.len() < salt_len + TAG_SIZE + 4 || packet.len() > MAX_PACKET_SIZE {
            return Err(invalid("invalid legacy Shadowsocks UDP packet size"));
        }
        let subkey = derive_subkey(self.kind, &self.key, &packet[..salt_len])?;
        let plain = Zeroizing::new(crypt_aead(
            self.kind,
            &subkey,
            &[0; 12],
            &packet[salt_len..],
            false,
        )?);
        let mut input = plain.as_slice();
        let destination = decode_destination(&mut input, true)?;
        Ok(Datagram {
            destination,
            payload: input.to_vec(),
        })
    }
}

struct SaltReplay {
    seen: HashSet<Vec<u8>>,
    order: VecDeque<(Instant, Vec<u8>)>,
    lifetime: Duration,
    capacity: usize,
}

impl SaltReplay {
    fn new(lifetime: Duration, capacity: usize) -> io::Result<Self> {
        if lifetime.is_zero() || capacity == 0 {
            return Err(invalid("invalid legacy replay cache limits"));
        }
        Ok(Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            lifetime,
            capacity,
        })
    }

    fn admit(&mut self, salt: &[u8], now: Instant) -> io::Result<()> {
        while self.order.front().is_some_and(|(at, _)| {
            now.checked_duration_since(*at)
                .is_some_and(|d| d >= self.lifetime)
        }) {
            let (_, old) = self.order.pop_front().unwrap();
            self.seen.remove(&old);
        }
        if self.seen.contains(salt) {
            return Err(invalid("replayed Shadowsocks UDP salt"));
        }
        // Never evict live entries to make room: doing so would reopen replays.
        if self.seen.len() >= self.capacity {
            return Err(invalid("legacy UDP replay cache capacity reached"));
        }
        self.seen.insert(salt.to_vec());
        self.order.push_back((now, salt.to_vec()));
        Ok(())
    }
}

/// Account-scoped legacy UDP codec with a bounded ten-minute salt cache. The
/// cache includes sent salts, preventing reflected locally generated packets.
pub struct LegacyUdp {
    cipher: LegacyCipher,
    replay: SaltReplay,
}

impl LegacyUdp {
    pub fn new(cipher: LegacyCipher) -> Self {
        Self {
            cipher,
            replay: SaltReplay::new(Duration::from_secs(600), 65_536).unwrap(),
        }
    }

    pub fn with_limits(
        cipher: LegacyCipher,
        lifetime: Duration,
        capacity: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            cipher,
            replay: SaltReplay::new(lifetime, capacity)?,
        })
    }

    pub fn encode<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        destination: &Destination,
        payload: &[u8],
        now: Instant,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        let packet = self.cipher.seal(destination, payload, rng)?;
        self.replay
            .admit(&packet[..self.cipher.kind.salt_len()], now)?;
        Ok(packet)
    }

    pub fn decode(&mut self, packet: &[u8], now: Instant) -> io::Result<Datagram> {
        let datagram = self.cipher.open(packet)?;
        // Unauthenticated salts and malformed destinations cannot poison cache.
        self.replay
            .admit(&packet[..self.cipher.kind.salt_len()], now)?;
        Ok(datagram)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method2022 {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method2022 {
    pub fn key_len(self) -> usize {
        if self == Self::Aes128Gcm { 16 } else { 32 }
    }
    fn aes_kind(self) -> io::Result<CipherKind> {
        match self {
            Self::Aes128Gcm => Ok(CipherKind::Aes128Gcm),
            Self::Aes256Gcm => Ok(CipherKind::Aes256Gcm),
            Self::ChaCha20Poly1305 => Err(invalid("2022 UDP ChaCha uses XChaCha, not AES")),
        }
    }
}

impl FromStr for Method2022 {
    type Err = io::Error;
    fn from_str(name: &str) -> io::Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(invalid("unsupported Shadowsocks 2022 UDP method")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Client,
    Server,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet2022 {
    pub direction: Direction,
    pub session_id: u64,
    pub packet_id: u64,
    pub timestamp: u64,
    /// Required only in server replies, binding them to the requesting client.
    pub client_session_id: Option<u64>,
    pub datagram: Datagram,
}

/// Stateless single-key 2022 cryptography. AES encrypts a separate 16-byte
/// header under the PSK and a body under a BLAKE3-derived session key. ChaCha
/// encrypts the complete header/body under XChaCha20-Poly1305 with a 24-byte nonce.
pub struct Cipher2022 {
    method: Method2022,
    key: Zeroizing<Vec<u8>>,
}

impl Cipher2022 {
    pub fn new(method: Method2022, psk: &[u8]) -> io::Result<Self> {
        if psk.len() < method.key_len() {
            return Err(invalid("Shadowsocks 2022 PSK too short"));
        }
        // This normalization is the pinned implementation's Key() behavior.
        let key = if psk.len() > method.key_len() {
            Sha256::digest(psk)[..method.key_len()].to_vec()
        } else {
            psk.to_vec()
        };
        Ok(Self {
            method,
            key: Zeroizing::new(key),
        })
    }

    pub fn from_password(method: Method2022, password: &str) -> io::Result<Self> {
        if password.contains(':') {
            return Err(invalid(
                "2022 UDP identity/relay key chains are unsupported",
            ));
        }
        let psk = Zeroizing::new(
            STANDARD
                .decode(password)
                .map_err(|_| invalid("invalid base64 Shadowsocks 2022 PSK"))?,
        );
        Self::new(method, &psk)
    }

    pub fn method(&self) -> Method2022 {
        self.method
    }

    /// AES UDP session subkey. The XChaCha UDP layout uses the PSK directly and
    /// does not use this derived key.
    pub fn session_key(&self, session_id: u64) -> Zeroizing<Vec<u8>> {
        let mut material = Zeroizing::new(self.key.to_vec());
        material.extend_from_slice(&session_id.to_be_bytes());
        let derived = Zeroizing::new(blake3::derive_key(
            "shadowsocks 2022 session subkey",
            &material,
        ));
        Zeroizing::new(derived[..self.method.key_len()].to_vec())
    }

    fn crypt_header(&self, header: &mut [u8; 16], encrypt: bool) -> io::Result<()> {
        match self.method {
            Method2022::Aes128Gcm => {
                let cipher = Aes128::new_from_slice(&self.key)
                    .map_err(|_| invalid("invalid AES-128 PSK"))?;
                if encrypt {
                    cipher.encrypt_block(header.into());
                } else {
                    cipher.decrypt_block(header.into());
                }
            }
            Method2022::Aes256Gcm => {
                let cipher = Aes256::new_from_slice(&self.key)
                    .map_err(|_| invalid("invalid AES-256 PSK"))?;
                if encrypt {
                    cipher.encrypt_block(header.into());
                } else {
                    cipher.decrypt_block(header.into());
                }
            }
            Method2022::ChaCha20Poly1305 => {
                return Err(invalid("ChaCha has no separate encrypted header"));
            }
        }
        Ok(())
    }

    /// Deterministic wire primitive. Never reuse a session/packet ID pair under
    /// a PSK, or an XChaCha nonce. For AES the supplied XChaCha nonce is unused.
    pub fn seal_with_nonce(
        &self,
        packet: &Packet2022,
        padding: &[u8],
        nonce: [u8; 24],
    ) -> io::Result<Vec<u8>> {
        if (packet.direction == Direction::Server) != packet.client_session_id.is_some() {
            return Err(invalid(
                "2022 UDP client-session field does not match direction",
            ));
        }
        let pad_len =
            u16::try_from(padding.len()).map_err(|_| invalid("2022 UDP padding too long"))?;
        let mut plain = Zeroizing::new(Vec::new());
        plain.extend_from_slice(&packet.session_id.to_be_bytes());
        plain.extend_from_slice(&packet.packet_id.to_be_bytes());
        plain.push(if packet.direction == Direction::Client {
            0
        } else {
            1
        });
        plain.extend_from_slice(&packet.timestamp.to_be_bytes());
        if let Some(client) = packet.client_session_id {
            plain.extend_from_slice(&client.to_be_bytes());
        }
        plain.extend_from_slice(&pad_len.to_be_bytes());
        plain.extend_from_slice(padding);
        encode_destination(&packet.datagram.destination, &mut plain)?;
        let extra = TAG_SIZE
            + if self.method == Method2022::ChaCha20Poly1305 {
                24
            } else {
                0
            };
        let wire_len = plain
            .len()
            .checked_add(extra)
            .and_then(|n| n.checked_add(packet.datagram.payload.len()))
            .ok_or_else(|| invalid("2022 UDP packet size overflow"))?;
        if wire_len > MAX_PACKET_SIZE {
            return Err(invalid("2022 UDP packet too large"));
        }
        plain.extend_from_slice(&packet.datagram.payload);
        if self.method == Method2022::ChaCha20Poly1305 {
            let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid XChaCha PSK"))?;
            let mut encrypted = plain.to_vec();
            cipher
                .encrypt_in_place((&nonce).into(), b"", &mut encrypted)
                .map_err(|_| invalid("2022 UDP encryption failed"))?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&encrypted);
            Ok(out)
        } else {
            let mut header: [u8; 16] = plain[..16].try_into().unwrap();
            let nonce: [u8; 12] = header[4..16].try_into().unwrap();
            let key = self.session_key(packet.session_id);
            let body = crypt_aead(self.method.aes_kind()?, &key, &nonce, &plain[16..], true)?;
            self.crypt_header(&mut header, true)?;
            let mut out = header.to_vec();
            out.extend_from_slice(&body);
            Ok(out)
        }
    }

    pub fn seal<R: RngCore + CryptoRng + ?Sized>(
        &self,
        packet: &Packet2022,
        padding: &[u8],
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        let mut nonce = [0; 24];
        if self.method == Method2022::ChaCha20Poly1305 {
            rng.fill_bytes(&mut nonce);
        }
        self.seal_with_nonce(packet, padding, nonce)
    }

    /// Authenticate, check direction/timestamp, and parse before returning any
    /// plaintext. Session binding/replay checks belong to Client2022/Server2022.
    pub fn open(
        &self,
        packet: &[u8],
        expected: Direction,
        unix_now: u64,
    ) -> io::Result<Packet2022> {
        if packet.len() > MAX_PACKET_SIZE {
            return Err(invalid("2022 UDP packet too large"));
        }
        let plain = if self.method == Method2022::ChaCha20Poly1305 {
            if packet.len() < 24 + 16 + TAG_SIZE {
                return Err(invalid("truncated XChaCha UDP packet"));
            }
            let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid XChaCha PSK"))?;
            let mut body = packet[24..].to_vec();
            if cipher
                .decrypt_in_place(
                    chacha20poly1305::XNonce::from_slice(&packet[..24]),
                    b"",
                    &mut body,
                )
                .is_err()
            {
                body.zeroize();
                return Err(invalid("2022 UDP authentication failed"));
            }
            Zeroizing::new(body)
        } else {
            if packet.len() < 16 + TAG_SIZE {
                return Err(invalid("truncated AES UDP packet"));
            }
            let mut header: [u8; 16] = packet[..16].try_into().unwrap();
            self.crypt_header(&mut header, false)?;
            let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
            let nonce: [u8; 12] = header[4..].try_into().unwrap();
            let key = self.session_key(session_id);
            let body = Zeroizing::new(crypt_aead(
                self.method.aes_kind()?,
                &key,
                &nonce,
                &packet[16..],
                false,
            )?);
            let mut plain = Zeroizing::new(header.to_vec());
            plain.extend_from_slice(&body);
            plain
        };
        let mut input = plain.as_slice();
        let session_id = read_u64(&mut input)?;
        let packet_id = read_u64(&mut input)?;
        let direction = match take(&mut input, 1)?[0] {
            0 => Direction::Client,
            1 => Direction::Server,
            _ => return Err(invalid("invalid 2022 UDP header type")),
        };
        if direction != expected {
            return Err(invalid("unexpected 2022 UDP packet direction"));
        }
        let timestamp = read_u64(&mut input)?;
        if timestamp.abs_diff(unix_now) > MAX_CLOCK_SKEW {
            return Err(invalid("2022 UDP timestamp outside 30-second window"));
        }
        let client_session_id = if direction == Direction::Server {
            Some(read_u64(&mut input)?)
        } else {
            None
        };
        let pad_len = usize::from(u16::from_be_bytes(take(&mut input, 2)?.try_into().unwrap()));
        take(&mut input, pad_len)?;
        let destination = decode_destination(&mut input, false)?;
        Ok(Packet2022 {
            direction,
            session_id,
            packet_id,
            timestamp,
            client_session_id,
            datagram: Datagram {
                destination,
                payload: input.to_vec(),
            },
        })
    }
}

/// Exact 128 x 64-bit ring and inclusive 8128-counter window of the pinned Go
/// implementation. Check/admit only after all packet authentication/validation.
#[derive(Clone)]
pub struct SlidingWindow {
    last: u64,
    ring: [u64; 128],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0; 128],
        }
    }
}

impl SlidingWindow {
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > REPLAY_WINDOW_SIZE {
            return false;
        }
        let index = ((counter >> 6) & 127) as usize;
        let bit = counter & 63;
        self.ring[index] & (1 << bit) == 0
    }

    pub fn admit(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        if counter > self.last {
            let old_block = self.last >> 6;
            let new_block = counter >> 6;
            for offset in 1..=(new_block - old_block).min(128) {
                self.ring[((old_block + offset) & 127) as usize] = 0;
            }
            self.last = counter;
        }
        self.ring[((counter >> 6) & 127) as usize] |= 1 << (counter & 63);
        true
    }
}

struct PacketCounter {
    next: Option<u64>,
}
impl Default for PacketCounter {
    fn default() -> Self {
        Self { next: Some(0) }
    }
}
impl PacketCounter {
    fn take(&mut self) -> io::Result<u64> {
        let value = self
            .next
            .ok_or_else(|| invalid("2022 UDP packet counter exhausted; create a fresh session"))?;
        self.next = value.checked_add(1);
        Ok(value)
    }
}

struct RemoteSession {
    id: u64,
    window: SlidingWindow,
}

/// One local client session, with current/previous server replay windows and
/// the pinned implementation's sixty-second server-session rotation rule.
pub struct Client2022 {
    cipher: Cipher2022,
    session_id: u64,
    counter: PacketCounter,
    current: Option<RemoteSession>,
    previous: Option<RemoteSession>,
    last_previous_seen: Option<u64>,
}

impl Client2022 {
    pub fn new<R: RngCore + CryptoRng + ?Sized>(cipher: Cipher2022, rng: &mut R) -> Self {
        Self::with_session_id(cipher, random_session_id(rng))
    }

    /// For externally generated fresh random session IDs and deterministic
    /// fixtures. Do not recreate this state with an old ID under the same PSK.
    pub fn with_session_id(cipher: Cipher2022, session_id: u64) -> Self {
        Self {
            cipher,
            session_id,
            counter: PacketCounter::default(),
            current: None,
            previous: None,
            last_previous_seen: None,
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn encode<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        destination: &Destination,
        payload: &[u8],
        unix_now: u64,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PACKET_SIZE {
            return Err(invalid("2022 UDP payload too large"));
        }
        let padding = dns_padding(destination, payload.len(), rng);
        let packet = Packet2022 {
            direction: Direction::Client,
            session_id: self.session_id,
            packet_id: self.counter.take()?,
            timestamp: unix_now,
            client_session_id: None,
            datagram: Datagram {
                destination: destination.clone(),
                payload: payload.to_vec(),
            },
        };
        self.cipher.seal(&packet, &padding, rng)
    }

    pub fn decode(&mut self, wire: &[u8], unix_now: u64) -> io::Result<Packet2022> {
        let packet = self.cipher.open(wire, Direction::Server, unix_now)?;
        if packet.client_session_id != Some(self.session_id) {
            return Err(invalid("2022 UDP reply belongs to another client session"));
        }
        if let Some(current) = &mut self.current
            && current.id == packet.session_id
        {
            if !current.window.admit(packet.packet_id) {
                return Err(invalid("replayed 2022 UDP packet ID"));
            }
            return Ok(packet);
        }
        if let Some(previous) = &mut self.previous
            && previous.id == packet.session_id
        {
            if !previous.window.admit(packet.packet_id) {
                return Err(invalid("replayed 2022 UDP packet ID"));
            }
            self.last_previous_seen = Some(unix_now);
            return Ok(packet);
        }
        if self.current.is_some() {
            if self
                .last_previous_seen
                .is_some_and(|last| unix_now.saturating_sub(last) < 60)
            {
                return Err(invalid(
                    "2022 UDP server session changed more than once in a minute",
                ));
            }
            self.previous = self.current.take();
            self.last_previous_seen = Some(unix_now);
        }
        let mut window = SlidingWindow::default();
        window.admit(packet.packet_id);
        self.current = Some(RemoteSession {
            id: packet.session_id,
            window,
        });
        Ok(packet)
    }
}

struct ServerSession {
    send_id: u64,
    counter: PacketCounter,
    window: SlidingWindow,
    last_seen: Instant,
}

/// Account-scoped 2022 server session table. Client session IDs, rather than
/// source IP/port, identify sessions, allowing authenticated UDP rebinding. The
/// dispatcher must update the return socket address only after `accept` succeeds.
pub struct Server2022 {
    cipher: Cipher2022,
    sessions: HashMap<u64, ServerSession>,
    timeout: Duration,
    capacity: usize,
}

impl Server2022 {
    pub fn new(cipher: Cipher2022) -> Self {
        Self {
            cipher,
            sessions: HashMap::new(),
            timeout: DEFAULT_SESSION_TIMEOUT,
            capacity: 4096,
        }
    }

    pub fn with_limits(cipher: Cipher2022, timeout: Duration, capacity: usize) -> io::Result<Self> {
        // Keep replay history beyond the complete [-30,+30] timestamp window.
        if timeout < Duration::from_secs(61) || capacity == 0 {
            return Err(invalid(
                "2022 UDP session timeout must be at least 61 seconds and capacity positive",
            ));
        }
        Ok(Self {
            cipher,
            sessions: HashMap::new(),
            timeout,
            capacity,
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn expire(&mut self, now: Instant) {
        self.sessions.retain(|_, s| {
            now.checked_duration_since(s.last_seen)
                .is_none_or(|age| age < self.timeout)
        });
    }

    pub fn accept<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        wire: &[u8],
        unix_now: u64,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<Packet2022> {
        let packet = self.cipher.open(wire, Direction::Client, unix_now)?;
        self.expire(now);
        if let Some(session) = self.sessions.get_mut(&packet.session_id) {
            if !session.window.admit(packet.packet_id) {
                return Err(invalid("replayed 2022 UDP packet ID"));
            }
            session.last_seen = now;
            return Ok(packet);
        }
        if self.sessions.len() >= self.capacity {
            return Err(invalid("2022 UDP session capacity reached"));
        }
        let send_id = (0..8)
            .map(|_| random_session_id(rng))
            .find(|id| *id != packet.session_id && self.sessions.values().all(|s| s.send_id != *id))
            .ok_or_else(|| invalid("failed to generate a fresh server session ID"))?;
        let mut window = SlidingWindow::default();
        window.admit(packet.packet_id);
        self.sessions.insert(
            packet.session_id,
            ServerSession {
                send_id,
                counter: PacketCounter::default(),
                window,
                last_seen: now,
            },
        );
        Ok(packet)
    }

    pub fn encode_reply<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        client_session_id: u64,
        destination: &Destination,
        payload: &[u8],
        unix_now: u64,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PACKET_SIZE {
            return Err(invalid("2022 UDP payload too large"));
        }
        self.expire(now);
        let session = self
            .sessions
            .get_mut(&client_session_id)
            .ok_or_else(|| invalid("unknown or expired 2022 UDP client session"))?;
        let padding = dns_padding(destination, payload.len(), rng);
        let packet = Packet2022 {
            direction: Direction::Server,
            session_id: session.send_id,
            packet_id: session.counter.take()?,
            timestamp: unix_now,
            client_session_id: Some(client_session_id),
            datagram: Datagram {
                destination: destination.clone(),
                payload: payload.to_vec(),
            },
        };
        let wire = self.cipher.seal(&packet, &padding, rng)?;
        session.last_seen = now;
        Ok(wire)
    }
}

fn random_session_id<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> u64 {
    let mut bytes = [0; 8];
    rng.fill_bytes(&mut bytes);
    u64::from_be_bytes(bytes)
}

fn dns_padding<R: Rng + CryptoRng + ?Sized>(
    destination: &Destination,
    payload_len: usize,
    rng: &mut R,
) -> Vec<u8> {
    if destination.port != 53 || payload_len >= MAX_DNS_PADDING {
        return Vec::new();
    }
    let length = rng.gen_range(1..=MAX_DNS_PADDING - payload_len);
    let mut bytes = vec![0; length];
    rng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    fn fixture_packet(server: bool) -> Packet2022 {
        Packet2022 {
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
            timestamp: 1_700_000_000,
            client_session_id: server.then_some(0x0102030405060708),
            datagram: Datagram {
                destination: Destination::new("8.8.8.8", 53).unwrap(),
                payload: b"\x12\x34dns".to_vec(),
            },
        }
    }

    fn cipher2022(method: Method2022) -> Cipher2022 {
        Cipher2022::new(method, &(0..method.key_len() as u8).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn legacy_known_answers_from_python_cryptography_hkdf_and_openssl() {
        // Independently generated from EVP_BytesToKey MD5, HKDF-SHA1 and
        // cryptography's AESGCM/ChaCha20Poly1305, not by this Rust implementation.
        let vectors = [
            (
                CipherKind::Aes128Gcm,
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafac46d6cb6bce9fa6045c63e62d29b8161be585db7f9e57b0e9f20c7a160de5a007de",
            ),
            (
                CipherKind::Aes256Gcm,
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfa81046fca7c2d2e88cb92490f92af8875ef879913888e226aef9e765379cf33290b7",
            ),
            (
                CipherKind::ChaCha20Poly1305,
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf2d8bb58cfd7659d4496dfcd1e14192a114af98ce826ccfa8f9bf2719cd8df91c8fe3",
            ),
        ];
        let target = Destination::new("203.0.113.7", 5353).unwrap();
        for (kind, hex) in vectors {
            let codec = LegacyCipher::from_password(kind, b"password");
            let salt: Vec<u8> = (0..kind.salt_len()).map(|i| 0xa0 + i as u8).collect();
            let wire = unhex(hex);
            assert_eq!(
                codec
                    .seal_with_salt(&target, b"udp fixture", &salt)
                    .unwrap(),
                wire
            );
            assert_eq!(
                codec.open(&wire).unwrap(),
                Datagram {
                    destination: target.clone(),
                    payload: b"udp fixture".to_vec()
                }
            );
            for len in 0..wire.len() {
                assert!(codec.open(&wire[..len]).is_err());
            }
            for index in 0..wire.len() {
                let mut bad = wire.clone();
                bad[index] ^= 1;
                assert!(codec.open(&bad).is_err());
            }
        }
    }

    #[test]
    fn legacy_address_families_empty_payload_and_high_atyp_bits() {
        let codec = LegacyCipher::from_password(CipherKind::Aes128Gcm, b"password");
        for host in ["203.0.113.7", "::1", "example.org"] {
            let target = Destination::new(host, 443).unwrap();
            let wire = codec.seal_with_salt(&target, b"", &[1; 16]).unwrap();
            assert_eq!(
                codec.open(&wire).unwrap(),
                Datagram {
                    destination: target,
                    payload: vec![]
                }
            );
        }
        let salt = [2; 16];
        let key = derive_subkey(codec.kind, &codec.key, &salt).unwrap();
        // The authenticated first address byte is masked to its low four bits.
        let mut wire = salt.to_vec();
        wire.extend(
            crypt_aead(
                codec.kind,
                &key,
                &[0; 12],
                &[0xf1, 127, 0, 0, 1, 0, 53, 42],
                true,
            )
            .unwrap(),
        );
        assert_eq!(codec.open(&wire).unwrap().payload, [42]);
        assert!(
            codec
                .seal_with_salt(
                    &Destination::new("::1", 1).unwrap(),
                    &vec![0; MAX_PACKET_SIZE],
                    &salt
                )
                .is_err()
        );
    }

    #[test]
    fn legacy_replays_cannot_evict_live_salts_or_poison_cache_before_authentication() {
        let cipher = LegacyCipher::from_password(CipherKind::Aes128Gcm, b"password");
        let target = Destination::new("example.org", 443).unwrap();
        let wire = cipher.seal_with_salt(&target, b"valid", &[1; 16]).unwrap();
        let other = cipher.seal_with_salt(&target, b"other", &[2; 16]).unwrap();
        let mut server = LegacyUdp::with_limits(cipher, Duration::from_secs(10), 1).unwrap();
        let now = Instant::now();
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(server.decode(&bad, now).is_err());
        assert_eq!(server.decode(&wire, now).unwrap().payload, b"valid");
        assert!(server.decode(&wire, now).is_err());
        assert!(server.decode(&other, now).is_err());
        assert!(server.decode(&wire, now).is_err());
        assert!(server.decode(&other, now + Duration::from_secs(10)).is_ok());
    }

    #[test]
    fn legacy_locally_sent_salts_are_rejected_on_reflection() {
        let mut session = LegacyUdp::new(LegacyCipher::from_password(
            CipherKind::Aes256Gcm,
            b"password",
        ));
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(1);
        let wire = session
            .encode(
                &Destination::new("127.0.0.1", 53).unwrap(),
                b"query",
                now,
                &mut rng,
            )
            .unwrap();
        assert!(session.decode(&wire, now).is_err());
    }

    #[test]
    fn ss2022_known_answers_cover_both_directions_and_all_methods() {
        // Independent Python fixtures: blake3 derive-key, cryptography AESGCM,
        // PyCryptodome AES-ECB and XChaCha20-Poly1305 (24-byte nonce).
        let vectors = [
            (
                Method2022::Aes128Gcm,
                false,
                "12f250371f475aa71c3ab38e1308b5b8e33d719e15cf7e1746399d1d83807145a026233bfc9cccf925c70106bf1f7aa6920b99c49db6074e4c74",
            ),
            (
                Method2022::Aes128Gcm,
                true,
                "ce8b012cf8173186af83e7dab1f0d99ac447a48189229d20e446498e795cb088e861fac99ffe606aeb41b1411252d3a9dc27dbf641a66cb6344c518456b0a7c49ac8",
            ),
            (
                Method2022::Aes256Gcm,
                false,
                "43af1bac10ead1bba3120598a2ea4edd06fab6b6129cc084c977125f89c6d5e32af6dc90cb1ea34dcb083f02efbc3540f64da752a6dcc52e1522",
            ),
            (
                Method2022::Aes256Gcm,
                true,
                "09a24bf73f92dc1a22496481611e7ace803efb5f3cce77d0cef7e7a6c4482690512902706d0c4def9c925edbb9ffd9195f755d53ebcb309cf0dc35ac46371803f409",
            ),
            (
                Method2022::ChaCha20Poly1305,
                false,
                "000102030405060708090a0b0c0d0e0f10111213141516179fc00c7b95d48aa6334426cecb52a8ef4b4728a5fdb34e1a7f1a3cc65cc9f451560ebee474753d00bbe688ff5e067546c304148b8759965375c3",
            ),
            (
                Method2022::ChaCha20Poly1305,
                true,
                "000102030405060708090a0b0c0d0e0f10111213141516178fd01c6b85c49ab6334426cecb52a8e14a4728a5fdb34e1a7f1b3db539a8f35e5606b5942003086cdd9da659fa3367061fc97be7d3eb8d2d40a7e785d8bb028a8f95",
            ),
        ];
        for (method, server, hex) in vectors {
            let cipher = cipher2022(method);
            let packet = fixture_packet(server);
            let wire = unhex(hex);
            let nonce = std::array::from_fn(|i| i as u8);
            assert_eq!(
                cipher.seal_with_nonce(&packet, b"pad", nonce).unwrap(),
                wire
            );
            assert_eq!(
                cipher
                    .open(&wire, packet.direction, packet.timestamp)
                    .unwrap(),
                packet
            );
            for len in 0..wire.len() {
                assert!(
                    cipher
                        .open(&wire[..len], packet.direction, packet.timestamp)
                        .is_err()
                );
            }
            for index in 0..wire.len() {
                let mut bad = wire.clone();
                bad[index] ^= 1;
                assert!(
                    cipher
                        .open(&bad, packet.direction, packet.timestamp)
                        .is_err()
                );
            }
        }
        assert_eq!(
            &*cipher2022(Method2022::Aes128Gcm).session_key(0x0102030405060708),
            &unhex("b8473b44792f673ee36a405dfa755cc4")
        );
        assert_eq!(
            &*cipher2022(Method2022::Aes256Gcm).session_key(0x0102030405060708),
            &unhex("b8208bed66846bcbb2876c8c9db990da1da0a6c39bbeaf132686bbab1a5e1bb4")
        );
    }

    #[test]
    fn ss2022_timestamp_and_direction_boundaries_are_checked_without_overflow() {
        for method in [Method2022::Aes128Gcm, Method2022::ChaCha20Poly1305] {
            let cipher = cipher2022(method);
            let packet = fixture_packet(false);
            let wire = cipher.seal_with_nonce(&packet, b"", [4; 24]).unwrap();
            assert!(
                cipher
                    .open(&wire, Direction::Client, packet.timestamp + 30)
                    .is_ok()
            );
            assert!(
                cipher
                    .open(&wire, Direction::Client, packet.timestamp - 30)
                    .is_ok()
            );
            assert!(
                cipher
                    .open(&wire, Direction::Client, packet.timestamp + 31)
                    .is_err()
            );
            assert!(
                cipher
                    .open(&wire, Direction::Client, packet.timestamp - 31)
                    .is_err()
            );
            assert!(cipher.open(&wire, Direction::Client, u64::MAX).is_err());
            assert!(
                cipher
                    .open(&wire, Direction::Server, packet.timestamp)
                    .is_err()
            );
        }
    }

    #[test]
    fn ss2022_authenticated_malformed_padding_and_addresses_are_rejected() {
        let cipher = cipher2022(Method2022::Aes128Gcm);
        let packet = fixture_packet(false);
        let mut header = [0; 16];
        header[..8].copy_from_slice(&packet.session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet.packet_id.to_be_bytes());
        let nonce: [u8; 12] = header[4..].try_into().unwrap();
        let key = cipher.session_key(packet.session_id);
        for suffix in [
            vec![0xff, 0xff, 0],
            vec![0, 0, 3, 0, 0, 53],
            vec![0, 0, 1, 127, 0, 0, 1, 0, 0],
            vec![0, 0, 9],
        ] {
            let mut body = vec![0];
            body.extend_from_slice(&packet.timestamp.to_be_bytes());
            body.extend(suffix);
            let encrypted = crypt_aead(CipherKind::Aes128Gcm, &key, &nonce, &body, true).unwrap();
            let mut wire_header = header;
            cipher.crypt_header(&mut wire_header, true).unwrap();
            let mut wire = wire_header.to_vec();
            wire.extend(encrypted);
            assert!(
                cipher
                    .open(&wire, Direction::Client, packet.timestamp)
                    .is_err()
            );
        }
    }

    #[test]
    fn replay_window_matches_set_reference_across_blocks_large_jumps_and_max_counter() {
        let mut window = SlidingWindow::default();
        let mut seen = HashSet::new();
        let mut last = 0u64;
        let counters = [
            0,
            0,
            1,
            63,
            64,
            63,
            8128,
            1,
            8129,
            1,
            16_384,
            8256,
            8255,
            16_383,
            16_384,
            u64::MAX,
            u64::MAX - 8128,
            u64::MAX - 8129,
            u64::MAX,
        ];
        for counter in counters {
            let expected = (counter > last || last - counter <= REPLAY_WINDOW_SIZE)
                && !seen.contains(&counter);
            assert_eq!(window.check(counter), expected, "counter {counter}");
            assert_eq!(window.admit(counter), expected, "counter {counter}");
            if expected {
                last = last.max(counter);
                seen.insert(counter);
            }
        }
    }

    #[test]
    fn packet_counter_uses_zero_first_and_never_wraps() {
        let mut counter = PacketCounter::default();
        assert_eq!(counter.take().unwrap(), 0);
        assert_eq!(counter.take().unwrap(), 1);
        counter.next = Some(u64::MAX);
        assert_eq!(counter.take().unwrap(), u64::MAX);
        assert!(counter.take().is_err());
    }

    #[test]
    fn client_binding_and_rotation_failures_do_not_poison_valid_reply_replay_state() {
        let cipher = cipher2022(Method2022::Aes128Gcm);
        let mut client = Client2022::with_session_id(cipher2022(Method2022::Aes128Gcm), 55);
        let now = 1_700_000_000;
        let reply = |sid, pid, client_id, time| {
            let mut packet = fixture_packet(true);
            packet.session_id = sid;
            packet.packet_id = pid;
            packet.client_session_id = Some(client_id);
            packet.timestamp = time;
            cipher.seal_with_nonce(&packet, b"", [0; 24]).unwrap()
        };
        assert!(client.decode(&reply(1, 0, 56, now), now).is_err());
        assert!(client.decode(&reply(1, 0, 55, now), now).is_ok());
        assert!(client.decode(&reply(1, 0, 55, now), now).is_err());
        assert!(client.decode(&reply(2, 0, 55, now), now).is_ok());
        assert!(client.decode(&reply(3, 0, 55, now + 59), now + 59).is_err());
        assert!(client.decode(&reply(1, 1, 55, now + 59), now + 59).is_ok());
        assert!(
            client
                .decode(&reply(3, 0, 55, now + 118), now + 118)
                .is_err()
        );
        assert!(
            client
                .decode(&reply(3, 0, 55, now + 119), now + 119)
                .is_ok()
        );
        assert!(
            client
                .decode(&reply(3, 1, 55, now + 200), now + 119)
                .is_err()
        );
        assert!(
            client
                .decode(&reply(3, 1, 55, now + 119), now + 119)
                .is_ok()
        );
    }

    #[test]
    fn all_2022_methods_support_request_reply_reordering_and_replay_rejection() {
        let target = Destination::new("8.8.8.8", 53).unwrap();
        let now = Instant::now();
        let epoch = 1_700_000_000;
        for method in [
            Method2022::Aes128Gcm,
            Method2022::Aes256Gcm,
            Method2022::ChaCha20Poly1305,
        ] {
            let mut rng = StdRng::seed_from_u64(42);
            let mut client = Client2022::new(cipher2022(method), &mut rng);
            let mut server = Server2022::new(cipher2022(method));
            let first = client.encode(&target, b"query1", epoch, &mut rng).unwrap();
            let second = client.encode(&target, b"query2", epoch, &mut rng).unwrap();
            let accepted = server.accept(&second, epoch, now, &mut rng).unwrap();
            assert_eq!(accepted.packet_id, 1);
            assert_eq!(
                server
                    .accept(&first, epoch, now, &mut rng)
                    .unwrap()
                    .packet_id,
                0
            );
            assert!(server.accept(&first, epoch, now, &mut rng).is_err());
            assert_eq!(server.session_count(), 1);
            let response = server
                .encode_reply(
                    accepted.session_id,
                    &target,
                    b"answer",
                    epoch,
                    now,
                    &mut rng,
                )
                .unwrap();
            assert_eq!(
                client.decode(&response, epoch).unwrap().datagram.payload,
                b"answer"
            );
            assert!(client.decode(&response, epoch).is_err());
        }
    }

    #[test]
    fn server_capacity_and_expiry_preserve_active_replay_history() {
        let mut server = Server2022::with_limits(
            cipher2022(Method2022::Aes128Gcm),
            Duration::from_secs(61),
            1,
        )
        .unwrap();
        let cipher = cipher2022(Method2022::Aes128Gcm);
        let mut rng = StdRng::seed_from_u64(2);
        let mut first = fixture_packet(false);
        let epoch = first.timestamp;
        let now = Instant::now();
        let wire = cipher.seal_with_nonce(&first, b"", [0; 24]).unwrap();
        let mut bad = wire.clone();
        bad[20] ^= 1;
        assert!(server.accept(&bad, epoch, now, &mut rng).is_err());
        assert_eq!(server.session_count(), 0);
        server.accept(&wire, epoch, now, &mut rng).unwrap();
        let mut second = first.clone();
        second.session_id = 9;
        let other = cipher.seal_with_nonce(&second, b"", [0; 24]).unwrap();
        assert!(server.accept(&other, epoch, now, &mut rng).is_err());
        assert!(server.accept(&wire, epoch, now, &mut rng).is_err());
        server.expire(now + Duration::from_secs(61));
        assert_eq!(server.session_count(), 0);
        assert!(
            server
                .accept(&wire, epoch + 61, now + Duration::from_secs(61), &mut rng)
                .is_err()
        );
        first.timestamp += 61;
        first.packet_id += 1;
        let fresh = cipher.seal_with_nonce(&first, b"", [0; 24]).unwrap();
        assert!(
            server
                .accept(&fresh, epoch + 61, now + Duration::from_secs(61), &mut rng)
                .is_ok()
        );
    }

    #[test]
    fn psk_normalization_dns_padding_and_unsupported_identity_chains_are_explicit() {
        let key = [42; 48];
        let cipher = Cipher2022::new(Method2022::Aes128Gcm, &key).unwrap();
        assert_eq!(&*cipher.key, &Sha256::digest(key)[..16]);
        assert!(Cipher2022::new(Method2022::Aes128Gcm, &[1; 15]).is_err());
        assert!(Cipher2022::from_password(Method2022::Aes128Gcm, "a:b").is_err());
        assert!(Cipher2022::from_password(Method2022::Aes128Gcm, "not-base64").is_err());
        let mut rng = StdRng::seed_from_u64(8);
        let dns = Destination::new("example.org", 53).unwrap();
        assert!((1..=800).contains(&dns_padding(&dns, 100, &mut rng).len()));
        assert!(dns_padding(&dns, 900, &mut rng).is_empty());
        assert!(
            dns_padding(&Destination::new("example.org", 443).unwrap(), 0, &mut rng).is_empty()
        );
        let mut oversize = fixture_packet(false);
        oversize.datagram.payload = vec![0; MAX_PACKET_SIZE];
        assert!(cipher.seal_with_nonce(&oversize, b"", [0; 24]).is_err());
        assert!(
            Server2022::with_limits(
                cipher2022(Method2022::Aes128Gcm),
                Duration::from_secs(60),
                1
            )
            .is_err()
        );
    }
}
