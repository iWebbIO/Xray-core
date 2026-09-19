//! Salamander BLAKE2b-256 XOR obfuscation and Gecko UDP fragmentation.
//! Sources: `salamander/{salamander,gecko,conn}.go`.
//!
//! This is obfuscation, not authenticated encryption. Invalid frames must be
//! discarded by a packet caller; successful decoding does not authenticate a peer.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use blake2::{Blake2b, Digest, digest::consts::U32};
use rand::{CryptoRng, RngCore};

use super::{UDP_SIZE, invalid};

pub const SALT_SIZE: usize = 8;
pub const GECKO_HEADER_SIZE: usize = 5;
pub const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
pub const GECKO_MAX_REASSEMBLY: usize = 4096;
pub const GECKO_MAX_PER_SOURCE: usize = 8;

#[derive(Clone)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl Salamander {
    pub fn new(psk: impl AsRef<[u8]>) -> io::Result<Self> {
        let psk = psk.as_ref();
        if psk.len() < 4 {
            return Err(invalid("Salamander PSK must be at least four bytes"));
        }
        Ok(Self { psk: psk.to_vec() })
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hash = Blake2b::<U32>::new();
        hash.update(&self.psk);
        hash.update(salt);
        hash.finalize().into()
    }

    pub fn encode<R: RngCore + CryptoRng + ?Sized>(
        &self,
        payload: &[u8],
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        let mut salt = [0; SALT_SIZE];
        rng.fill_bytes(&mut salt);
        self.encode_with_salt(payload, salt)
    }

    /// Deterministic framing entry point for supplied cryptographically random
    /// salts and interoperability fixtures. Production salts must be fresh.
    pub fn encode_with_salt(&self, payload: &[u8], salt: [u8; SALT_SIZE]) -> io::Result<Vec<u8>> {
        if payload.len() > UDP_SIZE - SALT_SIZE {
            return Err(invalid("Salamander packet exceeds UDP size"));
        }
        let key = self.key(&salt);
        let mut out = Vec::with_capacity(payload.len() + SALT_SIZE);
        out.extend_from_slice(&salt);
        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ key[i % key.len()]),
        );
        Ok(out)
    }

    pub fn decode(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.len() < SALT_SIZE {
            return Err(invalid("truncated Salamander salt"));
        }
        if packet.len() > UDP_SIZE {
            return Err(invalid("Salamander packet exceeds UDP size"));
        }
        let key = self.key(&packet[..SALT_SIZE]);
        Ok(packet[SALT_SIZE..]
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ key[i % key.len()])
            .collect())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeckoHeader {
    pub message_id: u8,
    pub chunk_index: u8,
    pub total_chunks: u8,
}

impl GeckoHeader {
    fn validate(self) -> io::Result<()> {
        if !(2..=8).contains(&self.total_chunks) || self.chunk_index >= self.total_chunks {
            return Err(invalid("invalid Gecko fragment index/count"));
        }
        Ok(())
    }

    /// `[0x80, message ID, index:4 | count:4, padding length BE16, padding, data]`.
    pub fn encode(self, padding: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
        self.validate()?;
        let padding_len =
            u16::try_from(padding.len()).map_err(|_| invalid("Gecko padding too long"))?;
        let length = GECKO_HEADER_SIZE
            .checked_add(padding.len())
            .and_then(|n| n.checked_add(payload.len()))
            .ok_or_else(|| invalid("Gecko frame size overflow"))?;
        if length > UDP_SIZE - SALT_SIZE {
            return Err(invalid("Gecko frame exceeds UDP size"));
        }
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(&[
            0x80,
            self.message_id,
            (self.chunk_index << 4) | self.total_chunks,
        ]);
        out.extend_from_slice(&padding_len.to_be_bytes());
        out.extend_from_slice(padding);
        out.extend_from_slice(payload);
        Ok(out)
    }

    pub fn decode(frame: &[u8]) -> io::Result<(Self, &[u8])> {
        if frame.len() < GECKO_HEADER_SIZE {
            return Err(invalid("truncated Gecko header"));
        }
        // Go only checks the high bit, leaving the low seven bits reserved.
        if frame[0] & 0x80 == 0 {
            return Err(invalid("missing Gecko fragment marker"));
        }
        let header = Self {
            message_id: frame[1],
            chunk_index: frame[2] >> 4,
            total_chunks: frame[2] & 0xf,
        };
        header.validate()?;
        let end = GECKO_HEADER_SIZE + usize::from(u16::from_be_bytes([frame[3], frame[4]]));
        let payload = frame
            .get(end..)
            .ok_or_else(|| invalid("truncated Gecko padding"))?;
        Ok((header, payload))
    }
}

struct Assembly {
    chunks: Vec<Option<Vec<u8>>>,
    deadline: Instant,
    bytes: usize,
}

/// Bounded source-isolated reassembly. Expiration is driven by incoming frames
/// and explicit `expire`, so no independent background task is required.
#[derive(Default)]
pub struct GeckoReassembler {
    entries: HashMap<(SocketAddr, u8), Assembly>,
    per_source: HashMap<SocketAddr, usize>,
}

impl GeckoReassembler {
    fn remove(&mut self, key: (SocketAddr, u8)) {
        if self.entries.remove(&key).is_some()
            && let Some(count) = self.per_source.get_mut(&key.0)
        {
            *count -= 1;
            if *count == 0 {
                self.per_source.remove(&key.0);
            }
        }
    }

    pub fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| (now > entry.deadline).then_some(*key))
            .collect();
        for key in expired {
            self.remove(key);
        }
    }

    pub fn pending(&self) -> usize {
        self.entries.len()
    }

    /// Duplicates and inconsistent chunk counts are silently ignored, as in Go.
    /// Oversized assembled payloads are rejected before unbounded allocation.
    pub fn accept(
        &mut self,
        peer: SocketAddr,
        header: GeckoHeader,
        payload: &[u8],
        now: Instant,
    ) -> io::Result<Option<Vec<u8>>> {
        header.validate()?;
        if payload.len() > UDP_SIZE {
            return Err(invalid("Gecko chunk exceeds UDP size"));
        }
        self.expire(now);
        let key = (peer, header.message_id);
        if !self.entries.contains_key(&key) {
            if self.per_source.get(&peer).copied().unwrap_or(0) >= GECKO_MAX_PER_SOURCE {
                return Ok(None);
            }
            if self.entries.len() >= GECKO_MAX_REASSEMBLY
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.deadline)
                    .map(|(key, _)| *key)
            {
                self.remove(oldest);
            }
            self.entries.insert(
                key,
                Assembly {
                    chunks: vec![None; header.total_chunks as usize],
                    deadline: now + GECKO_REASSEMBLY_TTL,
                    bytes: 0,
                },
            );
            *self.per_source.entry(peer).or_default() += 1;
        }
        let entry = self.entries.get_mut(&key).unwrap();
        let index = usize::from(header.chunk_index);
        if entry.chunks.len() != usize::from(header.total_chunks) || entry.chunks[index].is_some() {
            return Ok(None);
        }
        if entry.bytes + payload.len() > UDP_SIZE {
            self.remove(key);
            return Err(invalid("assembled Gecko datagram exceeds UDP size"));
        }
        entry.bytes += payload.len();
        entry.chunks[index] = Some(payload.to_vec());
        if entry.chunks.iter().any(Option::is_none) {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(entry.bytes);
        for chunk in &entry.chunks {
            out.extend_from_slice(chunk.as_ref().unwrap());
        }
        self.remove(key);
        Ok(Some(out))
    }
}

/// Stateful Gecko packet codec; output packets already include Salamander.
pub struct Gecko {
    salamander: Salamander,
    min_packet: usize,
    max_packet: usize,
    message_id: u8,
    reassembler: GeckoReassembler,
}

impl Gecko {
    /// Zero selects Go defaults of 512 and 1200 bytes, respectively.
    pub fn new(psk: impl AsRef<[u8]>, min_packet: usize, max_packet: usize) -> io::Result<Self> {
        let min_packet = if min_packet == 0 { 512 } else { min_packet };
        let max_packet = if max_packet == 0 { 1200 } else { max_packet };
        if min_packet > max_packet || max_packet > 2048 {
            return Err(invalid("invalid Gecko minimum/maximum packet size"));
        }
        Ok(Self {
            salamander: Salamander::new(psk)?,
            min_packet,
            max_packet,
            message_id: 0,
            reassembler: GeckoReassembler::default(),
        })
    }

    pub fn encode<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> io::Result<Vec<Vec<u8>>> {
        if payload.len() > UDP_SIZE {
            return Err(invalid("Gecko datagram exceeds UDP size"));
        }
        if payload.is_empty() {
            return Ok(Vec::new());
        }
        if payload[0] & 0x80 == 0 {
            return Ok(vec![self.salamander.encode(payload, rng)?]);
        }
        let chunks = 2 + random_below(7, rng);
        self.message_id = self.message_id.wrapping_add(1);
        let chunk_size = payload.len() / chunks;
        let mut out = Vec::with_capacity(chunks);
        for i in 0..chunks {
            let end = if i + 1 == chunks {
                payload.len()
            } else {
                (i + 1) * chunk_size
            };
            let chunk = &payload[i * chunk_size..end];
            let base = SALT_SIZE + GECKO_HEADER_SIZE + chunk.len();
            let lo = self.min_packet.max(base);
            let pad_len = if lo > self.max_packet {
                0
            } else {
                lo - base + random_below(self.max_packet - lo + 1, rng)
            };
            let mut padding = vec![0; pad_len];
            rng.fill_bytes(&mut padding);
            let header = GeckoHeader {
                message_id: self.message_id,
                chunk_index: i as u8,
                total_chunks: chunks as u8,
            };
            out.push(
                self.salamander
                    .encode(&header.encode(&padding, chunk)?, rng)?,
            );
        }
        Ok(out)
    }

    pub fn decode_from(
        &mut self,
        packet: &[u8],
        peer: SocketAddr,
        now: Instant,
    ) -> io::Result<Option<Vec<u8>>> {
        let bytes = self.salamander.decode(packet)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes[0] & 0x80 == 0 {
            return Ok(Some(bytes));
        }
        let (header, chunk) = GeckoHeader::decode(&bytes)?;
        self.reassembler.accept(peer, header, chunk, now)
    }

    pub fn expire(&mut self, now: Instant) {
        self.reassembler.expire(now);
    }
}

fn random_below<R: RngCore + CryptoRng + ?Sized>(n: usize, rng: &mut R) -> usize {
    if n <= 1 {
        return 0;
    }
    // Go samples a big-endian uint32 and applies modulo, rather than rejection.
    let mut bytes = [0; 4];
    rng.fill_bytes(&mut bytes);
    (u32::from_be_bytes(bytes) as usize) % n
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn salamander_golden_uses_blake2b_256_parameter_not_truncated_512() {
        // Independently generated with Python hashlib.blake2b(digest_size=32)
        // over PSK || salt, then the Go source's repeating-key XOR operation.
        let codec = Salamander::new(b"correct horse battery staple").unwrap();
        let payload: Vec<_> = (0..48).collect();
        let wire = codec
            .encode_with_salt(&payload, [0, 1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        assert_eq!(
            hex(&wire),
            "0001020304050607fa37342c99c84306e43f514760a908acc1b2082ebef591d0ee50c6dddcd8d93fda17140cb9e86326c41f71674089288c"
        );
        assert_eq!(codec.decode(&wire).unwrap(), payload);
        assert!(codec.decode(&[0; 7]).is_err());
        assert_eq!(codec.decode(&[0; 8]).unwrap(), Vec::<u8>::new());
        assert!(Salamander::new(b"abc").is_err());
        assert!(codec.encode_with_salt(&vec![0; UDP_SIZE], [0; 8]).is_err());
    }

    #[test]
    fn gecko_frame_golden_and_malformed_boundaries() {
        let h = GeckoHeader {
            message_id: 0x2a,
            chunk_index: 1,
            total_chunks: 3,
        };
        let wire = h.encode(&[0xaa, 0xbb], &[1, 2, 3]).unwrap();
        assert_eq!(wire, [0x80, 0x2a, 0x13, 0, 2, 0xaa, 0xbb, 1, 2, 3]);
        assert_eq!(
            GeckoHeader::decode(&wire).unwrap(),
            (h, [1, 2, 3].as_slice())
        );
        for len in 0..7 {
            assert!(GeckoHeader::decode(&wire[..len]).is_err());
        }
        for packed in [0, 1, 9, 0x22, 0x83] {
            assert!(GeckoHeader::decode(&[0x80, 0, packed, 0, 0]).is_err());
        }
        // Reserved bits are ignored by the Go decoder.
        assert!(GeckoHeader::decode(&[0xff, 0, 0x02, 0, 0]).is_ok());
    }

    #[test]
    fn reassembly_handles_reordering_duplicates_sources_and_expiration() {
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::default();
        let first = GeckoHeader {
            message_id: 7,
            chunk_index: 0,
            total_chunks: 2,
        };
        let last = GeckoHeader {
            chunk_index: 1,
            ..first
        };
        assert!(r.accept(a, last, b"def", now).unwrap().is_none());
        assert!(r.accept(a, last, b"bad", now).unwrap().is_none());
        assert!(r.accept(b, first, b"other", now).unwrap().is_none());
        assert_eq!(r.accept(a, first, b"abc", now).unwrap().unwrap(), b"abcdef");
        assert_eq!(r.pending(), 1);
        r.expire(now + GECKO_REASSEMBLY_TTL);
        assert_eq!(r.pending(), 1);
        r.expire(now + GECKO_REASSEMBLY_TTL + Duration::from_nanos(1));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn empty_chunks_are_counted_once_and_per_source_limit_is_bounded() {
        let peer = "127.0.0.1:1".parse().unwrap();
        let now = Instant::now();
        let mut r = GeckoReassembler::default();
        for id in 0..9 {
            r.accept(
                peer,
                GeckoHeader {
                    message_id: id,
                    chunk_index: 0,
                    total_chunks: 2,
                },
                b"",
                now,
            )
            .unwrap();
        }
        assert_eq!(r.pending(), 8);
        let last = GeckoHeader {
            message_id: 0,
            chunk_index: 1,
            total_chunks: 2,
        };
        assert_eq!(r.accept(peer, last, b"end", now).unwrap().unwrap(), b"end");
    }

    #[test]
    fn gecko_long_header_fragments_and_short_header_passes_through() {
        let mut tx = Gecko::new(b"password", 64, 100).unwrap();
        let mut rx = Gecko::new(b"password", 64, 100).unwrap();
        let peer = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(42);
        let mut payload = vec![0xab; 80];
        payload[0] = 0xc0;
        let packets = tx.encode(&payload, &mut rng).unwrap();
        assert!((2..=8).contains(&packets.len()));
        assert!(packets.iter().all(|p| (64..=100).contains(&p.len())));
        let mut result = None;
        for packet in packets.iter().rev() {
            if let Some(bytes) = rx.decode_from(packet, peer, now).unwrap() {
                result = Some(bytes);
            }
        }
        assert_eq!(result.unwrap(), payload);
        let packets = tx.encode(b"\x40data", &mut rng).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            rx.decode_from(&packets[0], peer, now).unwrap().unwrap(),
            b"\x40data"
        );
    }
}
