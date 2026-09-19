//! VMess version-one plaintext headers and authenticated body framing.
//!
//! The wire layout follows `proxy/vmess/encoding` and `common/crypto/auth.go`.
//! Header AEAD envelopes and user authentication live in the sibling `crypto`
//! module. Body codecs preserve packet boundaries; stream callers may concatenate
//! data frames. Legacy CFB/none security and response-command execution are not
//! supported by the current Go implementation or this module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use rand::RngCore;
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::crypto::{derive_response_key_iv, kdf16};
use crate::address::{Address, Destination};

pub const VERSION: u8 = 1;
pub const OPTION_CHUNK_STREAM: u8 = 0x01;
pub const OPTION_CHUNK_MASKING: u8 = 0x04;
pub const OPTION_GLOBAL_PADDING: u8 = 0x08;
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
pub const MAX_WRITE_FRAME: usize = 8192;
const TAG_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

impl TryFrom<u8> for Command {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            3 => Ok(Self::Mux),
            _ => bail!("unsupported VMess command {value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Security {
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
}

impl TryFrom<u8> for Security {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            3 => Ok(Self::Aes128Gcm),
            4 => Ok(Self::Chacha20Poly1305),
            _ => bail!("unsupported VMess security {value}"),
        }
    }
}

/// Decrypted request header. `destination` is absent for the Mux command.
/// Padding is explicit so callers can use cryptographic randomness and fixtures
/// can describe the complete plaintext. Keys intentionally have no Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestHeader {
    pub body_iv: [u8; 16],
    pub body_key: [u8; 16],
    pub response_auth: u8,
    pub options: u8,
    pub security: Security,
    pub command: Command,
    pub destination: Option<Destination>,
    pub padding: Vec<u8>,
}

impl RequestHeader {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.padding.len() <= 15,
            "VMess header padding exceeds 15 bytes"
        );
        validate_options(self.options)?;
        let mut output = Vec::with_capacity(320);
        output.push(VERSION);
        output.extend_from_slice(&self.body_iv);
        output.extend_from_slice(&self.body_key);
        output.extend_from_slice(&[
            self.response_auth,
            self.options,
            (self.padding.len() as u8) << 4 | self.security as u8,
            0,
            self.command as u8,
        ]);
        match self.command {
            Command::Mux => ensure!(self.destination.is_none(), "Mux has no wire destination"),
            Command::Tcp | Command::Udp => {
                encode_destination(
                    self.destination
                        .as_ref()
                        .context("missing VMess destination")?,
                    &mut output,
                )?;
            }
        }
        output.extend_from_slice(&self.padding);
        output.extend_from_slice(&fnv1a(&output).to_be_bytes());
        Ok(output)
    }

    /// Decode one plaintext header, returning its exact byte count. The caller
    /// must separately reject trailing data inside an AEAD header envelope.
    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        let mut cursor = Cursor::new(input);
        ensure!(cursor.byte()? == VERSION, "unsupported VMess version");
        let body_iv = cursor.array()?;
        let body_key = cursor.array()?;
        let response_auth = cursor.byte()?;
        let options = cursor.byte()?;
        validate_options(options)?;
        let security_padding = cursor.byte()?;
        let security = Security::try_from(security_padding & 0x0f)?;
        let _reserved = cursor.byte()?; // Go ignores this byte; emit zero above.
        let command = Command::try_from(cursor.byte()?)?;
        let destination = match command {
            Command::Mux => None,
            Command::Tcp | Command::Udp => Some(decode_destination(&mut cursor)?),
        };
        let padding = cursor.take((security_padding >> 4) as usize)?.to_vec();
        let checksum_offset = cursor.position;
        let checksum = u32::from_be_bytes(cursor.array()?);
        ensure!(
            checksum == fnv1a(&input[..checksum_offset]),
            "invalid VMess header checksum"
        );
        Ok((
            Self {
                body_iv,
                body_key,
                response_auth,
                options,
                security,
                command,
                destination,
                padding,
            },
            cursor.position,
        ))
    }
}

/// An opaque response command. The current Go source recognizes no command IDs.
/// Preserve its bytes for callers that inspect or forward headers; never execute
/// it as a supported operation. `checksum_valid` includes the Go minimum length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseCommand {
    pub id: u8,
    pub data: Vec<u8>,
}

impl ResponseCommand {
    pub fn checksum_valid(&self) -> bool {
        self.data.len() > 4
            && u32::from_be_bytes(self.data[..4].try_into().expect("length checked"))
                == fnv1a(&self.data[4..])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeader {
    pub response_auth: u8,
    pub options: u8,
    pub command: Option<ResponseCommand>,
}

impl ResponseHeader {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = vec![self.response_auth, self.options];
        if let Some(command) = &self.command {
            ensure!(command.id != 0, "VMess response command ID must be nonzero");
            ensure!(
                command.data.len() <= 255,
                "VMess response command is too long"
            );
            output.extend_from_slice(&[command.id, command.data.len() as u8]);
            output.extend_from_slice(&command.data);
        } else {
            output.extend_from_slice(&[0, 0]);
        }
        Ok(output)
    }

    pub fn decode(input: &[u8], expected_auth: u8) -> Result<(Self, usize)> {
        let mut cursor = Cursor::new(input);
        let response_auth = cursor.byte()?;
        ensure!(
            response_auth == expected_auth,
            "unexpected VMess response authentication byte"
        );
        let options = cursor.byte()?;
        let id = cursor.byte()?;
        let length = cursor.byte()? as usize;
        let command = if id == 0 {
            // Go ignores length when no command is present.
            None
        } else {
            Some(ResponseCommand {
                id,
                data: cursor.take(length)?.to_vec(),
            })
        };
        Ok((
            Self {
                response_auth,
                options,
                command,
            },
            cursor.position,
        ))
    }
}

pub fn fnv1a(input: &[u8]) -> u32 {
    input.iter().fold(0x811c9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

pub fn chacha20poly1305_key(key: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(key);
    let second = Md5::digest(first);
    let mut output = [0; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

/// A nonce replaces the first two IV bytes with the big-endian frame counter.
pub fn chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&iv[..12]);
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce
}

fn validate_options(options: u8) -> Result<()> {
    ensure!(
        options & OPTION_GLOBAL_PADDING == 0 || options & OPTION_CHUNK_MASKING != 0,
        "VMess global padding requires chunk masking"
    );
    Ok(()) // Preserve other bits, including the deprecated chunk-stream bit.
}

fn encode_destination(destination: &Destination, output: &mut Vec<u8>) -> Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.address {
        Address::Ip(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Address::Domain(host) => {
            ensure!(
                !host.is_empty() && host.len() <= 255,
                "invalid VMess domain length"
            );
            // The Go writer preserves an explicitly supplied domain verbatim,
            // including IP-looking domains. Validation and normalization happen
            // on the receiving side, not while choosing the wire address type.
            output.extend_from_slice(&[2, host.len() as u8]);
            output.extend_from_slice(host.as_bytes());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            output.push(3);
            output.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

fn decode_destination(cursor: &mut Cursor<'_>) -> Result<Destination> {
    let port = u16::from_be_bytes(cursor.array()?);
    let address = match cursor.byte()? {
        1 => Address::Ip(Ipv4Addr::from(cursor.array::<4>()?).into()),
        2 => {
            let length = cursor.byte()? as usize;
            let host =
                std::str::from_utf8(cursor.take(length)?).context("VMess domain is not UTF-8")?;
            decode_domain(host)?
        }
        3 => Address::Ip(normalize_ip(Ipv6Addr::from(cursor.array::<16>()?).into())),
        family => bail!("unsupported VMess address family {family}"),
    };
    Ok(Destination { address, port })
}

fn decode_domain(host: &str) -> Result<Address> {
    let first = *host.as_bytes().first().context("empty VMess domain")?;
    // common/protocol/address.go only attempts IP parsing for these prefixes.
    // In particular, an unbracketed IPv6 literal starting with a-f or ':' is
    // rejected by domain validation even though the IP parser could accept it.
    if first == b'[' || first.is_ascii_digit() {
        let candidate = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        // common/net.ParseAddress removes matching brackets, then trims space
        // when an endpoint is not ASCII alphanumeric. Trimming always here is
        // equivalent because space cannot be ASCII alphanumeric.
        if let Ok(ip) = candidate.trim().parse::<IpAddr>() {
            return Ok(Address::Ip(normalize_ip(ip)));
        }
    }
    ensure!(
        host.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')),
        "invalid VMess domain name"
    );
    Ok(Address::Domain(host.to_owned()))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    // net.IPAddress converts IPv4-mapped IPv6 to the IPv4 address family.
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("VMess header length overflow")?;
        let bytes = self
            .input
            .get(self.position..end)
            .context("truncated VMess header")?;
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("fixed length"))
    }
}

/// Directional body key material. Authenticated response lengths deliberately
/// derive from the *request* key/IV, matching both Go client and server.
#[derive(Clone)]
pub struct BodyKeys {
    pub body_key: [u8; 16],
    pub body_iv: [u8; 16],
    pub length_key: [u8; 16],
    pub length_iv: [u8; 16],
}

impl BodyKeys {
    pub fn request(header: &RequestHeader) -> Self {
        Self {
            body_key: header.body_key,
            body_iv: header.body_iv,
            length_key: kdf16(&header.body_key, &[b"auth_len"]),
            length_iv: header.body_iv,
        }
    }
    pub fn response(header: &RequestHeader) -> Self {
        let (body_key, body_iv) = derive_response_key_iv(&header.body_key, &header.body_iv);
        Self {
            body_key,
            body_iv,
            ..Self::request(header)
        }
    }
}

#[derive(Clone)]
struct BodyState {
    security: Security,
    options: u8,
    keys: BodyKeys,
    shake: Option<Shake128Reader>,
    counter: u32,
    finished: bool,
}

impl BodyState {
    fn new(security: Security, options: u8, keys: BodyKeys) -> Result<Self> {
        validate_options(options)?;
        let shake = if options & OPTION_CHUNK_MASKING != 0 {
            let mut hash = Shake128::default();
            Update::update(&mut hash, &keys.body_iv);
            Some(hash.finalize_xof())
        } else {
            None
        };
        Ok(Self {
            security,
            options,
            keys,
            shake,
            counter: 0,
            finished: false,
        })
    }
    fn ensure_active(&self) -> Result<()> {
        ensure!(!self.finished, "VMess body is already finished");
        // Go wraps this counter. Stop rather than reuse a key/nonce pair.
        ensure!(
            self.counter <= u16::MAX as u32,
            "VMess body nonce counter exhausted"
        );
        Ok(())
    }
    fn length_width(&self) -> usize {
        if self.options & OPTION_AUTHENTICATED_LENGTH != 0 {
            18
        } else {
            2
        }
    }
    fn next_shake(&mut self) -> u16 {
        let mut bytes = [0; 2];
        self.shake
            .as_mut()
            .expect("masking validated")
            .read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
    fn padding_length(&mut self) -> usize {
        if self.options & OPTION_GLOBAL_PADDING != 0 {
            usize::from(self.next_shake() % 64)
        } else {
            0
        }
    }
    fn encode_length(&mut self, length: usize) -> Result<Vec<u8>> {
        let length = u16::try_from(length).context("VMess body frame is too long")?;
        if self.options & OPTION_AUTHENTICATED_LENGTH != 0 {
            seal(
                self.security,
                &self.keys.length_key,
                &chunk_nonce(&self.keys.length_iv, self.counter as u16),
                &(length - TAG_LENGTH as u16).to_be_bytes(),
            )
        } else {
            let mask = if self.shake.is_some() {
                self.next_shake()
            } else {
                0
            };
            Ok((length ^ mask).to_be_bytes().to_vec())
        }
    }
    fn decode_length(&mut self, input: &[u8]) -> Result<usize> {
        if self.options & OPTION_AUTHENTICATED_LENGTH != 0 {
            let plaintext = open(
                self.security,
                &self.keys.length_key,
                &chunk_nonce(&self.keys.length_iv, self.counter as u16),
                input,
            )?;
            let length = u16::from_be_bytes(
                plaintext
                    .as_slice()
                    .try_into()
                    .context("invalid VMess authenticated length")?,
            );
            Ok(usize::from(
                length
                    .checked_add(TAG_LENGTH as u16)
                    .context("VMess authenticated length overflow")?,
            ))
        } else {
            let value = u16::from_be_bytes(input.try_into().context("invalid VMess length width")?);
            let mask = if self.shake.is_some() {
                self.next_shake()
            } else {
                0
            };
            Ok(usize::from(value ^ mask))
        }
    }
}

fn seal(security: Security, key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let result = match security {
        Security::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .expect("fixed AES key")
            .encrypt(nonce.into(), plaintext),
        Security::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&chacha20poly1305_key(key))
            .expect("fixed ChaCha key")
            .encrypt(nonce.into(), plaintext),
    };
    result.map_err(|_| anyhow::anyhow!("VMess body encryption failed"))
}

fn open(
    security: Security,
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let result = match security {
        Security::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .expect("fixed AES key")
            .decrypt(nonce.into(), ciphertext),
        Security::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&chacha20poly1305_key(key))
            .expect("fixed ChaCha key")
            .decrypt(nonce.into(), ciphertext),
    };
    result.map_err(|_| anyhow::anyhow!("VMess body authentication failed"))
}

/// Stream payloads must be divided at `max_payload_length`; each UDP datagram
/// must fit into a single frame. An empty payload emits authenticated EOF.
pub struct BodyEncoder {
    state: BodyState,
}

impl BodyEncoder {
    pub fn new(security: Security, options: u8, keys: BodyKeys) -> Result<Self> {
        Ok(Self {
            state: BodyState::new(security, options, keys)?,
        })
    }
    pub fn max_payload_length(&self) -> usize {
        MAX_WRITE_FRAME
            - TAG_LENGTH
            - self.state.length_width()
            - if self.state.options & OPTION_GLOBAL_PADDING != 0 {
                64
            } else {
                0
            }
    }
    pub fn encode_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encode_frame_with_rng(plaintext, &mut rand::rngs::OsRng)
    }
    /// Split one stream write according to the Go writer's 8192-byte buffers.
    /// An empty write is a no-op; call `encode_frame(&[])` explicitly for EOF.
    pub fn encode_stream(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.state.ensure_active()?;
        let chunk_length = self.max_payload_length();
        let frames = plaintext.len().div_ceil(chunk_length);
        ensure!(
            frames <= (u16::MAX as u32 + 1 - self.state.counter) as usize,
            "VMess body nonce counter would be exhausted"
        );
        let mut output = Vec::new();
        for chunk in plaintext.chunks(chunk_length) {
            output.extend(self.encode_frame(chunk)?);
        }
        Ok(output)
    }
    /// Random padding is transmitted in cleartext. Require a cryptographic RNG
    /// in production; injection also makes exact wire fixtures possible.
    pub fn encode_frame_with_rng<R: RngCore + rand::CryptoRng>(
        &mut self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        self.state.ensure_active()?;
        ensure!(
            plaintext.len() <= self.max_payload_length(),
            "VMess payload exceeds sender frame limit"
        );
        let mut next = self.state.clone();
        let padding_length = next.padding_length();
        let ciphertext = seal(
            next.security,
            &next.keys.body_key,
            &chunk_nonce(&next.keys.body_iv, next.counter as u16),
            plaintext,
        )?;
        let mut output = next.encode_length(ciphertext.len() + padding_length)?;
        output.extend_from_slice(&ciphertext);
        let padding_offset = output.len();
        output.resize(padding_offset + padding_length, 0);
        rng.try_fill_bytes(&mut output[padding_offset..])
            .context("VMess padding randomness failed")?;
        next.counter += 1;
        next.finished = plaintext.is_empty();
        self.state = next;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn header() -> RequestHeader {
        RequestHeader {
            body_iv: std::array::from_fn(|i| i as u8 + 16),
            body_key: std::array::from_fn(|i| i as u8),
            response_auth: 0xa5,
            options: 0x0d,
            security: Security::Aes128Gcm,
            command: Command::Tcp,
            destination: Some(Destination::new("example.org", 443).unwrap()),
            padding: vec![0xaa, 0xbb, 0xcc],
        }
    }

    // Fixtures were independently computed with Python hashlib (FNV written
    // directly from the definition), cryptography AESGCM/ChaCha20Poly1305, and
    // a separate nested-HMAC implementation of the Go KDF. They are not generated
    // by this Rust implementation, and cover source wire bytes, not just round trips.
    #[test]
    fn request_header_independent_fixtures() {
        let fixtures = [
            (
                Command::Tcp,
                Some(("example.org", 443)),
                "01101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0fa50d33000101bb020b6578616d706c652e6f7267aabbcc0794d070",
            ),
            (
                Command::Udp,
                Some(("192.0.2.1", 53)),
                "01101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0fa50d330002003501c0000201aabbcceae945b1",
            ),
            (
                Command::Tcp,
                Some(("::1", 443)),
                "01101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0fa50d33000101bb0300000000000000000000000000000001aabbccf58fab93",
            ),
            (
                Command::Mux,
                None,
                "01101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0fa50d330003aabbcc43a6470b",
            ),
        ];
        for (command, destination, fixture) in fixtures {
            let mut request = header();
            request.command = command;
            request.destination =
                destination.map(|(host, port)| Destination::new(host, port).unwrap());
            let wire = hex(fixture);
            assert_eq!(request.encode().unwrap(), wire);
            let (decoded, consumed) = RequestHeader::decode(&wire).unwrap();
            assert!(decoded == request);
            assert_eq!(consumed, wire.len());
            for length in 0..wire.len() {
                assert!(RequestHeader::decode(&wire[..length]).is_err());
            }
            let mut with_body = wire.clone();
            with_body.extend_from_slice(b"body");
            assert_eq!(RequestHeader::decode(&with_body).unwrap().1, wire.len());
            let mut corrupted = wire;
            corrupted[17] ^= 1;
            assert!(RequestHeader::decode(&corrupted).is_err());
        }
    }

    #[test]
    fn request_constraints_and_reserved_byte() {
        let mut request = header();
        for padding in 0..=15 {
            request.padding = vec![0xff; padding];
            assert!(RequestHeader::decode(&request.encode().unwrap()).unwrap().0 == request);
        }
        request.padding.push(0);
        assert!(request.encode().is_err());
        request.padding.clear();
        request.options = OPTION_GLOBAL_PADDING;
        assert!(request.encode().is_err());
        request.options = 0x82; // Unassigned option bits round trip unchanged.
        let mut wire = request.encode().unwrap();
        wire[36] = 0xf0;
        let end = wire.len() - 4;
        let checksum = fnv1a(&wire[..end]);
        wire[end..].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(RequestHeader::decode(&wire).unwrap().0.options, 0x82);
        for (position, value) in [(0, 0), (35, 0), (35, 1), (35, 2), (35, 5), (37, 4), (40, 9)] {
            let mut invalid = request.encode().unwrap();
            invalid[position] = value;
            assert!(RequestHeader::decode(&invalid).is_err());
        }
    }

    fn domain_destination_wire(host: &[u8]) -> Vec<u8> {
        let mut wire = vec![0x01, 0xbb, 2, u8::try_from(host.len()).unwrap()];
        wire.extend_from_slice(host);
        wire
    }

    #[test]
    fn domain_decoder_matches_source_character_and_ip_prefix_rules() {
        // common/protocol/address.go permits ASCII alphanumerics and -._.
        // It deliberately does not impose DNS label placement or case rules.
        for host in [
            "example.org",
            "EXAMPLE.org",
            "_srv.-._",
            ".",
            "1host.test",
            "192.0.2.999",
            "192.168.001.1",
        ] {
            let wire = domain_destination_wire(host.as_bytes());
            let mut cursor = Cursor::new(&wire);
            assert_eq!(
                decode_destination(&mut cursor).unwrap(),
                Destination {
                    address: Address::Domain(host.to_owned()),
                    port: 443
                }
            );
            assert_eq!(cursor.position, wire.len());
        }
        for host in [
            "",
            "bad!host",
            "user@host",
            "host name",
            "host/name",
            "host:80",
            "éxample.org",
            "例子.test",
            "host\0name",
            "host\n",
            "[example.org]",
            "[fe80::1%eth0]",
            "abcd::1",
            "fe80::1",
            "::1",
            " 192.0.2.1",
            " [::1]",
            "[::1] ",
        ] {
            let wire = domain_destination_wire(host.as_bytes());
            assert!(
                decode_destination(&mut Cursor::new(&wire)).is_err(),
                "{host:?}"
            );
        }
        assert!(decode_destination(&mut Cursor::new(&domain_destination_wire(&[0xff]))).is_err());

        // maybeIPPrefix permits '[' or a digit; net.ParseAddress removes a
        // matching pair of brackets and trims surrounding space inside them.
        for (host, expected) in [
            ("192.0.2.1", "192.0.2.1"),
            ("192.0.2.1 \t", "192.0.2.1"),
            ("[192.0.2.1]", "192.0.2.1"),
            ("2001:db8::1", "2001:db8::1"),
            ("[abcd::1]", "abcd::1"),
            ("[::1]", "::1"),
            ("[ ::1 ]", "::1"),
            ("[\u{00a0}::1\u{00a0}]", "::1"),
            ("[::ffff:192.0.2.1]", "192.0.2.1"),
            ("0:0:0:0:0:ffff:c000:201", "192.0.2.1"),
        ] {
            let wire = domain_destination_wire(host.as_bytes());
            assert_eq!(
                decode_destination(&mut Cursor::new(&wire)).unwrap(),
                Destination {
                    address: Address::Ip(expected.parse().unwrap()),
                    port: 443
                },
                "{host:?}"
            );
        }

        let mut mapped_ipv6 = vec![0x01, 0xbb, 3];
        mapped_ipv6.extend_from_slice(&hex("00000000000000000000ffffc0000201"));
        assert_eq!(
            decode_destination(&mut Cursor::new(&mapped_ipv6)).unwrap(),
            Destination::new("192.0.2.1", 443).unwrap()
        );
    }

    #[test]
    fn domain_encoder_preserves_explicit_wire_address_family() {
        for host in [
            "192.0.2.1",
            "[::1]",
            "192.0.2.1 ",
            "bad!host",
            "éxample.org",
        ] {
            let destination = Destination {
                address: Address::Domain(host.to_owned()),
                port: 443,
            };
            let mut encoded = Vec::new();
            encode_destination(&destination, &mut encoded).unwrap();
            assert_eq!(encoded, domain_destination_wire(host.as_bytes()));
        }
        for host in [String::new(), "x".repeat(256)] {
            let destination = Destination {
                address: Address::Domain(host),
                port: 443,
            };
            assert!(encode_destination(&destination, &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn response_header_auth_and_opaque_command_framing() {
        let response = ResponseHeader {
            response_auth: 0xa5,
            options: 1,
            command: None,
        };
        assert_eq!(response.encode().unwrap(), hex("a5010000"));
        assert_eq!(
            ResponseHeader::decode(&hex("a5010000"), 0xa5).unwrap(),
            (response, 4)
        );
        assert!(ResponseHeader::decode(&hex("a5010000"), 0xa4).is_err());
        // No ID dispatch exists in the source. Preserve bytes but flag bad FNV.
        let wire = hex("a5019905e40c292c61"); // FNV-1a("a") = e40c292c
        let (response, consumed) = ResponseHeader::decode(&wire, 0xa5).unwrap();
        assert_eq!(consumed, wire.len());
        assert!(response.command.as_ref().unwrap().checksum_valid());
        assert_eq!(response.encode().unwrap(), wire);
        for length in 0..wire.len() {
            assert!(ResponseHeader::decode(&wire[..length], 0xa5).is_err());
        }
        let mut malformed = wire;
        malformed[4] ^= 1;
        assert!(
            !ResponseHeader::decode(&malformed, 0xa5)
                .unwrap()
                .0
                .command
                .unwrap()
                .checksum_valid()
        );
        assert_eq!(ResponseHeader::decode(&hex("a50100ff"), 0xa5).unwrap().1, 4);
    }

    struct FixedPadding;
    impl RngCore for FixedPadding {
        fn next_u32(&mut self) -> u32 {
            0x5a5a5a5a
        }
        fn next_u64(&mut self) -> u64 {
            0x5a5a5a5a5a5a5a5a
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x5a);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    // Test-only marker; production uses OsRng.
    impl rand::CryptoRng for FixedPadding {}

    fn assert_body_fixture(security: Security, options: u8, keys: BodyKeys, fixture: &str) {
        let wire = hex(fixture);
        let mut encoder = BodyEncoder::new(security, options, keys.clone()).unwrap();
        assert_eq!(
            encoder
                .encode_frame_with_rng(b"VMess frame fixture", &mut FixedPadding)
                .unwrap(),
            wire
        );
        let mut decoder = BodyDecoder::new(security, options, keys).unwrap();
        for length in 0..wire.len() {
            assert_eq!(decoder.decode_frame(&wire[..length]).unwrap(), None);
        }
        let mut with_next_frame = wire.clone();
        with_next_frame.extend_from_slice(b"next frame");
        assert_eq!(
            decoder.decode_frame(&with_next_frame).unwrap(),
            Some((BodyFrame::Data(b"VMess frame fixture".to_vec()), wire.len()))
        );
    }

    #[test]
    fn aes_and_chacha_independent_body_and_eof_vectors() {
        let request = header();
        for (security, fixture, eof) in [
            (
                Security::Aes128Gcm,
                "00239d3ecdca9a91d60c2d796ea34c08deabb6e547c32f30ab50ab60e70e101e3bd0e16d2d",
                "001035c1d866430ee2a52d77f94eb568da9f",
            ),
            (
                Security::Chacha20Poly1305,
                "0023e9de6f49187ce5ca190d324d4f3b0d6ce5342ec0be19cb8f3dc8b79138fe1356882bbc",
                "0010864bcceef142cb6018451fb914f07b7a",
            ),
        ] {
            assert_body_fixture(security, 0, BodyKeys::request(&request), fixture);
            let mut encoder = BodyEncoder::new(security, 0, BodyKeys::request(&request)).unwrap();
            let mut decoder = BodyDecoder::new(security, 0, BodyKeys::request(&request)).unwrap();
            encoder.encode_frame(b"VMess frame fixture").unwrap();
            decoder.decode_frame(&hex(fixture)).unwrap();
            assert_eq!(encoder.encode_frame(&[]).unwrap(), hex(eof));
            assert_eq!(
                decoder.decode_frame(&hex(eof)).unwrap(),
                Some((BodyFrame::End, 18))
            );
            assert!(encoder.encode_frame(b"late").is_err());
            assert!(decoder.decode_frame(&hex(eof)).is_err());
        }
        assert_eq!(
            chacha20poly1305_key(&request.body_key).as_slice(),
            hex("1ac1ef01e96caf1be0d329331a4fc2a8e0542db5418c43d256a6a643afa553fe")
        );
        assert_eq!(
            chunk_nonce(&request.body_iv, 0x1234).as_slice(),
            hex("123412131415161718191a1b")
        );
    }

    #[test]
    fn shake_mask_and_padding_independent_vectors() {
        let request = header();
        assert_body_fixture(
            Security::Aes128Gcm,
            OPTION_CHUNK_MASKING,
            BodyKeys::request(&request),
            "fcb29d3ecdca9a91d60c2d796ea34c08deabb6e547c32f30ab50ab60e70e101e3bd0e16d2d",
        );
        assert_body_fixture(
            Security::Aes128Gcm,
            OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            BodyKeys::request(&request),
            "8e779d3ecdca9a91d60c2d796ea34c08deabb6e547c32f30ab50ab60e70e101e3bd0e16d2d5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        );
        let mut state = BodyState::new(
            Security::Aes128Gcm,
            OPTION_CHUNK_MASKING,
            BodyKeys::request(&request),
        )
        .unwrap();
        let expected = hex("fc918e43ecc4b6aea436a3be55984a75e0c01600dfda15041a69c312ea34160f");
        for pair in expected.chunks_exact(2) {
            assert_eq!(
                state.next_shake(),
                u16::from_be_bytes(pair.try_into().unwrap())
            );
        }
    }

    #[test]
    fn authenticated_lengths_in_both_directions_independent_vectors() {
        let request = header();
        assert_eq!(
            BodyKeys::request(&request).length_key.as_slice(),
            hex("1dccf11d87f6b6c6ffbaa5b90794383c")
        );
        let fixtures = [
            (
                false,
                Security::Aes128Gcm,
                false,
                "188a9c44a20acacf6381a008ef984b4ce6039d3ecdca9a91d60c2d796ea34c08deabb6e547c32f30ab50ab60e70e101e3bd0e16d2d",
            ),
            (
                false,
                Security::Chacha20Poly1305,
                false,
                "43d69511625b2d48f22e6f50c7cffbc2a0cce9de6f49187ce5ca190d324d4f3b0d6ce5342ec0be19cb8f3dc8b79138fe1356882bbc",
            ),
            (
                false,
                Security::Aes128Gcm,
                true,
                "18bd3860a348b068a1ca3a21c9723b696efc9d3ecdca9a91d60c2d796ea34c08deabb6e547c32f30ab50ab60e70e101e3bd0e16d2d5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            ),
            (
                false,
                Security::Chacha20Poly1305,
                true,
                "43e196d91de60eb28beb2b29b39c744fb5cce9de6f49187ce5ca190d324d4f3b0d6ce5342ec0be19cb8f3dc8b79138fe1356882bbc5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            ),
            (
                true,
                Security::Aes128Gcm,
                false,
                "188a9c44a20acacf6381a008ef984b4ce6035ccb4a5bb54851a87ec83483dfa4b763e665d0c87f2bb5ea75a94a412037b321c92560",
            ),
            (
                true,
                Security::Chacha20Poly1305,
                false,
                "43d69511625b2d48f22e6f50c7cffbc2a0ccd41947b6d39e964caea54142192b838760c888874a766b1ed42b803459237fd5431a28",
            ),
            (
                true,
                Security::Aes128Gcm,
                true,
                "18b63bf6f52d039887e86ed4b75548ff6ae55ccb4a5bb54851a87ec83483dfa4b763e665d0c87f2bb5ea75a94a412037b321c925605a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            ),
            (
                true,
                Security::Chacha20Poly1305,
                true,
                "43ea3c7db7b4dec237fa512074a1917c3a9ed41947b6d39e964caea54142192b838760c888874a766b1ed42b803459237fd5431a285a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            ),
        ];
        for (response, security, padding, fixture) in fixtures {
            let keys = if response {
                BodyKeys::response(&request)
            } else {
                BodyKeys::request(&request)
            };
            let options = OPTION_AUTHENTICATED_LENGTH
                | if padding {
                    OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING
                } else {
                    0
                };
            assert_body_fixture(security, options, keys, fixture);
        }
    }

    #[test]
    fn all_option_modes_keep_multiple_frame_state_and_stream_limits() {
        for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            for options in [0, 1, 4, 5, 12, 13, 16, 17, 20, 21, 28, 29] {
                for keys in [BodyKeys::request(&header()), BodyKeys::response(&header())] {
                    let mut encoder = BodyEncoder::new(security, options, keys.clone()).unwrap();
                    let mut decoder = BodyDecoder::new(security, options, keys).unwrap();
                    let limit = encoder.max_payload_length();
                    assert!(encoder.encode_frame(&vec![1; limit + 1]).is_err());
                    for payload in [
                        b"first".to_vec(),
                        vec![0xff; limit],
                        b"third".to_vec(),
                        Vec::new(),
                    ] {
                        let wire = encoder
                            .encode_frame_with_rng(&payload, &mut FixedPadding)
                            .unwrap();
                        assert!(wire.len() <= MAX_WRITE_FRAME);
                        for incomplete in [0, 1, wire.len() - 1] {
                            assert_eq!(decoder.decode_frame(&wire[..incomplete]).unwrap(), None);
                        }
                        let expected = if payload.is_empty() {
                            BodyFrame::End
                        } else {
                            BodyFrame::Data(payload)
                        };
                        assert_eq!(
                            decoder.decode_frame(&wire).unwrap(),
                            Some((expected, wire.len()))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn tampered_ciphertext_lengths_and_eof_are_rejected() {
        let request = header();
        for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            for options in [0, 12, 16, 28] {
                for payload in [b"secret".as_slice(), b""] {
                    let keys = BodyKeys::request(&request);
                    let mut encoder = BodyEncoder::new(security, options, keys.clone()).unwrap();
                    let wire = encoder
                        .encode_frame_with_rng(payload, &mut FixedPadding)
                        .unwrap();
                    let width = encoder.state.length_width();
                    for offset in [width, width + payload.len() + TAG_LENGTH - 1] {
                        let mut bad = wire.clone();
                        bad[offset] ^= 1;
                        let mut decoder =
                            BodyDecoder::new(security, options, keys.clone()).unwrap();
                        assert!(decoder.decode_frame(&bad).is_err());
                        assert!(decoder.decode_frame(&wire).is_err());
                    }
                    if options & OPTION_AUTHENTICATED_LENGTH != 0 {
                        let mut bad = wire;
                        bad[0] ^= 1;
                        assert!(
                            BodyDecoder::new(security, options, keys)
                                .unwrap()
                                .decode_frame(&bad)
                                .is_err()
                        );
                    }
                }
            }
        }
        for length in 0u16..16 {
            let mut decoder =
                BodyDecoder::new(Security::Aes128Gcm, 0, BodyKeys::request(&request)).unwrap();
            assert!(decoder.decode_frame(&length.to_be_bytes()).is_err());
        }
        assert!(
            BodyEncoder::new(
                Security::Aes128Gcm,
                OPTION_GLOBAL_PADDING,
                BodyKeys::request(&request)
            )
            .is_err()
        );
    }

    #[test]
    fn nonce_counter_never_wraps_and_stream_fragmentation_preserves_bytes() {
        let keys = BodyKeys::request(&header());
        let mut encoder = BodyEncoder::new(Security::Aes128Gcm, 0, keys.clone()).unwrap();
        let mut decoder = BodyDecoder::new(Security::Aes128Gcm, 0, keys.clone()).unwrap();
        let input = vec![0xa5; 20_000];
        let wire = encoder.encode_stream(&input).unwrap();
        let mut offset = 0;
        let mut output = Vec::new();
        while offset < wire.len() {
            let (frame, consumed) = decoder.decode_frame(&wire[offset..]).unwrap().unwrap();
            let BodyFrame::Data(data) = frame else {
                panic!("unexpected EOF");
            };
            output.extend(data);
            offset += consumed;
        }
        assert_eq!(output, input);
        assert!(encoder.encode_stream(&[]).unwrap().is_empty());
        encoder.state.counter = u16::MAX as u32;
        decoder.state.counter = u16::MAX as u32;
        let last = encoder.encode_frame(b"last nonce").unwrap();
        assert!(decoder.decode_frame(&last).unwrap().is_some());
        assert!(encoder.encode_frame(b"reused nonce").is_err());
        assert!(decoder.decode_frame(&last).is_err());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyFrame {
    Data(Vec<u8>),
    End,
}

/// Buffered decoder. `None` means incomplete input and consumes no cipher or
/// SHAKE state. After any malformed/authentication error, discard the decoder.
pub struct BodyDecoder {
    state: BodyState,
    failed: bool,
}

impl BodyDecoder {
    pub fn new(security: Security, options: u8, keys: BodyKeys) -> Result<Self> {
        Ok(Self {
            state: BodyState::new(security, options, keys)?,
            failed: false,
        })
    }
    pub fn decode_frame(&mut self, input: &[u8]) -> Result<Option<(BodyFrame, usize)>> {
        ensure!(!self.failed, "VMess body decoder failed previously");
        let result = self.decode_inner(input);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn decode_inner(&mut self, input: &[u8]) -> Result<Option<(BodyFrame, usize)>> {
        self.state.ensure_active()?;
        let width = self.state.length_width();
        if input.len() < width {
            return Ok(None);
        }
        let mut next = self.state.clone();
        let padding_length = next.padding_length();
        let length = next.decode_length(&input[..width])?;
        ensure!(
            length >= TAG_LENGTH + padding_length,
            "VMess frame is shorter than authentication tag and padding"
        );
        let consumed = width + length;
        if input.len() < consumed {
            return Ok(None);
        }
        // Unlike the Go reader's early EOF shortcut, authenticate and consume
        // the empty-body tag, so unauthenticated length bytes cannot close a stream.
        let plaintext = open(
            next.security,
            &next.keys.body_key,
            &chunk_nonce(&next.keys.body_iv, next.counter as u16),
            &input[width..consumed - padding_length],
        )?;
        next.counter += 1;
        next.finished = plaintext.is_empty();
        let frame = if next.finished {
            BodyFrame::End
        } else {
            BodyFrame::Data(plaintext)
        };
        self.state = next;
        Ok(Some((frame, consumed)))
    }
}
