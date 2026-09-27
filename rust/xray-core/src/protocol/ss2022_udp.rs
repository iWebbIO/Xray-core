// P06 ss2022_udp: multi-user Shadowsocks-2022 UDP (EIH) codec and relay pair.
#![allow(dead_code)]

//! Multi-user Shadowsocks-2022 UDP over the 2022 edition packet format.
//!
//! Ports the UDP paths of the Go references:
//! - `proxy/shadowsocks_2022/inbound_multi.go` (multi-user inbound: one server
//!   PSK plus per-user PSKs, 500-second UDP NAT timeout, user add/remove),
//! - the pinned `sing-shadowsocks v0.2.7/shadowaead_2022` package:
//!   `protocol.go` (`clientPacketConn.WritePacket/ReadPacket`, `udpSession`),
//!   `service.go` (`Service.newPacket`, `serverPacketWriter.WritePacket`,
//!   `serverUDPSession`), `service_multi.go` (`MultiService.newPacket`,
//!   `MultiService.newUDPSession`, `MultiService.UpdateUsers`).
//!
//! Request wire format (client -> multi-user server, AES methods):
//! `[16B header AES-ECB(iPSK): sessionId|packetId]`
//! `[16B EIH: AES-ECB(iPSK)(identityHash(uPSK) XOR header)]`
//! `[AEAD(sessionSubkey(uPSK, sessionId), nonce=header[4..16]):`
//! `  type=0 | timestamp | paddingLen | padding | SOCKS address | payload]`
//!
//! Reply wire format (server -> client, no EIH, entirely under the user PSK):
//! `[16B header AES-ECB(uPSK): serverSessionId|packetId]`
//! `[AEAD(sessionSubkey(uPSK, serverSessionId), nonce=header[4..16]):`
//! `  type=1 | timestamp | clientSessionId | paddingLen | padding | address | payload]`
//!
//! The body/session subkey and the identity hash use the same BLAKE3
//! derivations as `protocol::shadowsocks_udp::Cipher2022`; the sliding replay
//! window is reused from that module. This module adds extended identity
//! headers, multi-user selection, per-session replay windows, the server
//! session rotation rule, and a socket-free client/server relay pair. No
//! sockets are opened here: callers serialize access to one `UdpServer` per
//! listener, supply clocks and randomness, and route only admitted datagrams.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
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
use rand::{CryptoRng, Rng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    address::{Address, Destination},
    protocol::{
        shadowsocks::CipherKind,
        shadowsocks_udp::{MAX_CLOCK_SKEW, SlidingWindow},
        udp::Datagram,
    },
};

pub const HEADER_TYPE_CLIENT: u8 = 0;
pub const HEADER_TYPE_SERVER: u8 = 1;
pub const AES_BLOCK_SIZE: usize = 16;
pub const TAG_SIZE: usize = 16;
/// `shadowaead_2022.MaxPacketSize`.
pub const MAX_PACKET_SIZE: usize = 65_535;
/// `shadowaead_2022.MaxPaddingLength`.
pub const MAX_PADDING_LENGTH: usize = 900;
/// `shadowaead_2022.PacketMinimalHeaderSize`.
pub const PACKET_MINIMAL_HEADER_SIZE: usize = 30;
/// Inclusive timestamp window of the pinned implementation.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = MAX_CLOCK_SKEW;
/// `ErrTooManyServerSessions`: one remote-session change per minute.
pub const SERVER_SESSION_ROTATION_SECONDS: u64 = 60;
/// `inbound_multi.go` passes 500 seconds to `NewMultiService`.
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(500);
pub const DEFAULT_SESSION_CAPACITY: usize = 4096;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> io::Result<&'a [u8]> {
    if input.len() < len {
        return Err(invalid("truncated Shadowsocks 2022 UDP packet"));
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn read_u64(input: &mut &[u8]) -> io::Result<u64> {
    Ok(u64::from_be_bytes(take(input, 8)?.try_into().unwrap()))
}

/// The two methods `shadowaead_2022.NewMultiService` accepts. The XChaCha
/// single-key 2022 UDP method is implemented by `protocol::shadowsocks_udp`
/// and is rejected here by name, matching `NewMultiService`'s rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
}

impl Method {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
        }
    }

    fn cipher_kind(self) -> CipherKind {
        match self {
            Self::Aes128Gcm => CipherKind::Aes128Gcm,
            Self::Aes256Gcm => CipherKind::Aes256Gcm,
        }
    }
}

impl FromStr for Method {
    type Err = io::Error;
    fn from_str(name: &str) -> io::Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Err(invalid(
                "2022-blake3-chacha20-poly1305 is unsupported for multi-user \
                 Shadowsocks 2022 UDP; single-key XChaCha UDP is implemented by \
                 protocol::shadowsocks_udp",
            )),
            _ => Err(invalid("unknown Shadowsocks 2022 method")),
        }
    }
}

/// `shadowaead_2022.Key`: SHA256-truncate over-length PSKs, reject short ones.
fn normalize_key(method: Method, key: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    if key.len() < method.key_len() {
        return Err(invalid("Shadowsocks 2022 PSK is too short"));
    }
    if key.len() == method.key_len() {
        return Ok(Zeroizing::new(key.to_vec()));
    }
    Ok(Zeroizing::new(
        Sha256::digest(key)[..method.key_len()].to_vec(),
    ))
}

/// `blake3.Sum512(key)[0:16]`: the EIH user-identity fingerprint.
pub fn identity_hash(key: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 16];
    reader.fill(&mut out);
    out
}

/// `shadowaead_2022.SessionKey(psk, sessionIdBytes)`: the 2022 UDP session
/// subkey. Identical to `Cipher2022::session_key` for the same normalized key.
pub fn session_subkey(method: Method, key: &[u8], session_id: u64) -> Zeroizing<Vec<u8>> {
    let mut material = Zeroizing::new(key.to_vec());
    material.extend_from_slice(&session_id.to_be_bytes());
    let derived = blake3::derive_key("shadowsocks 2022 session subkey", &material);
    Zeroizing::new(derived[..method.key_len()].to_vec())
}

fn ecb_crypt(key: &[u8], block: &mut [u8; 16], encrypt: bool) -> io::Result<()> {
    if key.len() == 16 {
        let cipher = Aes128::new_from_slice(key).map_err(|_| invalid("invalid AES-128 PSK"))?;
        if encrypt {
            cipher.encrypt_block(block.into());
        } else {
            cipher.decrypt_block(block.into());
        }
    } else if key.len() == 32 {
        let cipher = Aes256::new_from_slice(key).map_err(|_| invalid("invalid AES-256 PSK"))?;
        if encrypt {
            cipher.encrypt_block(block.into());
        } else {
            cipher.decrypt_block(block.into());
        }
    } else {
        return Err(invalid(
            "Shadowsocks 2022 PSK length does not match the method",
        ));
    }
    Ok(())
}

fn aead_seal(kind: CipherKind, key: &[u8], nonce: &[u8; 12], plain: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = plain.to_vec();
    let result = match kind {
        CipherKind::Aes128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|_| invalid("invalid AES-128 PSK"))?;
            cipher.encrypt_in_place(nonce.into(), b"", &mut out)
        }
        CipherKind::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| invalid("invalid AES-256 PSK"))?;
            cipher.encrypt_in_place(nonce.into(), b"", &mut out)
        }
        CipherKind::ChaCha20Poly1305 => {
            return Err(invalid("XChaCha is not used by multi-user 2022 UDP"));
        }
    };
    if result.is_err() {
        out.zeroize();
        return Err(invalid("Shadowsocks 2022 UDP encryption failed"));
    }
    Ok(out)
}

fn aead_open(
    kind: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    wire: &[u8],
) -> io::Result<Zeroizing<Vec<u8>>> {
    if wire.len() < TAG_SIZE {
        return Err(invalid("truncated Shadowsocks 2022 UDP packet"));
    }
    let mut out = wire.to_vec();
    let result = match kind {
        CipherKind::Aes128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|_| invalid("invalid AES-128 PSK"))?;
            cipher.decrypt_in_place(nonce.into(), b"", &mut out)
        }
        CipherKind::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| invalid("invalid AES-256 PSK"))?;
            cipher.decrypt_in_place(nonce.into(), b"", &mut out)
        }
        CipherKind::ChaCha20Poly1305 => {
            return Err(invalid("XChaCha is not used by multi-user 2022 UDP"));
        }
    };
    if result.is_err() {
        out.zeroize();
        return Err(invalid("Shadowsocks 2022 UDP authentication failed"));
    }
    // decrypt_in_place consumes the tag and leaves exactly the plaintext.
    Ok(Zeroizing::new(out))
}

fn encode_address(destination: &Destination, out: &mut Vec<u8>) -> io::Result<()> {
    if destination.port == 0 {
        return Err(invalid("Shadowsocks 2022 UDP destination port is zero"));
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
                return Err(invalid("invalid Shadowsocks 2022 UDP domain length"));
            }
            out.extend_from_slice(&[3, name.len() as u8]);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn decode_address(input: &mut &[u8]) -> io::Result<Destination> {
    let family = take(input, 1)?[0];
    let address = match family {
        1 => Address::Ip(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(take(input, 4)?).unwrap(),
        ))),
        4 => Address::Ip(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(take(input, 16)?).unwrap(),
        ))),
        3 => {
            let len = usize::from(take(input, 1)?[0]);
            let name = std::str::from_utf8(take(input, len)?)
                .map_err(|_| invalid("Shadowsocks 2022 UDP domain is not UTF-8"))?;
            Address::parse(name).map_err(|e| invalid(e.to_string()))?
        }
        _ => return Err(invalid("unsupported Shadowsocks 2022 UDP address family")),
    };
    let port = u16::from_be_bytes(take(input, 2)?.try_into().unwrap());
    if port == 0 {
        return Err(invalid("Shadowsocks 2022 UDP destination port is zero"));
    }
    Ok(Destination { address, port })
}

/// `clientPacketConn.WritePacket/WriteTo`: padding is added only for DNS
/// (destination port 53) with payloads below the padding limit.
fn dns_padding<R: Rng + CryptoRng + ?Sized>(
    destination: &Destination,
    payload_len: usize,
    rng: &mut R,
) -> Vec<u8> {
    if destination.port != 53 || payload_len >= MAX_PADDING_LENGTH {
        return Vec::new();
    }
    let pad = rng.gen_range(1..=(MAX_PADDING_LENGTH - payload_len));
    let mut out = vec![0u8; pad];
    rng.fill_bytes(&mut out);
    out
}

fn parse_client_body(plain: &[u8], unix_now: u64) -> io::Result<(u64, Destination, Vec<u8>)> {
    let mut input = plain;
    let header_type = take(&mut input, 1)?[0];
    if header_type != HEADER_TYPE_CLIENT {
        return Err(invalid("bad Shadowsocks 2022 UDP header type"));
    }
    let timestamp = read_u64(&mut input)?;
    if timestamp.abs_diff(unix_now) > MAX_CLOCK_SKEW_SECONDS {
        return Err(invalid("bad Shadowsocks 2022 UDP timestamp"));
    }
    let padding_len = usize::from(u16::from_be_bytes(take(&mut input, 2)?.try_into().unwrap()));
    take(&mut input, padding_len)?;
    let destination = decode_address(&mut input)?;
    Ok((timestamp, destination, input.to_vec()))
}

fn parse_reply_body(plain: &[u8], unix_now: u64) -> io::Result<(u64, u64, Destination, Vec<u8>)> {
    let mut input = plain;
    let header_type = take(&mut input, 1)?[0];
    if header_type != HEADER_TYPE_SERVER {
        return Err(invalid("bad Shadowsocks 2022 UDP header type"));
    }
    let timestamp = read_u64(&mut input)?;
    if timestamp.abs_diff(unix_now) > MAX_CLOCK_SKEW_SECONDS {
        return Err(invalid("bad Shadowsocks 2022 UDP timestamp"));
    }
    let client_session_id = read_u64(&mut input)?;
    let padding_len = usize::from(u16::from_be_bytes(take(&mut input, 2)?.try_into().unwrap()));
    take(&mut input, padding_len)?;
    let destination = decode_address(&mut input)?;
    Ok((timestamp, client_session_id, destination, input.to_vec()))
}

/// Decrypted request identity: the packet header plus the EIH-selected user
/// fingerprint. `header` is the plaintext header; the body nonce is
/// `header[4..16]`.
pub struct RequestIdentity {
    pub session_id: u64,
    pub packet_id: u64,
    pub user_hash: [u8; 16],
    pub header: [u8; 16],
}

/// `MultiService.newPacket` through the user lookup: decrypt the header and
/// the single EIH block with the server PSK and recover the user fingerprint.
pub fn open_request_identity(server_key: &[u8], wire: &[u8]) -> io::Result<RequestIdentity> {
    if wire.len() < PACKET_MINIMAL_HEADER_SIZE {
        return Err(invalid("Shadowsocks 2022 UDP packet too short"));
    }
    if wire.len() < 2 * AES_BLOCK_SIZE + TAG_SIZE {
        return Err(invalid("truncated Shadowsocks 2022 UDP packet"));
    }
    let mut header: [u8; 16] = wire[..16].try_into().unwrap();
    ecb_crypt(server_key, &mut header, false)?;
    let mut eih: [u8; 16] = wire[16..32].try_into().unwrap();
    ecb_crypt(server_key, &mut eih, false)?;
    for (byte, mask) in eih.iter_mut().zip(header.iter()) {
        *byte ^= mask;
    }
    Ok(RequestIdentity {
        session_id: u64::from_be_bytes(header[..8].try_into().unwrap()),
        packet_id: u64::from_be_bytes(header[8..].try_into().unwrap()),
        user_hash: eih,
        header,
    })
}

/// AEAD-open the request body under a session-owner user PSK. Split from the
/// parse because the pinned server admits the replay window between the two.
pub fn open_request_ciphertext(
    method: Method,
    user_key: &[u8],
    session_id: u64,
    header: &[u8; 16],
    wire: &[u8],
) -> io::Result<Zeroizing<Vec<u8>>> {
    if wire.len() < 2 * AES_BLOCK_SIZE + TAG_SIZE {
        return Err(invalid("truncated Shadowsocks 2022 UDP packet"));
    }
    let nonce: [u8; 12] = header[4..].try_into().unwrap();
    let subkey = session_subkey(method, user_key, session_id);
    aead_open(
        method.cipher_kind(),
        &subkey,
        &nonce,
        &wire[2 * AES_BLOCK_SIZE..],
    )
}

/// `clientPacketConn.WritePacket`: seal a request for a PSK chain. The chain
/// is `[iPSK, uPSK]` for a multi-user client (one EIH block is emitted per
/// additional key, breaking at the second-to-last exactly like the Go loop);
/// a single-key chain emits no EIH block. The header is encrypted under the
/// first key, the body under a subkey of the last key.
#[allow(clippy::too_many_arguments)] // the 2022 UDP packet format carries each field separately
pub fn seal_request(
    method: Method,
    chain: &[&[u8]],
    session_id: u64,
    packet_id: u64,
    timestamp: u64,
    padding: &[u8],
    destination: &Destination,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if chain.is_empty() {
        return Err(invalid("missing Shadowsocks 2022 PSK"));
    }
    if padding.len() > MAX_PADDING_LENGTH {
        return Err(invalid("Shadowsocks 2022 UDP padding too long"));
    }
    let mut header = [0u8; AES_BLOCK_SIZE];
    header[..8].copy_from_slice(&session_id.to_be_bytes());
    header[8..].copy_from_slice(&packet_id.to_be_bytes());
    let nonce: [u8; 12] = header[4..].try_into().unwrap();

    let mut plain = Zeroizing::new(Vec::new());
    plain.push(HEADER_TYPE_CLIENT);
    plain.extend_from_slice(&timestamp.to_be_bytes());
    plain.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    plain.extend_from_slice(padding);
    encode_address(destination, &mut plain)?;
    let overhead = 2 * AES_BLOCK_SIZE + TAG_SIZE + AES_BLOCK_SIZE * (chain.len() - 1);
    let total = plain
        .len()
        .saturating_add(payload.len())
        .saturating_add(overhead);
    if total > MAX_PACKET_SIZE {
        return Err(invalid("Shadowsocks 2022 UDP packet too large"));
    }
    plain.extend_from_slice(payload);

    let subkey = session_subkey(method, chain[chain.len() - 1], session_id);
    let body = aead_seal(method.cipher_kind(), &subkey, &nonce, &plain)?;

    let mut wire = Vec::with_capacity(total);
    let mut wire_header = header;
    ecb_crypt(chain[0], &mut wire_header, true)?;
    wire.extend_from_slice(&wire_header);
    for index in 0..chain.len() - 1 {
        let mut block = identity_hash(chain[index + 1]);
        for (byte, mask) in block.iter_mut().zip(header.iter()) {
            *byte ^= mask;
        }
        ecb_crypt(chain[index], &mut block, true)?;
        wire.extend_from_slice(&block);
    }
    wire.extend_from_slice(&body);
    Ok(wire)
}

/// `serverPacketWriter.WritePacket`: seal a server reply under the user PSK.
/// Replies carry no EIH; the header is AES-ECB under the user PSK and the
/// body is AEAD under a subkey of the same PSK bound to the server session.
#[allow(clippy::too_many_arguments)] // the 2022 UDP packet format carries each field separately
pub fn seal_reply(
    method: Method,
    user_key: &[u8],
    server_session_id: u64,
    packet_id: u64,
    client_session_id: u64,
    timestamp: u64,
    padding: &[u8],
    origin: &Destination,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if padding.len() > MAX_PADDING_LENGTH {
        return Err(invalid("Shadowsocks 2022 UDP padding too long"));
    }
    let mut header = [0u8; AES_BLOCK_SIZE];
    header[..8].copy_from_slice(&server_session_id.to_be_bytes());
    header[8..].copy_from_slice(&packet_id.to_be_bytes());
    let nonce: [u8; 12] = header[4..].try_into().unwrap();

    let mut plain = Zeroizing::new(Vec::new());
    plain.push(HEADER_TYPE_SERVER);
    plain.extend_from_slice(&timestamp.to_be_bytes());
    plain.extend_from_slice(&client_session_id.to_be_bytes());
    plain.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    plain.extend_from_slice(padding);
    encode_address(origin, &mut plain)?;
    let overhead = AES_BLOCK_SIZE + TAG_SIZE;
    let total = plain
        .len()
        .saturating_add(payload.len())
        .saturating_add(overhead);
    if total > MAX_PACKET_SIZE {
        return Err(invalid("Shadowsocks 2022 UDP packet too large"));
    }
    plain.extend_from_slice(payload);

    let subkey = session_subkey(method, user_key, server_session_id);
    let body = aead_seal(method.cipher_kind(), &subkey, &nonce, &plain)?;
    let mut wire_header = header;
    ecb_crypt(user_key, &mut wire_header, true)?;
    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(&wire_header);
    wire.extend_from_slice(&body);
    Ok(wire)
}

/// A fully opened server reply (no replay/session state).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedReply {
    /// The server session that produced the reply.
    pub session_id: u64,
    pub packet_id: u64,
    pub timestamp: u64,
    pub client_session_id: u64,
    pub datagram: Datagram,
}

/// `clientPacketConn.ReadPacket` minus replay/session state: decrypt the
/// header with the last chain key, AEAD-open the body, and parse the fields.
pub fn open_reply(
    method: Method,
    user_key: &[u8],
    wire: &[u8],
    unix_now: u64,
) -> io::Result<DecodedReply> {
    if wire.len() < PACKET_MINIMAL_HEADER_SIZE {
        return Err(invalid("Shadowsocks 2022 UDP packet too short"));
    }
    let mut header: [u8; 16] = wire[..16].try_into().unwrap();
    ecb_crypt(user_key, &mut header, false)?;
    let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
    let packet_id = u64::from_be_bytes(header[8..].try_into().unwrap());
    let nonce: [u8; 12] = header[4..].try_into().unwrap();
    let subkey = session_subkey(method, user_key, session_id);
    let plain = aead_open(method.cipher_kind(), &subkey, &nonce, &wire[16..])?;
    let (timestamp, client_session_id, destination, payload) = parse_reply_body(&plain, unix_now)?;
    Ok(DecodedReply {
        session_id,
        packet_id,
        timestamp,
        client_session_id,
        datagram: Datagram {
            destination,
            payload,
        },
    })
}

/// A fully opened request (convenience for callers without session state).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRequest {
    pub session_id: u64,
    pub packet_id: u64,
    pub timestamp: u64,
    pub destination: Destination,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct UserKey {
    email: String,
    key: Zeroizing<Vec<u8>>,
    hash: [u8; 16],
}

/// `shadowaead_2022.MultiService` account state: one server PSK (the iPSK,
/// used for request headers and EIH blocks) and the per-user PSK table
/// selected by the EIH fingerprint.
#[derive(Clone)]
pub struct MultiUdpCodec {
    method: Method,
    server_key: Zeroizing<Vec<u8>>,
    users: Vec<UserKey>,
    by_hash: HashMap<[u8; 16], usize>,
}

impl MultiUdpCodec {
    pub fn new(method: Method, server_key: &[u8]) -> io::Result<Self> {
        Ok(Self {
            method,
            server_key: normalize_key(method, server_key)?,
            users: Vec::new(),
            by_hash: HashMap::new(),
        })
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn user_emails(&self) -> Vec<&str> {
        self.users.iter().map(|user| user.email.as_str()).collect()
    }

    /// `MultiService.UpdateUsers`: atomically replace the whole user table.
    /// Later entries with the same identity fingerprint win, like the Go map
    /// assignments. Existing relay sessions keep their own user PSK copies.
    pub fn update_users(&mut self, users: &[(String, Vec<u8>)]) -> io::Result<()> {
        let mut normalized = Vec::with_capacity(users.len());
        let mut by_hash = HashMap::with_capacity(users.len());
        for (email, key) in users {
            let key = normalize_key(self.method, key)?;
            let hash = identity_hash(&key);
            by_hash.insert(hash, normalized.len());
            normalized.push(UserKey {
                email: email.clone(),
                key,
                hash,
            });
        }
        self.users = normalized;
        self.by_hash = by_hash;
        Ok(())
    }

    /// EIH-selected request header: header, session/packet ids, user index.
    pub fn open_request_header(&self, wire: &[u8]) -> io::Result<RequestHeader> {
        let identity = open_request_identity(&self.server_key, wire)?;
        let user = self
            .by_hash
            .get(&identity.user_hash)
            .copied()
            .ok_or_else(|| {
                invalid("invalid request: Shadowsocks 2022 EIH does not match any user")
            })?;
        Ok(RequestHeader {
            session_id: identity.session_id,
            packet_id: identity.packet_id,
            user,
            header: identity.header,
        })
    }

    /// AEAD-open the request body under the given user's PSK.
    pub fn open_request_ciphertext(
        &self,
        user: usize,
        header: &RequestHeader,
        wire: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        let key = self
            .users
            .get(user)
            .ok_or_else(|| invalid("unknown Shadowsocks 2022 user"))?;
        open_request_ciphertext(
            self.method,
            &key.key,
            header.session_id,
            &header.header,
            wire,
        )
    }

    /// Full request decode; equivalent to the pinned Go flow when the EIH
    /// user also owns the target session.
    pub fn open_request(&self, wire: &[u8], unix_now: u64) -> io::Result<DecodedRequest> {
        let header = self.open_request_header(wire)?;
        let plain = self.open_request_ciphertext(header.user, &header, wire)?;
        let (timestamp, destination, payload) = parse_client_body(&plain, unix_now)?;
        Ok(DecodedRequest {
            session_id: header.session_id,
            packet_id: header.packet_id,
            timestamp,
            destination,
            payload,
        })
    }

    #[allow(clippy::too_many_arguments)] // the 2022 UDP packet format carries each field separately
    /// Seal a request as the given user against this server's PSK.
    pub fn seal_request(
        &self,
        user: usize,
        session_id: u64,
        packet_id: u64,
        timestamp: u64,
        padding: &[u8],
        destination: &Destination,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let key = self
            .users
            .get(user)
            .ok_or_else(|| invalid("unknown Shadowsocks 2022 user"))?;
        let chain = [self.server_key.as_slice(), key.key.as_slice()];
        seal_request(
            self.method,
            &chain,
            session_id,
            packet_id,
            timestamp,
            padding,
            destination,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)] // the 2022 UDP packet format carries each field separately
    /// Seal a server reply under the given user's PSK.
    pub fn seal_reply(
        &self,
        user: usize,
        server_session_id: u64,
        packet_id: u64,
        client_session_id: u64,
        timestamp: u64,
        padding: &[u8],
        origin: &Destination,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let key = self
            .users
            .get(user)
            .ok_or_else(|| invalid("unknown Shadowsocks 2022 user"))?;
        seal_reply(
            self.method,
            &key.key,
            server_session_id,
            packet_id,
            client_session_id,
            timestamp,
            padding,
            origin,
            payload,
        )
    }

    /// Open a server reply under the given user's PSK.
    pub fn open_reply(&self, user: usize, wire: &[u8], unix_now: u64) -> io::Result<DecodedReply> {
        let key = self
            .users
            .get(user)
            .ok_or_else(|| invalid("unknown Shadowsocks 2022 user"))?;
        open_reply(self.method, &key.key, wire, unix_now)
    }
}

/// EIH-selected request header bound to a server user table entry.
#[derive(Clone, Copy, Debug)]
pub struct RequestHeader {
    pub session_id: u64,
    pub packet_id: u64,
    pub user: usize,
    /// Plaintext packet header; the body nonce is `header[4..16]`.
    pub header: [u8; 16],
}

/// One remote (server) replay window tracked by a client session.
struct RemoteWindow {
    id: u64,
    window: SlidingWindow,
}

/// One local multi-user client session: `protocol.go udpSession` plus the
/// `clientPacketConn` chain keys. Requests are sealed with the full chain
/// (header under the first key, EIH per additional key, body under the last
/// key); replies are opened with the last key.
pub struct UdpClient {
    method: Method,
    keys: Vec<Zeroizing<Vec<u8>>>,
    session_id: u64,
    next_packet_id: u64,
    current_remote: Option<RemoteWindow>,
    previous_remote: Option<RemoteWindow>,
    last_previous_seen: Option<u64>,
}

impl UdpClient {
    /// `NewWithPassword`: colon-separated base64 PSK chain ("iPSK:uPSK").
    pub fn new<R: RngCore + CryptoRng + ?Sized>(
        method: Method,
        password: &str,
        rng: &mut R,
    ) -> io::Result<Self> {
        let mut session_id = [0u8; 8];
        rng.fill_bytes(&mut session_id);
        Self::with_session_id(method, password, u64::from_be_bytes(session_id))
    }

    /// For externally generated session ids and deterministic tests.
    pub fn with_session_id(method: Method, password: &str, session_id: u64) -> io::Result<Self> {
        Ok(Self {
            method,
            keys: parse_key_chain(method, password)?,
            session_id,
            next_packet_id: 0,
            current_remote: None,
            previous_remote: None,
            last_previous_seen: None,
        })
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// `clientPacketConn.WritePacket`: map one datagram to a request. The
    /// packet id starts at zero and never repeats.
    pub fn encode<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        destination: &Destination,
        payload: &[u8],
        unix_now: u64,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        let padding = dns_padding(destination, payload.len(), rng);
        let chain: Vec<&[u8]> = self.keys.iter().map(|key| key.as_slice()).collect();
        let packet_id = self.next_packet_id;
        self.next_packet_id = packet_id
            .checked_add(1)
            .ok_or_else(|| invalid("Shadowsocks 2022 UDP packet id exhausted"))?;
        seal_request(
            self.method,
            &chain,
            self.session_id,
            packet_id,
            unix_now,
            &padding,
            destination,
            payload,
        )
    }

    /// `clientPacketConn.ReadPacket`: authenticate one reply, enforce the
    /// per-remote-session replay windows, the one-change-per-minute server
    /// session rotation rule, and the client session binding, then return
    /// the origin address and payload. The pinned Go order is preserved:
    /// replay checks precede body decryption, and the window is admitted
    /// before the client session id is validated.
    pub fn decode_reply(&mut self, wire: &[u8], unix_now: u64) -> io::Result<Datagram> {
        if wire.len() < PACKET_MINIMAL_HEADER_SIZE {
            return Err(invalid("Shadowsocks 2022 UDP packet too short"));
        }
        let last = self
            .keys
            .last()
            .ok_or_else(|| invalid("missing Shadowsocks 2022 PSK"))?;
        let mut header: [u8; 16] = wire[..16].try_into().unwrap();
        ecb_crypt(last, &mut header, false)?;
        let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(header[8..].try_into().unwrap());
        let nonce: [u8; 12] = header[4..].try_into().unwrap();

        if let Some(current) = &self.current_remote
            && current.id == session_id
            && !current.window.check(packet_id)
        {
            return Err(invalid("Shadowsocks 2022 UDP packet id not unique"));
        }
        if let Some(previous) = &self.previous_remote
            && previous.id == session_id
            && !previous.window.check(packet_id)
        {
            return Err(invalid("Shadowsocks 2022 UDP packet id not unique"));
        }

        let subkey = session_subkey(self.method, last, session_id);
        let plain = aead_open(self.method.cipher_kind(), &subkey, &nonce, &wire[16..])?;

        let mut input: &[u8] = &plain;
        let header_type = take(&mut input, 1)?[0];
        if header_type != HEADER_TYPE_SERVER {
            return Err(invalid("bad Shadowsocks 2022 UDP header type"));
        }
        let timestamp = read_u64(&mut input)?;
        if timestamp.abs_diff(unix_now) > MAX_CLOCK_SKEW_SECONDS {
            return Err(invalid("bad Shadowsocks 2022 UDP timestamp"));
        }

        if let Some(current) = &mut self.current_remote
            && current.id == session_id
        {
            current.window.admit(packet_id);
        } else if let Some(previous) = &mut self.previous_remote
            && previous.id == session_id
        {
            previous.window.admit(packet_id);
            self.last_previous_seen = Some(unix_now);
        } else {
            if let Some(current) = self.current_remote.take() {
                if self.last_previous_seen.is_some_and(|seen| {
                    unix_now.saturating_sub(seen) < SERVER_SESSION_ROTATION_SECONDS
                }) {
                    return Err(invalid(
                        "Shadowsocks 2022 UDP server session changed more than once \
                         during the last minute",
                    ));
                }
                self.previous_remote = Some(current);
                self.last_previous_seen = Some(unix_now);
            }
            let mut window = SlidingWindow::default();
            window.admit(packet_id);
            self.current_remote = Some(RemoteWindow {
                id: session_id,
                window,
            });
        }

        let client_session_id = read_u64(&mut input)?;
        if client_session_id != self.session_id {
            return Err(invalid("bad Shadowsocks 2022 UDP client session id"));
        }
        let padding_len = usize::from(u16::from_be_bytes(take(&mut input, 2)?.try_into().unwrap()));
        take(&mut input, padding_len)?;
        let destination = decode_address(&mut input)?;
        Ok(Datagram {
            destination,
            payload: input.to_vec(),
        })
    }
}

fn parse_key_chain(method: Method, password: &str) -> io::Result<Vec<Zeroizing<Vec<u8>>>> {
    if password.is_empty() {
        return Err(invalid("missing Shadowsocks 2022 PSK"));
    }
    password
        .split(':')
        .map(|part| {
            let psk = STANDARD
                .decode(part)
                .map_err(|_| invalid("invalid base64 Shadowsocks 2022 PSK"))?;
            normalize_key(method, &psk)
        })
        .collect()
}

#[derive(Debug)]
struct SessionIdentity {
    client_session_id: u64,
}

/// Opaque capability to reply to one admitted session of one `UdpServer`.
/// Clones stay valid; expiry invalidates every clone, and a later session
/// reusing the same numeric id is a different identity.
#[derive(Clone, Debug)]
pub struct SessionToken {
    identity: Arc<SessionIdentity>,
}

impl SessionToken {
    pub fn session_id(&self) -> u64 {
        self.identity.client_session_id
    }
}

struct ServerSession {
    user_key: Zeroizing<Vec<u8>>,
    user_email: String,
    window: SlidingWindow,
    server_session_id: u64,
    next_reply_id: u64,
    last_seen: Instant,
    identity: Arc<SessionIdentity>,
}

/// A fully authenticated request plus the session needed to route replies.
#[derive(Clone, Debug)]
pub struct AcceptedPacket {
    pub session: SessionToken,
    pub user: String,
    pub session_id: u64,
    pub packet_id: u64,
    pub destination: Destination,
    pub payload: Vec<u8>,
}

/// `MultiService` UDP state: the multi-user codec plus the per-client-session
/// table of replay windows and reply sessions. Sessions are keyed by the
/// authenticated client session id, not by source address, so NAT rebinding
/// follows authentication like the pinned Go NAT map. One server belongs to
/// one listener; callers serialize mutations.
pub struct UdpServer {
    codec: MultiUdpCodec,
    sessions: HashMap<u64, ServerSession>,
    timeout: Duration,
    capacity: usize,
}

impl UdpServer {
    pub fn new(codec: MultiUdpCodec) -> Self {
        Self::with_limits(codec, DEFAULT_UDP_TIMEOUT, DEFAULT_SESSION_CAPACITY)
            .expect("default limits are valid")
    }

    /// Timeout must be at least 61 seconds to keep replay history throughout
    /// the inclusive +/-30-second timestamp window; capacity must be positive.
    /// Live sessions are never evicted to admit another session.
    pub fn with_limits(
        codec: MultiUdpCodec,
        timeout: Duration,
        capacity: usize,
    ) -> io::Result<Self> {
        if timeout < Duration::from_secs(61) {
            return Err(invalid(
                "Shadowsocks 2022 UDP session timeout must be at least 61 seconds",
            ));
        }
        if capacity == 0 {
            return Err(invalid(
                "Shadowsocks 2022 UDP session capacity must be positive",
            ));
        }
        Ok(Self {
            codec,
            sessions: HashMap::new(),
            timeout,
            capacity,
        })
    }

    pub fn from_config(config: &MultiUserUdpConfig) -> anyhow::Result<Self> {
        let method = config.method()?;
        let server_key = config.server_key()?;
        let mut codec = MultiUdpCodec::new(method, &server_key)?;
        codec.update_users(&config.user_keys()?)?;
        Ok(Self::new(codec))
    }

    pub fn user_count(&self) -> usize {
        self.codec.user_count()
    }

    pub fn user_emails(&self) -> Vec<&str> {
        self.codec.user_emails()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Update the user table (`MultiUserInbound.AddUser/RemoveUser` route
    /// through `MultiService.UpdateUsers`); existing sessions keep the PSK
    /// they were admitted with.
    pub fn update_users(&mut self, users: &[(String, Vec<u8>)]) -> io::Result<()> {
        self.codec.update_users(users)
    }

    pub fn expire(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.sessions.retain(|_, session| {
            now.checked_duration_since(session.last_seen)
                .is_none_or(|age| age < timeout)
        });
    }

    /// `MultiService.newPacket`: authenticate one request, select the user
    /// by EIH, enforce the per-session replay window, and admit/refresh the
    /// session. The pinned Go order is preserved: the window check precedes
    /// body decryption, the window is admitted after decryption but before
    /// the header type/timestamp/address parse, and a session whose first
    /// packet fails any check is removed instead of poisoning replay state.
    pub fn accept<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        wire: &[u8],
        unix_now: u64,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<AcceptedPacket> {
        self.expire(now);
        let header = self.codec.open_request_header(wire)?;
        let is_new = !self.sessions.contains_key(&header.session_id);
        if is_new {
            if self.sessions.len() >= self.capacity {
                return Err(invalid("Shadowsocks 2022 UDP session capacity exhausted"));
            }
            let user = self
                .codec
                .users
                .get(header.user)
                .ok_or_else(|| invalid("invalid request: unknown user"))?;
            let mut server_session_id = [0u8; 8];
            rng.fill_bytes(&mut server_session_id);
            self.sessions.insert(
                header.session_id,
                ServerSession {
                    user_key: user.key.clone(),
                    user_email: user.email.clone(),
                    window: SlidingWindow::default(),
                    server_session_id: u64::from_be_bytes(server_session_id),
                    next_reply_id: 0,
                    last_seen: now,
                    identity: Arc::new(SessionIdentity {
                        client_session_id: header.session_id,
                    }),
                },
            );
        }
        let result = self.accept_admitted(&header, wire, unix_now, now);
        if result.is_err() && is_new {
            self.sessions.remove(&header.session_id);
        }
        result
    }

    fn accept_admitted(
        &mut self,
        header: &RequestHeader,
        wire: &[u8],
        unix_now: u64,
        now: Instant,
    ) -> io::Result<AcceptedPacket> {
        let session = self
            .sessions
            .get_mut(&header.session_id)
            .expect("session was just inserted or already present");
        if !session.window.check(header.packet_id) {
            return Err(invalid("Shadowsocks 2022 UDP packet id not unique"));
        }
        let plain = open_request_ciphertext(
            self.codec.method,
            &session.user_key,
            header.session_id,
            &header.header,
            wire,
        )
        .map_err(|error| invalid(format!("decrypt packet: {error}")))?;
        session.window.admit(header.packet_id);
        let (_timestamp, destination, payload) = parse_client_body(&plain, unix_now)?;
        session.last_seen = now;
        Ok(AcceptedPacket {
            session: SessionToken {
                identity: Arc::clone(&session.identity),
            },
            user: session.user_email.clone(),
            session_id: header.session_id,
            packet_id: header.packet_id,
            destination,
            payload,
        })
    }

    /// `serverPacketWriter.WritePacket`: encode a reply whose address is the
    /// actual remote response origin. A token spans the session's
    /// destinations; the caller supplies the origin. Expired or foreign
    /// tokens fail closed.
    pub fn encode_reply<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        session: &SessionToken,
        origin: &Destination,
        payload: &[u8],
        unix_now: u64,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        self.expire(now);
        let entry = self
            .sessions
            .get_mut(&session.session_id())
            .filter(|entry| Arc::ptr_eq(&entry.identity, &session.identity))
            .ok_or_else(|| {
                invalid("unknown, expired, or foreign Shadowsocks 2022 UDP session token")
            })?;
        let padding = dns_padding(origin, payload.len(), rng);
        let packet_id = entry.next_reply_id;
        entry.next_reply_id = packet_id
            .checked_add(1)
            .ok_or_else(|| invalid("Shadowsocks 2022 UDP packet id exhausted"))?;
        let wire = seal_reply(
            self.codec.method,
            &entry.user_key,
            entry.server_session_id,
            packet_id,
            session.session_id(),
            unix_now,
            &padding,
            origin,
            payload,
        )?;
        entry.last_seen = now;
        Ok(wire)
    }
}

/// `proxy/shadowsocks_2022.MultiUserServerConfig` JSON (inbound settings of
/// `shadowsocks-2022-multi`), plus the per-user `RelayDestination`-style key
/// entries. Users are `{"key": base64, "email": string, "level": int}` or the
/// protobuf Any-wrapped `{"account": {"key": base64}}` form.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiUserUdpConfig {
    pub method: String,
    pub key: String,
    pub users: Vec<MultiUserUserConfig>,
    pub network: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiUserUserConfig {
    pub key: String,
    pub email: String,
    pub level: i32,
    pub account: Option<MultiUserAccountConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiUserAccountConfig {
    pub key: String,
}

impl MultiUserUdpConfig {
    pub fn from_value(value: &serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value.clone())?)
    }

    pub fn method(&self) -> anyhow::Result<Method> {
        Ok(Method::from_str(&self.method)?)
    }

    /// Empty network lists default to both networks, like the Go inbound;
    /// anything besides tcp/udp is rejected by name.
    pub fn networks(&self) -> anyhow::Result<Vec<&'static str>> {
        if self.network.is_empty() {
            return Ok(vec!["tcp", "udp"]);
        }
        self.network
            .iter()
            .map(|network| match network.as_str() {
                "tcp" => Ok("tcp"),
                "udp" => Ok("udp"),
                other => Err(anyhow::anyhow!(
                    "unsupported network {other:?} for shadowsocks-2022-multi inbound"
                )),
            })
            .collect()
    }

    pub fn server_key(&self) -> anyhow::Result<Vec<u8>> {
        Self::decode_key(&self.key, "server")
    }

    pub fn user_keys(&self) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let mut users = Vec::with_capacity(self.users.len());
        for (index, user) in self.users.iter().enumerate() {
            let key = if !user.key.is_empty() {
                &user.key
            } else if let Some(account) = &user.account {
                &account.key
            } else {
                anyhow::bail!("missing PSK for shadowsocks-2022-multi user {index}");
            };
            let email = if user.email.is_empty() {
                format!("unnamed-user-{index}")
            } else {
                user.email.clone()
            };
            users.push((email, Self::decode_key(key, "user")?));
        }
        Ok(users)
    }

    fn decode_key(value: &str, what: &'static str) -> anyhow::Result<Vec<u8>> {
        if value.is_empty() {
            anyhow::bail!("missing {what} PSK for shadowsocks-2022-multi");
        }
        let key = STANDARD
            .decode(value)
            .map_err(|error| anyhow::anyhow!("invalid base64 {what} PSK: {error}"))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::shadowsocks_udp::REPLAY_WINDOW_SIZE;
    use rand::{SeedableRng, rngs::StdRng};

    const UNIX_NOW: u64 = 1_700_000_000;
    const CLIENT_SESSION: u64 = 0x0102_0304_0506_0708;
    const SERVER_SESSION: u64 = 0x1112_1314_1516_1718;

    // Independently generated (Python AESGCM/PyCryptodome/BLAKE3) fixtures
    // reused from protocol::shadowsocks_udp's pinned known-answer tests.
    const REQUEST_128: &str = "12f250371f475aa71c3ab38e1308b5b8e33d719e15cf7e1746399d1d83807145a026233bfc9cccf925c70106bf1f7aa6920b99c49db6074e4c74";
    const REPLY_128: &str = "ce8b012cf8173186af83e7dab1f0d99ac447a48189229d20e446498e795cb088e861fac99ffe606aeb41b1411252d3a9dc27dbf641a66cb6344c518456b0a7c49ac8";
    const REQUEST_256: &str = "43af1bac10ead1bba3120598a2ea4edd06fab6b6129cc084c977125f89c6d5e32af6dc90cb1ea34dcb083f02efbc3540f64da752a6dcc52e1522";
    const REPLY_256: &str = "09a24bf73f92dc1a22496481611e7ace803efb5f3cce77d0cef7e7a6c4482690512902706d0c4def9c925edbb9ffd9195f755d53ebcb309cf0dc35ac46371803f409";
    const SUBKEY_128: &str = "b8473b44792f673ee36a405dfa755cc4";
    const SUBKEY_256: &str = "b8208bed66846bcbb2876c8c9db990da1da0a6c39bbeaf132686bbab1a5e1bb4";
    // EIH block known answers, independently generated with Python blake3
    // (Sum512, first 16 bytes) and AES-ECB, mirroring how the fixtures above
    // were produced: AES-ECB(K)(identityHash(K) XOR header) with both chain
    // keys equal to the fixture key.
    const EIH_128: &str = "efe2c2a0fba4415ee04b03d3cc0b5607";
    const EIH_256: &str = "d0d7733c49ec1ccbbb989f9a602aa66a";

    fn unhex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn target() -> Destination {
        Destination::new("8.8.8.8", 53).unwrap()
    }

    fn fixture_key(method: Method) -> Vec<u8> {
        (0..method.key_len() as u8).collect()
    }

    fn golden_codec(method: Method) -> MultiUdpCodec {
        let key = fixture_key(method);
        let mut codec = MultiUdpCodec::new(method, &key).unwrap();
        codec
            .update_users(&[("golden@example.org".to_owned(), key.clone())])
            .unwrap();
        codec
    }

    #[test]
    fn golden_request_and_reply_match_independent_fixtures() {
        let vectors = [
            (
                Method::Aes128Gcm,
                REQUEST_128,
                REPLY_128,
                SUBKEY_128,
                EIH_128,
            ),
            (
                Method::Aes256Gcm,
                REQUEST_256,
                REPLY_256,
                SUBKEY_256,
                EIH_256,
            ),
        ];
        for (method, request_hex, reply_hex, subkey_hex, eih_hex) in vectors {
            let codec = golden_codec(method);
            let key = fixture_key(method);

            // The request must be the independently pinned single-key packet
            // with exactly one EIH block inserted after the 16-byte header.
            let wire = codec
                .seal_request(
                    0,
                    CLIENT_SESSION,
                    7,
                    UNIX_NOW,
                    b"pad",
                    &target(),
                    b"\x12\x34dns",
                )
                .unwrap();
            let request = unhex(request_hex);
            assert_eq!(&wire[..16], &request[..16], "{method:?} header");
            assert_eq!(&wire[32..], &request[16..], "{method:?} body");
            assert_eq!(wire.len(), request.len() + AES_BLOCK_SIZE);
            assert_eq!(&wire[16..32], &unhex(eih_hex), "{method:?} EIH");

            let decoded = codec.open_request(&wire, UNIX_NOW).unwrap();
            assert_eq!(decoded.session_id, CLIENT_SESSION);
            assert_eq!(decoded.packet_id, 7);
            assert_eq!(decoded.timestamp, UNIX_NOW);
            assert_eq!(decoded.destination, target());
            assert_eq!(decoded.payload, b"\x12\x34dns".to_vec());

            // A reply has no EIH and is entirely under the user PSK, so it
            // must match the independent server-direction fixture exactly.
            let reply = codec
                .seal_reply(
                    0,
                    SERVER_SESSION,
                    9,
                    CLIENT_SESSION,
                    UNIX_NOW,
                    b"pad",
                    &target(),
                    b"\x12\x34dns",
                )
                .unwrap();
            assert_eq!(reply, unhex(reply_hex), "{method:?} reply");

            let opened = codec.open_reply(0, &reply, UNIX_NOW).unwrap();
            assert_eq!(opened.session_id, SERVER_SESSION);
            assert_eq!(opened.packet_id, 9);
            assert_eq!(opened.timestamp, UNIX_NOW);
            assert_eq!(opened.client_session_id, CLIENT_SESSION);
            assert_eq!(opened.datagram.destination, target());
            assert_eq!(opened.datagram.payload, b"\x12\x34dns".to_vec());

            // The session subkey matches the pinned BLAKE3 known answer.
            assert_eq!(
                &*session_subkey(method, &key, CLIENT_SESSION),
                &unhex(subkey_hex)
            );
        }
    }

    #[test]
    fn request_decode_rejects_short_corrupted_and_malformed_packets() {
        let method = Method::Aes128Gcm;
        let codec = golden_codec(method);
        let wire = codec
            .seal_request(0, CLIENT_SESSION, 0, UNIX_NOW, b"", &target(), b"query")
            .unwrap();

        for len in 0..wire.len() {
            assert!(codec.open_request(&wire[..len], UNIX_NOW).is_err(), "{len}");
        }
        for index in 0..wire.len() {
            let mut bad = wire.clone();
            bad[index] ^= 1;
            assert!(codec.open_request(&bad, UNIX_NOW).is_err(), "{index}");
        }

        // A multi-user request wire carries an EIH block between header and
        // body, so opening it as a reply (no EIH) pulls 16 foreign bytes into
        // the ciphertext and fails authentication before the direction byte.
        let error = codec
            .open_reply(0, &wire, UNIX_NOW)
            .expect_err("request is not a reply");
        assert!(error.to_string().contains("authentication"), "{error}");

        // The timestamp window is inclusive at +/-30 seconds.
        for timestamp in [UNIX_NOW - 30, UNIX_NOW + 30] {
            let ok = codec
                .seal_request(0, CLIENT_SESSION, 50, timestamp, b"", &target(), b"x")
                .unwrap();
            assert!(codec.open_request(&ok, UNIX_NOW).is_ok());
        }
        for timestamp in [UNIX_NOW - 31, UNIX_NOW + 31, u64::MAX] {
            let bad = codec
                .seal_request(0, CLIENT_SESSION, 51, timestamp, b"", &target(), b"x")
                .unwrap();
            assert!(codec.open_request(&bad, UNIX_NOW).is_err());
        }
    }

    #[test]
    fn per_session_replay_window_and_new_session_hygiene() {
        let method = Method::Aes128Gcm;
        let codec = golden_codec(method);
        let mut server = UdpServer::new(codec.clone());
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(1);

        let wire = |session_id: u64, packet_id: u64| {
            codec
                .seal_request(0, session_id, packet_id, UNIX_NOW, b"", &target(), b"q")
                .unwrap()
        };

        let accepted = server
            .accept(&wire(CLIENT_SESSION, 0), UNIX_NOW, now, &mut rng)
            .unwrap();
        assert_eq!(accepted.user, "golden@example.org");
        assert_eq!(accepted.session_id, CLIENT_SESSION);
        assert_eq!(server.session_count(), 1);

        // Duplicate and stale-below-window packet ids are rejected; ids
        // inside the window may arrive out of order.
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 0), UNIX_NOW, now, &mut rng)
                .is_err()
        );
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 3), UNIX_NOW, now, &mut rng)
                .is_ok()
        );
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 2), UNIX_NOW, now, &mut rng)
                .is_ok()
        );
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 3), UNIX_NOW, now, &mut rng)
                .is_err()
        );
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 0), UNIX_NOW, now, &mut rng)
                .is_err()
        );
        assert_eq!(server.session_count(), 1);
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 10_000), UNIX_NOW, now, &mut rng)
                .is_ok()
        );
        // 9900 below the newest packet id is outside the 8128 window.
        assert!(
            server
                .accept(&wire(CLIENT_SESSION, 100), UNIX_NOW, now, &mut rng)
                .is_err()
        );
        assert!(
            server
                .accept(
                    &wire(CLIENT_SESSION, 10_000 - REPLAY_WINDOW_SIZE - 1),
                    UNIX_NOW,
                    now,
                    &mut rng
                )
                .is_err()
        );
        assert_eq!(server.session_count(), 1);

        // A first packet of a new session that fails after the window admit
        // must remove the new session instead of poisoning its replay state.
        let second_session = 0x0a0b_0c0d_0e0f_1011;
        let mut corrupted = wire(second_session, 0);
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(server.accept(&corrupted, UNIX_NOW, now, &mut rng).is_err());
        assert_eq!(server.session_count(), 1, "failed new session removed");
        assert!(
            server
                .accept(&wire(second_session, 0), UNIX_NOW, now, &mut rng)
                .is_ok(),
            "fresh session admits the intact packet"
        );
        assert_eq!(server.session_count(), 2);

        // A failed body decryption of an existing session does not consume
        // the packet id (the pinned window.Add follows the AEAD open).
        let mut bad_body = wire(second_session, 1);
        *bad_body.last_mut().unwrap() ^= 1;
        assert!(server.accept(&bad_body, UNIX_NOW, now, &mut rng).is_err());
        assert!(
            server
                .accept(&wire(second_session, 1), UNIX_NOW, now, &mut rng)
                .is_ok()
        );

        // A malformed authenticated body (wrong direction byte) is rejected
        // only after the window admit, so the packet id is consumed.
        let key = fixture_key(method);
        let mut header = [0u8; AES_BLOCK_SIZE];
        header[..8].copy_from_slice(&second_session.to_be_bytes());
        header[8..].copy_from_slice(&2u64.to_be_bytes());
        let nonce: [u8; 12] = header[4..].try_into().unwrap();
        let mut plain = vec![HEADER_TYPE_SERVER];
        plain.extend_from_slice(&UNIX_NOW.to_be_bytes());
        plain.extend_from_slice(&[0, 0]);
        encode_address(&target(), &mut plain).unwrap();
        plain.extend_from_slice(b"q");
        let subkey = session_subkey(method, &key, second_session);
        let body = aead_seal(CipherKind::Aes128Gcm, &subkey, &nonce, &plain).unwrap();
        let mut eih = identity_hash(&key);
        for (byte, mask) in eih.iter_mut().zip(header.iter()) {
            *byte ^= mask;
        }
        ecb_crypt(&key, &mut eih, true).unwrap();
        let mut wire_header = header;
        ecb_crypt(&key, &mut wire_header, true).unwrap();
        let mut malformed = wire_header.to_vec();
        malformed.extend_from_slice(&eih);
        malformed.extend_from_slice(&body);
        let error = server
            .accept(&malformed, UNIX_NOW, now, &mut rng)
            .expect_err("wrong direction byte");
        assert!(error.to_string().contains("header type"), "{error}");
        assert!(
            server
                .accept(&wire(second_session, 2), UNIX_NOW, now, &mut rng)
                .is_err(),
            "packet id already consumed by the malformed parse failure"
        );
    }

    #[test]
    fn wrong_eih_and_wrong_user_are_rejected() {
        let method = Method::Aes128Gcm;
        let server_key: Vec<u8> = (0..16).collect();
        let user_a: Vec<u8> = (16..32).collect();
        let user_b: Vec<u8> = (32..48).collect();
        let mut codec = MultiUdpCodec::new(method, &server_key).unwrap();
        codec
            .update_users(&[("a@example.org".to_owned(), user_a.clone())])
            .unwrap();

        // A request for an unknown user (B) fails the EIH lookup.
        let chain_b = [server_key.as_slice(), user_b.as_slice()];
        let wire_b = seal_request(
            method,
            &chain_b,
            CLIENT_SESSION,
            0,
            UNIX_NOW,
            b"",
            &target(),
            b"q",
        )
        .unwrap();
        let error = codec
            .open_request(&wire_b, UNIX_NOW)
            .expect_err("user B is unknown");
        assert!(error.to_string().contains("EIH"), "{error}");

        // Flipping the EIH block corrupts the user fingerprint.
        let chain_a = [server_key.as_slice(), user_a.as_slice()];
        let wire_a = seal_request(
            method,
            &chain_a,
            CLIENT_SESSION,
            0,
            UNIX_NOW,
            b"",
            &target(),
            b"q",
        )
        .unwrap();
        let mut bad_eih = wire_a.clone();
        bad_eih[20] ^= 1;
        assert!(codec.open_request(&bad_eih, UNIX_NOW).is_err());
        // Flipping the encrypted header corrupts both ids and the EIH XOR.
        let mut bad_header = wire_a.clone();
        bad_header[0] ^= 1;
        assert!(codec.open_request(&bad_header, UNIX_NOW).is_err());
        // Flipping the body fails authentication.
        let mut bad_body = wire_a.clone();
        *bad_body.last_mut().unwrap() ^= 1;
        assert!(codec.open_request(&bad_body, UNIX_NOW).is_err());

        // After adding user B, the same wire is admitted and selects B.
        codec
            .update_users(&[
                ("a@example.org".to_owned(), user_a.clone()),
                ("b@example.org".to_owned(), user_b.clone()),
            ])
            .unwrap();
        let decoded = codec.open_request(&wire_b, UNIX_NOW).unwrap();
        assert_eq!(decoded.session_id, CLIENT_SESSION);
    }

    #[test]
    fn full_in_memory_relay_echo_with_two_users() {
        let method = Method::Aes128Gcm;
        let server_key: Vec<u8> = (0..16).collect();
        let user_a: Vec<u8> = (16..32).collect();
        let user_b: Vec<u8> = (32..48).collect();
        let mut codec = MultiUdpCodec::new(method, &server_key).unwrap();
        codec
            .update_users(&[
                ("a@example.org".to_owned(), user_a.clone()),
                ("b@example.org".to_owned(), user_b.clone()),
            ])
            .unwrap();
        let mut server = UdpServer::new(codec.clone());
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(7);

        let password =
            |user: &[u8]| format!("{}:{}", STANDARD.encode(&server_key), STANDARD.encode(user));
        let mut client_a =
            UdpClient::with_session_id(method, &password(&user_a), 0xaaaa_bbbb_cccc_0001).unwrap();
        let mut client_b =
            UdpClient::with_session_id(method, &password(&user_b), 0xbbbb_cccc_dddd_0002).unwrap();

        let cases: [(&str, u16, &[u8], &str, bool); 3] = [
            ("echo.example", 443, b"ping", "a@example.org", false),
            ("dns.example", 53, b"query", "a@example.org", false),
            ("b.example", 8443, b"pong", "b@example.org", true),
        ];
        for (host, port, payload, email, is_user_b) in cases {
            let client = if is_user_b {
                &mut client_b
            } else {
                &mut client_a
            };
            let destination = Destination::new(host, port).unwrap();
            let wire = client
                .encode(&destination, payload, UNIX_NOW, &mut rng)
                .unwrap();
            let accepted = server.accept(&wire, UNIX_NOW, now, &mut rng).unwrap();
            assert_eq!(accepted.user, email);
            assert_eq!(accepted.destination, destination);
            assert_eq!(accepted.payload, payload.to_vec());
            assert_eq!(accepted.session_id, client.session_id());
            assert_eq!(server.user_count(), 2);

            let reply = server
                .encode_reply(
                    &accepted.session,
                    &destination,
                    payload,
                    UNIX_NOW,
                    now,
                    &mut rng,
                )
                .unwrap();
            let datagram = client.decode_reply(&reply, UNIX_NOW).unwrap();
            assert_eq!(datagram.destination, destination);
            assert_eq!(datagram.payload, payload.to_vec());
        }
        // Distinct client sessions produced distinct server reply sessions.
        assert_eq!(server.session_count(), 2);

        // A session's first request and first reply use packet id zero, like
        // the pinned udpSession counters, and subsequent packets count up.
        let mut client_c =
            UdpClient::with_session_id(method, &password(&user_a), 0xcccc_0000_0000_0003).unwrap();
        let destination = Destination::new("echo.example", 443).unwrap();
        let wire = client_c
            .encode(&destination, b"first", UNIX_NOW, &mut rng)
            .unwrap();
        let accepted = server.accept(&wire, UNIX_NOW, now, &mut rng).unwrap();
        assert_eq!(accepted.packet_id, 0);
        let reply = server
            .encode_reply(
                &accepted.session,
                &destination,
                b"first",
                UNIX_NOW,
                now,
                &mut rng,
            )
            .unwrap();
        let opened = codec
            .open_reply(0, &reply, UNIX_NOW)
            .expect("reply is sealed under user A's key");
        assert_eq!(opened.packet_id, 0);

        // Replayed replies are rejected by the client replay window.
        let wire = client_a
            .encode(&destination, b"again", UNIX_NOW, &mut rng)
            .unwrap();
        let accepted = server.accept(&wire, UNIX_NOW, now, &mut rng).unwrap();
        assert_eq!(accepted.packet_id, 2, "client A already sent two packets");
        let reply = server
            .encode_reply(
                &accepted.session,
                &destination,
                b"again",
                UNIX_NOW,
                now,
                &mut rng,
            )
            .unwrap();
        let opened = codec.open_reply(0, &reply, UNIX_NOW).unwrap();
        assert_eq!(opened.packet_id, 2, "the session already replied twice");
        assert!(client_a.decode_reply(&reply, UNIX_NOW).is_ok());
        assert!(client_a.decode_reply(&reply, UNIX_NOW).is_err());

        // A reply for another client session is rejected, and the pinned
        // Go ordering admits the packet id before that check, so a corrected
        // retry of the same packet id is then refused as a replay.
        let forged_session = 0x5555_0000_0000_0001;
        let forged = seal_reply(
            method,
            &user_a,
            forged_session,
            0,
            0xdead_beef_dead_beef,
            UNIX_NOW,
            b"",
            &destination,
            b"x",
        )
        .unwrap();
        let error = client_a
            .decode_reply(&forged, UNIX_NOW)
            .expect_err("reply is for another client session");
        assert!(error.to_string().contains("client session id"), "{error}");
        let corrected = seal_reply(
            method,
            &user_a,
            forged_session,
            0,
            client_a.session_id(),
            UNIX_NOW,
            b"",
            &destination,
            b"x",
        )
        .unwrap();
        let error = client_a
            .decode_reply(&corrected, UNIX_NOW)
            .expect_err("packet id was admitted before the session check");
        assert!(error.to_string().contains("not unique"), "{error}");

        // A second server-session change within a minute of the previous
        // rotation is ErrTooManyServerSessions.
        let second_change = seal_reply(
            method,
            &user_a,
            0x6666_0000_0000_0002,
            0,
            client_a.session_id(),
            UNIX_NOW,
            b"",
            &destination,
            b"x",
        )
        .unwrap();
        let error = client_a
            .decode_reply(&second_change, UNIX_NOW)
            .expect_err("server session changed twice within a minute");
        assert!(error.to_string().contains("more than once"), "{error}");

        // After a minute of quiet the same rotation is allowed.
        let later = UNIX_NOW + 600;
        let rotated = seal_reply(
            method,
            &user_a,
            0x6666_0000_0000_0002,
            1,
            client_a.session_id(),
            later,
            b"",
            &destination,
            b"x",
        )
        .unwrap();
        assert!(client_a.decode_reply(&rotated, later).is_ok());
    }

    #[test]
    fn go_defaults_and_multi_user_config_parsing() {
        assert_eq!(DEFAULT_UDP_TIMEOUT, Duration::from_secs(500));
        assert_eq!(MAX_PADDING_LENGTH, 900);
        assert_eq!(MAX_CLOCK_SKEW_SECONDS, 30);
        assert_eq!(REPLAY_WINDOW_SIZE, 8128);
        assert_eq!(PACKET_MINIMAL_HEADER_SIZE, 30);
        assert_eq!(Method::Aes128Gcm.key_len(), 16);
        assert_eq!(Method::Aes256Gcm.key_len(), 32);
        assert_eq!(Method::Aes128Gcm.name(), "2022-blake3-aes-128-gcm");

        let server_key: Vec<u8> = (0..16).collect();
        let user_a: Vec<u8> = (16..32).collect();
        let user_b: Vec<u8> = (32..48).collect();
        let json = serde_json::json!({
            "method": "2022-blake3-aes-128-gcm",
            "key": STANDARD.encode(&server_key),
            "users": [
                {"key": STANDARD.encode(&user_a), "email": "a@example.org", "level": 3},
                {"account": {"key": STANDARD.encode(&user_b)}}
            ],
            "network": ["udp"]
        });
        let config = MultiUserUdpConfig::from_value(&json).unwrap();
        assert_eq!(config.networks().unwrap(), vec!["udp"]);
        let server = UdpServer::from_config(&config).unwrap();
        assert_eq!(
            server.user_emails(),
            vec!["a@example.org", "unnamed-user-1"]
        );

        // A long user PSK is SHA256-truncated like the pinned constructor and
        // the relay still round-trips for that user.
        let long_key: Vec<u8> = (0..48).collect();
        let mut codec = MultiUdpCodec::new(Method::Aes128Gcm, &server_key).unwrap();
        codec
            .update_users(&[
                ("a@example.org".to_owned(), user_a.clone()),
                ("long@example.org".to_owned(), long_key.clone()),
            ])
            .unwrap();
        let mut server = UdpServer::new(codec);
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(3);
        let password = format!(
            "{}:{}",
            STANDARD.encode(&server_key),
            STANDARD.encode(&long_key)
        );
        let mut client =
            UdpClient::with_session_id(Method::Aes128Gcm, &password, 0x1234_5678_9abc_def0)
                .unwrap();
        let destination = Destination::new("config.example", 443).unwrap();
        let wire = client
            .encode(&destination, b"config", UNIX_NOW, &mut rng)
            .unwrap();
        let accepted = server.accept(&wire, UNIX_NOW, now, &mut rng).unwrap();
        assert_eq!(accepted.user, "long@example.org");
        let reply = server
            .encode_reply(
                &accepted.session,
                &destination,
                b"config",
                UNIX_NOW,
                now,
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            client.decode_reply(&reply, UNIX_NOW).unwrap().payload,
            b"config".to_vec()
        );

        // Rejections.
        assert!(
            MultiUserUdpConfig::from_value(&serde_json::json!({
                "method": "2022-blake3-aes-128-gcm", "key": STANDARD.encode(&server_key), "extra": 1
            }))
            .is_err()
        );
        let chacha = MultiUserUdpConfig::from_value(&serde_json::json!({
            "method": "2022-blake3-chacha20-poly1305",
            "key": STANDARD.encode(&server_key)
        }))
        .unwrap();
        let error = chacha.method().unwrap_err().to_string();
        assert!(error.contains("chacha20-poly1305"), "{error}");
        let missing_key = MultiUserUdpConfig::from_value(&serde_json::json!({
            "method": "2022-blake3-aes-128-gcm"
        }))
        .unwrap();
        assert!(missing_key.server_key().is_err());
        let bad_base64 = MultiUserUdpConfig::from_value(&serde_json::json!({
            "method": "2022-blake3-aes-128-gcm",
            "key": "not base64!",
            "users": [{"key": "also not base64!"}]
        }))
        .unwrap();
        assert!(bad_base64.server_key().is_err());
        assert!(bad_base64.user_keys().is_err());
        let short_psk = MultiUserUdpConfig::from_value(&serde_json::json!({
            "method": "2022-blake3-aes-128-gcm",
            "key": STANDARD.encode(&server_key),
            "users": [{"key": STANDARD.encode([1u8, 2, 3])}]
        }))
        .unwrap();
        assert!(UdpServer::from_config(&short_psk).is_err());
        let bad_network = MultiUserUdpConfig::from_value(&serde_json::json!({
            "method": "2022-blake3-aes-128-gcm",
            "key": STANDARD.encode(&server_key),
            "network": ["grpc"]
        }))
        .unwrap();
        assert!(bad_network.networks().is_err());

        // Client password parsing.
        assert!(UdpClient::with_session_id(Method::Aes128Gcm, "", 1).is_err());
        assert!(UdpClient::with_session_id(Method::Aes128Gcm, "!!!", 1).is_err());
        assert!(
            UdpClient::with_session_id(
                Method::Aes128Gcm,
                &format!("{}:!", STANDARD.encode(&server_key)),
                1
            )
            .is_err()
        );
        assert!(Method::from_str("2022-blake3-chacha20-poly1305").is_err());
        assert!(Method::from_str("aes-256-gcm").is_err());

        // Server limit validation.
        let codec = MultiUdpCodec::new(Method::Aes128Gcm, &server_key).unwrap();
        assert!(UdpServer::with_limits(codec.clone(), Duration::from_secs(60), 1).is_err());
        assert!(UdpServer::with_limits(codec, Duration::from_secs(61), 0).is_err());
    }
}
