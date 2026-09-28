// P14 sniffing: connection sniffers (http/tls/quic) and the dispatcher
// sniff pipeline, ported from Go's app/dispatcher/sniffer.go, the sniffer
// loop of app/dispatcher/default.go and common/protocol/{http,tls,quic}/sniff.go.
#![allow(dead_code)]
//! Connection sniffing for inbound traffic: the port of Go's dispatcher
//! sniff pipeline (`app/dispatcher/sniffer.go` plus the `sniffer()` loop in
//! `app/dispatcher/default.go`) and the protocol sniffers of
//! `common/protocol/{http,tls,quic}/sniff.go`.
//!
//! # Runtime contract (the wiring is owned by `runtime.rs`)
//!
//! * **Where**: after the inbound proxy handshake produced
//!   `protocol::Request` and before routing (in `dispatch_common`, at the
//!   `router.select_with_route` call). Compile each inbound's sniffing
//!   settings once at startup:
//!   `SniffingRequest::compile(raw.sniffing.as_ref(), &store)` — the raw
//!   [`SniffingConfig`](crate::config::SniffingConfig) already rides the
//!   compiled inbound tuple (`ValidatedConfig::inbounds` carries the whole
//!   `InboundConfig`, whose `sniffing` field is the parsed object;
//!   `config.rs` validates it eagerly so `xray run --test` fails on bad
//!   sniffing objects). `compile` returns `None` when sniffing is absent or
//!   disabled — skip sniffing entirely in that case.
//! * **Bytes**: wrap the stream before routing:
//!   `let (stream, result) = sniffing::sniff(stream, Network::Tcp,
//!   request.metadata_only(), SniffLimits::default()).await`. The returned
//!   [`SniffedStream`] REPLAYS every byte read during sniffing (Go's
//!   `cachedReader`), so the relay loses nothing — hand the wrapper to the
//!   relay in place of the original stream. For UDP, run the same call with
//!   [`Network::Udp`] over the first datagram(s) of the session.
//! * **destOverride**: with a result present, decide via
//!   `request.destination_override(&result, &request.destination)`:
//!   `Some(Override { domain, route_only })`. Without `routeOnly` the
//!   destination address is replaced with the sniffed domain before routing
//!   AND dialing (Go `ob.Target = destination`); with `routeOnly` the
//!   ROUTER sees the sniffed domain while the outbound keeps the original
//!   target (Go `ob.RouteTarget = destination`). The fakedns arms of Go's
//!   `shouldOverride`/`Dispatch` are not ported (fakedns is rejected at
//!   config parse), so `route_only` is always honored.
//! * **Routing**: the sniffed protocol (`result.protocol` — `"http1"`,
//!   `"tls"` or `"quic"`) reaches the router through
//!   `Router::select_with_route_sniffed(&ctx, Some(result.protocol))`
//!   (router.rs). Routing rules with a `protocol` condition match by Go's
//!   `ProtocolMatcher` prefix semantics — a `"http"` rule matches a
//!   sniffed `"http1"`. Passing `None` keeps the pre-sniffing behavior
//!   (protocol rules never match), so the mux/reverse/UDP sites that do
//!   not sniff stay unchanged.
//! * **Unported, rejected explicitly**: `fakedns`/`fakedns+others` in
//!   `destOverride` fails config validation; the bittorrent/UTP sniffers
//!   and the HTTP header attribute collection (Go's `attrs` rule matching)
//!   are not ported — `"bittorrent"` is accepted as a routing-rule protocol
//!   but nothing sniffs it yet.
//!
//! Go's dispatcher constants are preserved: the payload peek is capped at
//! 32767 bytes, the whole sniff waits at most 200 ms, and inconclusive
//! payloads give up after 2 attempts (errSniffingTimeout ⇒ no result, the
//! connection relays with its original destination).

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
    aes::{Aes128, cipher::BlockEncrypt},
};
use anyhow::{Result, bail};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    address::{Address, Destination},
    config::SniffingConfig,
    geodata::{DomainMatcher, GeoDataStore, IpMatcher, domain},
};

/// The sniffed network, selecting the sniffer set like Go's `net.Network`
/// filter in `NewSniffer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// One successfully sniffed connection (Go's `SniffResult`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniffResult {
    /// Go `SniffResult.Protocol()`: `"http1"` for HTTP (Go's sniffer never
    /// reports `"http2"`), `"tls"` or `"quic"`.
    pub protocol: &'static str,
    /// Go `SniffResult.Domain()`.
    pub domain: String,
}

/// One sniffer's verdict over the current payload, collapsing Go's
/// `(SniffResult, error)` pairs: `Matched` (a result), `NoClue`
/// (`common.ErrNoClue` — inconclusive, retry with more bytes), `NeedMoreData`
/// (`protocol.ErrProtoNeedMoreData` — protocol identified, payload
/// truncated) and `Rejected` (every definitive error: errNotTLS, errNotQUIC,
/// ... — the sniffer is dropped).
#[derive(Debug)]
pub enum Outcome {
    Matched(SniffResult),
    NoClue,
    NeedMoreData,
    Rejected,
}

// ---------------------------------------------------------------------------
// HTTP sniffer — Go common/protocol/http/sniff.go
// ---------------------------------------------------------------------------

const HTTP_METHODS: [&str; 7] = ["get", "post", "head", "put", "delete", "options", "connect"];

/// Go `SniffHTTP` (Go's attribute collection for `attrs` routing rules is not
/// ported — only the domain is sniffed).
pub fn sniff_http(b: &[u8]) -> Outcome {
    // beginWithHTTPMethod: any prefix shorter than the current method is
    // ErrNoClue; a payload that matches no method at all is definitive.
    for method in HTTP_METHODS {
        if b.len() >= method.len() {
            if b[..method.len()].eq_ignore_ascii_case(method.as_bytes()) {
                return sniff_http_headers(b);
            }
        } else {
            return Outcome::NoClue;
        }
    }
    Outcome::Rejected
}

/// The header half of Go `SniffHTTP`: extract the Host header through
/// `ParseHost` (the port is validated but never part of the sniffed domain).
fn sniff_http_headers(b: &[u8]) -> Outcome {
    let mut host: Option<String> = None;
    // bytes.Split(b, '\n'): headers[0] is the request line.
    for header in b.split(|&byte| byte == b'\n').skip(1) {
        if header.is_empty() {
            break;
        }
        // Go's bytes.SplitN(header, ':', 2): split at the first colon.
        let Some(colon) = header.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let (key, value) = (&header[..colon], &header[colon + 1..]);
        let key = String::from_utf8_lossy(key).to_ascii_lowercase();
        if key != "host" {
            continue;
        }
        // Go overwrites sh.host on every Host header — the last one wins.
        let raw_host = String::from_utf8_lossy(value).trim().to_ascii_lowercase();
        match parse_host(&raw_host) {
            Ok(domain) => host = Some(domain),
            Err(()) => return Outcome::Rejected,
        }
    }
    match host {
        Some(domain) if !domain.is_empty() => Outcome::Matched(SniffResult {
            protocol: "http1",
            domain,
        }),
        _ => Outcome::NoClue,
    }
}

/// Go `net.SplitHostPort` error kinds, reduced to the taxonomy `ParseHost`
/// relies on ("missing port" is tolerated, every other error drops the
/// sniffer).
enum HostPortError {
    MissingPort,
    Other,
}

/// Port of Go's `net.SplitHostPort`.
fn split_host_port(host_port: &str) -> std::result::Result<(&str, &str), HostPortError> {
    let bytes = host_port.as_bytes();
    let Some(colon) = bytes.iter().rposition(|&byte| byte == b':') else {
        return Err(HostPortError::MissingPort);
    };
    let (host_start, host_end, scan_start) = if bytes[0] == b'[' {
        let Some(end) = bytes.iter().position(|&byte| byte == b']') else {
            return Err(HostPortError::Other); // "missing ']' in address"
        };
        match end + 1 {
            end_next if end_next == bytes.len() => {
                // ']' at the end: there cannot be a port behind it.
                return Err(HostPortError::MissingPort);
            }
            end_next if end_next == colon => (1, end, end + 1),
            end_next => {
                if bytes[end_next] == b':' {
                    return Err(HostPortError::Other); // "too many colons"
                }
                return Err(HostPortError::MissingPort);
            }
        }
    } else {
        let host = &host_port[..colon];
        if host.as_bytes().contains(&b':') {
            return Err(HostPortError::Other); // "too many colons" (bare IPv6)
        }
        (0, colon, 0)
    };
    if bytes[host_start..].contains(&b'[') {
        return Err(HostPortError::Other); // "unexpected '[' in address"
    }
    if bytes[scan_start..].contains(&b']') {
        return Err(HostPortError::Other); // "unexpected ']' in address"
    }
    Ok((&host_port[host_start..host_end], &host_port[colon + 1..]))
}

/// Go `common/protocol/http.ParseHost(rawHost, 80)`, reduced to the address
/// string (the port is validated then discarded).
fn parse_host(raw_host: &str) -> std::result::Result<String, ()> {
    let (host, port) = match split_host_port(raw_host) {
        Ok((host, port)) => (host, port),
        // "missing port": the whole value is the host.
        Err(HostPortError::MissingPort) => (raw_host, ""),
        Err(HostPortError::Other) => return Err(()),
    };
    if !port.is_empty() {
        // strconv.Atoi: any signed 64-bit number; the value is discarded.
        port.parse::<i64>().map_err(|_| ())?;
    }
    Ok(address_string(host))
}

/// Go `net.ParseAddress(host).String()`: IP literals canonicalize (a
/// v4-mapped IPv6 prints as IPv4, like Go's `net.IP.String`); anything else
/// stays a domain string.
fn address_string(host: &str) -> String {
    match host.parse() {
        Ok(std::net::IpAddr::V4(address)) => address.to_string(),
        Ok(std::net::IpAddr::V6(address)) => match address.to_ipv4_mapped() {
            Some(address) => address.to_string(),
            None => address.to_string(),
        },
        Err(_) => host.to_string(),
    }
}

// ---------------------------------------------------------------------------
// TLS sniffer — Go common/protocol/tls/sniff.go
// ---------------------------------------------------------------------------

/// Go `SniffTLS` + `ReadClientHello`: the SNI (server_name) of the client
/// hello. Note Go's sniffer extracts only the SNI, never the ALPN.
pub fn sniff_tls(b: &[u8]) -> Outcome {
    if b.len() < 5 {
        return Outcome::NoClue;
    }
    if b[0] != 0x16 {
        return Outcome::Rejected; // errNotTLS: not a handshake
    }
    if b[1] != 0x03 {
        return Outcome::Rejected; // IsValidTLSVersion: major must be 3
    }
    let header_len = u16::from_be_bytes([b[3], b[4]]) as usize;
    if 5 + header_len > b.len() {
        return Outcome::NoClue;
    }
    match read_client_hello(&b[5..5 + header_len]) {
        ClientHello::Domain(domain) => Outcome::Matched(SniffResult {
            protocol: "tls",
            domain,
        }),
        ClientHello::NeedMoreData => Outcome::NeedMoreData,
        ClientHello::NoClue => Outcome::NoClue,
        ClientHello::Rejected => Outcome::Rejected,
    }
}

enum ClientHello {
    Domain(String),
    NeedMoreData,
    NoClue,
    Rejected,
}

/// Go `ReadClientHello`: walks the client hello for the server_name
/// extension. An SNI byte `<= ' '` means the hello straddles packets — Go
/// reports `protocol.ErrProtoNeedMoreData` there (the QUIC sniffer relies on
/// it). A trailing dot in the SNI is rejected (RFC 6066 §3).
fn read_client_hello(mut data: &[u8]) -> ClientHello {
    if data.len() < 42 {
        return ClientHello::NoClue;
    }
    let session_id_len = data[38] as usize;
    if session_id_len > 32 || data.len() < 39 + session_id_len {
        return ClientHello::NoClue;
    }
    data = &data[39 + session_id_len..];
    if data.len() < 2 {
        return ClientHello::NoClue;
    }
    // The cipher suite list length counts uint16s, so it must be even.
    let cipher_suite_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if cipher_suite_len % 2 == 1 || data.len() < 2 + cipher_suite_len {
        return ClientHello::Rejected; // errNotClientHello
    }
    data = &data[2 + cipher_suite_len..];
    if data.is_empty() {
        return ClientHello::NoClue;
    }
    let compression_len = data[0] as usize;
    if data.len() < 1 + compression_len {
        return ClientHello::NoClue;
    }
    data = &data[1 + compression_len..];
    if data.len() < 2 {
        return ClientHello::Rejected;
    }
    let extensions_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    data = &data[2..];
    if extensions_len != data.len() {
        return ClientHello::Rejected;
    }
    while !data.is_empty() {
        if data.len() < 4 {
            return ClientHello::Rejected;
        }
        let extension = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if data.len() < length {
            return ClientHello::Rejected;
        }
        if extension == 0x00 {
            // extensionServerName
            let mut names = &data[..length];
            if names.len() < 2 {
                return ClientHello::Rejected;
            }
            let names_len = u16::from_be_bytes([names[0], names[1]]) as usize;
            names = &names[2..];
            if names.len() != names_len {
                return ClientHello::Rejected;
            }
            while !names.is_empty() {
                if names.len() < 3 {
                    return ClientHello::Rejected;
                }
                let name_type = names[0];
                let name_len = u16::from_be_bytes([names[1], names[2]]) as usize;
                names = &names[3..];
                if names.len() < name_len {
                    return ClientHello::Rejected;
                }
                if name_type == 0 {
                    let name = &names[..name_len];
                    // QUIC crypto data separated across packets may leave
                    // the SNI truncated.
                    if name.iter().any(|&byte| byte <= b' ') {
                        return ClientHello::NeedMoreData;
                    }
                    // An SNI may not end in a dot (RFC 6066 §3); an empty
                    // name keeps Go's zero byte and stays a match.
                    if name.last() == Some(&b'.') {
                        return ClientHello::Rejected;
                    }
                    return ClientHello::Domain(String::from_utf8_lossy(name).into_owned());
                }
                names = &names[name_len..];
            }
        }
        data = &data[length..];
    }
    // Extensions parsed without a server_name: Go's errNotTLS.
    ClientHello::Rejected
}

// ---------------------------------------------------------------------------
// QUIC sniffer — Go common/protocol/quic/sniff.go
// ---------------------------------------------------------------------------

struct QuicVersionSpec {
    version: u32,
    type_initial: u8,
    initial_salt: [u8; 20],
    label_prefix: &'static str,
}

static QUIC_DRAFT_29: QuicVersionSpec = QuicVersionSpec {
    version: 0xff00001d,
    type_initial: 0b00,
    initial_salt: [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ],
    label_prefix: "quic",
};
static QUIC_V1: QuicVersionSpec = QuicVersionSpec {
    version: 0x1,
    type_initial: 0b00,
    initial_salt: [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    label_prefix: "quic",
};
static QUIC_V2: QuicVersionSpec = QuicVersionSpec {
    version: 0x6b3343cf,
    type_initial: 0b01,
    initial_salt: [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    label_prefix: "quicv2",
};

fn quic_version(version: u32) -> Option<&'static QuicVersionSpec> {
    match version {
        0xff00001d => Some(&QUIC_DRAFT_29),
        0x1 => Some(&QUIC_V1),
        0x6b3343cf => Some(&QUIC_V2),
        _ => None,
    }
}

/// Go's byte cursor over a QUIC packet (the `buf` reads of SniffQUIC).
struct QuicReader<'a> {
    data: &'a [u8],
}

impl<'a> QuicReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    fn remaining(&self) -> usize {
        self.data.len()
    }
    fn u8(&mut self) -> Option<u8> {
        let (first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(*first)
    }
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if count > self.data.len() {
            return None;
        }
        let (bytes, rest) = self.data.split_at(count);
        self.data = rest;
        Some(bytes)
    }
    /// `quicvarint.Read` (RFC 9000 §16 variable-length integer).
    fn varint(&mut self) -> Option<u64> {
        let first = *self.data.first()?;
        let width = 1usize << (first >> 6);
        let bytes = self.take(width)?;
        let mut value = (first & 0x3f) as u64;
        for &byte in &bytes[1..] {
            value = (value << 8) | u64::from(byte);
        }
        Some(value)
    }
}

/// Go `readShortQUICVarint`: the length-related fields of an initial packet
/// are capped at 65535; EOF or an over-long value is a definitive rejection.
fn short_varint(reader: &mut QuicReader<'_>) -> Option<u32> {
    match reader.varint() {
        Some(value) if value <= 65535 => Some(value as u32),
        _ => None,
    }
}

/// Go `hkdfExpandLabel`: TLS 1.3 HKDF-Expand-Label with the "tls13 " prefix
/// and an empty context.
fn hkdf_expand_label(secret: &Hkdf<Sha256>, label: &str, length: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(6 + label.len() as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let mut out = vec![0u8; length];
    secret
        .expand(&info, &mut out)
        .expect("hkdf expand within the SHA-256 limit");
    out
}

/// Go `SniffQUIC`: detects QUIC initial packets, removes the header
/// protection (AES-ECB sample mask), decrypts the payload with AES-128-GCM
/// using the version's initial secrets, and reads the TLS client hello from
/// the CRYPTO frames. Like Go, this MUTATES `b` (the protection removal is
/// in place). Crypto data spans packets: every non-initial packet is
/// skipped and the accumulated hello re-read after each initial packet.
pub fn sniff_quic(b: &mut [u8]) -> Outcome {
    if b.is_empty() {
        return Outcome::NoClue;
    }
    let payload_len = b.len();
    // cryptoDataBuf: NewWithSize(32767) — the client hello cap.
    const CRYPTO_CAP: usize = 32767;
    let mut crypto_data: Vec<u8> = Vec::new();
    let mut crypto_len = 0usize;
    let mut offset = 0usize;
    while offset < payload_len {
        let packet = &mut b[offset..];
        let mut reader = QuicReader::new(packet);
        let Some(type_byte) = reader.u8() else {
            return Outcome::Rejected;
        };
        // Long header with the fixed bit set, else this is no initial.
        if type_byte & 0x80 == 0 || type_byte & 0x40 == 0 {
            return Outcome::Rejected; // errNotQUICInitial
        }
        let Some(version_bytes) = reader.take(4) else {
            return Outcome::Rejected;
        };
        let version = u32::from_be_bytes([
            version_bytes[0],
            version_bytes[1],
            version_bytes[2],
            version_bytes[3],
        ]);
        let Some(spec) = quic_version(version) else {
            return Outcome::Rejected; // errNotQUIC: unknown version
        };
        let Some(dest_conn_id_len) = reader.u8() else {
            return Outcome::Rejected;
        };
        let Some(dest_conn_id) = reader.take(dest_conn_id_len as usize) else {
            return Outcome::Rejected;
        };
        let Some(source_conn_id_len) = reader.u8() else {
            return Outcome::Rejected;
        };
        if reader.take(source_conn_id_len as usize).is_none() {
            return Outcome::Rejected;
        }
        let packet_type = (type_byte & 0x30) >> 4;
        let is_initial = packet_type == spec.type_initial;
        if is_initial {
            // Only initial packets carry a token (RFC 9000 §17.2.2).
            let Some(token_len) = short_varint(&mut reader) else {
                return Outcome::Rejected;
            };
            if token_len as usize > payload_len {
                return Outcome::Rejected;
            }
            if reader.take(token_len as usize).is_none() {
                return Outcome::Rejected;
            }
        }
        let Some(packet_len) = short_varint(&mut reader) else {
            return Outcome::Rejected;
        };
        if packet_len < 4 {
            return Outcome::Rejected; // shorter than a packet number + tag
        }
        let hdr_len = packet.len() - reader.remaining();
        let packet_len = packet_len as usize;
        if packet.len() < hdr_len + packet_len {
            return Outcome::NoClue; // not enough data for this packet
        }
        let next_offset = offset + hdr_len + packet_len;
        if !is_initial {
            offset = next_offset;
            continue; // skip non-initial packets
        }
        // Initial secrets from the destination connection ID (RFC 9001 §5.2).
        let initial_secret = Hkdf::<Sha256>::new(Some(spec.initial_salt.as_slice()), dest_conn_id);
        let client_in = hkdf_expand_label(&initial_secret, "client in", 32);
        let secret =
            Hkdf::<Sha256>::from_prk(&client_in).expect("the client in secret is 32 bytes");
        let hp_key = hkdf_expand_label(&secret, &format!("{} hp", spec.label_prefix), 16);
        if packet.len() < hdr_len + 4 + 16 {
            return Outcome::Rejected;
        }
        // Header protection: mask = AES-ECB(hp_key, sample of 16 bytes).
        let mut mask = [0u8; 16];
        mask.copy_from_slice(&packet[hdr_len + 4..hdr_len + 20]);
        let cipher = Aes128::new_from_slice(&hp_key).expect("the hkdf-derived hp key is 16 bytes");
        cipher.encrypt_block((&mut mask).into());
        packet[0] ^= mask[0] & 0x0f;
        let packet_number_len = (packet[0] & 0x03) as usize + 1;
        for i in 0..packet_number_len {
            packet[hdr_len + i] ^= mask[i + 1];
        }
        let key = hkdf_expand_label(&secret, &format!("{} key", spec.label_prefix), 16);
        let iv = hkdf_expand_label(&secret, &format!("{} iv", spec.label_prefix), 12);
        // Nonce: Go's aeadAESGCMTLS13 — the iv with the (big-endian) packet
        // number XORed into its last bytes.
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv);
        for i in 0..packet_number_len {
            nonce[12 - packet_number_len + i] ^= packet[hdr_len + i];
        }
        let ext_hdr_len = hdr_len + packet_number_len;
        let aead = Aes128Gcm::new_from_slice(&key).expect("the hkdf-derived key is 16 bytes");
        let message = &packet[ext_hdr_len..hdr_len + packet_len];
        let header = &packet[..ext_hdr_len];
        let Ok(decrypted) = aead.decrypt(
            (&nonce).into(),
            Payload {
                msg: message,
                aad: header,
            },
        ) else {
            return Outcome::Rejected;
        };
        // Frames permitted in an initial packet (RFC 9000 §17.2.2.8).
        let mut frames = QuicReader::new(&decrypted);
        while frames.remaining() > 0 {
            let mut frame_type = frames.u8().expect("remaining was checked");
            while frame_type == 0x00 && frames.remaining() > 0 {
                frame_type = frames.u8().expect("remaining was checked");
            }
            match frame_type {
                0x00 => {} // PADDING
                0x01 => {} // PING
                0x02 | 0x03 => {
                    // ACK: Largest Acknowledged, ACK Delay, ACK Range Count,
                    // First ACK Range, then per-range Gap and Length.
                    for _ in 0..4 {
                        if short_varint(&mut frames).is_none() {
                            return Outcome::Rejected;
                        }
                    }
                    let Some(ack_range_count) = short_varint(&mut frames) else {
                        return Outcome::Rejected;
                    };
                    for _ in 0..ack_range_count {
                        if short_varint(&mut frames).is_none() {
                            return Outcome::Rejected;
                        }
                        if short_varint(&mut frames).is_none() {
                            return Outcome::Rejected;
                        }
                    }
                    if frame_type == 0x03 {
                        // ECN counts: ECT0, ECT1, CE.
                        for _ in 0..3 {
                            if short_varint(&mut frames).is_none() {
                                return Outcome::Rejected;
                            }
                        }
                    }
                }
                0x06 => {
                    // CRYPTO: reassemble the TLS transcript.
                    let Some(frame_offset) = short_varint(&mut frames) else {
                        return Outcome::Rejected;
                    };
                    let Some(frame_length) = short_varint(&mut frames) else {
                        return Outcome::Rejected;
                    };
                    let (frame_offset, frame_length) =
                        (frame_offset as usize, frame_length as usize);
                    if frame_length > frames.remaining() {
                        return Outcome::Rejected;
                    }
                    let current = frame_offset + frame_length;
                    if crypto_len < current {
                        if current > CRYPTO_CAP {
                            return Outcome::Rejected; // io.ErrShortBuffer
                        }
                        crypto_data.resize(current, 0);
                        crypto_len = current;
                    }
                    // Go's buf.Read errors on an empty buffer even for an
                    // empty slice.
                    if frames.remaining() == 0 {
                        return Outcome::Rejected;
                    }
                    let Some(data) = frames.take(frame_length) else {
                        return Outcome::Rejected;
                    };
                    crypto_data[frame_offset..frame_offset + frame_length].copy_from_slice(data);
                }
                0x1c => {
                    // CONNECTION_CLOSE: error code, frame type, reason.
                    for _ in 0..3 {
                        if short_varint(&mut frames).is_none() {
                            return Outcome::Rejected;
                        }
                    }
                    let Some(reason_len) = short_varint(&mut frames) else {
                        return Outcome::Rejected;
                    };
                    if frames.take(reason_len as usize).is_none() {
                        return Outcome::Rejected;
                    }
                }
                _ => return Outcome::Rejected, // not permitted in initials
            }
        }
        match read_client_hello(&crypto_data[..crypto_len]) {
            ClientHello::Domain(domain) => {
                return Outcome::Matched(SniffResult {
                    protocol: "quic",
                    domain,
                });
            }
            // The crypto data may be incomplete in the packets seen so far:
            // continue with the rest of the payload.
            _ => offset = next_offset,
        }
    }
    // Every packet parsed but the client hello is still incomplete.
    Outcome::NeedMoreData
}

// ---------------------------------------------------------------------------
// Dispatcher pipeline — Go app/dispatcher/sniffer.go + default.go
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum SnifferKind {
    Http,
    Tls,
    Quic,
}

/// Go's per-connection `Sniffer`: the still-eligible sniffer set. TCP runs
/// http then tls; UDP runs quic (Go's bittorrent/UTP sniffers are unported).
#[derive(Debug)]
pub struct Sniffers {
    active: Vec<SnifferKind>,
}

impl Sniffers {
    pub fn new(network: Network) -> Self {
        Self {
            active: match network {
                Network::Tcp => vec![SnifferKind::Http, SnifferKind::Tls],
                Network::Udp => vec![SnifferKind::Quic],
            },
        }
    }

    /// Go `Sniffer.Sniff(payload, network)`.
    pub fn sniff(&mut self, payload: &mut [u8]) -> SniffFlow {
        let active = std::mem::take(&mut self.active);
        let mut pending = Vec::with_capacity(active.len());
        for kind in active {
            let outcome = match kind {
                SnifferKind::Http => sniff_http(payload),
                SnifferKind::Tls => sniff_tls(payload),
                SnifferKind::Quic => sniff_quic(payload),
            };
            match outcome {
                Outcome::Matched(result) => return SniffFlow::Matched(result),
                // The protocol matched but needs more bytes: narrow to this
                // sniffer; the retry does not consume an attempt.
                Outcome::NeedMoreData => {
                    self.active = vec![kind];
                    return SniffFlow::NeedMoreData;
                }
                Outcome::NoClue => pending.push(kind),
                Outcome::Rejected => {}
            }
        }
        if pending.is_empty() {
            return SniffFlow::UnknownContent;
        }
        self.active = pending;
        SniffFlow::NoClue
    }
}

/// Go `Sniff`'s return shape.
#[derive(Debug)]
pub enum SniffFlow {
    Matched(SniffResult),
    /// common.ErrNoClue: still inconclusive with the bytes seen.
    NoClue,
    /// protocol.ErrProtoNeedMoreData: identified, awaiting more bytes.
    NeedMoreData,
    /// errUnknownContent: every sniffer rejected the payload.
    UnknownContent,
}

/// The dispatcher's sniff budget (Go's constants in `sniffer()`).
#[derive(Clone, Copy, Debug)]
pub struct SniffLimits {
    /// Go `buf.NewWithSize(32767)`: the payload peek ceiling.
    pub payload_bytes: usize,
    /// Go's 200 ms cache deadline: the total wait budget.
    pub cache_deadline: std::time::Duration,
    /// Go's `totalAttempt >= 2` give-up threshold.
    pub attempts: u32,
}

impl Default for SniffLimits {
    fn default() -> Self {
        Self {
            payload_bytes: 32767,
            cache_deadline: std::time::Duration::from_millis(200),
            attempts: 2,
        }
    }
}

/// The stream returned by [`sniff`]: the sniffed bytes are replayed before
/// the relay (Go's `cachedReader`), so nothing read while sniffing is lost.
pub struct SniffedStream<S> {
    inner: S,
    replay: Vec<u8>,
    position: usize,
}

impl<S> SniffedStream<S> {
    pub fn new(inner: S, replay: Vec<u8>) -> Self {
        Self {
            inner,
            replay,
            position: 0,
        }
    }
    /// The sniffed bytes not yet replayed.
    pub fn pending(&self) -> &[u8] {
        &self.replay[self.position..]
    }
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SniffedStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.position < this.replay.len() {
            let remaining = &this.replay[this.position..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            this.position += count;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SniffedStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Go's dispatcher `sniffer()` loop: bounded peek over the stream plus the
/// [`Sniffers`] pipeline. Never consumes bytes for the relay — everything
/// read is replayed by the returned [`SniffedStream`]. Returns `None` when
/// sniffing fails (errSniffingTimeout, errUnknownContent, reader errors or
/// `metadataOnly` with no metadata sniffer ported): the connection then
/// relays with its original destination, exactly like Go.
pub async fn sniff<S>(
    stream: S,
    network: Network,
    metadata_only: bool,
    limits: SniffLimits,
) -> (SniffedStream<S>, Option<SniffResult>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // metadataOnly without the (unported) fakedns metadata sniffer always
    // yields no result — Go's SniffMetadata returns ErrNoClue — so the
    // payload is not read at all.
    if metadata_only {
        return (SniffedStream::new(stream, Vec::new()), None);
    }
    let mut stream = stream;
    let mut pipeline = Sniffers::new(network);
    let mut payload = vec![0u8; limits.payload_bytes.max(1)];
    let mut filled = 0usize;
    let mut remaining = limits.cache_deadline;
    let mut attempts = 0u32;
    let mut result = None;
    loop {
        let started = std::time::Instant::now();
        // Go cachedReader.Cache: wait within the remaining budget for more
        // bytes; a deadline expiry yields no error, only no progress.
        let got = match tokio::time::timeout(remaining, stream.read(&mut payload[filled..])).await {
            Ok(Ok(count)) => count,
            // Reader error or EOF: Go's Cache propagates the error and the
            // dispatcher gives up without a result.
            Ok(Err(_)) | Err(_) => break,
        };
        filled += got;
        remaining = remaining.saturating_sub(started.elapsed());
        if got > 0 {
            match pipeline.sniff(&mut payload[..filled]) {
                SniffFlow::Matched(sniffed) => {
                    result = Some(sniffed);
                    break;
                }
                // NeedMoreData does not consume an attempt.
                SniffFlow::NeedMoreData => {}
                SniffFlow::NoClue => attempts += 1,
                SniffFlow::UnknownContent => break,
            }
        } else {
            attempts += 1;
        }
        if attempts >= limits.attempts || remaining.is_zero() {
            break; // errSniffingTimeout
        }
    }
    (
        SniffedStream::new(stream, payload[..filled].to_vec()),
        result,
    )
}

// ---------------------------------------------------------------------------
// Compiled inbound sniffing request — Go session.SniffingRequest
// ---------------------------------------------------------------------------

/// The compiled per-inbound sniffing request (Go's `session.SniffingRequest`
/// built by `SniffingConfig.Build`): which protocols may override the
/// destination, the domain/IP exclusions, `routeOnly` and `metadataOnly`.
#[derive(Debug)]
pub struct SniffingRequest {
    /// Normalized `destOverride`: "http" | "tls" | "quic".
    pub dest_override: Vec<&'static str>,
    pub route_only: bool,
    pub metadata_only: bool,
    pub exclude_domains: Option<DomainMatcher>,
    pub exclude_ips: Option<IpMatcher>,
}

/// The outcome of a successful override decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Override {
    /// The sniffed domain replacing the destination address.
    pub domain: String,
    /// `routeOnly`: route by the sniffed domain, dial the original target.
    pub route_only: bool,
}

impl SniffingRequest {
    /// Go `SniffingConfig.Build` plus the proxyman handler wiring: normalize
    /// `destOverride` and compile the domain/IP exclusions against the
    /// geodata store. `None` when sniffing is absent or disabled.
    pub fn compile(config: Option<&SniffingConfig>, store: &GeoDataStore) -> Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };
        let mut dest_override = Vec::new();
        for protocol in &config.dest_override {
            match protocol.to_ascii_lowercase().as_str() {
                "http" => dest_override.push("http"),
                "tls" | "https" | "ssl" => dest_override.push("tls"),
                "quic" => dest_override.push("quic"),
                "fakedns" | "fakedns+others" => bail!("fakedns sniffing is not migrated yet"),
                other => bail!("unknown sniffing protocol {other:?}"),
            }
        }
        if !config.enabled {
            return Ok(None);
        }
        let exclude_domains = if config.domains_excluded.is_empty() {
            None
        } else {
            Some(store.build_domain_matcher(
                &store.parse_domain_rules(&config.domains_excluded, domain::Type::Substr)?,
            )?)
        };
        let exclude_ips = if config.ips_excluded.is_empty() {
            None
        } else {
            Some(store.build_ip_matcher(&store.parse_ip_rules(&config.ips_excluded)?)?)
        };
        Ok(Some(Self {
            dest_override,
            route_only: config.route_only,
            metadata_only: config.metadata_only,
            exclude_domains,
            exclude_ips,
        }))
    }

    /// Go `DefaultDispatcher.shouldOverride` (the fakedns arms are unported):
    /// the result's protocol must prefix-match a destOverride entry
    /// (bidirectionally, like Go), and neither the sniffed domain nor the
    /// original IP destination may be excluded.
    pub fn should_override(&self, result: &SniffResult, destination: &Destination) -> bool {
        if result.domain.is_empty() {
            return false;
        }
        if let Some(matcher) = &self.exclude_domains
            && matcher.match_any(&result.domain.to_lowercase())
        {
            return false;
        }
        if let (Some(matcher), Address::Ip(ip)) = (&self.exclude_ips, &destination.address)
            && matcher.match_ip(*ip)
        {
            return false;
        }
        self.dest_override.iter().any(|protocol| {
            result.protocol.starts_with(protocol) || protocol.starts_with(result.protocol)
        })
    }

    /// Go's Dispatch override block: replace the destination address with
    /// the sniffed domain — unless `routeOnly` keeps the original dial target
    /// for the outbound (the router still sees the sniffed domain).
    pub fn destination_override(
        &self,
        result: &SniffResult,
        destination: &Destination,
    ) -> Option<Override> {
        if !self.should_override(result, destination) {
            return None;
        }
        Some(Override {
            domain: result.domain.clone(),
            route_only: self.route_only,
        })
    }
}
