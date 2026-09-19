//! Bounded PROXY protocol v1/v2 processing before TLS or application framing.
//!
//! Xray's system_listener.go uses go-proxyproto REQUIRE. The pinned v0.15.0
//! defaults are a ten-second header deadline and a 4096-byte v2 payload limit.
//! Trust is an explicit decision about the real transport peer, never a fact
//! learned from this header. LOCAL, UNKNOWN, and SSL TLVs cannot authenticate
//! an end user or establish that the current connection is encrypted.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::BoxStream;

pub const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V1_SIGNATURE: &[u8; 5] = b"PROXY";
const MAX_V1_BYTES: usize = 107;
pub const DEFAULT_MAX_V2_PAYLOAD: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Xray acceptProxyProtocol semantics: reject connections without a header.
    Required,
    /// A header is optional, but any recognized header must be fully valid.
    Optional,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    /// None explicitly disables the header deadline; no task is spawned.
    pub timeout: Option<Duration>,
    /// Excludes the fixed 16-byte v2 prefix. Maximum configurable value 65535.
    pub max_v2_payload: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Required,
            timeout: Some(Duration::from_secs(10)),
            max_v2_payload: DEFAULT_MAX_V2_PAYLOAD,
        }
    }
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if self.max_v2_payload > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXY v2 maximum payload must be at most 65535",
            ));
        }
        Ok(())
    }
}

/// The caller must select this using the actual socket peer and its own trust
/// policy. Both Required and Optional reject Untrusted before reading bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerTrust {
    Trusted,
    Untrusted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Local,
    Proxy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Unspecified,
    Stream,
    Datagram,
}

/// The complete 108-byte Unix address slot, retaining non-UTF8 and abstract
/// address bytes. This parser never opens or resolves the advertised path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixAddress {
    pub raw: [u8; 108],
}

impl UnixAddress {
    /// The conventional NUL-terminated pathname, matching go-proxyproto.
    /// For abstract names use raw; the leading NUL is significant there.
    pub fn pathname(&self) -> &[u8] {
        &self.raw[..self.raw.iter().position(|b| *b == 0).unwrap_or(108)]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Addresses {
    Unspecified,
    Inet {
        source: SocketAddr,
        destination: SocketAddr,
    },
    Unix {
        source: UnixAddress,
        destination: UnixAddress,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlv {
    pub kind: u8,
    pub value: Bytes,
}

/// These are claims made by a trusted proxy, not independently verified TLS
/// identity or a property of the outer socket's TLS session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SslInfo {
    pub client_flags: u8,
    pub verify: u32,
    pub sub_tlvs: Vec<Tlv>,
}

impl Tlv {
    pub fn ssl_info(&self) -> io::Result<Option<SslInfo>> {
        if self.kind != 0x20 {
            return Ok(None);
        }
        if self.value.len() < 5 {
            return Err(invalid("truncated PROXY SSL TLV"));
        }
        Ok(Some(SslInfo {
            client_flags: self.value[0],
            verify: u32::from_be_bytes(self.value[1..5].try_into().expect("four bytes")),
            sub_tlvs: split_tlvs(&self.value[5..])?,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub command: Command,
    pub transport: Transport,
    pub addresses: Addresses,
    /// Only PROXY v2 metadata; unknown types and NOOP padding are retained.
    pub tlvs: Vec<Tlv>,
    /// LOCAL payload is opaque. It is not parsed as addresses or TLVs.
    pub local_payload: Bytes,
    /// True only if a supplied CRC32C TLV was structurally valid and matched.
    /// A checksum provides integrity checking, not sender authentication.
    pub checksum_verified: bool,
}

impl Header {
    pub fn source_addr(&self) -> Option<SocketAddr> {
        if self.command != Command::Proxy {
            return None;
        }
        match self.addresses {
            Addresses::Inet { source, .. } => Some(source),
            _ => None,
        }
    }

    pub fn destination_addr(&self) -> Option<SocketAddr> {
        if self.command != Command::Proxy {
            return None;
        }
        match self.addresses {
            Addresses::Inet { destination, .. } => Some(destination),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decode {
    Incomplete,
    Absent,
    Complete {
        header: Box<Header>,
        consumed: usize,
    },
}

/// Pure incremental parser. `consumed` excludes coalesced application bytes.
/// Datagram header formats are decoded here for inspection; the stream adapter
/// rejects PROXY+DGRAM because it cannot supply per-datagram framing.
pub fn decode(data: &[u8], max_v2_payload: usize) -> io::Result<Decode> {
    if max_v2_payload > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PROXY v2 maximum payload exceeds 65535",
        ));
    }
    if data.is_empty() {
        return Ok(Decode::Incomplete);
    }
    if data.starts_with(V1_SIGNATURE) {
        return decode_v1(data);
    }
    if data.starts_with(V2_SIGNATURE) {
        return decode_v2(data, max_v2_payload);
    }
    if V1_SIGNATURE.starts_with(data) || V2_SIGNATURE.starts_with(data) {
        return Ok(Decode::Incomplete);
    }
    Ok(Decode::Absent)
}

fn decode_v1(data: &[u8]) -> io::Result<Decode> {
    if data.get(5).is_some_and(|byte| *byte != b' ') {
        return Err(invalid("PROXY v1 signature must be followed by one space"));
    }
    let Some(end) = data
        .iter()
        .take(MAX_V1_BYTES)
        .position(|byte| *byte == b'\n')
    else {
        return if data.len() >= MAX_V1_BYTES {
            Err(invalid("PROXY v1 header exceeds 107 bytes"))
        } else {
            Ok(Decode::Incomplete)
        };
    };
    if end == 0 || data[end - 1] != b'\r' {
        return Err(invalid("PROXY v1 header must end with CRLF"));
    }
    let line = &data[..end - 1];
    if line.contains(&b'\r') || line.contains(&0) {
        return Err(invalid("control byte inside PROXY v1 header"));
    }
    let tokens: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
    if tokens.len() < 2 || tokens[0] != b"PROXY" {
        return Err(invalid("malformed PROXY v1 signature"));
    }
    let mut header = Header {
        version: 1,
        command: Command::Proxy,
        transport: Transport::Stream,
        addresses: Addresses::Unspecified,
        tlvs: Vec::new(),
        local_payload: Bytes::new(),
        checksum_verified: false,
    };
    if tokens[1] == b"UNKNOWN" {
        header.command = Command::Local;
        header.transport = Transport::Unspecified;
        return Ok(Decode::Complete {
            header: Box::new(header),
            consumed: end + 1,
        });
    }
    if tokens.len() != 6 {
        return Err(invalid("PROXY v1 TCP header requires exactly six tokens"));
    }
    let source = std::str::from_utf8(tokens[2]).map_err(invalid)?;
    let destination = std::str::from_utf8(tokens[3]).map_err(invalid)?;
    let source_port = parse_port(tokens[4])?;
    let destination_port = parse_port(tokens[5])?;
    let (source, destination) = match tokens[1] {
        b"TCP4" => (
            SocketAddr::from((source.parse::<Ipv4Addr>().map_err(invalid)?, source_port)),
            SocketAddr::from((
                destination.parse::<Ipv4Addr>().map_err(invalid)?,
                destination_port,
            )),
        ),
        b"TCP6" => (
            SocketAddr::from((source.parse::<Ipv6Addr>().map_err(invalid)?, source_port)),
            SocketAddr::from((
                destination.parse::<Ipv6Addr>().map_err(invalid)?,
                destination_port,
            )),
        ),
        _ => return Err(invalid("unsupported PROXY v1 transport")),
    };
    header.addresses = Addresses::Inet {
        source,
        destination,
    };
    Ok(Decode::Complete {
        header: Box::new(header),
        consumed: end + 1,
    })
}

fn parse_port(bytes: &[u8]) -> io::Result<u16> {
    if bytes.is_empty()
        || bytes.len() > 5
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(invalid(
            "PROXY v1 port must be decimal without a sign or leading zero",
        ));
    }
    std::str::from_utf8(bytes)
        .map_err(invalid)?
        .parse()
        .map_err(invalid)
}

fn decode_v2(data: &[u8], limit: usize) -> io::Result<Decode> {
    if data.len() < 16 {
        return Ok(Decode::Incomplete);
    }
    let command = match data[12] {
        0x20 => Command::Local,
        0x21 => Command::Proxy,
        _ => return Err(invalid("invalid PROXY v2 version or command")),
    };
    let (transport, address_size) = match data[13] {
        0x00 => (Transport::Unspecified, 0),
        0x11 => (Transport::Stream, 12),
        0x12 => (Transport::Datagram, 12),
        0x21 => (Transport::Stream, 36),
        0x22 => (Transport::Datagram, 36),
        0x31 => (Transport::Stream, 216),
        0x32 => (Transport::Datagram, 216),
        _ => return Err(invalid("undefined PROXY v2 family/transport combination")),
    };
    let length = u16::from_be_bytes([data[14], data[15]]) as usize;
    if length > limit {
        return Err(invalid("PROXY v2 payload exceeds configured limit"));
    }
    if command == Command::Proxy && (transport == Transport::Unspecified || length < address_size) {
        return Err(invalid("PROXY v2 address block is missing or truncated"));
    }
    let consumed = 16 + length;
    if data.len() < consumed {
        return Ok(Decode::Incomplete);
    }
    let payload = &data[16..consumed];
    let mut header = Header {
        version: 2,
        command,
        transport,
        addresses: Addresses::Unspecified,
        tlvs: Vec::new(),
        local_payload: Bytes::new(),
        checksum_verified: false,
    };
    if command == Command::Local {
        // The advertised family is syntactically checked to match the pinned
        // Go library, but its address layout, metadata, and checksum are ignored.
        header.transport = Transport::Unspecified;
        header.local_payload = Bytes::copy_from_slice(payload);
        return Ok(Decode::Complete {
            header: Box::new(header),
            consumed,
        });
    }
    header.addresses = match address_size {
        12 => Addresses::Inet {
            source: SocketAddr::from((
                Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]),
                u16::from_be_bytes([payload[8], payload[9]]),
            )),
            destination: SocketAddr::from((
                Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]),
                u16::from_be_bytes([payload[10], payload[11]]),
            )),
        },
        36 => Addresses::Inet {
            source: SocketAddr::from((
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16]).expect("sixteen bytes")),
                u16::from_be_bytes([payload[32], payload[33]]),
            )),
            destination: SocketAddr::from((
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[16..32]).expect("sixteen bytes")),
                u16::from_be_bytes([payload[34], payload[35]]),
            )),
        },
        216 => Addresses::Unix {
            source: UnixAddress {
                raw: payload[..108].try_into().expect("Unix address slot"),
            },
            destination: UnixAddress {
                raw: payload[108..216].try_into().expect("Unix address slot"),
            },
        },
        _ => unreachable!("validated PROXY address family"),
    };
    header.tlvs = split_tlvs(&payload[address_size..])?;
    let mut offset = 16 + address_size;
    let mut checksum_offset = None;
    for tlv in &header.tlvs {
        if tlv.kind == 0x03 {
            if tlv.value.len() != 4 || checksum_offset.is_some() {
                return Err(invalid("invalid or duplicate PROXY CRC32C TLV"));
            }
            checksum_offset = Some(offset + 3);
        }
        // Validate SSL vector structure, but never its identity claims.
        tlv.ssl_info()?;
        offset += 3 + tlv.value.len();
    }
    if let Some(offset) = checksum_offset {
        let supplied = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .expect("four checksum bytes"),
        );
        if crc32c_zeroed(&data[..consumed], offset..offset + 4) != supplied {
            return Err(invalid("PROXY v2 CRC32C checksum mismatch"));
        }
        header.checksum_verified = true;
    }
    Ok(Decode::Complete {
        header: Box::new(header),
        consumed,
    })
}

fn split_tlvs(data: &[u8]) -> io::Result<Vec<Tlv>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if data.len() - offset < 3 {
            return Err(invalid("truncated PROXY v2 TLV header"));
        }
        let length = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        if length > data.len() - offset - 3 {
            return Err(invalid("truncated PROXY v2 TLV value"));
        }
        result.push(Tlv {
            kind: data[offset],
            value: Bytes::copy_from_slice(&data[offset + 3..offset + 3 + length]),
        });
        offset += 3 + length;
    }
    Ok(result)
}

fn crc32c_zeroed(data: &[u8], zeros: std::ops::Range<usize>) -> u32 {
    let mut crc = !0u32;
    for (index, byte) in data.iter().enumerate() {
        crc ^= u32::from(if zeros.contains(&index) { 0 } else { *byte });
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

pub struct Accepted {
    pub stream: BoxStream,
    /// LOCAL/UNKNOWN return Some(Header), but source_addr/destination_addr
    /// remain None and the caller must retain the actual socket endpoints.
    pub header: Option<Header>,
}

/// Adapt one accepted byte stream. Call before TLS, WebSocket, HTTP Upgrade,
/// or proxy protocol decoding; the returned stream retains all non-header bytes.
/// On error or cancellation the owned stream closes; no detached read survives.
pub async fn accept(
    mut stream: BoxStream,
    config: &Config,
    trust: PeerTrust,
) -> io::Result<Accepted> {
    if trust != PeerTrust::Trusted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "real transport peer is not trusted to supply PROXY metadata",
        ));
    }
    config.validate()?;
    let mut buffered = Vec::with_capacity(256);
    let result = if let Some(timeout) = config.timeout {
        match tokio::time::timeout(timeout, read_header(&mut stream, &mut buffered, config)).await {
            Ok(result) => result,
            Err(_) if config.mode == Mode::Optional && !header_started(&buffered) => Ok(None),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PROXY header deadline exceeded",
            )),
        }
    } else {
        read_header(&mut stream, &mut buffered, config).await
    }?;
    let (header, consumed) = match result {
        Some((header, consumed)) => {
            if header.command == Command::Proxy && header.transport == Transport::Datagram {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "PROXY DGRAM requires per-datagram processing, not a stream listener",
                ));
            }
            (Some(header), consumed)
        }
        None => (None, 0),
    };
    let prefix = Bytes::copy_from_slice(&buffered[consumed..]);
    if !prefix.is_empty() {
        stream = Box::new(PrefixedStream {
            inner: stream,
            prefix,
        });
    }
    Ok(Accepted { stream, header })
}

async fn read_header(
    stream: &mut BoxStream,
    buffered: &mut Vec<u8>,
    config: &Config,
) -> io::Result<Option<(Header, usize)>> {
    loop {
        match decode(buffered, config.max_v2_payload)? {
            Decode::Complete { header, consumed } => return Ok(Some((*header, consumed))),
            Decode::Absent if config.mode == Mode::Optional => return Ok(None),
            Decode::Absent => return Err(invalid("required PROXY protocol header is absent")),
            Decode::Incomplete => {}
        }
        let mut chunk = [0u8; 256];
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            if config.mode == Mode::Optional && !header_started(buffered) {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF during required or recognized PROXY header",
            ));
        }
        buffered.extend_from_slice(&chunk[..length]);
        // decode checks the advertised length before further reads. At most one
        // additional read chunk can contain coalesced application bytes.
    }
}

fn header_started(data: &[u8]) -> bool {
    data.starts_with(V1_SIGNATURE) || data.starts_with(V2_SIGNATURE)
}

struct PrefixedStream {
    inner: BoxStream,
    prefix: Bytes,
}
impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let amount = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..amount]);
            self.prefix.advance(amount);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, data)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const V1: &[u8] = b"PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n";
    const IPV4: &[u8] = &[192, 0, 2, 1, 198, 51, 100, 2, 0x30, 0x39, 1, 0xbb];

    fn v2(command: u8, family: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = V2_SIGNATURE.to_vec();
        data.extend_from_slice(&[command, family]);
        data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        data.extend_from_slice(payload);
        data
    }

    fn parsed(data: &[u8]) -> (Header, usize) {
        match decode(data, DEFAULT_MAX_V2_PAYLOAD).unwrap() {
            Decode::Complete { header, consumed } => (*header, consumed),
            other => panic!("expected complete header, got {other:?}"),
        }
    }

    async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("PROXY test timed out")
    }

    #[test]
    fn v1_ipv4_golden_and_consumed_boundary() {
        let mut wire = V1.to_vec();
        wire.extend_from_slice(b"\x16\x03\x01\0\x05hello");
        let (header, consumed) = parsed(&wire);
        assert_eq!(consumed, V1.len());
        assert_eq!(header.version, 1);
        assert_eq!(header.command, Command::Proxy);
        assert_eq!(
            header.source_addr(),
            Some("192.0.2.1:12345".parse().unwrap())
        );
        assert_eq!(
            header.destination_addr(),
            Some("198.51.100.2:443".parse().unwrap())
        );
        assert_eq!(&wire[consumed..], b"\x16\x03\x01\0\x05hello");
    }

    #[test]
    fn v1_ipv6_and_mapped_ipv6_remain_the_declared_family() {
        let (header, _) = parsed(b"PROXY TCP6 2001:db8::1 ::ffff:192.0.2.2 0 65535\r\n");
        assert_eq!(
            header.source_addr(),
            Some("[2001:db8::1]:0".parse().unwrap())
        );
        assert!(header.destination_addr().unwrap().is_ipv6());
        assert_eq!(header.destination_addr().unwrap().port(), 65535);
    }

    #[test]
    fn v1_unknown_leaves_real_endpoints_intact() {
        for input in [
            b"PROXY UNKNOWN\r\n".as_slice(),
            b"PROXY UNKNOWN ignored arbitrary words 12345\r\n".as_slice(),
        ] {
            let (header, _) = parsed(input);
            assert_eq!(header.command, Command::Local);
            assert_eq!(header.addresses, Addresses::Unspecified);
            assert!(header.source_addr().is_none());
            assert!(header.destination_addr().is_none());
            assert!(header.tlvs.is_empty());
        }
    }

    #[test]
    fn v1_exact_107_byte_limit() {
        let mut maximum = b"PROXY UNKNOWN ".to_vec();
        maximum.resize(105, b'x');
        maximum.extend_from_slice(b"\r\n");
        assert_eq!(parsed(&maximum).1, 107);
        maximum.insert(104, b'x');
        assert!(decode(&maximum, 4096).is_err());
        assert!(decode(&[b'P'; 108], 4096).is_ok()); // Not a PROXY signature.
        let mut no_terminator = b"PROXY UNKNOWN ".to_vec();
        no_terminator.resize(107, b'x');
        assert!(decode(&no_terminator, 4096).is_err());
    }

    #[test]
    fn v1_strict_ports_families_tokens_and_crlf() {
        for wire in [
            "PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n",
            "PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n",
            "PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n",
            "PROXY TCP4 1.2.3.4 5.6.7.8 1 2 extra\r\n",
            "PROXY TCP4 ::1 5.6.7.8 1 2\r\n",
            "PROXY TCP6 1.2.3.4 ::1 1 2\r\n",
            "PROXY TCP6 fe80::1%eth0 ::1 1 2\r\n",
            "PROXY TCP4 01.2.3.4 5.6.7.8 1 2\r\n",
            "PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n",
            "PROXY  UNKNOWN\r\n",
            "PROXYjunk UNKNOWN\r\n",
            "PROXY UNKNOWN\n",
            "PROXY UNKNOWN stray\rinside\r\n",
        ] {
            assert!(decode(wire.as_bytes(), 4096).is_err(), "{wire:?}");
        }
    }

    #[test]
    fn v2_ipv4_golden() {
        let wire =
            b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c\xc0\0\x02\x01\xc6\x33\x64\x02\x30\x39\x01\xbb";
        let (header, consumed) = parsed(wire);
        assert_eq!(consumed, 28);
        assert_eq!(header.version, 2);
        assert_eq!(header.transport, Transport::Stream);
        assert_eq!(
            header.source_addr(),
            Some("192.0.2.1:12345".parse().unwrap())
        );
        assert_eq!(
            header.destination_addr(),
            Some("198.51.100.2:443".parse().unwrap())
        );
    }

    #[test]
    fn v2_ipv6_golden() {
        let payload = [
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2, 0xff, 0xff, 0, 0x50,
        ];
        let (header, _) = parsed(&v2(0x21, 0x21, &payload));
        assert_eq!(
            header.source_addr(),
            Some("[2001:db8::1]:65535".parse().unwrap())
        );
        assert_eq!(
            header.destination_addr(),
            Some("[2001:db8::2]:80".parse().unwrap())
        );
    }

    #[test]
    fn v2_unix_preserves_raw_bytes_and_full_address_slots() {
        let mut payload = [0u8; 216];
        payload[..11].copy_from_slice(b"/tmp/source");
        payload[108..113].copy_from_slice(b"\0name");
        payload[114] = 0xff;
        let (header, _) = parsed(&v2(0x21, 0x31, &payload));
        let Addresses::Unix {
            source,
            destination,
        } = header.addresses
        else {
            panic!("missing Unix addresses");
        };
        assert_eq!(source.pathname(), b"/tmp/source");
        assert!(destination.pathname().is_empty());
        assert_eq!(&destination.raw[..7], b"\0name\0\xff");
    }

    #[test]
    fn local_ignores_address_layout_and_opaque_tlv_like_payload() {
        for family in [0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32] {
            for payload in [b"".as_slice(), b"not an address or TLV".as_slice(), IPV4] {
                let (header, _) = parsed(&v2(0x20, family, payload));
                assert_eq!(header.command, Command::Local);
                assert_eq!(header.transport, Transport::Unspecified);
                assert_eq!(header.addresses, Addresses::Unspecified);
                assert!(header.source_addr().is_none());
                assert!(header.tlvs.is_empty());
                assert!(!header.checksum_verified);
                assert_eq!(header.local_payload.as_ref(), payload);
            }
        }
    }

    #[test]
    fn v2_invalid_command_family_and_address_lengths_are_rejected() {
        for command in [0x00, 0x10, 0x22, 0x2f, 0x31] {
            assert!(decode(&v2(command, 0x11, IPV4), 4096).is_err());
        }
        for family in [0x01, 0x02, 0x10, 0x13, 0x20, 0x23, 0x30, 0x33, 0x41, 0xff] {
            for command in [0x20, 0x21] {
                assert!(decode(&v2(command, family, IPV4), 4096).is_err());
            }
        }
        assert!(decode(&v2(0x21, 0, &[]), 4096).is_err());
        for (family, length) in [(0x11, 11), (0x21, 35), (0x31, 215)] {
            assert!(decode(&v2(0x21, family, &vec![0; length]), 4096).is_err());
        }
    }

    #[test]
    fn advertised_v2_length_is_checked_before_payload_allocation() {
        let mut wire = V2_SIGNATURE.to_vec();
        wire.extend_from_slice(&[0x20, 0, 0x10, 1]); // 4097 payload bytes.
        assert!(decode(&wire, 4096).is_err());
        assert_eq!(decode(&wire, 65535).unwrap(), Decode::Incomplete);
        assert!(decode(&wire, 65536).is_err());
        wire[14] = 0;
        wire[15] = 0;
        assert!(matches!(decode(&wire, 0).unwrap(), Decode::Complete { .. }));
    }

    #[test]
    fn unknown_tlvs_and_noop_bytes_are_preserved() {
        let mut payload = IPV4.to_vec();
        payload.extend_from_slice(&[0x01, 0, 2, b'h', b'2', 0xe0, 0, 3, 0, 0xff, 1, 4, 0, 1, 0]);
        let (header, _) = parsed(&v2(0x21, 0x11, &payload));
        assert_eq!(header.tlvs.len(), 3);
        assert_eq!(header.tlvs[0].value, b"h2".as_slice());
        assert_eq!(
            header.tlvs[1],
            Tlv {
                kind: 0xe0,
                value: Bytes::from_static(&[0, 0xff, 1])
            }
        );
        assert_eq!(header.tlvs[2].value, b"\0".as_slice());
    }

    #[test]
    fn ssl_tlv_is_structured_metadata_without_identity_claims() {
        let mut payload = IPV4.to_vec();
        payload.extend_from_slice(&[0x20, 0, 15, 0x03, 0, 0, 0, 0, 0x21, 0, 7]);
        payload.extend_from_slice(b"TLSv1.3");
        let (header, _) = parsed(&v2(0x21, 0x11, &payload));
        let ssl = header.tlvs[0].ssl_info().unwrap().unwrap();
        assert_eq!(ssl.client_flags, 3);
        assert_eq!(ssl.verify, 0);
        assert_eq!(ssl.sub_tlvs[0].kind, 0x21);
        assert_eq!(ssl.sub_tlvs[0].value, b"TLSv1.3".as_slice());
        assert!(!header.checksum_verified);
    }

    #[test]
    fn truncated_tlvs_ssl_and_duplicate_checksums_are_rejected() {
        for suffix in [
            vec![1],
            vec![1, 0],
            vec![1, 0, 2, b'h'],
            vec![0x20, 0, 4, 0, 0, 0, 0],
            vec![0x20, 0, 6, 0, 0, 0, 0, 0, 0x21],
            vec![3, 0, 3, 0, 0, 0],
            vec![3, 0, 4, 0, 0, 0, 0, 3, 0, 4, 0, 0, 0, 0],
        ] {
            let mut payload = IPV4.to_vec();
            payload.extend_from_slice(&suffix);
            assert!(decode(&v2(0x21, 0x11, &payload), 4096).is_err());
        }
    }

    #[test]
    fn crc32c_known_vector_and_go_aws_nlb_golden() {
        assert_eq!(crc32c_zeroed(b"123456789", 0..0), 0xe3069283);
        // go-proxyproto v0.15.0/tlvparse/aws_test.go's AWS NLB VPCE example.
        let mut payload = vec![
            0xac, 0x1f, 0x07, 0x71, 0xac, 0x1f, 0x0a, 0x1f, 0xc8, 0xf2, 0, 0x50, 3, 0, 4, 0xe8,
            0xd6, 0x89, 0x2d, 0xea, 0, 0x17, 1,
        ];
        payload.extend_from_slice(b"vpce-08d2bf15fac5001c9");
        payload.extend_from_slice(&[4, 0, 0x24]);
        payload.resize(84, 0);
        let mut wire = v2(0x21, 0x11, &payload);
        let (header, _) = parsed(&wire);
        assert!(header.checksum_verified);
        assert_eq!(
            header.tlvs[1].value.slice(1..),
            b"vpce-08d2bf15fac5001c9".as_slice()
        );
        wire[16] ^= 1;
        assert!(decode(&wire, 4096).is_err());
    }

    #[test]
    fn every_fragment_prefix_is_incomplete_until_a_complete_header() {
        for wire in [V1.to_vec(), v2(0x21, 0x11, IPV4), v2(0x20, 0, b"opaque")] {
            for length in 0..wire.len() {
                assert_eq!(
                    decode(&wire[..length], 4096).unwrap(),
                    Decode::Incomplete,
                    "{length}"
                );
            }
            assert_eq!(parsed(&wire).1, wire.len());
        }
        for ordinary in [
            b"GET /".as_slice(),
            b"POST /".as_slice(),
            b"\x16\x03\x01".as_slice(),
            b"\rX".as_slice(),
        ] {
            assert_eq!(decode(ordinary, 4096).unwrap(), Decode::Absent);
        }
    }

    #[tokio::test]
    async fn fragmented_header_and_coalesced_tls_bytes_survive() {
        bounded(async {
            for header in [V1.to_vec(), v2(0x21, 0x11, IPV4)] {
                let (mut writer, reader) = tokio::io::duplex(1024);
                let payload = b"\x16\x03\x01\0\x05hello";
                let ((), accepted) = tokio::join!(
                    async {
                        for byte in &header[..header.len() - 1] {
                            writer.write_all(&[*byte]).await.unwrap();
                            tokio::task::yield_now().await;
                        }
                        let mut final_chunk = vec![*header.last().unwrap()];
                        final_chunk.extend_from_slice(payload);
                        writer.write_all(&final_chunk).await.unwrap();
                        writer.shutdown().await.unwrap();
                    },
                    async {
                        let config = Config::default();
                        accept(Box::new(reader), &config, PeerTrust::Trusted).await
                    }
                );
                let mut accepted = accepted.unwrap();
                assert!(accepted.header.is_some());
                let mut actual = Vec::new();
                loop {
                    let mut one = [0u8; 1];
                    if accepted.stream.read(&mut one).await.unwrap() == 0 {
                        break;
                    }
                    actual.push(one[0]);
                }
                assert_eq!(actual, payload);
            }
        })
        .await;
    }

    #[tokio::test]
    async fn optional_passthrough_preserves_short_nonproxy_prefixes() {
        bounded(async {
            let optional = Config {
                mode: Mode::Optional,
                ..Config::default()
            };
            for data in [
                b"GET / HTTP/1.1\r\n\r\n".as_slice(),
                b"P".as_slice(),
                b"PROX".as_slice(),
                b"".as_slice(),
                b"\r\n".as_slice(),
            ] {
                let (mut writer, reader) = tokio::io::duplex(1024);
                writer.write_all(data).await.unwrap();
                writer.shutdown().await.unwrap();
                let mut accepted = accept(Box::new(reader), &optional, PeerTrust::Trusted)
                    .await
                    .unwrap();
                assert!(accepted.header.is_none());
                let mut actual = Vec::new();
                accepted.stream.read_to_end(&mut actual).await.unwrap();
                assert_eq!(actual, data);
            }
        })
        .await;
    }

    #[tokio::test]
    async fn required_absent_and_recognized_truncated_headers_fail() {
        bounded(async {
            for data in [
                b"GET /".as_slice(),
                b"".as_slice(),
                b"PROXY".as_slice(),
                b"PROXY TCP4 1.2.3.4".as_slice(),
                V2_SIGNATURE.as_slice(),
            ] {
                for mode in [Mode::Required, Mode::Optional] {
                    if mode == Mode::Optional && !header_started(data) {
                        continue;
                    }
                    let (mut writer, reader) = tokio::io::duplex(1024);
                    writer.write_all(data).await.unwrap();
                    writer.shutdown().await.unwrap();
                    let config = Config {
                        mode,
                        ..Config::default()
                    };
                    assert!(
                        accept(Box::new(reader), &config, PeerTrust::Trusted)
                            .await
                            .is_err()
                    );
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn timeout_is_explicit_and_optional_partial_prefix_is_retained() {
        bounded(async {
            let timeout = Some(Duration::from_millis(15));
            let (mut writer, reader) = tokio::io::duplex(1024);
            writer.write_all(b"P").await.unwrap();
            let config = Config {
                mode: Mode::Optional,
                timeout,
                ..Config::default()
            };
            let mut accepted = accept(Box::new(reader), &config, PeerTrust::Trusted)
                .await
                .unwrap();
            assert!(accepted.header.is_none());
            writer.write_all(b"later").await.unwrap();
            writer.shutdown().await.unwrap();
            let mut actual = Vec::new();
            accepted.stream.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, b"Plater");
            for mode in [Mode::Required, Mode::Optional] {
                let (mut writer, reader) = tokio::io::duplex(1024);
                writer.write_all(b"PROXY ").await.unwrap();
                let config = Config {
                    mode,
                    timeout,
                    ..Config::default()
                };
                let result = accept(Box::new(reader), &config, PeerTrust::Trusted).await;
                assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
                assert_eq!(writer.read(&mut [0u8; 1]).await.unwrap(), 0);
            }
        })
        .await;
    }

    #[tokio::test]
    async fn untrusted_required_and_optional_are_rejected_before_reading() {
        bounded(async {
            for mode in [Mode::Required, Mode::Optional] {
                let (mut writer, reader) = tokio::io::duplex(16);
                let config = Config {
                    mode,
                    timeout: None,
                    ..Config::default()
                };
                let result = accept(Box::new(reader), &config, PeerTrust::Untrusted).await;
                assert_eq!(
                    result.err().unwrap().kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert_eq!(writer.read(&mut [0u8; 1]).await.unwrap(), 0);
            }
        })
        .await;
    }

    #[tokio::test]
    async fn stream_adapter_rejects_datagram_but_accepts_opaque_local() {
        bounded(async {
            for command in [0x21, 0x20] {
                let wire = v2(command, 0x12, IPV4);
                let (header, _) = parsed(&wire);
                if command == 0x21 {
                    assert_eq!(header.transport, Transport::Datagram);
                }
                let (mut writer, reader) = tokio::io::duplex(1024);
                writer.write_all(&wire).await.unwrap();
                writer.shutdown().await.unwrap();
                let result = accept(Box::new(reader), &Config::default(), PeerTrust::Trusted).await;
                if command == 0x21 {
                    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
                } else {
                    assert!(result.unwrap().header.unwrap().source_addr().is_none());
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn canceled_accept_closes_owned_stream_without_a_detached_reader() {
        bounded(async {
            let (mut writer, reader) = tokio::io::duplex(16);
            let task = tokio::spawn(async move {
                accept(
                    Box::new(reader),
                    &Config {
                        timeout: None,
                        ..Config::default()
                    },
                    PeerTrust::Trusted,
                )
                .await
            });
            writer.write_all(b"PROXY ").await.unwrap();
            tokio::task::yield_now().await;
            task.abort();
            assert!(task.await.err().unwrap().is_cancelled());
            assert_eq!(writer.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await;
    }

    #[tokio::test]
    async fn local_tcp_listener_adapter_preserves_input_and_forwards_output() {
        bounded(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let ((), ()) = tokio::join!(
                async {
                    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
                    let mut request = V1.to_vec();
                    request.extend_from_slice(b"application");
                    client.write_all(&request).await.unwrap();
                    client.shutdown().await.unwrap();
                    let mut response = Vec::new();
                    client.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, b"accepted");
                },
                async {
                    let (stream, real_peer) = listener.accept().await.unwrap();
                    assert!(real_peer.ip().is_loopback());
                    // This test explicitly trusts its loopback test peer.
                    let mut accepted =
                        accept(Box::new(stream), &Config::default(), PeerTrust::Trusted)
                            .await
                            .unwrap();
                    assert_eq!(
                        accepted.header.unwrap().source_addr(),
                        Some("192.0.2.1:12345".parse().unwrap())
                    );
                    let mut request = Vec::new();
                    accepted.stream.read_to_end(&mut request).await.unwrap();
                    assert_eq!(request, b"application");
                    accepted.stream.write_all(b"accepted").await.unwrap();
                    accepted.stream.shutdown().await.unwrap();
                }
            );
        })
        .await;
    }
}
