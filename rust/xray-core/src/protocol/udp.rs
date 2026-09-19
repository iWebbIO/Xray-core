//! UDP framing and SOCKS5 association state, derived from `proxy/socks`,
//! `proxy/trojan/protocol.go`, and `proxy/vless/encoding/addons.go`.
//!
//! These helpers do not open sockets or authenticate protocol requests. The
//! caller must retain the SOCKS TCP control connection, close both sockets when
//! the association closes, and supply the VLESS request's fixed destination.
//! Stream readers consume exactly one frame; EOF between frames returns `None`,
//! while EOF within a frame is an error. A failed or cancelled stream operation
//! may have consumed bytes, so its connection must not be reused.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::address::{Address, Destination};

/// `common/buf.Size`: Go's SOCKS writer drops packets larger than this.
pub const SOCKS5_MAX_PACKET_SIZE: usize = 8192;
/// `proxy/trojan/protocol.go:maxLength` (payload only).
pub const TROJAN_MAX_PAYLOAD_SIZE: usize = 8192;
/// VLESS's two-byte, big-endian length field counts payload bytes.
pub const VLESS_MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

/// Parse one complete SOCKS5 UDP packet. Reserved bytes are ignored, as in Go;
/// fragmentation is unsupported and every nonzero FRAG value is rejected.
pub fn decode_socks5_packet(packet: &[u8]) -> Result<Datagram> {
    ensure!(packet.len() >= 3, "truncated SOCKS5 UDP header");
    ensure!(
        packet[2] == 0,
        "fragmented SOCKS5 UDP packet is unsupported"
    );
    let mut input = &packet[3..];
    let destination = decode_socks_destination(&mut input)?;
    Ok(Datagram {
        destination,
        payload: input.to_vec(),
    })
}

/// Encode one packet. Oversize packets return an error rather than Go's empty
/// drop buffer, so a dispatcher can count/drop the packet explicitly.
pub fn encode_socks5_packet(destination: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    encode_socks_destination(destination, &mut packet)?;
    ensure!(
        payload.len() <= SOCKS5_MAX_PACKET_SIZE - packet.len(),
        "SOCKS5 UDP packet exceeds {SOCKS5_MAX_PACKET_SIZE} bytes"
    );
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Decode the first Trojan UDP frame and return its consumed byte count.
/// A subsequent frame may follow in the same input buffer.
pub fn decode_trojan_frame(frame: &[u8]) -> Result<(Datagram, usize)> {
    let mut input = frame;
    let destination = decode_socks_destination(&mut input)?;
    let length = usize::from(take_u16(&mut input)?);
    ensure!(
        length <= TROJAN_MAX_PAYLOAD_SIZE,
        "oversize Trojan UDP payload"
    );
    ensure!(take(&mut input, 2)? == b"\r\n", "invalid Trojan UDP CRLF");
    let payload = take(&mut input, length)?.to_vec();
    Ok((
        Datagram {
            destination,
            payload,
        },
        frame.len() - input.len(),
    ))
}

pub fn encode_trojan_frame(destination: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= TROJAN_MAX_PAYLOAD_SIZE,
        "oversize Trojan UDP payload"
    );
    let mut frame = Vec::with_capacity(payload.len() + 263);
    encode_socks_destination(destination, &mut frame)?;
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Read one Trojan UDP frame after the authenticated UDP request header.
pub async fn read_trojan_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Datagram>> {
    let Some(family) = read_first_byte(reader).await? else {
        return Ok(None);
    };
    let destination = read_socks_destination(reader, family)
        .await
        .context("read Trojan UDP destination")?;
    let length = usize::from(reader.read_u16().await.context("read Trojan UDP length")?);
    ensure!(
        length <= TROJAN_MAX_PAYLOAD_SIZE,
        "oversize Trojan UDP payload"
    );
    let mut crlf = [0; 2];
    reader
        .read_exact(&mut crlf)
        .await
        .context("read Trojan UDP CRLF")?;
    ensure!(crlf == *b"\r\n", "invalid Trojan UDP CRLF");
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("read Trojan UDP payload")?;
    Ok(Some(Datagram {
        destination,
        payload,
    }))
}

pub async fn write_trojan_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    destination: &Destination,
    payload: &[u8],
) -> Result<()> {
    let frame = encode_trojan_frame(destination, payload)?;
    writer
        .write_all(&frame)
        .await
        .context("write Trojan UDP frame")
}

/// Decode one VLESS payload frame. Its destination comes from the authenticated
/// request, not this frame. The consumed count permits coalesced stream input.
pub fn decode_vless_frame(frame: &[u8]) -> Result<(&[u8], usize)> {
    let mut input = frame;
    let length = usize::from(take_u16(&mut input)?);
    let payload = take(&mut input, length)?;
    Ok((payload, length + 2))
}

/// Empty writes are omitted, matching Go's `LengthPacketWriter`. The reader
/// nevertheless accepts a zero-length frame received from another peer.
pub fn encode_vless_frame(payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= VLESS_MAX_PAYLOAD_SIZE,
        "oversize VLESS UDP payload"
    );
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub async fn read_vless_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let Some(high) = read_first_byte(reader).await? else {
        return Ok(None);
    };
    let low = reader.read_u8().await.context("read VLESS UDP length")?;
    let mut payload = vec![0; usize::from(u16::from_be_bytes([high, low]))];
    reader
        .read_exact(&mut payload)
        .await
        .context("read VLESS UDP payload")?;
    Ok(Some(payload))
}

pub async fn write_vless_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let frame = encode_vless_frame(payload)?;
    writer
        .write_all(&frame)
        .await
        .context("write VLESS UDP frame")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCloseReason {
    TcpClosed,
    IdleTimeout,
    Closed,
}

/// State for one SOCKS5 UDP ASSOCIATE control connection.
///
/// Call `accept_source` before dispatching any received packet, and send replies
/// only to `response_target`. Call `close_tcp` when its TCP connection reaches
/// EOF or fails. Schedule idle checks using `idle_remaining` and `is_open`; this
/// structure owns no sockets and does not spawn a background timer.
#[derive(Debug)]
pub struct Socks5UdpSession {
    expected_ip: IpAddr,
    expected_port: Option<u16>,
    remote: Option<SocketAddr>,
    last_activity: Instant,
    idle_timeout: Duration,
    close_reason: Option<SessionCloseReason>,
}

impl Socks5UdpSession {
    /// Match Go's SOCKS handshake: a domain or unspecified source address uses
    /// the TCP peer IP and learns its UDP port, even if a request port was given.
    /// A concrete requested source IP uses its given port, or learns port zero.
    pub fn new(
        tcp_peer: SocketAddr,
        requested_source: &Destination,
        idle_timeout: Duration,
        now: Instant,
    ) -> Self {
        let (expected_ip, port) = match &requested_source.address {
            Address::Ip(ip) if !canonical_ip(*ip).is_unspecified() => (*ip, requested_source.port),
            _ => (tcp_peer.ip(), 0),
        };
        let expected_port = (port != 0).then_some(port);
        Self {
            expected_ip: canonical_ip(expected_ip),
            expected_port,
            remote: expected_port.map(|port| {
                if canonical_ip(tcp_peer.ip()) == canonical_ip(expected_ip) {
                    let mut remote = tcp_peer;
                    remote.set_port(port);
                    remote
                } else {
                    SocketAddr::new(expected_ip, port)
                }
            }),
            last_activity: now,
            idle_timeout,
            close_reason: idle_timeout
                .is_zero()
                .then_some(SessionCloseReason::IdleTimeout),
        }
    }

    /// Return false without refreshing activity for an unexpected source. A
    /// learned port stays pinned until the association closes, including NAT
    /// rebindings. IP comparison accepts IPv4-mapped IPv6 like Go's IP.Equal.
    pub fn accept_source(&mut self, source: SocketAddr, now: Instant) -> bool {
        if !self.is_open(now)
            || canonical_ip(source.ip()) != self.expected_ip
            || source.port() == 0
            || self.expected_port.is_some_and(|port| port != source.port())
        {
            return false;
        }
        self.expected_port = Some(source.port());
        self.remote = Some(source);
        self.touch(now);
        true
    }

    /// Validate source before parsing. Rejected sources return `Ok(None)`;
    /// malformed frames from the permitted source return an error. Like Go,
    /// such a permitted packet still pins the source port and counts as activity.
    pub fn receive(
        &mut self,
        source: SocketAddr,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<Datagram>> {
        if !self.accept_source(source, now) {
            return Ok(None);
        }
        decode_socks5_packet(packet).map(Some)
    }

    /// Selecting a response target refreshes inactivity like an inbound packet.
    /// Returns None before a wildcard port is learned or after closure.
    pub fn response_target(&mut self, now: Instant) -> Option<SocketAddr> {
        if !self.is_open(now) {
            return None;
        }
        let remote = self.remote?;
        self.touch(now);
        Some(remote)
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote
    }

    pub fn close_reason(&self) -> Option<SessionCloseReason> {
        self.close_reason
    }

    pub fn close_tcp(&mut self) {
        self.close_reason
            .get_or_insert(SessionCloseReason::TcpClosed);
    }

    pub fn close(&mut self) {
        self.close_reason.get_or_insert(SessionCloseReason::Closed);
    }

    /// Once elapsed, timeout is permanent; later packets cannot revive it.
    pub fn is_open(&mut self, now: Instant) -> bool {
        if self.close_reason.is_none()
            && now.saturating_duration_since(self.last_activity) >= self.idle_timeout
        {
            self.close_reason = Some(SessionCloseReason::IdleTimeout);
        }
        self.close_reason.is_none()
    }

    /// Remaining inactivity window, or None for a closed association.
    pub fn idle_remaining(&mut self, now: Instant) -> Option<Duration> {
        self.is_open(now).then(|| {
            self.idle_timeout
                .saturating_sub(now.saturating_duration_since(self.last_activity))
        })
    }

    fn touch(&mut self, now: Instant) {
        // An earlier timestamp cannot move the activity deadline backwards.
        self.last_activity = self.last_activity.max(now);
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    ensure!(input.len() >= length, "truncated UDP frame");
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn take_u16(input: &mut &[u8]) -> Result<u16> {
    let bytes = take(input, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn decode_socks_destination(input: &mut &[u8]) -> Result<Destination> {
    let family = take(input, 1)?[0];
    let address = match family {
        1 => {
            let bytes = take(input, 4)?;
            Address::Ip(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into())
        }
        4 => {
            let bytes: [u8; 16] = take(input, 16)?.try_into().expect("16-byte slice");
            Address::Ip(Ipv6Addr::from(bytes).into())
        }
        3 => {
            let length = usize::from(take(input, 1)?[0]);
            let domain =
                std::str::from_utf8(take(input, length)?).context("UDP domain is not UTF-8")?;
            Address::Domain(domain.to_owned())
        }
        _ => bail!("unsupported UDP address family {family}"),
    };
    let mut destination = Destination {
        address,
        port: take_u16(input)?,
    };
    normalize_destination(&mut destination)?;
    Ok(destination)
}

/// Preserve domain wire bytes until the common decoder validates them. The
/// general Destination reader parses IP strings too early for Go's prefix gate.
async fn read_socks_destination<R: AsyncRead + Unpin>(
    reader: &mut R,
    family: u8,
) -> Result<Destination> {
    let mut header = vec![family];
    let address_length = match family {
        1 => 4,
        4 => 16,
        3 => {
            let length = reader.read_u8().await.context("read UDP domain length")?;
            header.push(length);
            usize::from(length)
        }
        _ => bail!("unsupported UDP address family {family}"),
    };
    let offset = header.len();
    header.resize(offset + address_length + 2, 0);
    reader
        .read_exact(&mut header[offset..])
        .await
        .context("read UDP address and port")?;
    decode_socks_destination(&mut header.as_slice())
}

fn normalize_destination(destination: &mut Destination) -> Result<()> {
    if let Address::Ip(ip) = &mut destination.address {
        *ip = canonical_ip(*ip);
        return Ok(());
    }
    if let Address::Domain(domain) = &destination.address {
        ensure!(
            !domain.is_empty() && domain.len() <= 255,
            "invalid UDP domain length"
        );
        let host = domain
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(domain)
            .trim();
        // Go's address parser only probes possible IP literals beginning with
        // '[' or a digit; other strings must satisfy hostname validation.
        if (domain.starts_with('[') || domain.as_bytes()[0].is_ascii_digit())
            && let Ok(ip) = host.parse::<IpAddr>()
        {
            destination.address = Address::Ip(canonical_ip(ip));
            return Ok(());
        }
        ensure!(
            domain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
            "invalid UDP domain name"
        );
    }
    Ok(())
}

fn encode_socks_destination(destination: &Destination, output: &mut Vec<u8>) -> Result<()> {
    match &destination.address {
        Address::Ip(ip) => match canonical_ip(*ip) {
            IpAddr::V4(ip) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                output.push(4);
                output.extend_from_slice(&ip.octets());
            }
        },
        Address::Domain(domain) => {
            let mut validated = destination.clone();
            normalize_destination(&mut validated)?;
            output.extend_from_slice(&[3, domain.len() as u8]);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

async fn read_first_byte<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<u8>> {
    let mut byte = [0];
    match reader
        .read(&mut byte)
        .await
        .context("read UDP stream frame")?
    {
        0 => Ok(None),
        _ => Ok(Some(byte[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };
    use tokio::io::ReadBuf;

    fn destination(host: &str, port: u16) -> Destination {
        Destination {
            address: Address::parse(host).unwrap(),
            port,
        }
    }

    fn socket(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    // Independent literal wire vectors from each Go writer's field ordering.
    #[test]
    fn socks5_source_vectors() {
        let vectors = [
            (
                destination("1.2.3.4", 53),
                vec![0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 0xde, 0xad],
            ),
            (
                destination("dns.example", 5353),
                b"\0\0\0\x03\x0bdns.example\x14\xe9\xde\xad".to_vec(),
            ),
            // The exact IPv6 address and port used by Go's TestUDPEncoding.
            (
                destination("102:304:506:708:900:102:304:506", 1024),
                vec![
                    0, 0, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 4, 0, 0xde, 0xad,
                ],
            ),
        ];
        for (target, wire) in vectors {
            assert_eq!(encode_socks5_packet(&target, &[0xde, 0xad]).unwrap(), wire);
            assert_eq!(
                decode_socks5_packet(&wire).unwrap(),
                Datagram {
                    destination: target,
                    payload: vec![0xde, 0xad],
                }
            );
            let header_length = wire.len() - 2;
            for length in 0..header_length {
                assert!(
                    decode_socks5_packet(&wire[..length]).is_err(),
                    "accepted prefix {length}"
                );
            }
            assert!(
                decode_socks5_packet(&wire[..header_length])
                    .unwrap()
                    .payload
                    .is_empty()
            );
        }
    }

    #[test]
    fn socks5_fragments_reserved_bytes_and_size_limits() {
        let target = destination("127.0.0.1", 53);
        let mut wire = encode_socks5_packet(&target, b"data").unwrap();
        wire[0] = 0xab;
        wire[1] = 0xcd;
        assert_eq!(decode_socks5_packet(&wire).unwrap().payload, b"data");
        for fragment in 1..=255 {
            wire[2] = fragment;
            assert!(decode_socks5_packet(&wire).is_err());
        }
        assert_eq!(
            encode_socks5_packet(&target, &vec![0; 8182]).unwrap().len(),
            8192
        );
        assert!(encode_socks5_packet(&target, &vec![0; 8183]).is_err());
    }

    #[test]
    fn malformed_addresses_and_ip_domains() {
        for wire in [
            &b"\0\0\0\x09\0\0"[..],
            &b"\0\0\0\x03\0\0\x35"[..],
            &b"\0\0\0\x03\x01\xff\0\x35"[..],
            &b"\0\0\0\x03\x03a/b\0\x35"[..],
        ] {
            assert!(decode_socks5_packet(wire).is_err());
        }
        let wire = b"\0\0\0\x03\x09127.0.0.1\0\x35";
        assert_eq!(
            decode_socks5_packet(wire).unwrap().destination,
            destination("127.0.0.1", 53)
        );
        let bracketed = b"\0\0\0\x03\x05[::1]\0\x35";
        assert_eq!(
            decode_socks5_packet(bracketed).unwrap().destination,
            destination("::1", 53)
        );
        for domain in ["", "a/b", "a b"] {
            let invalid = Destination {
                address: Address::Domain(domain.to_owned()),
                port: 53,
            };
            assert!(encode_trojan_frame(&invalid, b"x").is_err());
        }
        let long = Destination {
            address: Address::Domain("a".repeat(256)),
            port: 53,
        };
        assert!(encode_socks5_packet(&long, b"x").is_err());
    }

    fn domain_wire(domain: &str) -> Vec<u8> {
        let mut wire = vec![3, domain.len() as u8];
        wire.extend_from_slice(domain.as_bytes());
        wire.extend_from_slice(&[0, 53]);
        wire
    }

    #[tokio::test]
    async fn domain_ip_prefix_and_whitespace_match_go_in_both_decoders() {
        let cases = [
            ("2001:db8::1", destination("2001:db8::1", 53)),
            ("[abcd::1]", destination("abcd::1", 53)),
            ("[::1]", destination("::1", 53)),
            ("[ \t::1 \r\n]", destination("::1", 53)),
            ("[1.2.3.4]", destination("1.2.3.4", 53)),
            ("1.2.3.4 \t", destination("1.2.3.4", 53)),
            ("1.2.3.4\u{a0}", destination("1.2.3.4", 53)),
            ("[::ffff:192.0.2.1]", destination("192.0.2.1", 53)),
            ("0:0:0:0:0:ffff:c000:201", destination("192.0.2.1", 53)),
            ("[::192.0.2.1]", destination("::192.0.2.1", 53)),
            // Go falls back to the original domain when ParseIP fails.
            ("1.2.3.004", destination("1.2.3.004", 53)),
            ("3.example", destination("3.example", 53)),
        ];
        for (domain, expected) in cases {
            let address = domain_wire(domain);
            let mut socks = vec![0, 0, 0];
            socks.extend_from_slice(&address);
            socks.push(b'x');
            assert_eq!(
                decode_socks5_packet(&socks).unwrap().destination,
                expected,
                "{domain:?}"
            );
            let mut trojan = address;
            trojan.extend_from_slice(b"\0\x01\r\nx");
            assert_eq!(
                decode_trojan_frame(&trojan).unwrap().0.destination,
                expected,
                "{domain:?}"
            );
            let decoded = read_trojan_frame(&mut ByteReader(&trojan))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(decoded.destination, expected, "{domain:?}");
            assert_eq!(decoded.payload, b"x");
        }
        for domain in [
            "abcd::1",
            "::1",
            "::ffff:192.0.2.1",
            " [::1]",
            "[::1] ",
            "[example.org]",
            "1.example ",
        ] {
            let address = domain_wire(domain);
            let mut socks = vec![0, 0, 0];
            socks.extend_from_slice(&address);
            assert!(decode_socks5_packet(&socks).is_err(), "{domain:?}");
            let mut trojan = address;
            trojan.extend_from_slice(b"\0\x01\r\nx");
            assert!(decode_trojan_frame(&trojan).is_err(), "{domain:?}");
            assert!(
                read_trojan_frame(&mut ByteReader(&trojan)).await.is_err(),
                "{domain:?}"
            );
            let invalid = Destination {
                address: Address::Domain(domain.to_owned()),
                port: 53,
            };
            assert!(encode_trojan_frame(&invalid, b"x").is_err(), "{domain:?}");
        }
    }

    #[tokio::test]
    async fn mapped_ipv6_wire_addresses_are_canonical_ipv4() {
        let address = [
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1, 0, 53,
        ];
        let expected = destination("192.0.2.1", 53);
        let mut socks = vec![0, 0, 0];
        socks.extend_from_slice(&address);
        socks.push(b'x');
        assert_eq!(decode_socks5_packet(&socks).unwrap().destination, expected);
        let mut trojan = address.to_vec();
        trojan.extend_from_slice(b"\0\x01\r\nx");
        assert_eq!(
            decode_trojan_frame(&trojan).unwrap().0.destination,
            expected
        );
        assert_eq!(
            read_trojan_frame(&mut ByteReader(&trojan))
                .await
                .unwrap()
                .unwrap()
                .destination,
            expected
        );
        let mapped = destination("::ffff:192.0.2.1", 53);
        assert_eq!(
            encode_socks5_packet(&mapped, b"x").unwrap(),
            b"\0\0\0\x01\xc0\0\x02\x01\0\x35x"
        );
        assert_eq!(
            encode_trojan_frame(&mapped, b"x").unwrap(),
            b"\x01\xc0\0\x02\x01\0\x35\0\x01\r\nx"
        );
    }

    #[test]
    fn trojan_source_vectors_and_coalesced_frames() {
        let target = destination("dns.example", 53);
        let wire = b"\x03\x0bdns.example\0\x35\0\x03\r\nabc";
        assert_eq!(encode_trojan_frame(&target, b"abc").unwrap(), wire);
        let mut pair = wire.to_vec();
        pair.extend_from_slice(b"\x01\x7f\0\0\x01\x01\xbb\0\x01\r\nx");
        let (packet, consumed) = decode_trojan_frame(&pair).unwrap();
        assert_eq!(
            packet,
            Datagram {
                destination: target,
                payload: b"abc".to_vec()
            }
        );
        assert_eq!(consumed, wire.len());
        let (next, next_length) = decode_trojan_frame(&pair[consumed..]).unwrap();
        assert_eq!(next.destination, destination("127.0.0.1", 443));
        assert_eq!(next.payload, b"x");
        assert_eq!(consumed + next_length, pair.len());
        for length in 0..wire.len() {
            assert!(decode_trojan_frame(&wire[..length]).is_err());
        }
        assert!(decode_trojan_frame(b"\x01\x7f\0\0\x01\0\x35\0\0xx").is_err());
        assert!(decode_trojan_frame(b"\x01\x7f\0\0\x01\0\x35\x20\x01\r\n").is_err());
        assert!(encode_trojan_frame(&destination("::1", 53), &vec![0; 8193]).is_err());
    }

    #[test]
    fn vless_source_vectors_empty_and_length_boundaries() {
        assert_eq!(encode_vless_frame(b"hello").unwrap(), b"\0\x05hello");
        assert_eq!(
            decode_vless_frame(b"\0\x03abc\0\x01x").unwrap(),
            (&b"abc"[..], 5)
        );
        assert_eq!(decode_vless_frame(b"\0\0").unwrap(), (&b""[..], 2));
        assert!(encode_vless_frame(b"").unwrap().is_empty());
        for length in [1, 255, 256, 8192, 65535] {
            let payload = vec![0xa5; length];
            let wire = encode_vless_frame(&payload).unwrap();
            assert_eq!(wire[..2], (length as u16).to_be_bytes());
            assert_eq!(
                decode_vless_frame(&wire).unwrap(),
                (payload.as_slice(), length + 2)
            );
            assert!(decode_vless_frame(&wire[..wire.len() - 1]).is_err());
        }
        assert!(encode_vless_frame(&vec![0; 65536]).is_err());
        assert!(decode_vless_frame(&[]).is_err());
        assert!(decode_vless_frame(&[0]).is_err());
    }

    /// Force one byte per read, independently of Tokio's buffering behavior.
    struct ByteReader<'a>(&'a [u8]);

    impl AsyncRead for ByteReader<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.0.is_empty() && buffer.remaining() != 0 {
                buffer.put_slice(&self.0[..1]);
                self.0 = &self.0[1..];
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn stream_readers_handle_fragmentation_coalescing_and_eof() {
        let target = destination("127.0.0.1", 53);
        let first = b"\x01\x7f\0\0\x01\0\x35\0\x03\r\nabc";
        let mut trojan = first.to_vec();
        trojan.extend_from_slice(b"\x03\x01a\0\x50\0\0\r\n");
        let mut reader = ByteReader(&trojan);
        let packet = read_trojan_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(packet.destination, target);
        assert_eq!(packet.payload, b"abc");
        let empty = read_trojan_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(empty.destination, destination("a", 80));
        assert!(empty.payload.is_empty());
        assert!(read_trojan_frame(&mut reader).await.unwrap().is_none());
        for length in 1..first.len() {
            assert!(
                read_trojan_frame(&mut ByteReader(&first[..length]))
                    .await
                    .is_err()
            );
        }
        let mut vless = ByteReader(b"\0\x03abc\0\0\0\x01x");
        for expected in [&b"abc"[..], &b""[..], &b"x"[..]] {
            assert_eq!(
                read_vless_frame(&mut vless).await.unwrap().unwrap(),
                expected
            );
        }
        assert!(read_vless_frame(&mut vless).await.unwrap().is_none());
        let first = b"\0\x03abc";
        for length in 1..first.len() {
            assert!(
                read_vless_frame(&mut ByteReader(&first[..length]))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn stream_writers_validate_before_writing() {
        let target = destination("1.2.3.4", 53);
        let mut wire = Vec::new();
        write_trojan_frame(&mut wire, &target, b"abc")
            .await
            .unwrap();
        assert_eq!(wire, b"\x01\x01\x02\x03\x04\0\x35\0\x03\r\nabc");
        wire.clear();
        assert!(
            write_trojan_frame(&mut wire, &target, &vec![0; 8193])
                .await
                .is_err()
        );
        assert!(wire.is_empty());
        write_vless_frame(&mut wire, b"abc").await.unwrap();
        assert_eq!(wire, b"\0\x03abc");
        wire.clear();
        write_vless_frame(&mut wire, b"").await.unwrap();
        assert!(write_vless_frame(&mut wire, &vec![0; 65536]).await.is_err());
        assert!(wire.is_empty());
    }

    #[tokio::test]
    async fn stream_writers_handle_partial_writes() {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let send = async {
            write_trojan_frame(&mut writer, &destination("1.2.3.4", 53), b"abc")
                .await
                .unwrap();
            write_vless_frame(&mut writer, b"xyz").await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            let mut wire = Vec::new();
            reader.read_to_end(&mut wire).await.unwrap();
            wire
        };
        let (_, wire) = tokio::join!(send, receive);
        assert_eq!(wire, b"\x01\x01\x02\x03\x04\0\x35\0\x03\r\nabc\0\x03xyz");
    }

    #[test]
    fn association_learns_source_and_rejects_spoofing() {
        let now = Instant::now();
        let client = socket("192.0.2.1:40000");
        let mut session = Socks5UdpSession::new(
            client,
            &destination("0.0.0.0", 1234),
            Duration::from_secs(10),
            now,
        );
        assert_eq!(session.remote_addr(), None);
        assert_eq!(session.response_target(now), None);
        assert!(!session.accept_source(socket("192.0.2.2:50000"), now));
        assert_eq!(session.remote_addr(), None);
        let udp = socket("192.0.2.1:50000");
        assert!(session.accept_source(udp, now));
        assert_eq!(session.response_target(now), Some(udp));
        assert!(!session.accept_source(socket("192.0.2.1:50001"), now));
        assert!(!session.accept_source(socket("192.0.2.2:50000"), now));
        assert_eq!(session.remote_addr(), Some(udp));
        let mut domain = Socks5UdpSession::new(
            client,
            &destination("example.org", 1234),
            Duration::from_secs(10),
            now,
        );
        assert!(domain.accept_source(udp, now));
    }

    #[test]
    fn association_explicit_source_and_mapped_ipv4() {
        let now = Instant::now();
        let timeout = Duration::from_secs(10);
        let mut session = Socks5UdpSession::new(
            socket("192.0.2.1:40000"),
            &destination("192.0.2.2", 50000),
            timeout,
            now,
        );
        assert!(!session.accept_source(socket("192.0.2.1:50000"), now));
        assert!(!session.accept_source(socket("192.0.2.2:50001"), now));
        let source = socket("[::ffff:192.0.2.2]:50000");
        assert!(session.accept_source(source, now));
        assert_eq!(session.response_target(now), Some(source));
        let mut wildcard = Socks5UdpSession::new(
            socket("192.0.2.1:40000"),
            &destination("192.0.2.2", 0),
            timeout,
            now,
        );
        assert!(wildcard.accept_source(socket("192.0.2.2:51000"), now));
        assert!(!wildcard.accept_source(socket("192.0.2.2:52000"), now));
    }

    #[test]
    fn association_lifetime_and_response_activity() {
        let now = Instant::now();
        let client = socket("192.0.2.1:40000");
        let source = socket("192.0.2.1:50000");
        let timeout = Duration::from_secs(10);
        let mut session = Socks5UdpSession::new(client, &destination("0.0.0.0", 0), timeout, now);
        assert!(session.accept_source(source, now + Duration::from_secs(9)));
        assert_eq!(
            session.idle_remaining(now + Duration::from_secs(10)),
            Some(Duration::from_secs(9))
        );
        assert_eq!(
            session.response_target(now + Duration::from_secs(18)),
            Some(source)
        );
        assert!(session.is_open(now + Duration::from_secs(27)));
        assert!(!session.accept_source(socket("192.0.2.2:50000"), now + Duration::from_secs(27)));
        assert!(!session.is_open(now + Duration::from_secs(28)));
        assert_eq!(
            session.close_reason(),
            Some(SessionCloseReason::IdleTimeout)
        );
        assert!(!session.accept_source(source, now + Duration::from_secs(29)));
        assert_eq!(session.response_target(now + Duration::from_secs(29)), None);
        assert_eq!(session.idle_remaining(now), None);
        session.close_tcp();
        assert_eq!(
            session.close_reason(),
            Some(SessionCloseReason::IdleTimeout)
        );
        let mut session = Socks5UdpSession::new(client, &destination("0.0.0.0", 0), timeout, now);
        session.close_tcp();
        assert_eq!(session.close_reason(), Some(SessionCloseReason::TcpClosed));
        assert!(!session.accept_source(source, now));
        assert_eq!(session.response_target(now), None);
        let mut disabled =
            Socks5UdpSession::new(client, &destination("0.0.0.0", 0), Duration::ZERO, now);
        assert!(!disabled.is_open(now));
    }

    #[test]
    fn association_validates_source_before_decoding() {
        let now = Instant::now();
        let source = socket("192.0.2.1:50000");
        let mut session = Socks5UdpSession::new(
            socket("192.0.2.1:40000"),
            &destination("0.0.0.0", 0),
            Duration::from_secs(10),
            now,
        );
        assert_eq!(
            session
                .receive(socket("192.0.2.2:50000"), &[], now)
                .unwrap(),
            None
        );
        assert!(session.receive(source, &[], now).is_err());
        assert_eq!(session.remote_addr(), Some(source));
        let packet = b"\0\0\0\x01\x01\x02\x03\x04\0\x35dns";
        assert_eq!(
            session
                .receive(source, packet, now)
                .unwrap()
                .unwrap()
                .payload,
            b"dns"
        );
        session.close_tcp();
        assert_eq!(session.receive(source, packet, now).unwrap(), None);
    }
}
