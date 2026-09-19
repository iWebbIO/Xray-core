//! Raw L3 IP, UDP and ICMP wire handling. No Ethernet or TUN PI header is used.
//!
//! Echo replies and UDP packet construction mirror `stack_gvisor.go` and
//! `icmp/packet.go`: fresh IP headers, TTL/hop limit 64, and proper pseudo-header
//! checksums. Fragment reassembly, IPv6 extension headers, and jumbograms are
//! explicitly unsupported rather than misinterpreted as transport payloads.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub const ICMPV4: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMPV6: u8 = 58;
pub const MAX_IP_PACKET: usize = 65_575;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug)]
pub struct IpPacket<'a> {
    pub version: IpVersion,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub hop_limit: u8,
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchoRequest<'a> {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

fn malformed(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Internet checksum, including the zero padding for an odd final octet.
pub fn checksum(bytes: &[u8]) -> u16 {
    finish(sum(bytes))
}

fn sum(bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    let value: u64 = chunks
        .by_ref()
        .map(|b| u64::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    value + chunks.remainder().first().map_or(0, |b| u64::from(*b) << 8)
}

fn finish(mut value: u64) -> u16 {
    while value >> 16 != 0 {
        value = (value & 0xffff) + (value >> 16);
    }
    !(value as u16)
}

fn transport_checksum(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    message: &[u8],
) -> io::Result<u16> {
    let mut value = sum(message) + u64::from(protocol);
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            if message.len() > u16::MAX as usize {
                return Err(malformed("IPv4 transport message is too large"));
            }
            value += sum(&source.octets()) + sum(&destination.octets()) + message.len() as u64;
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let len =
                u32::try_from(message.len()).map_err(|_| malformed("IPv6 message is too large"))?;
            value += sum(&source.octets()) + sum(&destination.octets()) + sum(&len.to_be_bytes());
        }
        _ => return Err(malformed("IP source and destination families differ")),
    }
    Ok(finish(value))
}

pub fn parse_ip(bytes: &[u8]) -> io::Result<IpPacket<'_>> {
    match bytes.first().map(|b| b >> 4) {
        Some(4) => {
            if bytes.len() < 20 {
                return Err(malformed("truncated IPv4 header"));
            }
            let header_len = usize::from(bytes[0] & 15) * 4;
            let packet_len = usize::from(word(bytes, 2));
            if header_len < 20 || header_len > packet_len || packet_len != bytes.len() {
                return Err(malformed("invalid IPv4 header or total length"));
            }
            if checksum(&bytes[..header_len]) != 0 {
                return Err(malformed("invalid IPv4 header checksum"));
            }
            let fragments = word(bytes, 6);
            if fragments & 0x8000 != 0 {
                return Err(malformed("IPv4 reserved fragment bit is set"));
            }
            if fragments & 0x3fff != 0 {
                return Err(unsupported("IPv4 fragment reassembly is not implemented"));
            }
            Ok(IpPacket {
                version: IpVersion::V4,
                source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).into(),
                destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]).into(),
                protocol: bytes[9],
                hop_limit: bytes[8],
                header: &bytes[..header_len],
                payload: &bytes[header_len..],
            })
        }
        Some(6) => {
            if bytes.len() < 40 {
                return Err(malformed("truncated IPv6 header"));
            }
            let packet_len = 40 + usize::from(word(bytes, 4));
            if packet_len != bytes.len() {
                return Err(malformed(
                    "invalid IPv6 payload length or unsupported jumbogram",
                ));
            }
            if matches!(bytes[6], 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140) {
                return Err(unsupported(
                    "IPv6 extension headers and fragment reassembly are not implemented",
                ));
            }
            let mut source = [0; 16];
            source.copy_from_slice(&bytes[8..24]);
            let mut destination = [0; 16];
            destination.copy_from_slice(&bytes[24..40]);
            Ok(IpPacket {
                version: IpVersion::V6,
                source: Ipv6Addr::from(source).into(),
                destination: Ipv6Addr::from(destination).into(),
                protocol: bytes[6],
                hop_limit: bytes[7],
                header: &bytes[..40],
                payload: &bytes[40..],
            })
        }
        _ => Err(malformed("expected raw IPv4 or IPv6 packet")),
    }
}

pub fn parse_udp<'a>(packet: &IpPacket<'a>) -> io::Result<UdpPacket<'a>> {
    let message = packet.payload;
    if packet.protocol != UDP || message.len() < 8 {
        return Err(malformed("expected UDP header"));
    }
    let length = usize::from(word(message, 4));
    if length != message.len() {
        return Err(malformed("invalid UDP length"));
    }
    let check = word(message, 6);
    if (check == 0 && packet.version == IpVersion::V6)
        || (check != 0 && transport_checksum(packet.source, packet.destination, UDP, message)? != 0)
    {
        return Err(malformed("invalid UDP checksum"));
    }
    Ok(UdpPacket {
        source: SocketAddr::new(packet.source, word(message, 0)),
        destination: SocketAddr::new(packet.destination, word(message, 2)),
        payload: &message[8..],
    })
}

/// Validate TCP framing/checksum before passing a packet to a userspace stack.
pub fn validate_tcp(packet: &IpPacket<'_>) -> io::Result<()> {
    let message = packet.payload;
    if packet.protocol != TCP || message.len() < 20 {
        return Err(malformed("expected TCP header"));
    }
    let header_len = usize::from(message[12] >> 4) * 4;
    if header_len < 20 || header_len > message.len() {
        return Err(malformed("invalid TCP data offset"));
    }
    if transport_checksum(packet.source, packet.destination, TCP, message)? != 0 {
        return Err(malformed("invalid TCP checksum"));
    }
    Ok(())
}

pub fn parse_echo_request<'a>(packet: &IpPacket<'a>) -> io::Result<EchoRequest<'a>> {
    let (protocol, message_type) = match packet.version {
        IpVersion::V4 => (ICMPV4, 8),
        IpVersion::V6 => (ICMPV6, 128),
    };
    let message = packet.payload;
    if packet.protocol != protocol
        || message.len() < 8
        || message[0] != message_type
        || message[1] != 0
    {
        return Err(malformed("expected ICMP echo request with code zero"));
    }
    let check = match packet.version {
        IpVersion::V4 => checksum(message),
        IpVersion::V6 => transport_checksum(packet.source, packet.destination, ICMPV6, message)?,
    };
    if check != 0 {
        return Err(malformed("invalid ICMP checksum"));
    }
    Ok(EchoRequest {
        identifier: word(message, 4),
        sequence: word(message, 6),
        payload: &message[8..],
    })
}

/// Construct a complete raw IP packet, not just the transport message.
pub fn build_echo_reply(packet: &IpPacket<'_>) -> io::Result<Vec<u8>> {
    parse_echo_request(packet)?;
    let mut reply = packet.payload.to_vec();
    reply[0] = match packet.version {
        IpVersion::V4 => 0,
        IpVersion::V6 => 129,
    };
    reply[2..4].fill(0);
    let check = match packet.version {
        IpVersion::V4 => checksum(&reply),
        IpVersion::V6 => transport_checksum(packet.destination, packet.source, ICMPV6, &reply)?,
    };
    reply[2..4].copy_from_slice(&check.to_be_bytes());
    build_ip(packet.destination, packet.source, packet.protocol, &reply)
}

pub fn build_udp(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let length = payload
        .len()
        .checked_add(8)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| malformed("UDP payload exceeds wire length"))?;
    let mut message = Vec::with_capacity(usize::from(length));
    message.extend_from_slice(&source.port().to_be_bytes());
    message.extend_from_slice(&destination.port().to_be_bytes());
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(payload);
    let mut check = transport_checksum(source.ip(), destination.ip(), UDP, &message)?;
    // A computed zero is encoded as all ones; zero on the wire disables the
    // IPv4 UDP checksum and is invalid for IPv6.
    if check == 0 {
        check = 0xffff;
    }
    message[6..8].copy_from_slice(&check.to_be_bytes());
    build_ip(source.ip(), destination.ip(), UDP, &message)
}

pub fn build_ip(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut packet = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = payload
                .len()
                .checked_add(20)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| malformed("IPv4 packet exceeds wire length"))?;
            let mut packet = vec![0; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            packet[8] = 64;
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let check = checksum(&packet);
            packet[10..12].copy_from_slice(&check.to_be_bytes());
            packet
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u16::try_from(payload.len())
                .map_err(|_| malformed("IPv6 jumbograms are unsupported"))?;
            let mut packet = vec![0; 40];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&length.to_be_bytes());
            packet[6] = protocol;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
            packet
        }
        _ => return Err(malformed("IP source and destination families differ")),
    };
    packet.extend_from_slice(payload);
    Ok(packet)
}

#[cfg(test)]
#[path = "packet_tests.rs"]
mod tests;
