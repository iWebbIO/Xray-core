// P17 masque_connectip: RFC 9484 CONNECT-IP capsule codec and helpers.
#![allow(dead_code)]

//! CONTRACT-CAPSULE: the RFC 9484 (CONNECT-IP) capsule protocol codec plus the
//! helpers the MASQUE transport builds on, ported from the Go reference
//! `transport/internet/masque/connectip`:
//!
//! - `capsule` — capsule framing (RFC 9297: varint type, varint length, value)
//!   with the CONNECT-IP control capsules of `capsule.go`. Capsule type values
//!   follow the Go reference exactly (and the IANA "HTTP Capsule Types"
//!   registry): DATAGRAM 0x00, ADDRESS_ASSIGN 0x01, ADDRESS_REQUEST 0x02,
//!   ROUTE_ADVERTISEMENT 0x03.
//! - `range_to_prefixes_ipv4` / `range_to_prefixes_ipv6` — `iprange.go`.
//! - `calculate_ipv4_checksum` — `checksum.go`.
//! - `ConnectIpRequest` — the extended-CONNECT request builder of `request.go`.
//!
//! Capsule type notes for integrators: the CONTRACT-CAPSULE prose mentions
//! "datagram type 0x40", which is the draft-era CONNECT-UDP value; RFC 9484,
//! the IANA registry and the Go reference all use 0x00, so 0x00 is
//! implemented. RFC 9484 has no CLOSE capsule (the Go code closes by
//! FIN-ing the stream); the contract's `Capsule::Close` variant is encoded at
//! the (currently unassigned) type 0x0f with an empty value, which a Go peer
//! discards through the unknown-capsule default branch.

use ipnet::{Ipv4Net, Ipv6Net};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The extended CONNECT protocol identifier (Go `requestProtocol`).
pub const CONNECT_IP_PROTOCOL: &str = "connect-ip";
/// Header name by which capsule-protocol support is negotiated (Go
/// `http3.CapsuleProtocolHeader`).
pub const CAPSULE_PROTOCOL_HEADER: &str = "Capsule-Protocol";
/// The only capsule-protocol header value Xray emits (Go
/// `capsuleProtocolHeaderValue`).
pub const CAPSULE_PROTOCOL_HEADER_VALUE: &str = "?1";

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn eof(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg.into())
}

pub mod capsule {
    //! RFC 9297 capsule framing and the RFC 9484 CONNECT-IP control capsules,
    //! ported from `capsule.go` / `address.go`.

    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use std::cmp::Ordering;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{eof, host_mask, invalid, range_to_prefixes_ipv4, range_to_prefixes_ipv6};

    /// Capsule type of HTTP datagrams carried in capsules (IANA 0x00; Go
    /// `capsuleTypeDatagram`).
    pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;
    /// ADDRESS_ASSIGN (IANA 0x01; Go `capsuleTypeAddressAssign`).
    pub const CAPSULE_TYPE_ADDRESS_ASSIGN: u64 = 0x01;
    /// ADDRESS_REQUEST (IANA 0x02; Go `capsuleTypeAddressRequest`).
    pub const CAPSULE_TYPE_ADDRESS_REQUEST: u64 = 0x02;
    /// ROUTE_ADVERTISEMENT (IANA 0x03; Go `capsuleTypeRouteAdvertisement`).
    pub const CAPSULE_TYPE_ROUTE_ADVERTISEMENT: u64 = 0x03;
    /// CLOSE: not defined by RFC 9484 or the Go reference (closure there is a
    /// stream FIN). Local convention for the CONTRACT-CAPSULE enum: type 0x0f
    /// (unassigned in the IANA registry today) with an empty value. A Go peer
    /// discards it through the unknown-capsule branch.
    pub const CAPSULE_TYPE_CLOSE: u64 = 0x0f;

    /// Bound the memory used to parse a peer's addresses (Go
    /// `maxAddressesPerCapsule`).
    const MAX_ADDRESSES_PER_CAPSULE: usize = 8192;
    /// Bound the memory used to parse a peer's routes (Go
    /// `maxRoutesPerCapsule`).
    const MAX_ROUTES_PER_CAPSULE: usize = 8192;

    /// A parsed CONNECT-IP capsule (CONTRACT-CAPSULE enum).
    ///
    /// `AddressAssigned` entries are `(assigned prefix, request ID)`; the Go
    /// wire request ID is a u64 varint but the contract exposes u8, so request
    /// IDs above 255 are rejected by name on decode. `RouteAdvertisement`
    /// entries are `(advertised prefix, IP protocol)`; every wire address
    /// range is expanded into prefixes with `range_to_prefixes_ipv4/6`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Capsule {
        /// Local close signal (see `CAPSULE_TYPE_CLOSE`).
        Close,
        /// ADDRESS_ASSIGN: assigned addresses per family.
        AddressAssigned {
            ipv4: Vec<(Ipv4Net, u8)>,
            ipv6: Vec<(Ipv6Net, u8)>,
        },
        /// ROUTE_ADVERTISEMENT: advertised prefixes per family.
        RouteAdvertisement {
            ipv4: Vec<(Ipv4Net, u8)>,
            ipv6: Vec<(Ipv6Net, u8)>,
        },
        /// DATAGRAM: varint context ID followed by one IP packet.
        Datagram { context_id: u32, payload: Vec<u8> },
        /// Any other capsule type, preserved byte-exactly. An ADDRESS_REQUEST
        /// capsule (type 0x02) surfaces here as `Unknown { kind: 0x02 }`; use
        /// `parse_address_request_payload` on its payload and
        /// `encode_address_request` to produce one.
        Unknown { kind: u64, payload: Vec<u8> },
    }

    // ---------------------------------------------------------------- varint

    /// QUIC variable-length integer size in bytes (RFC 9000 section 16),
    /// minimal encoding as produced by Go `quicvarint.Append`.
    fn varint_len(v: u64) -> usize {
        if v < 1 << 6 {
            1
        } else if v < 1 << 14 {
            2
        } else if v < 1 << 30 {
            4
        } else {
            8
        }
    }

    fn append_varint(out: &mut Vec<u8>, v: u64) {
        if v < 1 << 6 {
            out.push(v as u8);
        } else if v < 1 << 14 {
            out.push(0x40 | (v >> 8) as u8);
            out.push(v as u8);
        } else if v < 1 << 30 {
            out.push(0x80 | (v >> 24) as u8);
            out.push((v >> 16) as u8);
            out.push((v >> 8) as u8);
            out.push(v as u8);
        } else {
            out.push(0xc0 | (v >> 56) as u8);
            for i in (0..8).rev() {
                out.push((v >> (i * 8)) as u8);
            }
        }
    }

    /// Reads a QUIC varint, returning `(value, bytes consumed)`.
    fn read_varint(input: &[u8]) -> Option<(u64, usize)> {
        let first = *input.first()?;
        let len = 1usize << (first >> 6);
        if input.len() < len {
            return None;
        }
        let mut v = (first & 0x3f) as u64;
        for &b in &input[1..len] {
            v = (v << 8) | b as u64;
        }
        Some((v, len))
    }

    // ---------------------------------------------------------------- framing

    fn encode_frame(kind: u64, value: &[u8], out: &mut Vec<u8>) {
        append_varint(out, kind);
        append_varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }

    /// Appends the wire encoding of `capsule` to `out` (CONTRACT-CAPSULE).
    ///
    /// Networks are written as their masked network address, which is what
    /// the Go `netip.Prefix` type always carries. `Unknown` capsule kinds that
    /// do not fit the 62-bit varint space cannot be encoded and are skipped
    /// with a warning.
    pub fn encode(capsule: &Capsule, out: &mut Vec<u8>) {
        match capsule {
            Capsule::Close => encode_frame(CAPSULE_TYPE_CLOSE, &[], out),
            Capsule::AddressAssigned { ipv4, ipv6 } => {
                let mut value = Vec::new();
                for (net, request_id) in ipv4 {
                    append_varint(&mut value, *request_id as u64);
                    value.push(4);
                    value.extend_from_slice(&net.network().octets());
                    value.push(net.prefix_len());
                }
                for (net, request_id) in ipv6 {
                    append_varint(&mut value, *request_id as u64);
                    value.push(6);
                    value.extend_from_slice(&net.network().octets());
                    value.push(net.prefix_len());
                }
                encode_frame(CAPSULE_TYPE_ADDRESS_ASSIGN, &value, out)
            }
            Capsule::RouteAdvertisement { ipv4, ipv6 } => {
                let mut value = Vec::new();
                for (net, protocol) in ipv4 {
                    value.push(4);
                    value.extend_from_slice(&net.network().octets());
                    value.extend_from_slice(&net.broadcast().octets());
                    value.push(*protocol);
                }
                for (net, protocol) in ipv6 {
                    value.push(6);
                    value.extend_from_slice(&net.network().octets());
                    value.extend_from_slice(&net.broadcast().octets());
                    value.push(*protocol);
                }
                encode_frame(CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &value, out)
            }
            Capsule::Datagram {
                context_id,
                payload,
            } => {
                let mut value = Vec::with_capacity(varint_len(*context_id as u64) + payload.len());
                append_varint(&mut value, *context_id as u64);
                value.extend_from_slice(payload);
                encode_frame(CAPSULE_TYPE_DATAGRAM, &value, out)
            }
            Capsule::Unknown { kind, payload } => {
                if *kind >= 1 << 62 {
                    tracing::warn!(
                        "connect-ip: capsule type {kind} exceeds the 62-bit varint space; not encoding"
                    );
                    return;
                }
                encode_frame(*kind, payload, out)
            }
        }
    }

    /// Decodes one capsule from the start of `input`, returning the capsule
    /// and the number of bytes consumed (CONTRACT-CAPSULE). Truncated input is
    /// rejected with `io::ErrorKind::UnexpectedEof`; malformed values with
    /// `io::ErrorKind::InvalidData` using the Go reference's messages.
    pub fn decode(input: &[u8]) -> io::Result<(Capsule, usize)> {
        let (kind, n) =
            read_varint(input).ok_or_else(|| eof("connect-ip: truncated capsule type varint"))?;
        let (len, m) = read_varint(&input[n..])
            .ok_or_else(|| eof("connect-ip: truncated capsule length varint"))?;
        let start = n + m;
        let value_len = usize::try_from(len)
            .map_err(|_| invalid("connect-ip: capsule length exceeds the address space"))?;
        let end = start
            .checked_add(value_len)
            .ok_or_else(|| invalid("connect-ip: capsule length exceeds the address space"))?;
        if input.len() < end {
            return Err(eof("connect-ip: capsule value is truncated"));
        }
        let value = &input[start..end];
        let capsule = match kind {
            CAPSULE_TYPE_DATAGRAM => parse_datagram(value)?,
            CAPSULE_TYPE_ADDRESS_ASSIGN => parse_address_assign(value)?,
            CAPSULE_TYPE_ROUTE_ADVERTISEMENT => parse_route_advertisement(value)?,
            CAPSULE_TYPE_CLOSE => {
                if value.is_empty() {
                    Capsule::Close
                } else {
                    return Err(invalid(
                        "connect-ip: CLOSE capsule must carry an empty value",
                    ));
                }
            }
            _ => Capsule::Unknown {
                kind,
                payload: value.to_vec(),
            },
        };
        Ok((capsule, end))
    }

    // ---------------------------------------------------------------- address

    /// One `parseAddress` entry: varint request ID, IP version byte, address,
    /// prefix length byte. Returns `(request ID, prefix, bytes consumed)`.
    fn parse_address(data: &[u8]) -> io::Result<(u64, IpNet, usize)> {
        let (request_id, n) =
            read_varint(data).ok_or_else(|| eof("connect-ip: truncated address request ID"))?;
        let version = *data
            .get(n)
            .ok_or_else(|| eof("connect-ip: truncated IP version"))?;
        let bit_len = match version {
            4 => 32,
            6 => 128,
            v => return Err(invalid(format!("invalid IP version: {v}"))),
        };
        let addr_len = bit_len / 8;
        let addr_end = n + 1 + addr_len;
        let plen = data
            .get(addr_end)
            .copied()
            .ok_or_else(|| eof("connect-ip: truncated IP address"))? as usize;
        if plen > bit_len {
            return Err(invalid(format!(
                "prefix length {plen} exceeds IP address length ({bit_len})"
            )));
        }
        let octets = &data[n + 1..addr_end];
        let net = match version {
            4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(octets);
                let addr = Ipv4Addr::from(a);
                if u32::from(addr) & host_mask(32, plen as u8) as u32 != 0 {
                    return Err(invalid(
                        "lower bits not covered by prefix length are not all zero",
                    ));
                }
                IpNet::V4(
                    Ipv4Net::new(addr, plen as u8)
                        .map_err(|_| invalid("connect-ip: invalid IPv4 prefix length"))?,
                )
            }
            _ => {
                let mut a = [0u8; 16];
                a.copy_from_slice(octets);
                let addr = Ipv6Addr::from(a);
                if u128::from(addr) & host_mask(128, plen as u8) != 0 {
                    return Err(invalid(
                        "lower bits not covered by prefix length are not all zero",
                    ));
                }
                IpNet::V6(
                    Ipv6Net::new(addr, plen as u8)
                        .map_err(|_| invalid("connect-ip: invalid IPv6 prefix length"))?,
                )
            }
        };
        Ok((request_id, net, addr_end + 1))
    }

    /// Go `parseAddressAssignCapsule`.
    fn parse_address_assign(value: &[u8]) -> io::Result<Capsule> {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            if ipv4.len() + ipv6.len() >= MAX_ADDRESSES_PER_CAPSULE {
                return Err(invalid(format!(
                    "connect-ip: capsule limit exceeded: ADDRESS_ASSIGN capsule contains too many addresses (maximum {MAX_ADDRESSES_PER_CAPSULE})"
                )));
            }
            let (request_id, net, n) = parse_address(rest)?;
            if request_id > u8::MAX as u64 {
                return Err(invalid(format!(
                    "connect-ip: ADDRESS_ASSIGN capsule request ID {request_id} exceeds the u8 limit of the CONTRACT-CAPSULE AddressAssigned API"
                )));
            }
            rest = &rest[n..];
            match net {
                IpNet::V4(net) => ipv4.push((net, request_id as u8)),
                IpNet::V6(net) => ipv6.push((net, request_id as u8)),
            }
        }
        Ok(Capsule::AddressAssigned { ipv4, ipv6 })
    }

    /// Go `isRejected`: an assignment of 0.0.0.0/32 or ::/128 rejects the
    /// corresponding address request.
    pub fn is_rejected_assignment(net: &IpNet) -> bool {
        match net {
            IpNet::V4(n) => n.prefix_len() == 32 && n.network().is_unspecified(),
            IpNet::V6(n) => n.prefix_len() == 128 && n.network().is_unspecified(),
        }
    }

    /// Encodes an ADDRESS_REQUEST capsule (Go `addressRequestCapsule.append`),
    /// the request the Xray MASQUE client sends via `RequestAddresses`.
    /// Prefixes must be masked, as Go's `RequestAddresses` validates.
    pub fn encode_address_request(entries: &[(u64, IpNet)], out: &mut Vec<u8>) -> io::Result<()> {
        let mut value = Vec::new();
        for (i, (request_id, net)) in entries.iter().enumerate() {
            let masked = match net {
                IpNet::V4(n) => *n == n.trunc(),
                IpNet::V6(n) => *n == n.trunc(),
            };
            if !masked {
                return Err(invalid(format!(
                    "connect-ip: invalid requested prefix {i}: {net}"
                )));
            }
            append_varint(&mut value, *request_id);
            match net {
                IpNet::V4(n) => {
                    value.push(4);
                    value.extend_from_slice(&n.network().octets());
                    value.push(n.prefix_len());
                }
                IpNet::V6(n) => {
                    value.push(6);
                    value.extend_from_slice(&n.network().octets());
                    value.push(n.prefix_len());
                }
            }
        }
        encode_frame(CAPSULE_TYPE_ADDRESS_REQUEST, &value, out);
        Ok(())
    }

    /// Decodes the payload of an ADDRESS_REQUEST capsule (Go
    /// `parseAddressRequestCapsule`); apply this to
    /// `Capsule::Unknown { kind: CAPSULE_TYPE_ADDRESS_REQUEST, payload }`.
    pub fn parse_address_request_payload(value: &[u8]) -> io::Result<Vec<(u64, IpNet)>> {
        if value.is_empty() {
            return Err(invalid("ADDRESS_REQUEST capsule contains no addresses"));
        }
        let mut entries = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            if entries.len() >= MAX_ADDRESSES_PER_CAPSULE {
                return Err(invalid(format!(
                    "connect-ip: capsule limit exceeded: ADDRESS_REQUEST capsule contains too many addresses (maximum {MAX_ADDRESSES_PER_CAPSULE})"
                )));
            }
            let (request_id, net, n) = parse_address(rest)?;
            if request_id == 0 {
                return Err(invalid(
                    "ADDRESS_REQUEST capsule contains a zero request ID",
                ));
            }
            rest = &rest[n..];
            entries.push((request_id, net));
        }
        Ok(entries)
    }

    // ----------------------------------------------------------------- routes

    /// One wire route of a ROUTE_ADVERTISEMENT capsule: `start`/`end` are
    /// full-length (host) prefixes carrying the raw range endpoints.
    struct IpRange {
        start: IpNet,
        end: IpNet,
        bit_len: u32,
        protocol: u8,
    }

    impl IpRange {
        fn start_addr(&self) -> String {
            match self.start {
                IpNet::V4(n) => n.network().to_string(),
                IpNet::V6(n) => n.network().to_string(),
            }
        }
        fn end_addr(&self) -> String {
            match self.end {
                IpNet::V4(n) => n.network().to_string(),
                IpNet::V6(n) => n.network().to_string(),
            }
        }
    }

    fn range_value(net: &IpNet) -> u128 {
        match net {
            IpNet::V4(n) => u32::from(n.network()) as u128,
            IpNet::V6(n) => u128::from(n.network()),
        }
    }

    /// Go `parseIPAddressRange`.
    fn parse_route(data: &[u8]) -> io::Result<(IpRange, usize)> {
        let version = *data
            .first()
            .ok_or_else(|| eof("connect-ip: truncated route IP version"))?;
        let (bit_len, addr_len) = match version {
            4 => (32, 4),
            6 => (128, 16),
            v => return Err(invalid(format!("invalid IP version: {v}"))),
        };
        let addr_end = 1 + addr_len;
        let end_ip_pos = addr_end + addr_len;
        // Layout: version, start IP, end IP, protocol byte.
        let protocol_pos = end_ip_pos;
        if data.len() <= protocol_pos {
            return Err(eof("connect-ip: truncated route"));
        }
        let net_of = |octets: &[u8]| -> io::Result<IpNet> {
            match version {
                4 => {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(octets);
                    Ok(IpNet::V4(
                        Ipv4Net::new(Ipv4Addr::from(a), bit_len as u8)
                            .map_err(|_| invalid("connect-ip: invalid IPv4 prefix length"))?,
                    ))
                }
                _ => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(octets);
                    Ok(IpNet::V6(
                        Ipv6Net::new(Ipv6Addr::from(a), bit_len as u8)
                            .map_err(|_| invalid("connect-ip: invalid IPv6 prefix length"))?,
                    ))
                }
            }
        };
        let start = net_of(&data[1..addr_end])?;
        let end = net_of(&data[addr_end..end_ip_pos])?;
        if range_value(&start) > range_value(&end) {
            return Err(invalid("start IP is greater than end IP"));
        }
        let protocol = data[protocol_pos];
        Ok((
            IpRange {
                start,
                end,
                bit_len,
                protocol,
            },
            protocol_pos + 1,
        ))
    }

    /// Go `checkRouteOrder`.
    fn check_route_order(prev: &IpRange, cur: &IpRange) -> io::Result<()> {
        let order = prev
            .bit_len
            .cmp(&cur.bit_len)
            .then(prev.protocol.cmp(&cur.protocol));
        match order {
            Ordering::Greater => Err(invalid(format!(
                "routes are not ordered by IP version and IP protocol: {}-{} (protocol {}) precedes {}-{} (protocol {})",
                prev.start_addr(),
                prev.end_addr(),
                prev.protocol,
                cur.start_addr(),
                cur.end_addr(),
                cur.protocol
            ))),
            Ordering::Equal => {
                // Same family and protocol: ranges must be ascending and
                // non-overlapping (Go rejects a.EndIP >= b.StartIP).
                if range_value(&prev.end) >= range_value(&cur.start) {
                    return Err(invalid(format!(
                        "IP address ranges {}-{} and {}-{} (protocol {}) overlap or are not in ascending order",
                        prev.start_addr(),
                        prev.end_addr(),
                        cur.start_addr(),
                        cur.end_addr(),
                        cur.protocol
                    )));
                }
                Ok(())
            }
            Ordering::Less => Ok(()),
        }
    }

    /// Go `parseRouteAdvertisementCapsule` followed by `IPRoute.Prefixes()`
    /// expansion: every range becomes its prefix list.
    fn parse_route_advertisement(value: &[u8]) -> io::Result<Capsule> {
        let mut ranges: Vec<IpRange> = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            if ranges.len() >= MAX_ROUTES_PER_CAPSULE {
                return Err(invalid(format!(
                    "connect-ip: capsule limit exceeded: ROUTE_ADVERTISEMENT capsule contains too many routes (maximum {MAX_ROUTES_PER_CAPSULE})"
                )));
            }
            let (route, n) = parse_route(rest)?;
            if let Some(prev) = ranges.last() {
                check_route_order(prev, &route)?;
            }
            ranges.push(route);
            rest = &rest[n..];
        }
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for route in ranges {
            match (&route.start, &route.end) {
                (IpNet::V4(s), IpNet::V4(e)) => {
                    for prefix in range_to_prefixes_ipv4(s.network(), e.network()) {
                        ipv4.push((prefix, route.protocol));
                    }
                }
                (IpNet::V6(s), IpNet::V6(e)) => {
                    for prefix in range_to_prefixes_ipv6(s.network(), e.network()) {
                        ipv6.push((prefix, route.protocol));
                    }
                }
                _ => unreachable!("mixed-family ranges are rejected while parsing"),
            }
        }
        Ok(Capsule::RouteAdvertisement { ipv4, ipv6 })
    }

    // --------------------------------------------------------------- datagram

    /// The DATAGRAM capsule value is a varint context ID followed by one IP
    /// packet (Go `composeDatagram` / `ReadPacket`).
    fn parse_datagram(value: &[u8]) -> io::Result<Capsule> {
        let (context_id, n) = read_varint(value)
            .ok_or_else(|| eof("connect-ip: DATAGRAM capsule is missing its context ID varint"))?;
        if context_id > u32::MAX as u64 {
            return Err(invalid(format!(
                "connect-ip: DATAGRAM capsule context ID {context_id} exceeds the u32 limit of the CONTRACT-CAPSULE Datagram API"
            )));
        }
        Ok(Capsule::Datagram {
            context_id: context_id as u32,
            payload: value[n..].to_vec(),
        })
    }
}

// ------------------------------------------------------------------ iprange.go

/// Host-bits mask for a `bits`-long address (32 or 128) with a `plen` prefix
/// length: the bits outside the prefix, as a u128.
fn host_mask(bits: u32, plen: u8) -> u128 {
    debug_assert!(plen as u32 <= bits);
    // Go lastIPInPrefix masks within the address family; only a full
    // 128-bit host field saturates u128.
    let host_bits = bits - u32::from(plen);
    if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    }
}

/// Go `findLargestPrefix`: the longest prefix that starts at `start`, does not
/// pass `end`, and keeps `start` aligned.
fn largest_prefix_len(start: u128, end: u128, bits: u32) -> u8 {
    if start == end {
        return bits as u8;
    }
    let mut plen = bits;
    while plen > 0 {
        let l = plen - 1;
        let host = host_mask(bits, l as u8);
        let last = (start & !host) | host;
        if last > end || start & host != 0 {
            break;
        }
        plen -= 1;
    }
    plen as u8
}

fn ipv4_net(network: u32, plen: u8) -> Ipv4Net {
    Ipv4Net::new(Ipv4Addr::from(network), plen)
        .map_err(|_| invalid("connect-ip: invalid IPv4 prefix length"))
        .expect("prefix length comes from largest_prefix_len")
}

fn ipv6_net(network: u128, plen: u8) -> Ipv6Net {
    Ipv6Net::new(Ipv6Addr::from(network), plen)
        .map_err(|_| invalid("connect-ip: invalid IPv6 prefix length"))
        .expect("prefix length comes from largest_prefix_len")
}

/// Go `rangeToPrefixes` for IPv4: the minimal list of prefixes covering
/// exactly `start..=end`.
pub fn range_to_prefixes_ipv4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Net> {
    let s = u32::from(start) as u128;
    let e = u32::from(end) as u128;
    let mut out = Vec::new();
    let mut current = s;
    while current <= e {
        let plen = largest_prefix_len(current, e, 32);
        let host = host_mask(32, plen);
        let network = current & !host;
        out.push(ipv4_net(network as u32, plen));
        let last = network | host;
        if last >= e {
            break;
        }
        current = last + 1;
    }
    out
}

/// Go `rangeToPrefixes` for IPv6.
pub fn range_to_prefixes_ipv6(start: Ipv6Addr, end: Ipv6Addr) -> Vec<Ipv6Net> {
    let s = u128::from(start);
    let e = u128::from(end);
    let mut out = Vec::new();
    let mut current = s;
    while current <= e {
        let plen = largest_prefix_len(current, e, 128);
        let host = host_mask(128, plen);
        let network = current & !host;
        out.push(ipv6_net(network, plen));
        let last = network | host;
        if last >= e {
            break;
        }
        current = last + 1;
    }
    out
}

// ---------------------------------------------------------------- checksum.go

/// Go `calculateIPv4Checksum`: the one's-complement IPv4 header checksum with
/// the checksum field itself (offset 10) skipped. `header` must have even
/// length; Go would fault on odd input, this returns an error instead.
pub fn calculate_ipv4_checksum(header: &[u8]) -> io::Result<u16> {
    if !header.len().is_multiple_of(2) {
        return Err(invalid(
            "connect-ip: IPv4 checksum requires an even-length header",
        ));
    }
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < header.len() {
        if i != 10 {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        }
        i += 2;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    Ok(!(sum as u16))
}

// ----------------------------------------------------------------- request.go

/// The extended-CONNECT request built by Go `connectip.NewRequest`: an HTTP
/// CONNECT to an absolute https URL with protocol "connect-ip" and the
/// Capsule-Protocol header set. Extra headers (Authorization, User-Agent ...)
/// are added by the caller, as the Xray MASQUE dialer does.
#[derive(Debug, Clone)]
pub struct ConnectIpRequest {
    host: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl ConnectIpRequest {
    /// Go `NewRequest`: rejects URI Templates ("{}" in the URL), then
    /// requires an absolute https URL with a host and a path.
    pub fn new(raw_url: &str) -> io::Result<Self> {
        if raw_url.contains('{') || raw_url.contains('}') {
            return Err(invalid(
                "connect-ip: IP flow forwarding not supported: URL contains a URI Template expression",
            ));
        }
        // Go's net/url rejects control characters before anything else.
        if raw_url.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(invalid(
                "connect-ip: failed to create request: URL contains control characters",
            ));
        }
        let invalid_url = || {
            invalid(format!(
                "connect-ip: invalid proxy URL {raw_url:?}: expected an absolute https URL with a host and a path"
            ))
        };
        let (scheme, rest) = raw_url.split_once("://").ok_or_else(invalid_url)?;
        if scheme != "https" {
            return Err(invalid_url());
        }
        let (authority, path) = match rest.split_once('/') {
            Some((a, tail)) => (a, format!("/{tail}")),
            None => (rest, String::new()),
        };
        if authority.is_empty() || !path.starts_with('/') {
            return Err(invalid_url());
        }
        Ok(Self {
            host: authority.to_string(),
            path,
            headers: vec![(
                CAPSULE_PROTOCOL_HEADER.to_string(),
                CAPSULE_PROTOCOL_HEADER_VALUE.to_string(),
            )],
        })
    }

    /// Always `CONNECT` (Go `http.MethodConnect`).
    pub fn method(&self) -> &'static str {
        "CONNECT"
    }

    /// Always "connect-ip" (Go `requestProtocol`).
    pub fn protocol(&self) -> &'static str {
        CONNECT_IP_PROTOCOL
    }

    /// The request authority (Go sets `req.Host = req.URL.Host`).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The request path (and query), always starting with '/'.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Replaces any previous value of `name` (Go `http.Header.Set`).
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// First value of `name` (Go `http.Header.Get`).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All headers, starting with Capsule-Protocol.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

#[cfg(test)]
mod tests {
    use super::capsule::{self, Capsule};
    use super::*;
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn net4(a: [u8; 4], plen: u8) -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::from(a), plen).unwrap()
    }

    fn net6(octets: [u8; 16], plen: u8) -> Ipv6Net {
        Ipv6Net::new(Ipv6Addr::from(octets), plen).unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// Wraps a capsule value in RFC 9297 framing (varint type + varint
    /// length) by encoding it as an Unknown capsule.
    fn frame(kind: u64, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        capsule::encode(
            &Capsule::Unknown {
                kind,
                payload: value.to_vec(),
            },
            &mut out,
        );
        out
    }

    // ----------------------------------------------------------- capsule codec

    #[test]
    fn datagram_capsule_golden_round_trip() {
        // composeDatagram for context ID 0 and a 4-byte IPv4 packet: type
        // 0x00, length 5 (one context-id byte + 4 payload bytes), value =
        // varint(0) || packet.
        let golden = [0x00, 0x05, 0x00, 0x45, 0x00, 0x00, 0x73];
        let mut encoded = Vec::new();
        capsule::encode(
            &Capsule::Datagram {
                context_id: 0,
                payload: vec![0x45, 0x00, 0x00, 0x73],
            },
            &mut encoded,
        );
        assert_eq!(encoded, golden);
        let (capsule, consumed) = capsule::decode(&golden).unwrap();
        assert_eq!(consumed, golden.len());
        assert_eq!(
            capsule,
            Capsule::Datagram {
                context_id: 0,
                payload: vec![0x45, 0x00, 0x00, 0x73],
            }
        );

        // Two-byte context ID varint (1337 = 0x539): type 0x00, length 2.
        let golden = [0x00, 0x02, 0x45, 0x39];
        let mut encoded = Vec::new();
        capsule::encode(
            &Capsule::Datagram {
                context_id: 1337,
                payload: Vec::new(),
            },
            &mut encoded,
        );
        assert_eq!(encoded, golden);
        assert_eq!(
            capsule::decode(&golden).unwrap().0,
            Capsule::Datagram {
                context_id: 1337,
                payload: Vec::new(),
            }
        );

        // Two-byte length varint: 300-byte payload needs a length of 301.
        let payload = vec![0xab; 300];
        let mut encoded = Vec::new();
        capsule::encode(
            &Capsule::Datagram {
                context_id: 0,
                payload: payload.clone(),
            },
            &mut encoded,
        );
        assert_eq!(&encoded[..3], &[0x00, 0x41, 0x2d]); // varint(301) = 41 2d
        let (capsule, consumed) = capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            capsule,
            Capsule::Datagram {
                context_id: 0,
                payload,
            }
        );
    }

    #[test]
    fn close_capsule_golden_round_trip() {
        let golden = [0x0f, 0x00];
        let mut encoded = Vec::new();
        capsule::encode(&Capsule::Close, &mut encoded);
        assert_eq!(encoded, golden);
        let (capsule, consumed) = capsule::decode(&golden).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(capsule, Capsule::Close);
        // Non-empty CLOSE values are rejected.
        assert!(capsule::decode(&[0x0f, 0x01, 0x00]).is_err());
    }

    #[test]
    fn address_assign_capsule_golden_round_trip() {
        // Go TestParseAddressAssignCapsule layout with request IDs 1 and 2
        // (the contract's u8 API): entry = varint id, IP version, address,
        // prefix length. Value length 26 = 7 (IPv4 entry) + 19 (IPv6 entry).
        let golden = [
            0x01, 0x1a, // type ADDRESS_ASSIGN, length 26
            0x01, 0x04, 0x01, 0x02, 0x03, 0x00, 0x18, // id 1, 1.2.3.0/24
            0x02, 0x06, // id 2, IPv6
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x80, // 2001:db8::1/128
        ];
        let mut encoded = Vec::new();
        capsule::encode(
            &Capsule::AddressAssigned {
                ipv4: vec![(net4([1, 2, 3, 0], 24), 1)],
                ipv6: vec![(net6(v6("2001:db8::1").octets(), 128), 2)],
            },
            &mut encoded,
        );
        assert_eq!(encoded, golden);
        let (capsule, consumed) = capsule::decode(&golden).unwrap();
        assert_eq!(consumed, golden.len());
        assert_eq!(
            capsule,
            Capsule::AddressAssigned {
                ipv4: vec![(net4([1, 2, 3, 0], 24), 1)],
                ipv6: vec![(net6(v6("2001:db8::1").octets(), 128), 2)],
            }
        );

        // Unsolicited assignments use request ID 0 (Go: "RequestID is zero
        // for an unsolicited assignment").
        let (capsule, _) = capsule::decode(&frame(
            capsule::CAPSULE_TYPE_ADDRESS_ASSIGN,
            &[0x00, 0x04, 192, 0, 2, 1, 32],
        ))
        .unwrap();
        assert_eq!(
            capsule,
            Capsule::AddressAssigned {
                ipv4: vec![(net4([192, 0, 2, 1], 32), 0)],
                ipv6: Vec::new(),
            }
        );

        // An empty capsule assigns nothing.
        let (capsule, _) =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ADDRESS_ASSIGN, &[])).unwrap();
        assert_eq!(
            capsule,
            Capsule::AddressAssigned {
                ipv4: Vec::new(),
                ipv6: Vec::new(),
            }
        );

        // Rejected assignments are the unspecified address at full prefix
        // length (Go TestAssignedAddressRejected).
        assert!(capsule::is_rejected_assignment(&IpNet::V4(net4(
            [0, 0, 0, 0],
            32
        ))));
        assert!(capsule::is_rejected_assignment(&IpNet::V6(net6(
            v6("::").octets(),
            128
        ))));
        for net in [
            IpNet::V4(net4([0, 0, 0, 0], 0)),
            IpNet::V4(net4([0, 0, 0, 0], 31)),
            IpNet::V6(net6(v6("::").octets(), 0)),
            IpNet::V6(net6(v6("::").octets(), 127)),
            IpNet::V4(net4([192, 0, 2, 1], 32)),
            IpNet::V6(net6(v6("2001:db8::1").octets(), 128)),
        ] {
            assert!(!capsule::is_rejected_assignment(&net));
        }
    }

    #[test]
    fn route_advertisement_capsule_golden_round_trip() {
        // Entry = IP version, start IP, end IP, IP protocol. Each prefix
        // covers [network, broadcast]; both entries below are single-prefix
        // ranges so the round trip is byte-exact. Value length 44 = 10 + 34.
        let mut golden = vec![0x03, 44]; // type ROUTE_ADVERTISEMENT, length 44
        golden.extend_from_slice(&[0x04, 10, 0, 0, 0, 10, 0, 0, 255, 13]); // 10.0.0.0/24, proto 13
        golden.push(0x06);
        golden.extend_from_slice(&v6("2001:db8:1234:5678::").octets());
        golden.extend_from_slice(&v6("2001:db8:1234:5678:ffff:ffff:ffff:ffff").octets());
        golden.push(37);
        let mut encoded = Vec::new();
        capsule::encode(
            &Capsule::RouteAdvertisement {
                ipv4: vec![(net4([10, 0, 0, 0], 24), 13)],
                ipv6: vec![(net6(v6("2001:db8:1234:5678::").octets(), 64), 37)],
            },
            &mut encoded,
        );
        assert_eq!(encoded, golden);
        let (capsule, consumed) = capsule::decode(&golden).unwrap();
        assert_eq!(consumed, golden.len());
        assert_eq!(
            capsule,
            Capsule::RouteAdvertisement {
                ipv4: vec![(net4([10, 0, 0, 0], 24), 13)],
                ipv6: vec![(net6(v6("2001:db8:1234:5678::").octets(), 64), 37)],
            }
        );

        // An empty capsule advertises nothing.
        let (capsule, _) =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &[])).unwrap();
        assert_eq!(
            capsule,
            Capsule::RouteAdvertisement {
                ipv4: Vec::new(),
                ipv6: Vec::new(),
            }
        );
    }

    #[test]
    fn route_advertisement_expands_ranges_to_prefixes() {
        // Go TestParseRouteAdvertisementCapsule: 1.1.1.1-1.2.3.4 (proto 13)
        // and 2001:db8::1-2001:db8::100 (proto 37) decode to the prefix
        // expansion of each range, sharing the range's IP protocol.
        let mut value = vec![0x04, 1, 1, 1, 1, 1, 2, 3, 4, 13];
        value.push(0x06);
        value.extend_from_slice(&v6("2001:db8::1").octets());
        value.extend_from_slice(&v6("2001:db8::100").octets());
        value.push(37);
        let (capsule, _) =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &value)).unwrap();
        let Capsule::RouteAdvertisement { ipv4, ipv6 } = capsule else {
            panic!("expected RouteAdvertisement");
        };
        let expected4: Vec<(Ipv4Net, u8)> =
            range_to_prefixes_ipv4(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 2, 3, 4))
                .into_iter()
                .map(|p| (p, 13))
                .collect();
        let expected6: Vec<(Ipv6Net, u8)> =
            range_to_prefixes_ipv6(v6("2001:db8::1"), v6("2001:db8::100"))
                .into_iter()
                .map(|p| (p, 37))
                .collect();
        assert_eq!(ipv4, expected4);
        assert_eq!(ipv6, expected6);
        // The 1.1.1.1-1.2.3.4 range really needs multiple prefixes.
        assert!(expected4.len() > 1);
    }

    #[test]
    fn route_advertisement_order_validation() {
        let route4 = |start: [u8; 4], end: [u8; 4], proto: u8| {
            let mut v = vec![0x04];
            v.extend_from_slice(&start);
            v.extend_from_slice(&end);
            v.push(proto);
            v
        };
        // Adjacent ranges are accepted (Go "adjacent ranges").
        let ok = [
            route4([10, 0, 0, 0], [10, 0, 0, 9], 0),
            route4([10, 0, 0, 10], [10, 0, 0, 20], 0),
        ]
        .concat();
        assert!(capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &ok)).is_ok());

        // Same range with different IP protocols is accepted (Go
        // "same range for different IP protocols").
        let ok = [
            route4([10, 0, 0, 0], [10, 0, 0, 9], 6),
            route4([10, 0, 0, 0], [10, 0, 0, 9], 17),
        ]
        .concat();
        assert!(capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &ok)).is_ok());

        // Descending IP protocols are rejected (Go "descending IP protocols").
        let bad = [
            route4([10, 0, 0, 0], [10, 0, 0, 9], 17),
            route4([10, 0, 0, 10], [10, 0, 0, 20], 6),
        ]
        .concat();
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &bad)).unwrap_err();
        assert!(
            err.to_string()
                .contains("not ordered by IP version and IP protocol"),
            "{err}"
        );

        // Descending ranges are rejected (Go "descending ranges").
        let bad = [
            route4([10, 0, 0, 10], [10, 0, 0, 20], 0),
            route4([10, 0, 0, 0], [10, 0, 0, 9], 0),
        ]
        .concat();
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &bad)).unwrap_err();
        assert!(
            err.to_string()
                .contains("overlap or are not in ascending order"),
            "{err}"
        );

        // IPv6 before IPv4 is rejected (Go "IPv6 before IPv4").
        let mut bad = vec![0x06];
        bad.extend_from_slice(&v6("2001:db8::").octets());
        bad.extend_from_slice(&v6("2001:db8::ffff").octets());
        bad.push(0);
        bad.extend_from_slice(&route4([10, 0, 0, 0], [10, 0, 0, 9], 0));
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &bad)).unwrap_err();
        assert!(
            err.to_string()
                .contains("not ordered by IP version and IP protocol"),
            "{err}"
        );

        // start IP greater than end IP is rejected.
        let bad = route4([1, 2, 3, 4], [1, 1, 1, 1], 13);
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &bad)).unwrap_err();
        assert!(
            err.to_string().contains("start IP is greater than end IP"),
            "{err}"
        );
    }

    #[test]
    fn unknown_capsule_golden_round_trip() {
        // Kind 0x1234 needs a two-byte varint (0x52 0x34).
        let golden = [0x52, 0x34, 0x02, 0xde, 0xad];
        let mut encoded = Vec::new();
        capsule::encode(
            &Capsule::Unknown {
                kind: 0x1234,
                payload: vec![0xde, 0xad],
            },
            &mut encoded,
        );
        assert_eq!(encoded, golden);
        let (capsule, consumed) = capsule::decode(&golden).unwrap();
        assert_eq!(consumed, golden.len());
        assert_eq!(
            capsule,
            Capsule::Unknown {
                kind: 0x1234,
                payload: vec![0xde, 0xad],
            }
        );
    }

    #[test]
    fn address_request_helper_golden_round_trip() {
        // Go TestParseAddressRequestCapsule layout with request IDs 1337/1338:
        // value length 28 = 8 (IPv4 entry) + 20 (IPv6 entry).
        let mut golden = vec![0x02, 0x1c];
        golden.extend_from_slice(&[0x45, 0x39, 0x04, 1, 2, 3, 0, 0x18]); // 1337, 1.2.3.0/24
        golden.extend_from_slice(&[0x45, 0x3a, 0x06]); // 1338, IPv6
        golden.extend_from_slice(&v6("2001:db8::1").octets());
        golden.push(0x80);
        let entries = vec![
            (1337, IpNet::V4(net4([1, 2, 3, 0], 24))),
            (1338, IpNet::V6(net6(v6("2001:db8::1").octets(), 128))),
        ];
        let mut encoded = Vec::new();
        capsule::encode_address_request(&entries, &mut encoded).unwrap();
        assert_eq!(encoded, golden);

        // A decoded ADDRESS_REQUEST surfaces as Unknown{kind: 0x02} and its
        // payload parses to the entries above.
        let (capsule, consumed) = capsule::decode(&golden).unwrap();
        assert_eq!(consumed, golden.len());
        match &capsule {
            Capsule::Unknown { kind, payload } => {
                assert_eq!(*kind, capsule::CAPSULE_TYPE_ADDRESS_REQUEST);
                assert_eq!(
                    capsule::parse_address_request_payload(payload).unwrap(),
                    entries
                );
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        // Re-encoding is byte-exact.
        let mut reencoded = Vec::new();
        capsule::encode(&capsule, &mut reencoded);
        assert_eq!(reencoded, golden);
    }

    #[test]
    fn address_request_rejections() {
        // Empty payload (Go "contains no addresses").
        let err = capsule::parse_address_request_payload(&[]).unwrap_err();
        assert!(err.to_string().contains("contains no addresses"), "{err}");
        // Zero request ID (Go "zero request ID"): id 0, 192.0.2.1/32.
        let err =
            capsule::parse_address_request_payload(&[0x00, 0x04, 192, 0, 2, 1, 32]).unwrap_err();
        assert!(err.to_string().contains("zero request ID"), "{err}");
        // Unmasked prefixes are rejected at encode time (Go RequestAddresses).
        let err = capsule::encode_address_request(
            &[(
                1,
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(1, 2, 3, 4), 24).unwrap()),
            )],
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid requested prefix 0"),
            "{err}"
        );
    }

    #[test]
    fn capsule_truncated_and_malformed_rejection() {
        // Empty input, incomplete type varint, incomplete length varint.
        assert!(capsule::decode(&[]).is_err());
        assert!(capsule::decode(&[0x40]).is_err());
        assert!(capsule::decode(&[0x00, 0x40]).is_err());
        // Length larger than the remaining input.
        assert!(capsule::decode(&[0x00, 0x0a, 0x01]).is_err());

        // ADDRESS_ASSIGN with an invalid IP version (Go "invalid IP version: 5").
        let value = [0x01, 0x05, 1, 2, 3, 4, 32];
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ADDRESS_ASSIGN, &value)).unwrap_err();
        assert!(err.to_string().contains("invalid IP version: 5"), "{err}");

        // Prefix length beyond the address (Go "prefix length 33 ...").
        let value = [0x01, 0x04, 1, 2, 3, 4, 33];
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ADDRESS_ASSIGN, &value)).unwrap_err();
        assert!(
            err.to_string()
                .contains("prefix length 33 exceeds IP address length (32)"),
            "{err}"
        );

        // Lower bits not covered by the prefix length.
        let value = [0x01, 0x04, 1, 2, 3, 4, 28];
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ADDRESS_ASSIGN, &value)).unwrap_err();
        assert!(
            err.to_string()
                .contains("lower bits not covered by prefix length are not all zero"),
            "{err}"
        );

        // Request IDs above the contract's u8 API are rejected by name
        // (1337 = varint 0x45 0x39, the value used by the Go tests).
        let value = [0x45, 0x39, 0x04, 1, 2, 3, 0, 24];
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ADDRESS_ASSIGN, &value)).unwrap_err();
        assert!(
            err.to_string()
                .contains("request ID 1337 exceeds the u8 limit"),
            "{err}"
        );

        // Truncated address entry (id + version only).
        let value = [0x01, 0x04];
        assert!(capsule::decode(&frame(capsule::CAPSULE_TYPE_ADDRESS_ASSIGN, &value)).is_err());

        // ROUTE_ADVERTISEMENT with an invalid IP version.
        let value = [0x05, 1, 1, 1, 1, 1, 1, 1, 2, 13];
        let err =
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &value)).unwrap_err();
        assert!(err.to_string().contains("invalid IP version: 5"), "{err}");

        // Truncated route entry.
        let value = [0x04, 10, 0, 0, 0];
        assert!(
            capsule::decode(&frame(capsule::CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &value)).is_err()
        );

        // DATAGRAM without a context ID varint.
        let err = capsule::decode(&frame(capsule::CAPSULE_TYPE_DATAGRAM, &[])).unwrap_err();
        assert!(err.to_string().contains("missing its context ID"), "{err}");

        // DATAGRAM context ID above the contract's u32 API (2^32 as an
        // eight-byte varint: c0 00 00 01 00 00 00 00).
        let value = [0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let err = capsule::decode(&frame(capsule::CAPSULE_TYPE_DATAGRAM, &value)).unwrap_err();
        assert!(err.to_string().contains("exceeds the u32 limit"), "{err}");

        // Two concatenated datagrams: decode reports the first capsule's
        // exact length so the caller can advance.
        let first = [0x00, 0x02, 0x00, 0x45];
        let second = [0x00, 0x01, 0x00];
        let mut stream = first.to_vec();
        stream.extend_from_slice(&second);
        let (capsule, consumed) = capsule::decode(&stream).unwrap();
        assert_eq!(consumed, first.len());
        assert_eq!(
            capsule,
            Capsule::Datagram {
                context_id: 0,
                payload: vec![0x45],
            }
        );
        let (capsule, consumed) = capsule::decode(&stream[consumed..]).unwrap();
        assert_eq!(consumed, second.len());
        assert_eq!(
            capsule,
            Capsule::Datagram {
                context_id: 0,
                payload: Vec::new(),
            }
        );
    }

    // ---------------------------------------------------------------- iprange

    #[test]
    #[allow(clippy::type_complexity)] // Go test vectors verbatim
    fn range_to_prefixes_matches_go_vectors() {
        // Go TestIPRanges, verbatim.
        let cases4: &[([u8; 4], [u8; 4], Vec<(Ipv4Addr, u8)>)] = &[
            (
                [192, 168, 1, 1],
                [192, 168, 1, 1],
                vec![(Ipv4Addr::new(192, 168, 1, 1), 32)],
            ),
            (
                [192, 168, 1, 0],
                [192, 168, 1, 1],
                vec![(Ipv4Addr::new(192, 168, 1, 0), 31)],
            ),
            (
                [192, 168, 1, 1],
                [192, 168, 1, 2],
                vec![
                    (Ipv4Addr::new(192, 168, 1, 1), 32),
                    (Ipv4Addr::new(192, 168, 1, 2), 32),
                ],
            ),
            (
                [192, 168, 1, 0],
                [192, 168, 1, 255],
                vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
            ),
            (
                [10, 0, 0, 0],
                [10, 1, 0, 255],
                vec![
                    (Ipv4Addr::new(10, 0, 0, 0), 16),
                    (Ipv4Addr::new(10, 1, 0, 0), 24),
                ],
            ),
        ];
        for (start, end, want) in cases4 {
            let got = range_to_prefixes_ipv4(Ipv4Addr::from(*start), Ipv4Addr::from(*end));
            let want: Vec<Ipv4Net> = want
                .iter()
                .map(|(a, l)| Ipv4Net::new(*a, *l).unwrap())
                .collect();
            assert_eq!(got, want, "{start:?}-{end:?}");
        }

        let cases6: &[(&str, &str, Vec<(Ipv6Addr, u8)>)] = &[
            (
                "2001:0db8:85a3::8a2e:0370:7334",
                "2001:0db8:85a3::8a2e:0370:7334",
                vec![(v6("2001:0db8:85a3::8a2e:0370:7334"), 128)],
            ),
            (
                "2001:db8::0",
                "2001:db8::ffff:ffff:ffff:ffff",
                vec![(v6("2001:db8::"), 64)],
            ),
            (
                "2001:db8::1",
                "2001:db8::2",
                vec![(v6("2001:db8::1"), 128), (v6("2001:db8::2"), 128)],
            ),
            (
                "2001:db8:1234:5678::",
                "2001:db8:1234:5679::",
                vec![
                    (v6("2001:db8:1234:5678::"), 64),
                    (v6("2001:db8:1234:5679::"), 128),
                ],
            ),
        ];
        for (start, end, want) in cases6 {
            let got = range_to_prefixes_ipv6(v6(start), v6(end));
            let want: Vec<Ipv6Net> = want
                .iter()
                .map(|(a, l)| Ipv6Net::new(*a, *l).unwrap())
                .collect();
            assert_eq!(got, want, "{start}-{end}");
        }

        // The full IPv4 space collapses to one prefix (loop runs to /0).
        assert_eq!(
            range_to_prefixes_ipv4(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST),
            vec![Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()]
        );
        // An inverted range yields nothing, as in Go.
        assert!(
            range_to_prefixes_ipv4(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 0))
                .is_empty()
        );
    }

    // --------------------------------------------------------------- checksum

    #[test]
    fn ipv4_checksum_go_vectors() {
        // Go TestIPv4ChecksumTestVector: the classic 20-byte header.
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(calculate_ipv4_checksum(&data).unwrap(), 0xb861);

        // Go TestIPv4ChecksumWithOptions, hand-computed from the same
        // algorithm: the 24-byte header (checksum field zeroed, one IPv4
        // option word appended) sums to 0xDCA6 before folding, so the
        // checksum is !0xDCA6 = 0x2359. Inserting it makes the header's
        // 16-bit sum (including the field itself) fold to 0xFFFF.
        let mut data = [
            0x46, 0x00, 0x00, 0x77, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0x94, 0x04, 0x00, 0x00,
        ];
        let checksum = calculate_ipv4_checksum(&data).unwrap();
        assert_eq!(checksum, 0x2359);
        data[10] = (checksum >> 8) as u8;
        data[11] = checksum as u8;
        // Validity: summing every pair, including the checksum field, folds
        // to 0xFFFF (the one's-complement of zero).
        let mut sum: u32 = 0;
        for pair in data.chunks(2) {
            sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff);
        // The options must be covered: the first 20 bytes alone give a
        // different checksum (!0x48A2 = 0xB75D).
        assert_eq!(calculate_ipv4_checksum(&data[..20]).unwrap(), 0xb75d);
        assert_ne!(calculate_ipv4_checksum(&data[..20]).unwrap(), checksum);

        // Odd-length input is rejected (Go would fault).
        assert!(calculate_ipv4_checksum(&[0x45, 0x00, 0x00]).is_err());
    }

    // ---------------------------------------------------------------- request

    #[test]
    fn new_request_output_shape() {
        // Go TestNewRequest.
        let mut req = ConnectIpRequest::new("https://localhost:1234/masque/ip").unwrap();
        assert_eq!(req.method(), "CONNECT");
        assert_eq!(req.protocol(), "connect-ip");
        assert_eq!(req.host(), "localhost:1234");
        assert_eq!(req.path(), "/masque/ip");
        assert_eq!(req.header("Capsule-Protocol"), Some("?1"));
        req.set_header("Authorization", "Bearer token");
        assert_eq!(req.header("Authorization"), Some("Bearer token"));
        // Set replaces, like http.Header.Set.
        req.set_header("Authorization", "Bearer other");
        assert_eq!(req.header("Authorization"), Some("Bearer other"));
        assert_eq!(req.headers().len(), 2);
    }

    #[test]
    fn new_request_invalid_urls() {
        // Go TestNewRequestInvalidURL, verbatim cases.
        let cases = [
            (
                "https://localhost/.well-known/masque/ip/{target}/{ipproto}/",
                "IP flow forwarding not supported",
            ),
            (
                "https://localhost/masque/ip{?target,ipproto}",
                "IP flow forwarding not supported",
            ),
            (
                "http://localhost/masque/ip",
                "expected an absolute https URL",
            ),
            ("https:///masque/ip", "expected an absolute https URL"),
            ("https://localhost", "expected an absolute https URL"),
            ("/masque/ip", "expected an absolute https URL"),
            ("https://local\x7fhost/", "failed to create request"),
        ];
        for (url, want) in cases {
            let err = ConnectIpRequest::new(url).unwrap_err();
            assert!(err.to_string().contains(want), "{url}: {err}");
        }
    }
}
