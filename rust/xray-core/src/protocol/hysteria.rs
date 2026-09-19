//! Hysteria 2 wire codecs, derived from `proxy/hysteria/protocol.go`.
//!
//! These are raw QUIC DATAGRAM payloads, not HTTP/3 datagrams. TCP requests
//! follow the HTTP/3 extension frame type 0x401 on a bidirectional stream.

use std::{
    collections::HashMap,
    io::{self, Cursor, Read},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const MAX_UDP_PAYLOAD: usize = 65_535;
pub const MAX_VARINT: u64 = (1 << 62) - 1;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn varint_size(value: u64) -> io::Result<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_VARINT => Ok(8),
        _ => Err(invalid("QUIC varint exceeds 62 bits")),
    }
}

pub fn write_varint(output: &mut Vec<u8>, value: u64) -> io::Result<()> {
    let size = varint_size(value)?;
    let tag = match size {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    let bytes = value.to_be_bytes();
    let start = output.len();
    output.extend_from_slice(&bytes[8 - size..]);
    output[start] |= tag;
    Ok(())
}

/// Accepts legal non-minimal QUIC varints, like quic-go's reader.
pub fn read_varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut first = [0];
    reader.read_exact(&mut first)?;
    let size = 1usize << (first[0] >> 6);
    let mut bytes = [0u8; 8];
    bytes[8 - size] = first[0] & 0x3f;
    reader.read_exact(&mut bytes[9 - size..])?;
    Ok(u64::from_be_bytes(bytes))
}

pub async fn read_varint_async<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let size = 1usize << (first >> 6);
    let mut bytes = [0u8; 8];
    bytes[8 - size] = first & 0x3f;
    reader.read_exact(&mut bytes[9 - size..]).await?;
    Ok(u64::from_be_bytes(bytes))
}

fn check_length(len: usize, max: usize, nonempty: bool) -> io::Result<()> {
    if len > max || (nonempty && len == 0) {
        Err(invalid("invalid Hysteria field length"))
    } else {
        Ok(())
    }
}

fn read_field(reader: &mut impl Read, max: usize, nonempty: bool) -> io::Result<Vec<u8>> {
    let len = read_varint(reader)?;
    if len > max as u64 || (nonempty && len == 0) {
        return Err(invalid("invalid Hysteria field length"));
    }
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data)?;
    Ok(data)
}

async fn read_field_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
    nonempty: bool,
) -> io::Result<Vec<u8>> {
    let len = read_varint_async(reader).await?;
    if len > max as u64 || (nonempty && len == 0) {
        return Err(invalid("invalid Hysteria field length"));
    }
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

fn write_field(output: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
    write_varint(output, data.len() as u64)?;
    output.extend_from_slice(data);
    Ok(())
}

fn address_from_bytes(data: Vec<u8>) -> io::Result<String> {
    String::from_utf8(data).map_err(|_| invalid("Hysteria address is not UTF-8"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpRequest {
    pub address: String,
    pub padding: Vec<u8>,
}

impl TcpRequest {
    /// Encodes the proxy request body; the transport adds the 0x401 prefix.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        check_length(self.address.len(), MAX_ADDRESS_LENGTH, true)?;
        check_length(self.padding.len(), MAX_PADDING_LENGTH, false)?;
        let mut output = Vec::new();
        write_field(&mut output, self.address.as_bytes())?;
        write_field(&mut output, &self.padding)?;
        Ok(output)
    }

    pub fn encode_stream(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        write_varint(&mut output, FRAME_TYPE_TCP_REQUEST)?;
        output.extend_from_slice(&self.encode()?);
        Ok(output)
    }

    /// Returns the consumed size; application bytes following the header remain.
    pub fn decode(input: &[u8]) -> io::Result<(Self, usize)> {
        let mut cursor = Cursor::new(input);
        let address = address_from_bytes(read_field(&mut cursor, MAX_ADDRESS_LENGTH, true)?)?;
        let padding = read_field(&mut cursor, MAX_PADDING_LENGTH, false)?;
        Ok((Self { address, padding }, cursor.position() as usize))
    }

    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let address =
            address_from_bytes(read_field_async(reader, MAX_ADDRESS_LENGTH, true).await?)?;
        let padding = read_field_async(reader, MAX_PADDING_LENGTH, false).await?;
        Ok(Self { address, padding })
    }

    pub async fn read_stream<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        if read_varint_async(reader).await? != FRAME_TYPE_TCP_REQUEST {
            return Err(invalid("not a Hysteria TCP request stream"));
        }
        Self::read(reader).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpResponse {
    /// Any nonzero status is an error, as in the pinned Go reader.
    pub status: u8,
    pub message: Vec<u8>,
    pub padding: Vec<u8>,
}

impl TcpResponse {
    pub fn is_ok(&self) -> bool {
        self.status == 0
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        check_length(self.message.len(), MAX_MESSAGE_LENGTH, false)?;
        check_length(self.padding.len(), MAX_PADDING_LENGTH, false)?;
        let mut output = vec![self.status];
        write_field(&mut output, &self.message)?;
        write_field(&mut output, &self.padding)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<(Self, usize)> {
        let mut cursor = Cursor::new(input);
        let mut status = [0];
        Read::read_exact(&mut cursor, &mut status)?;
        let message = read_field(&mut cursor, MAX_MESSAGE_LENGTH, false)?;
        let padding = read_field(&mut cursor, MAX_PADDING_LENGTH, false)?;
        Ok((
            Self {
                status: status[0],
                message,
                padding,
            },
            cursor.position() as usize,
        ))
    }

    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let status = reader.read_u8().await?;
        let message = read_field_async(reader, MAX_MESSAGE_LENGTH, false).await?;
        let padding = read_field_async(reader, MAX_PADDING_LENGTH, false).await?;
        Ok(Self {
            status,
            message,
            padding,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: String,
    pub payload: Vec<u8>,
}

impl UdpMessage {
    fn validate(&self) -> io::Result<()> {
        check_length(self.address.len(), MAX_ADDRESS_LENGTH, true)?;
        check_length(self.payload.len(), MAX_UDP_PAYLOAD, true)?;
        if self.fragment_count == 0 || self.fragment_id >= self.fragment_count {
            return Err(invalid("invalid Hysteria UDP fragment index/count"));
        }
        Ok(())
    }

    pub fn header_size(&self) -> io::Result<usize> {
        check_length(self.address.len(), MAX_ADDRESS_LENGTH, true)?;
        Ok(8 + varint_size(self.address.len() as u64)? + self.address.len())
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut output = Vec::with_capacity(self.header_size()? + self.payload.len());
        // Go fills these four bytes later in InterConn.Write; encode the complete wire frame.
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        output.extend_from_slice(&[self.fragment_id, self.fragment_count]);
        write_field(&mut output, self.address.as_bytes())?;
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> io::Result<Self> {
        if input.len() < 9 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut cursor = Cursor::new(&input[8..]);
        let address = address_from_bytes(read_field(&mut cursor, MAX_ADDRESS_LENGTH, true)?)?;
        let payload_offset = 8 + cursor.position() as usize;
        check_length(input.len() - payload_offset, MAX_UDP_PAYLOAD, true)?;
        let message = Self {
            session_id: u32::from_be_bytes(input[..4].try_into().expect("fixed slice")),
            packet_id: u16::from_be_bytes(input[4..6].try_into().expect("fixed slice")),
            fragment_id: input[6],
            fragment_count: input[7],
            address,
            payload: input[payload_offset..].to_vec(),
        };
        message.validate()?;
        Ok(message)
    }

    pub fn fragment(&self, max_datagram_size: usize) -> io::Result<Vec<Self>> {
        self.validate()?;
        if self.fragment_count != 1 || self.fragment_id != 0 {
            return Err(invalid("cannot fragment an already fragmented UDP message"));
        }
        let size = max_datagram_size
            .checked_sub(self.header_size()?)
            .filter(|n| *n > 0)
            .ok_or_else(|| invalid("datagram has no room for payload"))?;
        let count = self.payload.len().div_ceil(size);
        if count > u8::MAX as usize {
            return Err(invalid("UDP message exceeds 255 fragments"));
        }
        Ok(self
            .payload
            .chunks(size)
            .enumerate()
            .map(|(index, payload)| Self {
                session_id: self.session_id,
                packet_id: self.packet_id,
                fragment_id: index as u8,
                fragment_count: count as u8,
                address: self.address.clone(),
                payload: payload.to_vec(),
            })
            .collect())
    }
}

#[derive(Clone, Debug)]
pub struct ReassemblyLimits {
    pub max_packets: usize,
    pub max_buffered_bytes: usize,
    pub max_packet_bytes: usize,
    pub max_fragments: u8,
    pub lifetime: Duration,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_packets: 64,
            max_buffered_bytes: 1024 * 1024,
            max_packet_bytes: MAX_UDP_PAYLOAD,
            max_fragments: 255,
            lifetime: Duration::from_secs(10),
        }
    }
}

#[derive(Hash, Eq, PartialEq)]
struct PacketKey {
    session_id: u32,
    packet_id: u16,
    address: String,
}

struct PendingPacket {
    created: Instant,
    fragments: Vec<Option<Vec<u8>>>,
    bytes: usize,
    received: usize,
}

/// A bounded assembler. Unlike the Go single-packet helper, interleaved packets
/// do not discard one another. Instantiate per authenticated QUIC connection.
pub struct UdpReassembler {
    limits: ReassemblyLimits,
    packets: HashMap<PacketKey, PendingPacket>,
    buffered_bytes: usize,
}

impl UdpReassembler {
    pub fn new(limits: ReassemblyLimits) -> io::Result<Self> {
        if limits.max_packets == 0
            || limits.max_buffered_bytes == 0
            || limits.max_packet_bytes == 0
            || limits.max_packet_bytes > MAX_UDP_PAYLOAD
            || limits.max_fragments == 0
            || limits.lifetime.is_zero()
        {
            return Err(invalid("invalid UDP reassembly limits"));
        }
        Ok(Self {
            limits,
            packets: HashMap::new(),
            buffered_bytes: 0,
        })
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }
    pub fn pending_packets(&self) -> usize {
        self.packets.len()
    }

    pub fn expire(&mut self, now: Instant) {
        self.packets.retain(|_, packet| {
            let keep = now.saturating_duration_since(packet.created) < self.limits.lifetime;
            if !keep {
                self.buffered_bytes -= packet.bytes;
            }
            keep
        });
    }

    fn remove(&mut self, key: &PacketKey) -> Option<PendingPacket> {
        let packet = self.packets.remove(key)?;
        self.buffered_bytes -= packet.bytes;
        Some(packet)
    }

    pub fn feed(&mut self, message: UdpMessage, now: Instant) -> io::Result<Option<UdpMessage>> {
        self.expire(now);
        message.validate()?;
        if message.payload.len() > self.limits.max_packet_bytes
            || message.fragment_count > self.limits.max_fragments
        {
            return Err(invalid("UDP packet exceeds reassembly limits"));
        }
        let key = PacketKey {
            session_id: message.session_id,
            packet_id: message.packet_id,
            address: message.address.clone(),
        };
        if let Some(packet) = self.packets.get(&key) {
            if packet.fragments.len() != message.fragment_count as usize {
                self.remove(&key);
                return Err(invalid("conflicting UDP fragment count"));
            }
            if let Some(prior) = &packet.fragments[message.fragment_id as usize] {
                if prior != &message.payload {
                    self.remove(&key);
                    return Err(invalid("conflicting duplicate UDP fragment"));
                }
                return Ok(None);
            }
        }
        if message.fragment_count == 1 {
            return Ok(Some(message));
        }
        if !self.packets.contains_key(&key) {
            if self.packets.len() >= self.limits.max_packets {
                return Err(invalid("too many pending UDP packets"));
            }
            self.packets.insert(
                PacketKey {
                    session_id: key.session_id,
                    packet_id: key.packet_id,
                    address: key.address.clone(),
                },
                PendingPacket {
                    created: now,
                    fragments: vec![None; message.fragment_count as usize],
                    bytes: 0,
                    received: 0,
                },
            );
        }
        let packet = self.packets.get(&key).expect("inserted packet");
        if message.payload.len() > self.limits.max_packet_bytes.saturating_sub(packet.bytes)
            || message.payload.len()
                > self
                    .limits
                    .max_buffered_bytes
                    .saturating_sub(self.buffered_bytes)
        {
            self.remove(&key);
            return Err(invalid("UDP reassembly byte limit exceeded"));
        }
        let packet = self.packets.get_mut(&key).expect("inserted packet");
        packet.bytes += message.payload.len();
        self.buffered_bytes += message.payload.len();
        packet.received += 1;
        packet.fragments[message.fragment_id as usize] = Some(message.payload);
        if packet.received != packet.fragments.len() {
            return Ok(None);
        }
        let packet = self.remove(&key).expect("completed packet");
        let mut payload = Vec::with_capacity(packet.bytes);
        for fragment in packet.fragments {
            payload.extend(fragment.expect("all fragments present"));
        }
        Ok(Some(UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: message.address,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_varint_vectors_and_overlong_values() {
        for (value, bytes) in [
            (37, vec![0x25]),
            (15_293, vec![0x7b, 0xbd]),
            (494_878_333, vec![0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ] {
            let mut encoded = Vec::new();
            write_varint(&mut encoded, value).unwrap();
            assert_eq!(encoded, bytes);
            assert_eq!(read_varint(&mut bytes.as_slice()).unwrap(), value);
            for end in 0..bytes.len() {
                assert!(read_varint(&mut &bytes[..end]).is_err());
            }
        }
        assert_eq!(read_varint(&mut &[0x40, 0x25][..]).unwrap(), 37);
        assert!(write_varint(&mut Vec::new(), 1 << 62).is_err());
    }

    #[test]
    fn go_tcp_layout_golden_and_application_boundary() {
        let req = TcpRequest {
            address: "example.com:443".into(),
            padding: b"xy".to_vec(),
        };
        let golden = b"\x44\x01\x0fexample.com:443\x02xy";
        assert_eq!(req.encode_stream().unwrap(), golden);
        let mut with_data = golden[2..].to_vec();
        with_data.extend(b"application");
        assert_eq!(
            TcpRequest::decode(&with_data).unwrap(),
            (req, golden.len() - 2)
        );
        let res = TcpResponse {
            status: 7,
            message: b"no".to_vec(),
            padding: vec![b'p'],
        };
        assert_eq!(res.encode().unwrap(), b"\x07\x02no\x01p");
        assert!(!TcpResponse::decode(b"\x07\x02no\x01p").unwrap().0.is_ok());
        assert_eq!(TcpResponse::decode(b"\0\0\0data").unwrap().1, 3);
        for n in 0..golden.len() - 2 {
            assert!(TcpRequest::decode(&golden[2..2 + n]).is_err());
        }
        assert!(TcpRequest::decode(b"\0\0").is_err());
        assert!(TcpRequest::decode(b"\x48\x01").is_err()); // 2049-byte address rejected before allocation
        assert!(TcpResponse::decode(b"\0\0\x50\x01").is_err()); // 4097-byte padding
    }

    fn message() -> UdpMessage {
        UdpMessage {
            session_id: 0x01020304,
            packet_id: 0x1122,
            fragment_id: 0,
            fragment_count: 1,
            address: "a:53".into(),
            payload: b"abcdef".to_vec(),
        }
    }

    #[test]
    fn go_udp_complete_wire_golden_and_malformed_input() {
        let mut msg = message();
        msg.payload = vec![0xde, 0xad];
        let golden = b"\x01\x02\x03\x04\x11\x22\0\x01\x04a:53\xde\xad";
        assert_eq!(msg.encode().unwrap(), golden);
        assert_eq!(UdpMessage::decode(golden).unwrap(), msg);
        for n in 0..14 {
            assert!(UdpMessage::decode(&golden[..n]).is_err());
        }
        let mut bad = golden.to_vec();
        bad[7] = 0;
        assert!(UdpMessage::decode(&bad).is_err());
        bad[7] = 1;
        bad[6] = 1;
        assert!(UdpMessage::decode(&bad).is_err());
        assert!(msg.fragment(msg.header_size().unwrap()).is_err());
        msg.payload = vec![0; 256];
        assert!(msg.fragment(msg.header_size().unwrap() + 1).is_err());
    }

    #[test]
    fn out_of_order_duplicate_and_session_isolation() {
        let msg = message();
        let fragments = msg.fragment(msg.header_size().unwrap() + 2).unwrap();
        let now = Instant::now();
        let mut df = UdpReassembler::new(ReassemblyLimits::default()).unwrap();
        assert!(df.feed(fragments[2].clone(), now).unwrap().is_none());
        assert!(df.feed(fragments[2].clone(), now).unwrap().is_none());
        let mut other = fragments[0].clone();
        other.session_id += 1;
        assert!(df.feed(other, now).unwrap().is_none());
        assert!(df.feed(fragments[0].clone(), now).unwrap().is_none());
        assert_eq!(df.feed(fragments[1].clone(), now).unwrap(), Some(msg));
        assert_eq!(df.pending_packets(), 1);
        assert_eq!(df.buffered_bytes(), 2);
        df.expire(now + Duration::from_secs(10));
        assert_eq!(df.buffered_bytes(), 0);
    }

    #[test]
    fn conflicting_fragments_and_resource_limits() {
        let msg = message();
        let fragments = msg.fragment(msg.header_size().unwrap() + 2).unwrap();
        let now = Instant::now();
        let mut df = UdpReassembler::new(ReassemblyLimits {
            max_packets: 1,
            max_buffered_bytes: 3,
            ..ReassemblyLimits::default()
        })
        .unwrap();
        df.feed(fragments[0].clone(), now).unwrap();
        let mut conflict = fragments[0].clone();
        conflict.payload[0] ^= 1;
        assert!(df.feed(conflict, now).is_err());
        assert_eq!(df.buffered_bytes(), 0);
        df.feed(fragments[0].clone(), now).unwrap();
        let mut other = fragments[0].clone();
        other.address = "b:53".into();
        assert!(df.feed(other, now).is_err());
        assert!(df.feed(fragments[1].clone(), now).is_err());
        assert_eq!(df.buffered_bytes(), 0);
        df.feed(fragments[0].clone(), now).unwrap();
        let mut changed = fragments[1].clone();
        changed.fragment_count = 4;
        assert!(df.feed(changed, now).is_err());
        assert_eq!(df.pending_packets(), 0);
    }

    #[tokio::test]
    async fn async_header_does_not_consume_application_data() {
        let mut input = &b"\x44\x01\x04a:80\0payload"[..];
        assert_eq!(
            TcpRequest::read_stream(&mut input).await.unwrap().address,
            "a:80"
        );
        assert_eq!(input, b"payload");
        assert!(TcpRequest::read_stream(&mut &b"\0"[..]).await.is_err());
    }
}
