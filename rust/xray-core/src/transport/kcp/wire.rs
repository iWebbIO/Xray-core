//! Xray's KCP framing, from `transport/internet/kcp/segment.go`.
//!
//! This is deliberately not the little-endian, 24-byte stock ikcp format.
use std::io;

pub const DATA_OVERHEAD: usize = 18;
pub const ACK_OVERHEAD: usize = 17;
pub const CLOSE: u8 = 1;
pub const ACK_LIMIT: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Segment {
    Data {
        conv: u16,
        option: u8,
        timestamp: u32,
        number: u32,
        sending_next: u32,
        payload: Vec<u8>,
    },
    Ack {
        conv: u16,
        option: u8,
        receiving_window: u32,
        receiving_next: u32,
        timestamp: u32,
        numbers: Vec<u32>,
    },
    Command {
        conv: u16,
        option: u8,
        command: Command,
        sending_next: u32,
        receiving_next: u32,
        peer_rto: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Terminate = 2,
    Ping = 3,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked segment length"),
    )
}

impl Segment {
    pub fn conversation(&self) -> u16 {
        match self {
            Self::Data { conv, .. } | Self::Ack { conv, .. } | Self::Command { conv, .. } => *conv,
        }
    }
    pub fn option(&self) -> u8 {
        match self {
            Self::Data { option, .. } | Self::Ack { option, .. } | Self::Command { option, .. } => {
                *option
            }
        }
    }
    pub fn is_terminate(&self) -> bool {
        matches!(
            self,
            Self::Command {
                command: Command::Terminate,
                ..
            }
        )
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.option() & !CLOSE != 0 {
            return Err(invalid("unknown Xray KCP segment option"));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.conversation().to_be_bytes());
        out.push(match self {
            Self::Data { .. } => 1,
            Self::Ack { .. } => 0,
            Self::Command { command, .. } => *command as u8,
        });
        out.push(self.option());
        match self {
            Self::Data {
                timestamp,
                number,
                sending_next,
                payload,
                ..
            } => {
                if payload.is_empty() || payload.len() > u16::MAX as usize {
                    return Err(invalid("invalid Xray KCP data length"));
                }
                for value in [timestamp, number, sending_next] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::Ack {
                receiving_window,
                receiving_next,
                timestamp,
                numbers,
                ..
            } => {
                // Go's parser accepts a byte-sized list, although its sender caps it at 128.
                if numbers.len() > u8::MAX as usize {
                    return Err(invalid("too many Xray KCP ACK numbers"));
                }
                for value in [receiving_window, receiving_next, timestamp] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                out.push(numbers.len() as u8);
                for value in numbers {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Self::Command {
                sending_next,
                receiving_next,
                peer_rto,
                ..
            } => {
                for value in [sending_next, receiving_next, peer_rto] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
        }
        Ok(out)
    }
}

/// Decode the entire datagram before changing conversation state. Unlike Go's
/// permissive prefix parser, a malformed suffix is rejected atomically.
pub fn decode_datagram(mut bytes: &[u8], mtu: usize) -> io::Result<Vec<Segment>> {
    if bytes.is_empty() || bytes.len() > mtu {
        return Err(invalid("empty or oversized Xray KCP datagram"));
    }
    let mut segments = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid("truncated Xray KCP header"));
        }
        let conv = u16::from_be_bytes([bytes[0], bytes[1]]);
        let option = bytes[3];
        if option & !CLOSE != 0 {
            return Err(invalid("unknown Xray KCP segment option"));
        }
        let (segment, size) = match bytes[2] {
            1 => {
                if bytes.len() < DATA_OVERHEAD {
                    return Err(invalid("truncated Xray KCP data header"));
                }
                let length = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
                let size = DATA_OVERHEAD + length;
                if length == 0 || bytes.len() < size {
                    return Err(invalid("truncated or empty Xray KCP payload"));
                }
                (
                    Segment::Data {
                        conv,
                        option,
                        timestamp: u32_at(bytes, 4),
                        number: u32_at(bytes, 8),
                        sending_next: u32_at(bytes, 12),
                        payload: bytes[DATA_OVERHEAD..size].to_vec(),
                    },
                    size,
                )
            }
            0 => {
                if bytes.len() < ACK_OVERHEAD {
                    return Err(invalid("truncated Xray KCP ACK header"));
                }
                let size = ACK_OVERHEAD + bytes[16] as usize * 4;
                if bytes.len() < size {
                    return Err(invalid("truncated Xray KCP ACK numbers"));
                }
                (
                    Segment::Ack {
                        conv,
                        option,
                        receiving_window: u32_at(bytes, 4),
                        receiving_next: u32_at(bytes, 8),
                        timestamp: u32_at(bytes, 12),
                        numbers: (ACK_OVERHEAD..size)
                            .step_by(4)
                            .map(|offset| u32_at(bytes, offset))
                            .collect(),
                    },
                    size,
                )
            }
            command @ (2 | 3) => {
                if bytes.len() < 16 {
                    return Err(invalid("truncated Xray KCP command"));
                }
                (
                    Segment::Command {
                        conv,
                        option,
                        command: if command == 2 {
                            Command::Terminate
                        } else {
                            Command::Ping
                        },
                        sending_next: u32_at(bytes, 4),
                        receiving_next: u32_at(bytes, 8),
                        peer_rto: u32_at(bytes, 12),
                    },
                    16,
                )
            }
            _ => return Err(invalid("unknown Xray KCP command")),
        };
        segments.push(segment);
        bytes = &bytes[size..];
    }
    let conv = segments[0].conversation();
    if segments
        .iter()
        .any(|segment| segment.conversation() != conv)
    {
        return Err(invalid("mixed conversations in Xray KCP datagram"));
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_data_fixture() {
        let segment = Segment::Data {
            conv: 1,
            option: 0,
            timestamp: 3,
            number: 4,
            sending_next: 5,
            payload: b"abcd".to_vec(),
        };
        let golden = [
            0, 1, 1, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 4, b'a', b'b', b'c', b'd',
        ];
        assert_eq!(segment.encode().unwrap(), golden);
        assert_eq!(decode_datagram(&golden, 1350).unwrap(), vec![segment]);
    }
    #[test]
    fn go_ack_and_command_fixtures() {
        let ack = Segment::Ack {
            conv: 1,
            option: 0,
            receiving_window: 2,
            receiving_next: 3,
            timestamp: 10,
            numbers: vec![1, 3, 5, 7, 9],
        };
        let golden = [
            0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 10, 5, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5,
            0, 0, 0, 7, 0, 0, 0, 9,
        ];
        assert_eq!(ack.encode().unwrap(), golden);
        let ping = Segment::Command {
            conv: 1,
            option: CLOSE,
            command: Command::Ping,
            sending_next: 11,
            receiving_next: 13,
            peer_rto: 15,
        };
        let command = [0, 1, 3, 1, 0, 0, 0, 11, 0, 0, 0, 13, 0, 0, 0, 15];
        assert_eq!(ping.encode().unwrap(), command);
        let packet = [golden.as_slice(), command.as_slice()].concat();
        assert_eq!(decode_datagram(&packet, 1350).unwrap(), vec![ack, ping]);
    }
    #[test]
    fn all_truncations_and_invalid_suffix_rejected() {
        let packet = Segment::Data {
            conv: 0x1234,
            option: 0,
            timestamp: 1,
            number: 2,
            sending_next: 0,
            payload: vec![8; 100],
        }
        .encode()
        .unwrap();
        for n in 0..packet.len() {
            assert!(decode_datagram(&packet[..n], 1350).is_err(), "length {n}");
        }
        let mut packet = packet;
        packet.push(0);
        assert!(decode_datagram(&packet, 1350).is_err());
        assert!(decode_datagram(&[0, 0, 4, 0], 1350).is_err());
        assert!(decode_datagram(&[0, 0, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1350).is_err());
    }
    #[test]
    fn ack_count_mtu_and_conversation_bounds() {
        let ack = Segment::Ack {
            conv: 1,
            option: 0,
            receiving_window: 32,
            receiving_next: 0,
            timestamp: 0,
            numbers: vec![0; 255],
        };
        let packet = ack.encode().unwrap();
        assert_eq!(decode_datagram(&packet, 1350).unwrap(), vec![ack]);
        assert!(decode_datagram(&packet[..packet.len() - 1], 1350).is_err());
        assert!(decode_datagram(&packet, 100).is_err());
        let mut mixed = packet.clone();
        let mut other = packet;
        other[1] = 2;
        mixed.extend(other);
        assert!(decode_datagram(&mixed, 4096).is_err());
    }

    #[test]
    fn independent_non_symmetric_big_endian_fixture() {
        let data = Segment::Data {
            conv: 7,
            option: 0,
            timestamp: 0x01020304,
            number: 0x0a0b0c0d,
            sending_next: 0x11223344,
            payload: b"abc".to_vec(),
        };
        assert_eq!(
            data.encode().unwrap(),
            [
                0, 7, 1, 0, 1, 2, 3, 4, 10, 11, 12, 13, 17, 34, 51, 68, 0, 3, 97, 98, 99
            ]
        );
    }
}
