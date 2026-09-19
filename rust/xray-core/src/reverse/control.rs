//! Wire-compatible protobuf for app/reverse/config.proto Control. Kept
//! dependency-free so source-derived control fixtures can run with rustc.

use std::io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum State {
    #[default]
    Active,
    Drain,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Control {
    pub state: State,
    pub random: Vec<u8>,
}

impl Control {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if self.state == State::Drain {
            bytes.extend_from_slice(&[8, 1]);
        }
        if !self.random.is_empty() {
            bytes.extend_from_slice(&[0x9a, 0x06]); // protobuf bytes field 99
            write_varint(self.random.len() as u64, &mut bytes);
            bytes.extend_from_slice(&self.random);
        }
        bytes
    }
    pub fn decode(mut input: &[u8]) -> io::Result<Self> {
        let mut result = Self::default();
        while !input.is_empty() {
            let tag = read_varint(&mut input)?;
            let field = tag >> 3;
            if field == 0 || field >= 1 << 29 {
                return Err(invalid("invalid reverse Control field number"));
            }
            match (field, tag & 7) {
                (1, 0) => {
                    result.state = match read_varint(&mut input)? {
                        0 => State::Active,
                        1 => State::Drain,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::Unsupported,
                                "unknown reverse Control state",
                            ));
                        }
                    }
                }
                (99, 2) => {
                    let size = usize::try_from(read_varint(&mut input)?)
                        .map_err(|_| invalid("reverse Control length overflow"))?;
                    result.random = take(&mut input, size)?.to_vec();
                }
                (1, _) | (99, _) => {
                    return Err(invalid(
                        "wrong protobuf wire type for reverse Control field",
                    ));
                }
                (_, 0) => {
                    read_varint(&mut input)?;
                }
                (_, 1) => {
                    take(&mut input, 8)?;
                }
                (_, 2) => {
                    let size = usize::try_from(read_varint(&mut input)?)
                        .map_err(|_| invalid("reverse Control length overflow"))?;
                    take(&mut input, size)?;
                }
                (_, 5) => {
                    take(&mut input, 4)?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "protobuf groups are unsupported in reverse Control",
                    ));
                }
            }
        }
        Ok(result)
    }
}

fn read_varint(input: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0_u64;
    for offset in 0..10 {
        let byte = take(input, 1)?[0];
        if offset == 9 && byte > 1 {
            return Err(invalid("protobuf varint overflows uint64"));
        }
        value |= u64::from(byte & 0x7f) << (7 * offset);
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(invalid("protobuf varint is too long"))
}
fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push(value as u8 | 128);
        value >>= 7;
    }
    output.push(value as u8);
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    if input.len() < count {
        return Err(invalid("truncated reverse Control protobuf"));
    }
    let (head, rest) = input.split_at(count);
    *input = rest;
    Ok(head)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_and_drain_go_protobuf_fixtures() {
        for (state, fixture) in [
            (State::Active, vec![0x9a, 0x06, 2, 0xaa, 0xbb]),
            (State::Drain, vec![8, 1, 0x9a, 0x06, 2, 0xaa, 0xbb]),
        ] {
            let control = Control {
                state,
                random: vec![0xaa, 0xbb],
            };
            assert_eq!(control.encode(), fixture);
            assert_eq!(Control::decode(&fixture).unwrap(), control);
        }
        assert_eq!(Control::decode(&[]).unwrap().state, State::Active);
    }
    #[test]
    fn unknown_fields_skip_and_last_known_field_wins() {
        let bytes = [8, 1, 0x12, 3, 1, 2, 3, 0x1d, 0, 0, 0, 0, 8, 0, 0x20, 255, 1];
        assert_eq!(Control::decode(&bytes).unwrap().state, State::Active);
    }
    #[test]
    fn truncated_overflow_and_unknown_state_fail_explicitly() {
        for bytes in [
            &[0x9a, 0x06, 2, 1][..],
            &[8],
            &[0],
            &[8, 2],
            &[8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
            &[0x0a, 0],
        ] {
            assert!(Control::decode(bytes).is_err());
        }
    }
}
