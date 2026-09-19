//! Standard-library-only Mux.Cool metadata and frame codec.
//! Derived from common/mux/{frame,writer,reader}.go; address tags are Xray
//! protocol tags (IPv4=1, domain=2, IPv6=3), not SOCKS address tags.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const MAX_METADATA: usize = 512;
pub const STREAM_CHUNK: usize = 8192;
pub const MAX_PACKET: usize = 8192;
pub const OPTION_DATA: u8 = 1;
pub const OPTION_ERROR: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Status {
    New = 1,
    Keep = 2,
    End = 3,
    KeepAlive = 4,
}

impl TryFrom<u8> for Status {
    type Error = io::Error;
    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::New),
            2 => Ok(Self::Keep),
            3 => Ok(Self::End),
            4 => Ok(Self::KeepAlive),
            _ => Err(invalid("unknown Mux.Cool session status")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Network {
    Tcp = 1,
    Udp = 2,
}

impl TryFrom<u8> for Network {
    type Error = io::Error;
    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(invalid("unknown Mux.Cool network")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Target {
    pub network: Network,
    pub host: Host,
    pub port: u16,
}

impl Target {
    /// Zero ports are valid for reverse bridge/control destinations.
    pub fn new(network: Network, host: &str, port: u16) -> io::Result<Self> {
        let host = match host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_)
                if !host.is_empty()
                    && host.len() <= 255
                    && !host
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) =>
            {
                Host::Domain(host.into())
            }
            Err(_) => return Err(invalid("invalid Mux.Cool domain")),
        };
        Ok(Self {
            network,
            host,
            port,
        })
    }
    pub fn is_domain(&self, domain: &str) -> bool {
        matches!(&self.host, Host::Domain(value) if value == domain)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MetadataMode {
    #[default]
    Ordinary,
    Reverse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub session_id: u16,
    pub status: Status,
    /// OPTION_DATA is derived from payload on encoding. Unknown bits survive.
    pub options: u8,
    pub target: Option<Target>,
    pub source: Option<Target>,
    pub local: Option<Target>,
    pub global_id: Option<[u8; 8]>,
    pub payload: Option<Vec<u8>>,
    /// Uninterpreted extension bytes after the recognized metadata.
    pub padding: Vec<u8>,
}

impl Frame {
    pub fn new(session_id: u16, target: Target, payload: Option<Vec<u8>>) -> Self {
        Self {
            target: Some(target),
            payload,
            ..Self::control(session_id, Status::New)
        }
    }
    pub fn control(session_id: u16, status: Status) -> Self {
        Self {
            session_id,
            status,
            options: 0,
            target: None,
            source: None,
            local: None,
            global_id: None,
            payload: None,
            padding: Vec::new(),
        }
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut meta = Vec::with_capacity(64);
        meta.extend_from_slice(&self.session_id.to_be_bytes());
        meta.push(self.status as u8);
        meta.push(
            (self.options & !OPTION_DATA)
                | if self.payload.is_some() {
                    OPTION_DATA
                } else {
                    0
                },
        );
        if self.status == Status::New {
            let target = self
                .target
                .as_ref()
                .ok_or_else(|| invalid("New frame lacks a target"))?;
            write_target(target, &mut meta)?;
            if self.source.is_some() && self.global_id.is_some() {
                return Err(invalid(
                    "reverse source metadata and XUDP global ID are mutually exclusive",
                ));
            }
            if let Some(source) = &self.source {
                write_target(source, &mut meta)?;
                if let Some(local) = &self.local {
                    write_target(local, &mut meta)?;
                }
            } else if self.local.is_some() {
                return Err(invalid("reverse local metadata requires source metadata"));
            } else if let Some(id) = self.global_id {
                if target.network != Network::Udp || self.payload.is_none() {
                    return Err(invalid("XUDP global ID requires a New UDP frame with data"));
                }
                meta.extend_from_slice(&id);
            }
        } else {
            if self.source.is_some() || self.local.is_some() || self.global_id.is_some() {
                return Err(invalid("source/local/global ID only belong on New frames"));
            }
            if let Some(target) = &self.target {
                if self.status != Status::Keep || target.network != Network::Udp {
                    return Err(invalid("only Keep UDP frames can override their target"));
                }
                write_target(target, &mut meta)?;
            }
        }
        meta.extend_from_slice(&self.padding);
        if meta.len() > MAX_METADATA {
            return Err(invalid("Mux.Cool metadata exceeds 512 bytes"));
        }
        let mut bytes =
            Vec::with_capacity(meta.len() + self.payload.as_ref().map_or(2, |p| p.len() + 4));
        bytes.extend_from_slice(&(meta.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&meta);
        if let Some(payload) = &self.payload {
            let length = u16::try_from(payload.len())
                .map_err(|_| invalid("Mux.Cool payload exceeds 65535 bytes"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(payload);
        }
        Ok(bytes)
    }
}

/// Returns None for a partial frame, or a complete frame plus bytes consumed.
/// The caller may retain any following frames in the input buffer.
pub fn decode(input: &[u8], mode: MetadataMode) -> io::Result<Option<(Frame, usize)>> {
    if input.len() < 2 {
        return Ok(None);
    }
    let meta_len = usize::from(u16::from_be_bytes([input[0], input[1]]));
    if !(4..=MAX_METADATA).contains(&meta_len) {
        return Err(invalid("Mux.Cool metadata length must be 4..512"));
    }
    if input.len() < 2 + meta_len {
        return Ok(None);
    }
    let meta = &input[2..2 + meta_len];
    let mut frame = Frame::control(
        u16::from_be_bytes([meta[0], meta[1]]),
        Status::try_from(meta[2])?,
    );
    frame.options = meta[3];
    let mut rest = &meta[4..];
    if frame.status == Status::New
        || (frame.status == Status::Keep && rest.first() == Some(&(Network::Udp as u8)))
    {
        frame.target = Some(read_target(&mut rest)?);
    }
    if frame.status == Status::New && mode == MetadataMode::Reverse {
        if rest.first().is_some_and(|b| *b != 0) {
            frame.source = Some(read_target(&mut rest)?);
            if rest.first().is_some_and(|b| *b != 0) {
                frame.local = Some(read_target(&mut rest)?);
            }
        }
    } else if frame.status == Status::New
        && frame.options & OPTION_DATA != 0
        && frame
            .target
            .as_ref()
            .is_some_and(|t| t.network == Network::Udp)
        && rest.len() >= 8
    {
        frame.global_id = Some(take(&mut rest, 8)?.try_into().expect("eight bytes"));
    }
    frame.padding = rest.to_vec();
    let mut consumed = 2 + meta_len;
    if frame.options & OPTION_DATA != 0 {
        if input.len() < consumed + 2 {
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes([input[consumed], input[consumed + 1]]));
        consumed += 2;
        if input.len() < consumed + length {
            return Ok(None);
        }
        frame.payload = Some(input[consumed..consumed + length].to_vec());
        consumed += length;
    }
    Ok(Some((frame, consumed)))
}

fn write_target(target: &Target, output: &mut Vec<u8>) -> io::Result<()> {
    output.push(target.network as u8);
    output.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| invalid("Mux.Cool domain exceeds 255 bytes"))?;
            if length == 0 {
                return Err(invalid("empty Mux.Cool domain"));
            }
            output.extend_from_slice(&[2, length]);
            output.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            output.push(3);
            output.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

fn read_target(input: &mut &[u8]) -> io::Result<Target> {
    let network = Network::try_from(take(input, 1)?[0])?;
    let port = u16::from_be_bytes(take(input, 2)?.try_into().expect("two bytes"));
    let host = match take(input, 1)?[0] {
        1 => Host::Ip(
            Ipv4Addr::from(<[u8; 4]>::try_from(take(input, 4)?).expect("four bytes")).into(),
        ),
        2 => {
            let length = usize::from(take(input, 1)?[0]);
            if length == 0 {
                return Err(invalid("empty Mux.Cool domain"));
            }
            Host::Domain(
                std::str::from_utf8(take(input, length)?)
                    .map_err(|_| invalid("Mux.Cool domain is not UTF-8"))?
                    .into(),
            )
        }
        3 => Host::Ip(
            Ipv6Addr::from(<[u8; 16]>::try_from(take(input, 16)?).expect("sixteen bytes")).into(),
        ),
        _ => return Err(invalid("unknown Mux.Cool address family")),
    };
    Ok(Target {
        network,
        host,
        port,
    })
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    if input.len() < count {
        return Err(invalid("truncated Mux.Cool metadata"));
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
    fn go_new_tcp_ipv4_golden() {
        let frame = Frame::new(
            0x1234,
            Target::new(Network::Tcp, "1.2.3.4", 443).unwrap(),
            Some(b"hi".to_vec()),
        );
        let fixture = [
            0, 12, 0x12, 0x34, 1, 1, 1, 1, 0xbb, 1, 1, 2, 3, 4, 0, 2, b'h', b'i',
        ];
        assert_eq!(frame.encode().unwrap(), fixture);
        let (decoded, used) = decode(&fixture, MetadataMode::Ordinary).unwrap().unwrap();
        assert_eq!(decoded.target, frame.target);
        assert_eq!(decoded.payload, frame.payload);
        assert_eq!(used, fixture.len());
        for length in 0..fixture.len() {
            assert!(
                decode(&fixture[..length], MetadataMode::Ordinary)
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn go_domain_and_udp_global_id_golden() {
        let mut frame = Frame::new(
            0,
            Target::new(Network::Udp, "a.test", 53).unwrap(),
            Some(vec![0xaa]),
        );
        frame.global_id = Some([1, 2, 3, 4, 5, 6, 7, 8]);
        let fixture = [
            0, 23, 0, 0, 1, 1, 2, 0, 53, 2, 6, b'a', b'.', b't', b'e', b's', b't', 1, 2, 3, 4, 5,
            6, 7, 8, 0, 1, 0xaa,
        ];
        assert_eq!(frame.encode().unwrap(), fixture);
        assert_eq!(
            decode(&fixture, MetadataMode::Ordinary)
                .unwrap()
                .unwrap()
                .0
                .global_id,
            frame.global_id
        );
    }
    #[test]
    fn reverse_source_local_and_ipv6_roundtrip() {
        let mut frame = Frame::new(7, Target::new(Network::Udp, "reverse", 0).unwrap(), None);
        frame.source = Some(Target::new(Network::Tcp, "2001:db8::1", 8443).unwrap());
        frame.local = Some(Target::new(Network::Udp, "127.0.0.1", 1080).unwrap());
        let bytes = frame.encode().unwrap();
        assert_eq!(
            decode(&bytes, MetadataMode::Reverse).unwrap().unwrap().0,
            frame
        );
    }

    #[test]
    fn reverse_zero_padding_does_not_become_source_or_global_id() {
        let mut frame = Frame::new(
            1,
            Target::new(Network::Udp, "reverse", 0).unwrap(),
            Some(vec![1]),
        );
        frame.padding = vec![0, 99, 88, 77, 66, 55, 44, 33];
        let bytes = frame.encode().unwrap();
        let reverse = decode(&bytes, MetadataMode::Reverse).unwrap().unwrap().0;
        assert_eq!(reverse.source, None);
        assert_eq!(reverse.local, None);
        assert_eq!(reverse.global_id, None);
        assert_eq!(reverse.padding, frame.padding);
        let ordinary = decode(&bytes, MetadataMode::Ordinary).unwrap().unwrap().0;
        assert_eq!(ordinary.global_id, Some([0, 99, 88, 77, 66, 55, 44, 33]));
        frame.payload = None;
        assert_eq!(
            decode(&frame.encode().unwrap(), MetadataMode::Ordinary)
                .unwrap()
                .unwrap()
                .0
                .global_id,
            None
        );
    }
    #[test]
    fn keep_override_padding_and_empty_payload() {
        let mut frame = Frame::control(2, Status::Keep);
        frame.target = Some(Target::new(Network::Udp, "8.8.8.8", 53).unwrap());
        frame.payload = Some(Vec::new());
        frame.options = OPTION_DATA;
        assert_eq!(
            decode(&frame.encode().unwrap(), MetadataMode::Ordinary)
                .unwrap()
                .unwrap()
                .0,
            frame
        );
        let mut padding = Frame::control(2, Status::Keep);
        padding.padding = vec![0, 2, 3, 4];
        assert!(
            decode(&padding.encode().unwrap(), MetadataMode::Ordinary)
                .unwrap()
                .unwrap()
                .0
                .target
                .is_none()
        );
    }
    #[test]
    fn reject_invalid_lengths_network_status_and_new_without_target() {
        for bytes in [
            &[0, 3][..],
            &[2, 1],
            &[0, 4, 0, 1, 99, 0],
            &[0, 8, 0, 1, 1, 0, 9, 0, 80, 1],
        ] {
            assert!(decode(bytes, MetadataMode::Ordinary).is_err());
        }
        assert!(Frame::control(1, Status::New).encode().is_err());
        let mut frame = Frame::new(1, Target::new(Network::Udp, "1.1.1.1", 53).unwrap(), None);
        frame.global_id = Some([1; 8]);
        assert!(frame.encode().is_err());
    }
    #[test]
    fn end_error_and_keepalive_fixture() {
        let mut end = Frame::control(0xabcd, Status::End);
        end.options = OPTION_ERROR;
        assert_eq!(end.encode().unwrap(), [0, 4, 0xab, 0xcd, 3, 2]);
        assert_eq!(
            Frame::control(0, Status::KeepAlive).encode().unwrap(),
            [0, 4, 0, 0, 4, 0]
        );
    }
}
