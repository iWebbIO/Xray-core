//! Bounded DNS message decoding and address-query encoding without a C resolver.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{DnsError, Result};

pub const CLASS_IN: u16 = 1;
pub const MAX_MESSAGE_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecordType(pub u16);

impl RecordType {
    pub const A: Self = Self(1);
    pub const CNAME: Self = Self(5);
    pub const AAAA: Self = Self(28);
    pub const OPT: Self = Self(41);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    /// Absolute DNS name, including its final dot.
    pub name: String,
    pub record_type: RecordType,
    pub class: u16,
}

impl Question {
    pub fn new(name: &str, record_type: RecordType) -> Result<Self> {
        Ok(Self {
            name: fqdn(name)?,
            record_type,
            class: CLASS_IN,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
}

impl Header {
    pub fn is_response(self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn is_truncated(self) -> bool {
        self.flags & 0x0200 != 0
    }

    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0xf) as u8
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    /// Unknown RDATA is opaque and may contain message-relative pointers.
    /// It must not be copied to a newly encoded message.
    Other(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub name: String,
    pub record_type: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    pub fn response_code(&self) -> u16 {
        let extended = self
            .additionals
            .iter()
            .find(|record| record.record_type == RecordType::OPT && record.ttl & 0x00ff_0000 == 0)
            .map_or(0, |record| (record.ttl >> 24) as u16);
        (extended << 4) | (self.header.flags & 0xf)
    }

    pub fn udp_payload_size(&self) -> usize {
        self.additionals
            .iter()
            .find(|record| record.record_type == RecordType::OPT)
            .map_or(512, |record| usize::from(record.class).max(512))
    }

    pub fn has_edns(&self) -> bool {
        self.additionals
            .iter()
            .any(|record| record.record_type == RecordType::OPT)
    }
}

/// Preserve case like Go's Fqdn; callers case-fold only comparison/cache keys.
pub fn fqdn(name: &str) -> Result<String> {
    if name == "." {
        return Ok(name.to_owned());
    }
    let bare = name.strip_suffix('.').unwrap_or(name);
    if bare.is_empty()
        || !bare.is_ascii()
        || bare
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'\\')
        || bare
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
        || bare.len() + 2 > 255
    {
        return Err(DnsError::InvalidName(name.to_owned()));
    }
    Ok(format!("{bare}."))
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_name(output: &mut Vec<u8>, name: &str) -> Result<()> {
    let name = fqdn(name)?;
    if name != "." {
        for label in name[..name.len() - 1].split('.') {
            output.push(label.len() as u8);
            output.extend_from_slice(label.as_bytes());
        }
    }
    output.push(0);
    Ok(())
}

fn put_question(output: &mut Vec<u8>, question: &Question) -> Result<()> {
    put_name(output, &question.name)?;
    put_u16(output, question.record_type.0);
    put_u16(output, question.class);
    Ok(())
}

/// Encode RD=1, one IN question, and optional Xray-style client subnet.
/// ECS uses IPv4 /24 or IPv6 /96, UDP payload size 1350 and DNSSEC OK.
pub fn encode_query(id: u16, question: &Question, client_ip: Option<IpAddr>) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(512);
    for value in [id, 0x0100, 1, 0, 0, u16::from(client_ip.is_some())] {
        put_u16(&mut output, value);
    }
    put_question(&mut output, question)?;
    if let Some(ip) = client_ip {
        let (family, prefix, bytes): (u16, u8, Vec<u8>) = match ip {
            IpAddr::V4(ip) => (1, 24, ip.octets()[..3].to_vec()),
            IpAddr::V6(ip) => (2, 96, ip.octets()[..12].to_vec()),
        };
        output.push(0);
        put_u16(&mut output, RecordType::OPT.0);
        put_u16(&mut output, 1350);
        // Preserve Go SetEDNS0(1350, 0xfe00, true), including its unusual
        // extended-RCODE byte: uint32(0xfe00) >> 4 << 24 == 0xe0000000.
        put_u32(&mut output, 0xe000_8000);
        put_u16(&mut output, (8 + bytes.len()) as u16);
        put_u16(&mut output, 8);
        put_u16(&mut output, (4 + bytes.len()) as u16);
        put_u16(&mut output, family);
        output.extend_from_slice(&[prefix, 0]);
        output.extend_from_slice(&bytes);
    }
    Ok(output)
}

/// Build the AA, RD, RA address replies used by Xray's DNS outbound.
/// `max_size` applies the negotiated UDP limit; omitted answers set TC.
pub fn encode_response(
    id: u16,
    question: &Question,
    ips: &[IpAddr],
    ttl: u32,
    response_code: u16,
    edns_payload: Option<u16>,
    max_size: usize,
) -> Result<Vec<u8>> {
    if response_code > 0xfff || (response_code > 15 && edns_payload.is_none()) {
        return Err(DnsError::Unsupported("extended RCODE without EDNS".into()));
    }
    let max_size = max_size.min(MAX_MESSAGE_SIZE);
    let mut output = Vec::with_capacity(512);
    for value in [
        id,
        0x8580 | (response_code & 0xf),
        1,
        0,
        0,
        u16::from(edns_payload.is_some()),
    ] {
        put_u16(&mut output, value);
    }
    put_question(&mut output, question)?;
    let reserved = usize::from(edns_payload.is_some()) * 11;
    if output.len() + reserved > max_size {
        return Err(DnsError::InvalidConfig(
            "DNS response limit cannot fit its question",
        ));
    }
    let mut answers = 0u16;
    if response_code == 0 {
        for ip in ips {
            let data = match (question.record_type, ip) {
                (RecordType::A, IpAddr::V4(ip)) => ip.octets().to_vec(),
                (RecordType::AAAA, IpAddr::V6(ip)) => ip.octets().to_vec(),
                _ => continue,
            };
            if output.len() + 12 + data.len() + reserved > max_size {
                output[2] |= 0x02;
                break;
            }
            put_u16(&mut output, 0xc00c);
            put_u16(&mut output, question.record_type.0);
            put_u16(&mut output, CLASS_IN);
            put_u32(&mut output, ttl);
            put_u16(&mut output, data.len() as u16);
            output.extend_from_slice(&data);
            answers += 1;
        }
    }
    output[6..8].copy_from_slice(&answers.to_be_bytes());
    if let Some(payload) = edns_payload {
        output.push(0);
        put_u16(&mut output, RecordType::OPT.0);
        put_u16(&mut output, payload.max(512));
        put_u32(&mut output, u32::from(response_code >> 4) << 24);
        put_u16(&mut output, 0);
    }
    Ok(output)
}

pub fn encode_error(id: u16, code: u16) -> Vec<u8> {
    let mut output = Vec::with_capacity(12);
    for value in [id, 0x8180 | (code & 15), 0, 0, 0, 0] {
        put_u16(&mut output, value);
    }
    output
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(DnsError::Malformed("length overflow"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(DnsError::Malformed("unexpected end of message"))?;
        self.cursor = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn name(&mut self) -> Result<String> {
        let mut position = self.cursor;
        let mut jumped = false;
        let mut jumps = 0;
        let mut name = String::new();
        let mut expanded_size = 1usize;
        loop {
            let byte = *self
                .bytes
                .get(position)
                .ok_or(DnsError::Malformed("name exceeds message"))?;
            if byte & 0xc0 == 0xc0 {
                let next = *self
                    .bytes
                    .get(position + 1)
                    .ok_or(DnsError::Malformed("incomplete compression pointer"))?;
                let target = (usize::from(byte & 0x3f) << 8) | usize::from(next);
                if target >= position || target < 12 || jumps >= 128 {
                    return Err(DnsError::Malformed("invalid or cyclic compression pointer"));
                }
                if !jumped {
                    self.cursor = position + 2;
                    jumped = true;
                }
                jumps += 1;
                position = target;
                continue;
            }
            if byte & 0xc0 != 0 {
                return Err(DnsError::Malformed("reserved label encoding"));
            }
            position += 1;
            if byte == 0 {
                if !jumped {
                    self.cursor = position;
                }
                if name.is_empty() {
                    name.push('.');
                }
                return Ok(name);
            }
            let end = position + usize::from(byte);
            let label = self
                .bytes
                .get(position..end)
                .ok_or(DnsError::Malformed("incomplete name label"))?;
            if !label.is_ascii()
                || label.iter().any(|b| {
                    b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'.' | b'\\')
                })
            {
                return Err(DnsError::Malformed("unsupported binary DNS label"));
            }
            expanded_size += label.len() + 1;
            if expanded_size > 255 {
                return Err(DnsError::Malformed("expanded DNS name exceeds 255 octets"));
            }
            name.push_str(
                std::str::from_utf8(label)
                    .map_err(|_| DnsError::Malformed("invalid name label"))?,
            );
            name.push('.');
            position = end;
        }
    }

    fn question(&mut self) -> Result<Question> {
        Ok(Question {
            name: self.name()?,
            record_type: RecordType(self.u16()?),
            class: self.u16()?,
        })
    }

    fn record(&mut self) -> Result<Record> {
        let name = self.name()?;
        let record_type = RecordType(self.u16()?);
        let class = self.u16()?;
        let ttl = self.u32()?;
        let length = usize::from(self.u16()?);
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DnsError::Malformed("RDATA exceeds message"))?;
        let data = match record_type {
            RecordType::A => {
                if length != 4 {
                    return Err(DnsError::Malformed("A record length is not four"));
                }
                let bytes = self.take(4)?;
                RecordData::A(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            RecordType::AAAA => {
                if length != 16 {
                    return Err(DnsError::Malformed("AAAA record length is not sixteen"));
                }
                let mut octets = [0; 16];
                octets.copy_from_slice(self.take(16)?);
                RecordData::Aaaa(Ipv6Addr::from(octets))
            }
            RecordType::CNAME => RecordData::Cname(self.name()?),
            _ => RecordData::Other(self.take(length)?.to_vec()),
        };
        if self.cursor != end {
            return Err(DnsError::Malformed("RDATA length mismatch"));
        }
        Ok(Record {
            name,
            record_type,
            class,
            ttl,
            data,
        })
    }
}

pub fn decode(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 12 || bytes.len() > MAX_MESSAGE_SIZE {
        return Err(DnsError::Malformed("message length outside 12..65535"));
    }
    let mut decoder = Decoder { bytes, cursor: 0 };
    let header = Header {
        id: decoder.u16()?,
        flags: decoder.u16()?,
    };
    let counts = [
        decoder.u16()?,
        decoder.u16()?,
        decoder.u16()?,
        decoder.u16()?,
    ];
    // Every question uses at least five bytes, every RR at least eleven.
    if usize::from(counts[0]) * 5
        + counts[1..]
            .iter()
            .map(|n| usize::from(*n) * 11)
            .sum::<usize>()
        > bytes.len() - 12
    {
        return Err(DnsError::Malformed("section counts exceed message size"));
    }
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        questions.push(decoder.question()?);
    }
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (records, count) in sections.iter_mut().zip(&counts[1..]) {
        for _ in 0..*count {
            records.push(decoder.record()?);
        }
    }
    if decoder.cursor != bytes.len() {
        return Err(DnsError::Malformed("trailing bytes after DNS sections"));
    }
    let [answers, authorities, additionals] = sections;
    let mut opt_seen = false;
    for record in &additionals {
        if record.record_type == RecordType::OPT {
            if opt_seen || record.name != "." {
                return Err(DnsError::Malformed("duplicate OPT or non-root OPT owner"));
            }
            opt_seen = true;
            if let RecordData::Other(bytes) = &record.data {
                let mut options = Decoder { bytes, cursor: 0 };
                while options.cursor < bytes.len() {
                    options.u16()?;
                    let length = usize::from(options.u16()?);
                    options.take(length)?;
                }
            }
        }
    }
    Ok(Message {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

/// Decode only the header/questions of a TC packet. Its answer section can
/// legally end mid-record, so full-message validation must wait for TCP retry.
pub(crate) fn decode_question_section(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 12 || bytes.len() > MAX_MESSAGE_SIZE {
        return Err(DnsError::Malformed("message length outside 12..65535"));
    }
    let mut decoder = Decoder { bytes, cursor: 0 };
    let header = Header {
        id: decoder.u16()?,
        flags: decoder.u16()?,
    };
    let count = decoder.u16()?;
    decoder.take(6)?;
    if usize::from(count) * 5 > bytes.len() - 12 {
        return Err(DnsError::Malformed("question count exceeds message size"));
    }
    let mut questions = Vec::new();
    for _ in 0..count {
        questions.push(decoder.question()?);
    }
    Ok(Message {
        header,
        questions,
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    })
}
