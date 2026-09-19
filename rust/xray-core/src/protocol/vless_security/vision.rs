//! Vision framing and bounded TLS inspection from `proxy/proxy.go`.
//!
//! A Direct command is only a signal. Switching the underlying TLS/socket path,
//! draining TLS buffers, and splice/accounting policy must be handled separately.

use rand::Rng;
use std::io;
use subtle::ConstantTimeEq;

pub const UUID_LEN: usize = 16;
pub const FRAME_HEADER_LEN: usize = 5;
pub const GO_BUFFER_SIZE: usize = 8192;
pub const MAX_FRAME_BODY: usize = GO_BUFFER_SIZE - UUID_LEN - FRAME_HEADER_LEN;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for Command {
    type Error = io::Error;
    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            _ => Err(invalid("unknown Vision padding command")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaddingSettings {
    pub long_threshold: u32,
    pub long_range: u32,
    pub long_base: u32,
    pub short_range: u32,
}

impl Default for PaddingSettings {
    fn default() -> Self {
        Self {
            long_threshold: 900,
            long_range: 500,
            long_base: 900,
            short_range: 256,
        }
    }
}

impl PaddingSettings {
    /// `draw` is uniform in 0..long_range or 0..short_range (upper bound excluded).
    /// Supplying it explicitly permits deterministic source-derived fixtures.
    pub fn length_for_draw(&self, content: usize, long: bool, draw: u32) -> io::Result<usize> {
        if content > MAX_FRAME_BODY {
            return Err(invalid("Vision content exceeds source buffer limit"));
        }
        let use_long = long && (content as u64) < u64::from(self.long_threshold);
        let range = if use_long {
            self.long_range
        } else {
            self.short_range
        };
        if range == 0 || draw >= range {
            return Err(invalid("invalid Vision padding draw/range"));
        }
        let length = if use_long {
            (u64::from(draw) + u64::from(self.long_base))
                .checked_sub(content as u64)
                .ok_or_else(|| invalid("negative Vision padding length"))?
        } else {
            u64::from(draw)
        };
        Ok(length.min((MAX_FRAME_BODY - content) as u64) as usize)
    }

    pub fn random_length(&self, content: usize, long: bool) -> io::Result<usize> {
        let range = if long && (content as u64) < u64::from(self.long_threshold) {
            self.long_range
        } else {
            self.short_range
        };
        if range == 0 {
            return Err(invalid("Vision padding range is zero"));
        }
        self.length_for_draw(content, long, rand::thread_rng().gen_range(0..range))
    }
}

/// A directional frame encoder: UUID appears once, then five-byte headers.
/// After End/Direct, the runtime must route subsequent bytes without this codec.
pub struct Encoder {
    uuid: Option<[u8; 16]>,
    ended: bool,
}

impl Encoder {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid: Some(uuid),
            ended: false,
        }
    }

    pub fn encode_with_padding(
        &mut self,
        content: &[u8],
        command: Command,
        padding: &[u8],
    ) -> io::Result<Vec<u8>> {
        if self.ended {
            return Err(invalid("Vision padding has already ended"));
        }
        if content.len() > MAX_FRAME_BODY || padding.len() > MAX_FRAME_BODY - content.len() {
            return Err(invalid("Vision frame exceeds source buffer limit"));
        }
        let mut output = Vec::with_capacity(21 + content.len() + padding.len());
        if let Some(uuid) = self.uuid.take() {
            output.extend_from_slice(&uuid);
        }
        output.push(command as u8);
        output.extend_from_slice(&(content.len() as u16).to_be_bytes());
        output.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        output.extend_from_slice(content);
        output.extend_from_slice(padding);
        self.ended = command != Command::Continue;
        Ok(output)
    }

    pub fn encode(
        &mut self,
        content: &[u8],
        command: Command,
        long: bool,
        settings: PaddingSettings,
    ) -> io::Result<Vec<u8>> {
        let length = settings.random_length(content.len(), long)?;
        let mut padding = vec![0; length];
        rand::thread_rng().fill(padding.as_mut_slice());
        self.encode_with_padding(content, command, &padding)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DecodedChunk {
    pub content: Vec<u8>,
    /// Bytes consumed from this call's input. At End/Direct the remainder is
    /// untouched and belongs to the caller's selected next transport layer.
    pub consumed: usize,
    pub transition: Option<Command>,
}

struct Block {
    command: Command,
    content: usize,
    padding: usize,
}

/// Strict framed Vision decoder. The surrounding protocol must select Vision
/// before constructing it. It deliberately does not guess whether arbitrary
/// input lacking the UUID should instead pass through as ordinary traffic.
pub struct Decoder {
    uuid: [u8; 16],
    prefix_read: usize,
    header: [u8; 5],
    header_read: usize,
    block: Option<Block>,
    completed_frame: bool,
    ended: bool,
    failed: bool,
}

impl Decoder {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            prefix_read: 0,
            header: [0; 5],
            header_read: 0,
            block: None,
            completed_frame: false,
            ended: false,
            failed: false,
        }
    }

    pub fn push(&mut self, input: &[u8]) -> io::Result<DecodedChunk> {
        if self.failed {
            return Err(invalid("Vision decoder is poisoned"));
        }
        if self.ended {
            return Err(invalid(
                "Vision padding has ended; route remaining bytes outside this decoder",
            ));
        }
        let result = self.push_inner(input);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn push_inner(&mut self, input: &[u8]) -> io::Result<DecodedChunk> {
        let mut output = DecodedChunk {
            content: Vec::new(),
            consumed: 0,
            transition: None,
        };
        while output.consumed < input.len()
            || self
                .block
                .as_ref()
                .is_some_and(|block| block.content == 0 && block.padding == 0)
        {
            if self.prefix_read < UUID_LEN {
                let take = (UUID_LEN - self.prefix_read).min(input.len() - output.consumed);
                if !bool::from(
                    self.uuid[self.prefix_read..self.prefix_read + take]
                        .ct_eq(&input[output.consumed..output.consumed + take]),
                ) {
                    return Err(invalid("Vision UUID prefix mismatch"));
                }
                self.prefix_read += take;
                output.consumed += take;
                continue;
            }
            if self.block.is_none() {
                let take = (5 - self.header_read).min(input.len() - output.consumed);
                self.header[self.header_read..self.header_read + take]
                    .copy_from_slice(&input[output.consumed..output.consumed + take]);
                self.header_read += take;
                output.consumed += take;
                if self.header_read < 5 {
                    continue;
                }
                let command = Command::try_from(self.header[0])?;
                let content = u16::from_be_bytes([self.header[1], self.header[2]]) as usize;
                let padding = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if content + padding > MAX_FRAME_BODY {
                    return Err(invalid("Vision frame exceeds source buffer limit"));
                }
                self.block = Some(Block {
                    command,
                    content,
                    padding,
                });
                self.header_read = 0;
            }
            let block = self.block.as_mut().expect("parsed block");
            let take = block.content.min(input.len() - output.consumed);
            output
                .content
                .extend_from_slice(&input[output.consumed..output.consumed + take]);
            output.consumed += take;
            block.content -= take;
            if block.content != 0 {
                continue;
            }
            let skip = block.padding.min(input.len() - output.consumed);
            block.padding -= skip;
            output.consumed += skip;
            if block.padding != 0 {
                continue;
            }
            let command = block.command;
            self.block = None;
            self.completed_frame = true;
            if command != Command::Continue {
                self.ended = true;
                output.transition = Some(command);
                break;
            }
        }
        Ok(output)
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(invalid("Vision decoder is poisoned"));
        }
        if self.prefix_read != UUID_LEN
            || self.header_read != 0
            || self.block.is_some()
            || !self.completed_frame
        {
            self.failed = true;
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

/// True only for nonempty concatenations of complete TLS application records
/// with version 0x0303 and nonempty bodies, matching the source record check.
pub fn complete_tls_application_records(mut input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    while !input.is_empty() {
        if input.len() < 5 || input[..3] != [23, 3, 3] {
            return false;
        }
        let length = u16::from_be_bytes([input[3], input[4]]) as usize;
        if length == 0 || input.len() < length + 5 {
            return false;
        }
        input = &input[length + 5..];
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerHello {
    pub cipher_suite: u16,
    pub tls13: bool,
    /// Matches Vision's supported TLS 1.3 cipher set, excluding CCM_8 (0x1305).
    /// This alone is not authorization to bypass TLS or enable raw-copy mode.
    pub direct_copy_eligible: bool,
}

/// Inspects a complete TLS handshake record. Unlike the Go byte-pattern probe,
/// extension lengths are parsed so embedded lookalike bytes do not enable XTLS.
/// The caller owns buffering of split TLS records and the source's packet budget.
pub fn inspect_server_hello(record: &[u8]) -> io::Result<Option<ServerHello>> {
    if record.len() < 5 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + record_len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if record[..3] != [22, 3, 3] {
        return Ok(None);
    }
    let body = &record[5..5 + record_len];
    if body.len() < 4 {
        return Err(invalid("truncated TLS handshake header"));
    }
    if body[0] != 2 {
        return Ok(None);
    }
    let length = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if length + 4 > body.len() || length < 38 {
        return Err(invalid("invalid TLS ServerHello length"));
    }
    let hello = &body[4..4 + length];
    if hello[..2] != [3, 3] {
        return Ok(None);
    }
    let sid_len = hello[34] as usize;
    if sid_len > 32 || hello.len() < 38 + sid_len {
        return Err(invalid("invalid ServerHello session ID"));
    }
    let cipher_suite = u16::from_be_bytes([hello[35 + sid_len], hello[36 + sid_len]]);
    if hello[37 + sid_len] != 0 {
        return Err(invalid("unsupported TLS compression"));
    }
    let mut extensions = &hello[38 + sid_len..];
    let mut tls13 = false;
    if !extensions.is_empty() {
        if extensions.len() < 2 {
            return Err(invalid("truncated ServerHello extensions"));
        }
        let length = u16::from_be_bytes([extensions[0], extensions[1]]) as usize;
        if extensions.len() != length + 2 {
            return Err(invalid("invalid ServerHello extensions length"));
        }
        extensions = &extensions[2..];
        let mut seen_version = false;
        while !extensions.is_empty() {
            if extensions.len() < 4 {
                return Err(invalid("truncated TLS extension header"));
            }
            let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
            let length = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
            if extensions.len() < 4 + length {
                return Err(invalid("truncated TLS extension"));
            }
            if kind == 43 {
                if seen_version || length != 2 {
                    return Err(invalid("invalid supported_versions extension"));
                }
                seen_version = true;
                tls13 = extensions[4..6] == [3, 4];
            }
            extensions = &extensions[4 + length..];
        }
    }
    Ok(Some(ServerHello {
        cipher_suite,
        tls13,
        direct_copy_eligible: tls13 && matches!(cipher_suite, 0x1301..=0x1304),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_layout_uuid_once_and_exact_transition_boundary() {
        let uuid = std::array::from_fn(|i| i as u8);
        let mut encoder = Encoder::new(uuid);
        let first = encoder
            .encode_with_padding(b"abc", Command::Continue, b"zz")
            .unwrap();
        let golden = [uuid.as_slice(), b"\0\0\x03\0\x02abczz"].concat();
        assert_eq!(first, golden);
        let last = encoder
            .encode_with_padding(b"de", Command::Direct, b"p")
            .unwrap();
        assert_eq!(last, b"\x02\0\x02\0\x01dep");
        assert!(
            encoder
                .encode_with_padding(b"x", Command::End, &[])
                .is_err()
        );
        let wire = [first.as_slice(), &last, b"raw"].concat();
        for split in 0..first.len() + last.len() {
            let mut decoder = Decoder::new(uuid);
            let mut content = decoder.push(&wire[..split]).unwrap().content;
            let result = decoder.push(&wire[split..]).unwrap();
            content.extend(result.content);
            assert_eq!(content, b"abcde");
            assert_eq!(result.transition, Some(Command::Direct));
            assert_eq!(&wire[split + result.consumed..], b"raw");
            decoder.finish().unwrap();
            assert!(decoder.push(b"raw").is_err());
        }
    }

    #[test]
    fn strict_uuid_command_limits_and_truncation() {
        let uuid = [1; 16];
        let frame = Encoder::new(uuid)
            .encode_with_padding(b"x", Command::End, b"pad")
            .unwrap();
        for cut in 0..frame.len() {
            let mut decoder = Decoder::new(uuid);
            decoder.push(&frame[..cut]).unwrap();
            assert!(decoder.finish().is_err());
        }
        let mut wrong = frame.clone();
        wrong[0] ^= 1;
        let mut decoder = Decoder::new(uuid);
        assert!(decoder.push(&wrong).is_err());
        assert!(decoder.push(&frame).is_err());
        wrong = frame.clone();
        wrong[16] = 3;
        assert!(Decoder::new(uuid).push(&wrong).is_err());
        wrong = frame.clone();
        wrong[17..19].copy_from_slice(&8192u16.to_be_bytes());
        assert!(Decoder::new(uuid).push(&wrong).is_err());
        let empty = Encoder::new(uuid)
            .encode_with_padding(&[], Command::End, &[])
            .unwrap();
        let mut decoder = Decoder::new(uuid);
        assert_eq!(decoder.push(&empty).unwrap().transition, Some(Command::End));
        decoder.finish().unwrap();
    }

    #[test]
    fn source_padding_draws_and_complete_record_rules() {
        let settings = PaddingSettings::default();
        assert_eq!(settings.length_for_draw(100, true, 0).unwrap(), 800);
        assert_eq!(settings.length_for_draw(100, true, 499).unwrap(), 1299);
        assert_eq!(settings.length_for_draw(900, true, 255).unwrap(), 255);
        assert_eq!(
            settings
                .length_for_draw(MAX_FRAME_BODY, false, 255)
                .unwrap(),
            0
        );
        assert!(settings.length_for_draw(10, true, 500).is_err());
        assert!(complete_tls_application_records(
            b"\x17\x03\x03\0\x02ab\x17\x03\x03\0\x01c"
        ));
        assert!(!complete_tls_application_records(b"\x17\x03\x03\0\x02a"));
        assert!(!complete_tls_application_records(b"\x17\x03\x03\0\0"));
    }

    fn hello(cipher: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend(cipher.to_be_bytes());
        body.push(0);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![2, 0, 0, body.len() as u8];
        handshake.extend(body);
        let mut record = vec![22, 3, 3];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    #[test]
    fn server_hello_cipher_policy_and_fake_extension_pattern() {
        for cipher in 0x1301..=0x1305 {
            let record = hello(cipher, b"\0\x2b\0\x02\x03\x04");
            let parsed = inspect_server_hello(&record).unwrap().unwrap();
            assert!(parsed.tls13);
            assert_eq!(parsed.direct_copy_eligible, cipher != 0x1305);
            for cut in 0..record.len() {
                assert!(inspect_server_hello(&record[..cut]).is_err());
            }
        }
        let fake = hello(0x1301, b"\x12\x34\0\x06\0\x2b\0\x02\x03\x04");
        assert!(
            !inspect_server_hello(&fake)
                .unwrap()
                .unwrap()
                .direct_copy_eligible
        );
        let duplicate = hello(0x1301, b"\0\x2b\0\x02\x03\x04\0\x2b\0\x02\x03\x04");
        assert!(inspect_server_hello(&duplicate).is_err());
    }
}
