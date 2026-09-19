use std::{
    collections::BTreeSet,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use super::{CipherSuite, ClientConfig, invalid};

pub(crate) struct Cursor<'a> {
    pub(crate) rest: &'a [u8],
}
impl<'a> Cursor<'a> {
    pub(crate) fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }
    pub(crate) fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if len > self.rest.len() {
            return Err(invalid("truncated TLS handshake field"));
        }
        let (result, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(result)
    }
    pub(crate) fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub(crate) fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }
    pub(crate) fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
    pub(crate) fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let b = self.take(3)?;
        let len = (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]);
        self.take(len)
    }
    pub(crate) fn done(&self) -> io::Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing TLS handshake bytes"))
        }
    }
}

pub(crate) fn vector16(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(bytes.len()).map_err(|_| invalid("TLS vector exceeds 65535 bytes"))?;
    let mut result = len.to_be_bytes().to_vec();
    result.extend_from_slice(bytes);
    Ok(result)
}

pub(crate) fn handshake(kind: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    if body.len() > 0xff_ffff {
        return Err(invalid("TLS handshake too large"));
    }
    let len = body.len();
    let mut result = vec![kind, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    result.extend_from_slice(body);
    Ok(result)
}

pub(crate) fn extension(output: &mut Vec<u8>, id: u16, data: &[u8]) -> io::Result<()> {
    output.extend_from_slice(&id.to_be_bytes());
    output.extend(vector16(data)?);
    Ok(())
}

pub(crate) fn client_hello(
    config: &ClientConfig,
    random: &[u8; 32],
    hybrid: &[u8],
    x25519: &[u8; 32],
) -> io::Result<Vec<u8>> {
    let mut body = vec![3, 3];
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(&[0; 32]);
    body.extend(vector16(&[0x13, 1, 0x13, 2, 0x13, 3])?);
    body.extend_from_slice(&[1, 0]);
    let mut extensions = Vec::new();
    let mut name = vec![0];
    name.extend(vector16(config.server_name.as_bytes())?);
    extension(&mut extensions, 0, &vector16(&name)?)?;
    let mut groups = vec![0x11, 0xec];
    if !config.hybrid_only {
        groups.extend_from_slice(&[0, 0x1d]);
    }
    extension(&mut extensions, 10, &vector16(&groups)?)?;
    // Include target-compatible algorithms even though an authenticated REALITY
    // temporary certificate must use Ed25519.
    extension(
        &mut extensions,
        13,
        &vector16(&[4, 3, 8, 4, 8, 5, 8, 6, 8, 7, 5, 3, 6, 3])?,
    )?;
    if !config.alpn.is_empty() {
        let mut protocols = Vec::new();
        for protocol in &config.alpn {
            protocols.push(protocol.len() as u8);
            protocols.extend_from_slice(protocol);
        }
        extension(&mut extensions, 16, &vector16(&protocols)?)?;
    }
    extension(&mut extensions, 43, &[2, 3, 4])?;
    let mut shares = vec![0x11, 0xec];
    shares.extend(vector16(hybrid)?);
    if !config.hybrid_only {
        shares.extend_from_slice(&[0, 0x1d]);
        shares.extend(vector16(x25519)?);
    }
    extension(&mut extensions, 51, &vector16(&shares)?)?;
    body.extend(vector16(&extensions)?);
    handshake(1, &body)
}

pub(crate) struct ServerHello<'a> {
    pub(crate) suite: CipherSuite,
    pub(crate) group: u16,
    pub(crate) share: &'a [u8],
}

pub(crate) fn parse_server_hello<'a>(
    message: &'a [u8],
    session_id: &[u8],
    hybrid_only: bool,
) -> io::Result<ServerHello<'a>> {
    let mut outer = Cursor::new(message);
    if outer.u8()? != 2 {
        return Err(invalid("expected TLS ServerHello"));
    }
    let mut hello = Cursor::new(outer.vec24()?);
    outer.done()?;
    if hello.u16()? != 0x0303 {
        return Err(invalid("TLS ServerHello legacy version mismatch"));
    }
    let random = hello.take(32)?;
    const RETRY: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    if random == RETRY {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "REALITY HelloRetryRequest is not supported",
        ));
    }
    if hello.vec8()? != session_id {
        return Err(invalid("TLS ServerHello session ID echo mismatch"));
    }
    let suite = CipherSuite::from_id(hello.u16()?)?;
    if hello.u8()? != 0 {
        return Err(invalid("TLS ServerHello compression must be null"));
    }
    let mut extensions = Cursor::new(hello.vec16()?);
    hello.done()?;
    let mut seen = BTreeSet::new();
    let mut supported_version = false;
    let mut key_share = None;
    while !extensions.rest.is_empty() {
        let id = extensions.u16()?;
        let data = extensions.vec16()?;
        if !seen.insert(id) {
            return Err(invalid("duplicate ServerHello extension"));
        }
        match id {
            43 if data == [3, 4] => supported_version = true,
            51 => {
                let mut share = Cursor::new(data);
                let group = share.u16()?;
                let key = share.vec16()?;
                share.done()?;
                if !matches!((group, key.len()), (0x11ec, 1120) | (0x001d, 32))
                    || (hybrid_only && group != 0x11ec)
                {
                    return Err(invalid("invalid or unoffered TLS server key share"));
                }
                key_share = Some((group, key));
            }
            _ => return Err(invalid("unsupported or unsolicited ServerHello extension")),
        }
    }
    if !supported_version {
        return Err(invalid("server did not select TLS 1.3"));
    }
    let (group, share) = key_share.ok_or_else(|| invalid("ServerHello lacks key share"))?;
    Ok(ServerHello {
        suite,
        group,
        share,
    })
}

pub(crate) fn encrypted_extensions(
    body: &[u8],
    offered_alpn: &[Vec<u8>],
) -> io::Result<Option<Vec<u8>>> {
    let mut message = Cursor::new(body);
    let mut extensions = Cursor::new(message.vec16()?);
    message.done()?;
    let mut seen = BTreeSet::new();
    let mut selected = None;
    while !extensions.rest.is_empty() {
        let id = extensions.u16()?;
        let data = extensions.vec16()?;
        if !seen.insert(id) {
            return Err(invalid("duplicate EncryptedExtensions extension"));
        }
        match id {
            0 if data.is_empty() => {}
            10 => {
                let mut groups = Cursor::new(data);
                let bytes = groups.vec16()?;
                if bytes.is_empty() || bytes.len() % 2 != 0 {
                    return Err(invalid("invalid server supported groups"));
                }
                groups.done()?;
            }
            16 => {
                let mut list = Cursor::new(data);
                let mut protocols = Cursor::new(list.vec16()?);
                list.done()?;
                let protocol = protocols.vec8()?;
                protocols.done()?;
                if protocol.is_empty() || !offered_alpn.iter().any(|offered| offered == protocol) {
                    return Err(invalid("server selected an unoffered ALPN protocol"));
                }
                selected = Some(protocol.to_vec());
            }
            _ => {
                return Err(invalid(
                    "unsupported or unsolicited encrypted TLS extension",
                ));
            }
        }
    }
    Ok(selected)
}

pub(crate) struct HandshakeBuffer {
    bytes: Vec<u8>,
    limit: usize,
}
impl HandshakeBuffer {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit + 4 {
            return Err(invalid("TLS handshake buffer limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn take(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.bytes.len() < 4 {
            return Ok(None);
        }
        let size = (usize::from(self.bytes[1]) << 16)
            | (usize::from(self.bytes[2]) << 8)
            | usize::from(self.bytes[3]);
        if size > self.limit {
            return Err(invalid("TLS handshake message exceeds configured limit"));
        }
        if self.bytes.len() < size + 4 {
            return Ok(None);
        }
        Ok(Some(self.bytes.drain(..size + 4).collect()))
    }
}

pub(crate) struct Record {
    pub(crate) header: [u8; 5],
    pub(crate) payload: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct RecordReader {
    header: [u8; 5],
    header_used: usize,
    payload: Vec<u8>,
    payload_used: usize,
}
impl RecordReader {
    pub(crate) fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        stream: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Record>> {
        while self.header_used < 5 {
            let mut buf = ReadBuf::new(&mut self.header[self.header_used..]);
            match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS connection ended without close_notify",
                    )));
                }
                Poll::Ready(Ok(())) => self.header_used += buf.filled().len(),
            }
        }
        if self.payload.is_empty() {
            let len = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
            if self.header[1..3] != [3, 3] || !(1..=16640).contains(&len) {
                return Poll::Ready(Err(invalid("invalid TLS record header or length")));
            }
            self.payload.resize(len, 0);
        }
        while self.payload_used < self.payload.len() {
            let mut buf = ReadBuf::new(&mut self.payload[self.payload_used..]);
            match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS record",
                    )));
                }
                Poll::Ready(Ok(())) => self.payload_used += buf.filled().len(),
            }
        }
        let record = Record {
            header: self.header,
            payload: std::mem::take(&mut self.payload),
        };
        self.header_used = 0;
        self.payload_used = 0;
        Poll::Ready(Ok(record))
    }
}
