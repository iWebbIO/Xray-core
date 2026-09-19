use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::transport::BoxStream;

use super::{
    crypto::RecordCipher,
    invalid,
    wire::{Cursor, HandshakeBuffer, RecordReader},
};

/// Authenticated TLS 1.3 byte stream. Created only after the REALITY marker,
/// CertificateVerify and server Finished have all passed verification.
///
/// EOF without close_notify is an error. Read and write half-closes are separate.
/// KeyUpdate is processed in both directions, with automatic outbound updates
/// before the conservative 2^20-record per-key limit.
pub struct ClientStream {
    stream: BoxStream,
    read_cipher: RecordCipher,
    write_cipher: RecordCipher,
    record_reader: RecordReader,
    post_handshake: HandshakeBuffer,
    plain: Vec<u8>,
    plain_offset: usize,
    output: Vec<u8>,
    output_offset: usize,
    read_closed: bool,
    write_closed: bool,
    server_role: bool,
    fatal: Option<(io::ErrorKind, String)>,
}

impl ClientStream {
    pub(crate) fn new(
        stream: BoxStream,
        read_cipher: RecordCipher,
        write_cipher: RecordCipher,
        limit: usize,
    ) -> Self {
        Self {
            stream,
            read_cipher,
            write_cipher,
            record_reader: RecordReader::default(),
            post_handshake: HandshakeBuffer::new(limit),
            plain: Vec::new(),
            plain_offset: 0,
            output: Vec::new(),
            output_offset: 0,
            read_closed: false,
            write_closed: false,
            server_role: false,
            fatal: None,
        }
    }

    /// Server-direction authenticated streams must reject client-origin tickets.
    pub(crate) fn new_server(
        stream: BoxStream,
        read_cipher: RecordCipher,
        write_cipher: RecordCipher,
        limit: usize,
    ) -> Self {
        let mut stream = Self::new(stream, read_cipher, write_cipher, limit);
        stream.server_role = true;
        stream
    }

    fn error(&self) -> Option<io::Error> {
        self.fatal
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn fail<T>(&mut self, error: io::Error) -> Poll<io::Result<T>> {
        self.fatal = Some((error.kind(), error.to_string()));
        self.output.clear();
        self.plain.clear();
        Poll::Ready(Err(error))
    }

    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.output_offset < self.output.len() {
            match Pin::new(&mut self.stream).poll_write(cx, &self.output[self.output_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return self.fail(error),
                Poll::Ready(Ok(0)) => {
                    return self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS transport write returned zero",
                    ));
                }
                Poll::Ready(Ok(written)) => self.output_offset += written,
            }
        }
        self.output.clear();
        self.output_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_key_update(&mut self) -> io::Result<()> {
        if self.write_closed {
            return Err(invalid(
                "TLS peer requested KeyUpdate after local close_notify",
            ));
        }
        if self.output.len() > 65536 {
            return Err(invalid("too many pending TLS KeyUpdate responses"));
        }
        self.output
            .extend(self.write_cipher.seal(22, &[24, 0, 0, 1, 0])?);
        self.write_cipher.update()
    }

    fn handle_handshake(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.post_handshake.push(bytes)?;
        while let Some(message) = self.post_handshake.take()? {
            match message[0] {
                4 if !self.server_role => validate_ticket(&message[4..])?,
                24 => {
                    if !self.post_handshake.is_empty() || message.len() != 5 || message[4] > 1 {
                        return Err(invalid(
                            "TLS KeyUpdate must end at the old-key record boundary",
                        ));
                    }
                    self.read_cipher.update()?;
                    if message[4] == 1 {
                        self.queue_key_update()?;
                    }
                }
                _ => return Err(invalid("unexpected post-handshake TLS message")),
            }
        }
        Ok(())
    }
}

fn validate_ticket(body: &[u8]) -> io::Result<()> {
    let mut ticket = Cursor::new(body);
    ticket.take(8)?;
    ticket.vec8()?;
    if ticket.vec16()?.is_empty() {
        return Err(invalid("TLS NewSessionTicket has an empty ticket"));
    }
    let mut extensions = Cursor::new(ticket.vec16()?);
    ticket.done()?;
    let mut seen = std::collections::BTreeSet::new();
    while !extensions.rest.is_empty() {
        let id = extensions.u16()?;
        let value = extensions.vec16()?;
        if !seen.insert(id) || (id == 42 && value.len() != 4) {
            return Err(invalid("invalid TLS session ticket extension"));
        }
    }
    // Resumption and 0-RTT are deliberately not enabled by receiving a ticket.
    Ok(())
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..64 {
            if this.plain_offset < this.plain.len() {
                let len = buf.remaining().min(this.plain.len() - this.plain_offset);
                buf.put_slice(&this.plain[this.plain_offset..this.plain_offset + len]);
                this.plain_offset += len;
                if this.plain_offset == this.plain.len() {
                    this.plain.clear();
                    this.plain_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            match this.poll_output(cx) {
                Poll::Ready(Ok(())) => {}
                // A full write buffer must not block reads: both peers may be
                // sending simultaneously. Register interest in both directions.
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
            let record = match this.record_reader.poll_read(&mut this.stream, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return this.fail(error),
                Poll::Ready(Ok(record)) => record,
            };
            let (kind, plain) = match this.read_cipher.open(&record.header, record.payload) {
                Ok(result) => result,
                Err(error) => return this.fail(error),
            };
            if kind != 22 && !this.post_handshake.is_empty() {
                return this.fail(invalid(
                    "TLS non-handshake record interrupted a handshake message",
                ));
            }
            match kind {
                23 => {
                    this.plain = plain;
                }
                22 => {
                    if let Err(error) = this.handle_handshake(&plain) {
                        return this.fail(error);
                    }
                }
                21 if plain.len() == 2 && plain[1] == 0 => this.read_closed = true,
                21 => return this.fail(invalid("peer sent a TLS alert")),
                _ => return this.fail(invalid("unexpected TLS record type")),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS write side is closed",
            )));
        }
        match this.poll_output(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_cipher.needs_update()
            && let Err(error) = this.queue_key_update()
        {
            return this.fail(error);
        }
        let len = buf.len().min(16384);
        match this.write_cipher.seal(23, &buf[..len]) {
            Ok(record) => {
                this.output.extend(record);
                Poll::Ready(Ok(len))
            }
            Err(error) => this.fail(error),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        match this.poll_output(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Err(error)) => this.fail(error),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(error) = this.error() {
            return Poll::Ready(Err(error));
        }
        match this.poll_output(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        if !this.write_closed {
            match this.write_cipher.seal(21, &[1, 0]) {
                Ok(record) => this.output.extend(record),
                Err(error) => return this.fail(error),
            }
            this.write_closed = true;
        }
        match this.poll_output(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return this.fail(error),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut this.stream).poll_shutdown(cx) {
            Poll::Ready(Err(error)) => this.fail(error),
            other => other,
        }
    }
}
