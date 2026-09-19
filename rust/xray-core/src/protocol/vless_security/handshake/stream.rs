use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::encryption::{
    Algorithm, MAX_WRITE_PLAINTEXT, RecordCipher, decode_record_header,
};
use super::{Session, invalid};

/// Authenticated VLESS encrypted byte stream after the native hybrid handshake.
/// Partial records survive Pending; no plaintext is released before its tag is
/// checked. At most one incoming and one outgoing wire record are buffered.
pub struct EncryptedStream<S> {
    inner: S,
    inbound: RecordCipher,
    outbound: RecordCipher,
    algorithm: Algorithm,
    read_wire: Vec<u8>,
    read_filled: usize,
    read_plaintext: Vec<u8>,
    read_offset: usize,
    write_wire: Vec<u8>,
    write_offset: usize,
    failed: bool,
    eof: bool,
}

impl<S> EncryptedStream<S> {
    pub fn new(inner: S, session: Session) -> Self {
        Self {
            inner,
            inbound: session.inbound,
            outbound: session.outbound,
            algorithm: session.algorithm,
            read_wire: vec![0; 5],
            read_filled: 0,
            read_plaintext: Vec::new(),
            read_offset: 0,
            write_wire: Vec::new(),
            write_offset: 0,
            failed: false,
            eof: false,
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncWrite + Unpin> EncryptedStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_wire.len() {
            match ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_wire[self.write_offset..])
            ) {
                Ok(0) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(count) => self.write_offset += count,
                Err(error) => {
                    self.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.write_wire.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("VLESS encrypted stream is poisoned")));
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // A request accepted by poll_write must reach the peer before waiting
        // for its response, even when a caller writes then reads without flush.
        // Continue receiving while a write is backpressured: both peers may
        // write before reading, and requiring a complete flush would deadlock.
        if let Poll::Ready(result) = this.poll_drain(cx) {
            result?;
        }
        loop {
            if this.read_offset < this.read_plaintext.len() {
                let count = output
                    .remaining()
                    .min(this.read_plaintext.len() - this.read_offset);
                output.put_slice(&this.read_plaintext[this.read_offset..this.read_offset + count]);
                this.read_offset += count;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut buffer = ReadBuf::new(&mut this.read_wire[this.read_filled..]);
            match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer)) {
                Ok(()) => (),
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
            let count = buffer.filled().len();
            if count == 0 {
                if this.read_filled == 0 && this.read_wire.len() == 5 {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.failed = true;
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.read_filled += count;
            if this.read_filled != this.read_wire.len() {
                continue;
            }
            if this.read_wire.len() == 5 {
                match decode_record_header(&this.read_wire) {
                    Ok(length) => this.read_wire.resize(5 + length, 0),
                    Err(error) => {
                        this.failed = true;
                        return Poll::Ready(Err(error));
                    }
                }
                continue;
            }
            match this.inbound.open_record(&this.read_wire) {
                Ok(plaintext) => this.read_plaintext = plaintext,
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
            this.read_offset = 0;
            this.read_filled = 0;
            this.read_wire.resize(5, 0);
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("VLESS encrypted stream is poisoned")));
        }
        ready!(this.poll_drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(MAX_WRITE_PLAINTEXT);
        this.write_wire = match this.outbound.seal_record(&input[..count]) {
            Ok(wire) => wire,
            Err(error) => {
                this.failed = true;
                return Poll::Ready(Err(error));
            }
        };
        // Once buffered, these plaintext bytes have been accepted even if the
        // underlying transport is Pending. Do not encrypt them again on retry.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("VLESS encrypted stream is poisoned")));
        }
        ready!(this.poll_drain(cx))?;
        let result = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        if result.is_err() {
            this.failed = true;
        }
        Poll::Ready(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("VLESS encrypted stream is poisoned")));
        }
        ready!(this.poll_drain(cx))?;
        let result = ready!(Pin::new(&mut this.inner).poll_shutdown(cx));
        if result.is_err() {
            this.failed = true;
        }
        Poll::Ready(result)
    }
}
