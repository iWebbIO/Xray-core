use super::{
    Account, MAX_PAYLOAD_LENGTH,
    codec::{self, Cipher, TAG_LENGTH},
    unix_time,
};
use crate::transport::BoxStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy)]
enum ReadStage {
    ResponseSalt,
    ResponseFixed,
    ResponseFirst(usize),
    Length,
    Payload(usize),
}

/// Owned, bounded record state. Cancelling individual I/O futures cannot lose
/// partial headers/ciphertext or advance a nonce twice. EOF is valid only between
/// ordinary complete records; a missing response handshake is an error.
pub struct Shadowsocks2022Stream {
    inner: BoxStream,
    account: Account,
    request_salt: Vec<u8>,
    response_salt: Vec<u8>,
    read_cipher: Option<Cipher>,
    stage: ReadStage,
    read_wire: Vec<u8>,
    read_offset: usize,
    plaintext: Vec<u8>,
    plain_offset: usize,
    read_eof: bool,
    write_cipher: Option<Cipher>,
    write_wire: Vec<u8>,
    write_offset: usize,
    output_started: bool,
    shutdown_requested: bool,
    shutdown_done: bool,
    failure: Option<(io::ErrorKind, String)>,
}

impl Shadowsocks2022Stream {
    pub(super) fn server(
        inner: BoxStream,
        account: Account,
        request_salt: Vec<u8>,
        reader: Cipher,
        initial: Vec<u8>,
    ) -> Self {
        Self::new(
            inner,
            account,
            request_salt,
            (Some(reader), None),
            ReadStage::Length,
            initial,
            false,
        )
    }
    pub(super) fn client(
        inner: BoxStream,
        account: Account,
        request_salt: Vec<u8>,
        writer: Cipher,
    ) -> Self {
        Self::new(
            inner,
            account,
            request_salt,
            (None, Some(writer)),
            ReadStage::ResponseSalt,
            Vec::new(),
            true,
        )
    }
    fn new(
        inner: BoxStream,
        account: Account,
        request_salt: Vec<u8>,
        ciphers: (Option<Cipher>, Option<Cipher>),
        stage: ReadStage,
        plaintext: Vec<u8>,
        output_started: bool,
    ) -> Self {
        let (read_cipher, write_cipher) = ciphers;
        Self {
            inner,
            account,
            request_salt,
            response_salt: Vec::new(),
            read_cipher,
            stage,
            read_wire: Vec::new(),
            read_offset: 0,
            plaintext,
            plain_offset: 0,
            read_eof: false,
            write_cipher,
            write_wire: Vec::new(),
            write_offset: 0,
            output_started,
            shutdown_requested: false,
            shutdown_done: false,
            failure: None,
        }
    }
    fn stored_error(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }
    fn fail(&mut self, error: io::Error) -> io::Error {
        self.failure = Some((error.kind(), error.to_string()));
        error
    }
    fn invalid(&mut self, error: anyhow::Error) -> io::Error {
        self.fail(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{error:#}"),
        ))
    }
    fn needed(&self) -> usize {
        match self.stage {
            ReadStage::ResponseSalt => self.account.kind.key_len(),
            ReadStage::ResponseFixed => {
                codec::REQUEST_FIXED_LENGTH + self.account.kind.key_len() + TAG_LENGTH
            }
            ReadStage::ResponseFirst(length) | ReadStage::Payload(length) => length + TAG_LENGTH,
            ReadStage::Length => 2 + TAG_LENGTH,
        }
    }
    fn process_record(&mut self) -> anyhow::Result<()> {
        if matches!(self.stage, ReadStage::ResponseSalt) {
            anyhow::ensure!(
                self.read_wire != self.request_salt,
                "Shadowsocks2022 response reuses request salt"
            );
            self.response_salt = self.read_wire.clone();
            self.read_cipher = Some(Cipher::new(&self.account, &self.response_salt)?);
            self.stage = ReadStage::ResponseFixed;
        } else {
            let plain = self
                .read_cipher
                .as_mut()
                .expect("cipher initialized by handshake")
                .open(&self.read_wire)?;
            match self.stage {
                ReadStage::ResponseFixed => {
                    let length =
                        codec::parse_response_fixed(&plain, &self.request_salt, unix_time()?)?;
                    self.stage = ReadStage::ResponseFirst(length);
                }
                ReadStage::ResponseFirst(_) => {
                    self.account.admit_received(&self.response_salt)?;
                    self.plaintext = plain;
                    self.stage = ReadStage::Length;
                }
                ReadStage::Length => {
                    let length =
                        usize::from(u16::from_be_bytes(plain.as_slice().try_into().map_err(
                            |_| anyhow::anyhow!("invalid Shadowsocks2022 length record"),
                        )?));
                    self.stage = ReadStage::Payload(length);
                }
                ReadStage::Payload(_) => {
                    self.plaintext = plain;
                    self.stage = ReadStage::Length;
                }
                ReadStage::ResponseSalt => unreachable!(),
            }
        }
        self.read_wire.clear();
        self.read_offset = 0;
        Ok(())
    }
    fn encode(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        if let Some(cipher) = &mut self.write_cipher {
            self.write_wire = cipher.frame(payload)?;
        } else {
            let salt = self.account.fresh_salt()?;
            let (wire, cipher) = codec::response(
                &self.account,
                &salt,
                &self.request_salt,
                payload,
                unix_time()?,
            )?;
            self.write_wire = wire;
            self.write_cipher = Some(cipher);
        }
        self.write_offset = 0;
        self.output_started = true;
        Ok(())
    }
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_wire.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_wire[self.write_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks2022 transport wrote zero bytes",
                    ))));
                }
                Poll::Ready(Ok(count)) => self.write_offset += count,
            }
        }
        self.write_wire.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
    fn poll_flush_started(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => (),
            other => return other,
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
            other => other,
        }
    }
}

impl AsyncRead for Shadowsocks2022Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        // Never block reading on outgoing backpressure; drive both sides.
        if this.output_started
            && !this.shutdown_done
            && let Poll::Ready(Err(error)) = this.poll_flush_started(cx)
        {
            return Poll::Ready(Err(error));
        }
        for _ in 0..64 {
            if this.plain_offset < this.plaintext.len() {
                let count = output
                    .remaining()
                    .min(this.plaintext.len() - this.plain_offset);
                output.put_slice(&this.plaintext[this.plain_offset..this.plain_offset + count]);
                this.plain_offset += count;
                if this.plain_offset == this.plaintext.len() {
                    this.plaintext.clear();
                    this.plain_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            let needed = this.needed();
            if this.read_wire.len() != needed {
                this.read_wire.resize(needed, 0);
            }
            if this.read_offset < needed {
                let mut input = ReadBuf::new(&mut this.read_wire[this.read_offset..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
                    Poll::Ready(Ok(())) if input.filled().is_empty() => {
                        if matches!(this.stage, ReadStage::Length) && this.read_offset == 0 {
                            this.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(this.fail(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Shadowsocks2022 record or response handshake",
                        ))));
                    }
                    Poll::Ready(Ok(())) => this.read_offset += input.filled().len(),
                }
            }
            if this.read_offset == needed
                && let Err(error) = this.process_record()
            {
                return Poll::Ready(Err(this.invalid(error)));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for Shadowsocks2022Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        if this.shutdown_requested {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Shadowsocks2022 write side is shut down",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => (),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let count = input.len().min(MAX_PAYLOAD_LENGTH);
        if let Err(error) = this.encode(&input[..count]) {
            return Poll::Ready(Err(this.invalid(error)));
        }
        // Once encoded, plaintext is accepted even if ciphertext is only partly
        // written. Persistent offsets keep retries/cancellation from duplicating it.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        if this.write_cipher.is_none()
            && let Err(error) = this.encode(&[])
        {
            return Poll::Ready(Err(this.invalid(error)));
        }
        this.poll_flush_started(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        if this.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        this.shutdown_requested = true;
        if this.write_cipher.is_none()
            && let Err(error) = this.encode(&[])
        {
            return Poll::Ready(Err(this.invalid(error)));
        }
        match this.poll_flush_started(cx) {
            Poll::Ready(Ok(())) => (),
            other => return other,
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown_done = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.fail(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
