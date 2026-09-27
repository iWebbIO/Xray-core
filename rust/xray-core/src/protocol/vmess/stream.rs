//! Native VMess AEAD TCP sessions over an already connected transport.
//!
//! The caller supplies connection/handshake deadlines. `accept` authenticates
//! without writing a response; the encrypted response is queued until the first
//! write, flush, or shutdown after the runtime has connected the destination.
//! Outbound response authentication is lazy, so writes never wait for a response.
//! UDP and Mux need packet/session dispatch and are explicitly rejected here.
//! The codec permits at most 65,536 frames per direction, including the EOF
//! frame, rather than reusing a nonce after the wire counter wraps.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{
    Account, BodyDecoder, BodyEncoder, BodyFrame, BodyKeys, Command, RequestHeader, ResponseHeader,
    Security, ServerAuthenticator, crypto, encoding, seal_request, seal_response,
};
use crate::{
    address::Destination,
    protocol::{Reply, Request},
    transport::BoxStream,
};

/// Share one replay authenticator across every connection on the inbound.
pub type SharedAuthenticator = Arc<Mutex<ServerAuthenticator>>;

// Fixed fields38 + port2 + family1 + domain length1 + domain255 + padding15 + FNV4.
const MAX_REQUEST_PLAINTEXT: usize = 316;
const MAX_REQUEST_WIRE: usize =
    crypto::REQUEST_HEADER_PREFIX_LEN + MAX_REQUEST_PLAINTEXT + crypto::AEAD_TAG_LEN;
// Token, options, command, length, and at most 255 command bytes.
const MAX_RESPONSE_PLAINTEXT: usize = 259;
const MAX_BODY_WIRE: usize = u16::MAX as usize + crypto::ENCRYPTED_LENGTH_LEN;
const READ_BLOCK: usize = 8192;

fn unix_time() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("VMess system time exceeds signed Unix seconds")
}

/// Authenticate a TCP request without sending success before destination routing.
/// Exact header reads leave pipelined encrypted application data in the transport.
/// Cancelling this owning future drops the connection, not a partially consumed
/// stream returned to the caller. No authenticator lock is held across an await.
pub async fn accept(
    mut stream: BoxStream,
    authenticator: &SharedAuthenticator,
) -> Result<(BoxStream, Request)> {
    let mut wire = vec![0; crypto::REQUEST_HEADER_PREFIX_LEN];
    stream
        .read_exact(&mut wire)
        .await
        .context("read VMess request prefix")?;
    let length = {
        let auth = authenticator
            .lock()
            .map_err(|_| anyhow::anyhow!("VMess authenticator mutex poisoned"))?;
        auth.request_wire_len(&wire, unix_time()?)?
    };
    ensure!(
        length <= MAX_REQUEST_WIRE,
        "VMess request header exceeds supported wire layout"
    );
    wire.resize(length, 0);
    stream
        .read_exact(&mut wire[crypto::REQUEST_HEADER_PREFIX_LEN..])
        .await
        .context("read VMess request payload")?;
    let (authenticated, user) = {
        let mut auth = authenticator
            .lock()
            .map_err(|_| anyhow::anyhow!("VMess authenticator mutex poisoned"))?;
        let request = auth.open_request(&wire, unix_time()?)?;
        let user = auth
            .account(request.account_index)
            .context("VMess authenticated account disappeared")?
            .email()
            .to_owned();
        (request, user)
    };
    ensure!(
        authenticated.consumed == wire.len(),
        "VMess request envelope length mismatch"
    );
    ensure!(
        authenticated.header.command == Command::Tcp,
        "VMess stream adapter supports TCP only; UDP datagrams and Mux require separate dispatch"
    );
    let destination = authenticated
        .header
        .destination
        .clone()
        .context("VMess TCP request has no destination")?;
    ensure!(
        destination.port != 0,
        "VMess destination port must be nonzero"
    );
    let session = VmessStream::server(stream, &authenticated.header)?;
    Ok((
        Box::new(session),
        Request {
            destination,
            user,
            initial_payload: Vec::new(),
            reply: Reply::None,
        },
    ))
}

/// Send a fresh AEAD TCP request, returning before the response arrives.
pub async fn connect(
    stream: BoxStream,
    account: &Account,
    target: &Destination,
) -> Result<BoxStream> {
    connect_with_options(
        stream,
        account,
        target,
        Security::Aes128Gcm,
        encoding::OPTION_CHUNK_STREAM
            | encoding::OPTION_CHUNK_MASKING
            | encoding::OPTION_GLOBAL_PADDING,
    )
    .await
}

/// As `connect`, with explicit supported cipher and framing options.
pub async fn connect_with_options(
    mut stream: BoxStream,
    account: &Account,
    target: &Destination,
    security: Security,
    options: u8,
) -> Result<BoxStream> {
    ensure!(target.port != 0, "VMess destination port must be nonzero");
    let mut random = [0; 49];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .context("generate VMess session entropy")?;
    let header = RequestHeader {
        body_key: random[..16].try_into().expect("fixed key length"),
        body_iv: random[16..32].try_into().expect("fixed IV length"),
        response_auth: random[32],
        options,
        security,
        command: Command::Tcp,
        destination: Some(target.clone()),
        padding: random[34..34 + usize::from(random[33] & 15)].to_vec(),
    };
    // Validate both local construction and the receiving address rules before I/O.
    RequestHeader::decode(&header.encode()?).context("invalid VMess outbound request")?;
    let wire = seal_request(account, &header, unix_time()?)?;
    stream
        .write_all(&wire)
        .await
        .context("write VMess request header")?;
    stream.flush().await.context("flush VMess request header")?;
    Ok(Box::new(VmessStream::client(stream, &header)?))
}

struct ResponseState {
    key: [u8; 16],
    iv: [u8; 16],
    auth: u8,
    wire_length: Option<usize>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Shutdown {
    Open,
    EofQueued,
    Done,
}

/// A single TCP session. Ciphertext offsets and partial frame input live on the
/// stream, so dropping a read/flush/shutdown future never discards framing state.
/// Writes may be buffered up to one frame; use flush or shutdown to finish them.
pub struct VmessStream {
    inner: BoxStream,
    decoder: BodyDecoder,
    encoder: BodyEncoder,
    response: Option<ResponseState>,
    read_wire: Vec<u8>,
    read_plain: Vec<u8>,
    plain_offset: usize,
    read_eof: bool,
    require_termination: bool,
    write_wire: Vec<u8>,
    write_offset: usize,
    output_started: bool,
    shutdown: Shutdown,
    failure: Option<(io::ErrorKind, String)>,
}

impl VmessStream {
    fn server(inner: BoxStream, header: &RequestHeader) -> Result<Self> {
        let response = ResponseHeader {
            response_auth: header.response_auth,
            options: 0,
            command: None,
        };
        Ok(Self::new(
            inner,
            BodyDecoder::new(header.security, header.options, BodyKeys::request(header))?,
            BodyEncoder::new(header.security, header.options, BodyKeys::response(header))?,
            None,
            header.options,
            seal_response(header, &response)?,
            false,
        ))
    }

    fn client(inner: BoxStream, header: &RequestHeader) -> Result<Self> {
        let (key, iv) = crypto::derive_response_key_iv(&header.body_key, &header.body_iv);
        Ok(Self::new(
            inner,
            BodyDecoder::new(header.security, header.options, BodyKeys::response(header))?,
            BodyEncoder::new(header.security, header.options, BodyKeys::request(header))?,
            Some(ResponseState {
                key,
                iv,
                auth: header.response_auth,
                wire_length: None,
            }),
            header.options,
            Vec::new(),
            true,
        ))
    }

    fn new(
        inner: BoxStream,
        decoder: BodyDecoder,
        encoder: BodyEncoder,
        response: Option<ResponseState>,
        options: u8,
        write_wire: Vec<u8>,
        output_started: bool,
    ) -> Self {
        Self {
            inner,
            decoder,
            encoder,
            response,
            read_wire: Vec::new(),
            read_plain: Vec::new(),
            plain_offset: 0,
            read_eof: false,
            require_termination: options & encoding::OPTION_CHUNK_STREAM != 0,
            write_wire,
            write_offset: 0,
            output_started,
            shutdown: Shutdown::Open,
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

    fn poll_drain(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_wire.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_wire[self.write_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(error))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess transport wrote zero bytes",
                    ))));
                }
                Poll::Ready(Ok(count)) => self.write_offset += count,
            }
        }
        self.write_wire.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_flush_output(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => (),
            result => return result,
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
            result => result,
        }
    }

    /// Return the bounded byte count required for the next response-header step.
    fn response_progress(&mut self) -> Result<Option<usize>> {
        let Some(response) = &mut self.response else {
            return Ok(None);
        };
        if response.wire_length.is_none() {
            if self.read_wire.len() < crypto::ENCRYPTED_LENGTH_LEN {
                return Ok(Some(crypto::ENCRYPTED_LENGTH_LEN));
            }
            let prefix = self.read_wire[..crypto::ENCRYPTED_LENGTH_LEN]
                .try_into()
                .expect("fixed response prefix");
            let length = crypto::open_response_header_length(&response.key, &response.iv, prefix)?;
            ensure!(
                (4..=MAX_RESPONSE_PLAINTEXT).contains(&length),
                "VMess response header length exceeds supported layout"
            );
            response.wire_length =
                Some(crypto::ENCRYPTED_LENGTH_LEN + length + crypto::AEAD_TAG_LEN);
        }
        let length = response.wire_length.expect("response length authenticated");
        if self.read_wire.len() < length {
            return Ok(Some(length));
        }
        let (plaintext, consumed) =
            crypto::open_response_header(&response.key, &response.iv, &self.read_wire)?;
        let (_, decoded) = ResponseHeader::decode(&plaintext, response.auth)?;
        ensure!(
            decoded == plaintext.len(),
            "trailing bytes in VMess response header"
        );
        self.read_wire.drain(..consumed);
        self.response = None;
        Ok(None)
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        // An accepted application write can still have ciphertext pending. Make
        // progress without waiting for the write side before polling the read
        // side: full-duplex peers can both have backpressured outgoing buffers.
        // Untouched inbound response headers remain queued until routing succeeds.
        if this.output_started
            && this.shutdown != Shutdown::Done
            && let Poll::Ready(Err(error)) = this.poll_flush_output(cx)
        {
            return Poll::Ready(Err(error));
        }
        for _ in 0..32 {
            if this.plain_offset < this.read_plain.len() {
                let count = output
                    .remaining()
                    .min(this.read_plain.len() - this.plain_offset);
                output.put_slice(&this.read_plain[this.plain_offset..this.plain_offset + count]);
                this.plain_offset += count;
                if this.plain_offset == this.read_plain.len() {
                    this.read_plain.clear();
                    this.plain_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            let header_needed = match this.response_progress() {
                Ok(value) => value,
                Err(error) => return Poll::Ready(Err(this.invalid(error))),
            };
            if header_needed.is_none() {
                match this.decoder.decode_frame(&this.read_wire) {
                    Ok(Some((BodyFrame::Data(plaintext), consumed))) => {
                        this.read_wire.drain(..consumed);
                        this.read_plain = plaintext;
                        continue;
                    }
                    Ok(Some((BodyFrame::End, consumed))) => {
                        this.read_wire.drain(..consumed);
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Ok(None) => (),
                    Err(error) => return Poll::Ready(Err(this.invalid(error))),
                }
            }
            let bound = header_needed.unwrap_or(MAX_BODY_WIRE);
            let available = bound.saturating_sub(this.read_wire.len()).min(READ_BLOCK);
            if available == 0 {
                return Poll::Ready(Err(this.fail(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMess input exceeds bounded frame buffer",
                ))));
            }
            let mut block = [0; READ_BLOCK];
            let mut incoming = ReadBuf::new(&mut block[..available]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut incoming) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(this.fail(error))),
                Poll::Ready(Ok(())) if incoming.filled().is_empty() => {
                    if this.response.is_none()
                        && this.read_wire.is_empty()
                        && !this.require_termination
                    {
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(this.fail(io::Error::new(io::ErrorKind::UnexpectedEof, "VMess transport closed before a complete authenticated frame or termination"))));
                }
                Poll::Ready(Ok(())) => this.read_wire.extend_from_slice(incoming.filled()),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        if this.shutdown != Shutdown::Open {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VMess write side is shut down",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.output_started = true;
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => (),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let count = input.len().min(this.encoder.max_payload_length());
        this.write_wire = match this.encoder.encode_frame(&input[..count]) {
            Ok(wire) => wire,
            Err(error) => return Poll::Ready(Err(this.invalid(error))),
        };
        // The plaintext is now accepted even if only a ciphertext prefix fits
        // into the transport. Returning Pending here would let cancellation or
        // a different retry buffer duplicate/replace accepted plaintext.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        this.output_started = true;
        this.poll_flush_output(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.stored_error() {
            return Poll::Ready(Err(error));
        }
        if this.shutdown == Shutdown::Done {
            return Poll::Ready(Ok(()));
        }
        this.output_started = true;
        if this.shutdown == Shutdown::Open {
            // Freeze writes as soon as shutdown is requested, and append exactly
            // one EOF after any partially written data/header bytes.
            let eof = match this.encoder.encode_frame(&[]) {
                Ok(wire) => wire,
                Err(error) => return Poll::Ready(Err(this.invalid(error))),
            };
            this.write_wire.extend_from_slice(&eof);
            this.shutdown = Shutdown::EofQueued;
        }
        match this.poll_flush_output(cx) {
            Poll::Ready(Ok(())) => (),
            result => return result,
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown = Shutdown::Done;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.fail(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{Future, poll_fn},
        time::Duration,
    };
    use tokio::{io::duplex, time::timeout};

    fn account() -> Account {
        Account::new([0x11; 16], "vmess@example.test")
    }

    fn shared_auth() -> SharedAuthenticator {
        Arc::new(Mutex::new(
            ServerAuthenticator::new(vec![account()], 64).unwrap(),
        ))
    }

    fn header(security: Security, options: u8) -> RequestHeader {
        RequestHeader {
            body_iv: [0x22; 16],
            body_key: [0x33; 16],
            response_auth: 0x44,
            options,
            security,
            command: Command::Tcp,
            destination: Some(Destination::new("example.test", 443).unwrap()),
            padding: vec![0x55; 3],
        }
    }

    /// Force a Pending before every one-byte transport read/write. This exercises
    /// persistent offsets, not just a convenient in-memory all-at-once path.
    struct OneByte<S> {
        inner: S,
        read_ready: bool,
        write_ready: bool,
    }
    impl<S> OneByte<S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                read_ready: false,
                write_ready: false,
            }
        }
    }
    impl<S: AsyncRead + Unpin> AsyncRead for OneByte<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !this.read_ready {
                this.read_ready = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.read_ready = false;
            let mut byte = [0];
            let mut input = ReadBuf::new(&mut byte);
            match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
                Poll::Ready(Ok(())) => {
                    output.put_slice(input.filled());
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for OneByte<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if !this.write_ready {
                this.write_ready = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.write_ready = false;
            Pin::new(&mut this.inner).poll_write(cx, &input[..1])
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn tcp_handshake_delayed_response_and_large_bidirectional_payloads() {
        timeout(Duration::from_secs(10), async {
            for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
                let (client_io, server_io) = duplex(23);
                let auth = shared_auth();
                let server = tokio::spawn(async move {
                    let (mut server, request) = accept(Box::new(server_io), &auth).await.unwrap();
                    assert_eq!(
                        request.destination,
                        Destination::new("example.test", 443).unwrap()
                    );
                    assert_eq!(request.user, "vmess@example.test");
                    assert!(request.initial_payload.is_empty());
                    assert!(matches!(request.reply, Reply::None));
                    // The server intentionally withholds its response until it
                    // receives application data and authenticated request EOF.
                    let mut payload = Vec::new();
                    server.read_to_end(&mut payload).await.unwrap();
                    assert_eq!(payload, vec![0xa5; 25_000]);
                    server.write_all(&payload).await.unwrap();
                    server.shutdown().await.unwrap();
                });
                let options = encoding::OPTION_CHUNK_STREAM
                    | encoding::OPTION_CHUNK_MASKING
                    | encoding::OPTION_GLOBAL_PADDING
                    | encoding::OPTION_AUTHENTICATED_LENGTH;
                let mut client = connect_with_options(
                    Box::new(client_io),
                    &account(),
                    &Destination::new("example.test", 443).unwrap(),
                    security,
                    options,
                )
                .await
                .unwrap();
                client.write_all(&vec![0xa5; 25_000]).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, vec![0xa5; 25_000]);
                server.await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn inbound_does_not_send_success_on_accept_or_read_and_keeps_pipeline() {
        let header = header(Security::Aes128Gcm, encoding::OPTION_CHUNK_STREAM);
        let mut wire = seal_request(&account(), &header, unix_time().unwrap()).unwrap();
        let mut encoder =
            BodyEncoder::new(header.security, header.options, BodyKeys::request(&header)).unwrap();
        wire.extend(encoder.encode_frame(b"pipelined request").unwrap());
        wire.extend(encoder.encode_frame(&[]).unwrap());
        let (mut client, server) = duplex(4096);
        client.write_all(&wire).await.unwrap();
        let (mut server, _) = accept(Box::new(server), &shared_auth()).await.unwrap();
        let mut payload = Vec::new();
        server.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"pipelined request");
        let mut byte = [0];
        let mut output = ReadBuf::new(&mut byte);
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut client).poll_read(cx, &mut output)))
                .await
                .is_pending()
        );
        server.flush().await.unwrap(); // Explicit success, but never EOF.
        let mut received = vec![0; crypto::ENCRYPTED_LENGTH_LEN + 4 + crypto::AEAD_TAG_LEN];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(
            super::super::open_response(&header, &received).unwrap().1,
            received.len()
        );
        let mut output = ReadBuf::new(&mut byte);
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut client).poll_read(cx, &mut output)))
                .await
                .is_pending()
        );
        server.write_all(b"response").await.unwrap();
        server.shutdown().await.unwrap();
        let mut body = Vec::new();
        client.read_to_end(&mut body).await.unwrap();
        let mut decoder =
            BodyDecoder::new(header.security, header.options, BodyKeys::response(&header)).unwrap();
        let (frame, consumed) = decoder.decode_frame(&body).unwrap().unwrap();
        assert_eq!(frame, BodyFrame::Data(b"response".to_vec()));
        assert_eq!(
            decoder.decode_frame(&body[consumed..]).unwrap(),
            Some((BodyFrame::End, body.len() - consumed))
        );
    }

    #[tokio::test]
    async fn one_byte_partial_io_and_cancelled_read_write_flush_shutdown_keep_state() {
        timeout(Duration::from_secs(10), async {
            let header = header(Security::Chacha20Poly1305, 29);
            let (client_io, server_io) = duplex(4096);
            let mut client =
                VmessStream::client(Box::new(OneByte::new(client_io)), &header).unwrap();
            let mut server =
                VmessStream::server(Box::new(OneByte::new(server_io)), &header).unwrap();
            // Cancelling this pending first write must not accept "discard me".
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_write(cx, b"discard me")))
                    .await
                    .is_pending()
            );
            server.write_all(b"first").await.unwrap();
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_write(cx, b"discard too")))
                    .await
                    .is_pending()
            );
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_flush(cx)))
                    .await
                    .is_pending()
            );
            server.write_all(b"second").await.unwrap();
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut server).poll_shutdown(cx)))
                    .await
                    .is_pending()
            );
            assert!(server.write_all(b"after shutdown").await.is_err());
            // Re-poll shutdown after cancellation: no duplicate EOF frame.
            server.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
            let mut scratch = [0; 64];
            let mut read = ReadBuf::new(&mut scratch);
            for _ in 0..8 {
                assert!(
                    poll_fn(|cx| Poll::Ready(Pin::new(&mut client).poll_read(cx, &mut read)))
                        .await
                        .is_pending()
                );
            }
            assert!(!client.read_wire.is_empty());
            assert!(client.read_wire.len() < crypto::ENCRYPTED_LENGTH_LEN);
            let mut payload = Vec::new();
            client.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"firstsecond");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn accepted_buffered_write_is_driven_while_waiting_for_response() {
        timeout(Duration::from_secs(5), async {
            let header = header(Security::Aes128Gcm, 1);
            let (client_io, server_io) = duplex(1);
            let mut client = VmessStream::client(Box::new(client_io), &header).unwrap();
            let mut server = VmessStream::server(Box::new(server_io), &header).unwrap();
            let server_task = tokio::spawn(async move {
                let mut request = [0; 5];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"hello");
                server.write_all(b"world").await.unwrap();
                server.shutdown().await.unwrap();
            });
            // write_all accepts one buffered frame. read_exact must drive its
            // pending ciphertext even though no explicit flush was requested.
            client.write_all(b"hello").await.unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"world");
            let mut end = [0];
            assert_eq!(client.read(&mut end).await.unwrap(), 0);
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fresh_connects_share_replay_state_without_waiting_for_responses() {
        timeout(Duration::from_secs(5), async {
            let auth = shared_auth();
            for _ in 0..3 {
                let (client, server) = duplex(4096);
                // No peer has read the request or sent a response yet. Returning
                // here proves connect performs no eager response-header read.
                let _client = connect(
                    Box::new(client),
                    &account(),
                    &Destination::new("example.test", 443).unwrap(),
                )
                .await
                .unwrap();
                let (_server, request) = accept(Box::new(server), &auth).await.unwrap();
                assert_eq!(request.user, "vmess@example.test");
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn concurrent_read_and_write_halves_work_under_bidirectional_backpressure() {
        timeout(Duration::from_secs(10), async {
            let header = header(Security::Aes128Gcm, 13);
            let (client, server) = duplex(17);
            let client = VmessStream::client(Box::new(client), &header).unwrap();
            let server = VmessStream::server(Box::new(server), &header).unwrap();
            let (mut cr, mut cw) = tokio::io::split(client);
            let (mut sr, mut sw) = tokio::io::split(server);
            let request = vec![0x31; 18_000];
            let response = vec![0x72; 19_000];
            let client_write = async {
                cw.write_all(&request).await?;
                cw.shutdown().await
            };
            let server_write = async {
                sw.write_all(&response).await?;
                sw.shutdown().await
            };
            let client_read = async {
                let mut bytes = Vec::new();
                cr.read_to_end(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            };
            let server_read = async {
                let mut bytes = Vec::new();
                sr.read_to_end(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            };
            let (_, _, received_response, received_request) =
                tokio::try_join!(client_write, server_write, client_read, server_read).unwrap();
            assert_eq!(received_response, response);
            assert_eq!(received_request, request);
        })
        .await
        .unwrap();
    }

    async fn accept_wire(wire: &[u8], auth: &SharedAuthenticator) -> Result<(BoxStream, Request)> {
        let (mut client, server) = duplex(4096);
        client.write_all(wire).await.unwrap();
        accept(Box::new(server), auth).await
    }

    #[tokio::test]
    async fn replay_account_selection_and_unsupported_commands_fail_closed() {
        let auth = shared_auth();
        let base = header(Security::Aes128Gcm, 1);
        let wire = seal_request(&account(), &base, unix_time().unwrap()).unwrap();
        assert!(accept_wire(&wire, &auth).await.is_ok());
        assert!(accept_wire(&wire, &auth).await.is_err());
        for command in [Command::Udp, Command::Mux] {
            let mut request = base.clone();
            request.command = command;
            if command == Command::Mux {
                request.destination = None;
            }
            let wire = seal_request(&account(), &request, unix_time().unwrap()).unwrap();
            let error = accept_wire(&wire, &shared_auth()).await.err().unwrap();
            assert!(error.to_string().contains("TCP only"));
        }
        let wire = seal_request(
            &Account::new([0x99; 16], "unknown"),
            &base,
            unix_time().unwrap(),
        )
        .unwrap();
        assert!(accept_wire(&wire, &shared_auth()).await.is_err());
    }

    #[tokio::test]
    async fn request_bounds_and_replay_lock_do_not_wait_for_header_payload() {
        timeout(Duration::from_secs(5), async {
            let command_key = crypto::command_key(&[0x11; 16]);
            let auth_id = crypto::create_auth_id(&command_key, unix_time().unwrap(), [1; 4]);
            let wire = crypto::seal_request_header(
                &command_key,
                &vec![0; MAX_REQUEST_PLAINTEXT + 1],
                &auth_id,
                &[2; 8],
            )
            .unwrap();
            let (mut client, server) = duplex(4096);
            client
                .write_all(&wire[..crypto::REQUEST_HEADER_PREFIX_LEN])
                .await
                .unwrap();
            assert!(
                accept(Box::new(server), &shared_auth())
                    .await
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("supported wire layout")
            );

            let auth = shared_auth();
            let request = header(Security::Aes128Gcm, 1);
            let wire = seal_request(&account(), &request, unix_time().unwrap()).unwrap();
            let (mut client, server) = duplex(4096);
            client
                .write_all(&wire[..crypto::REQUEST_HEADER_PREFIX_LEN])
                .await
                .unwrap();
            let mut future = Box::pin(accept(Box::new(server), &auth));
            assert!(
                poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            assert!(auth.try_lock().is_ok());
            client
                .write_all(&wire[crypto::REQUEST_HEADER_PREFIX_LEN..])
                .await
                .unwrap();
            assert!(future.await.is_ok());
        })
        .await
        .unwrap();
    }

    async fn malformed_response_reader(header: &RequestHeader, wire: &[u8]) -> VmessStream {
        let (client, mut server) = duplex(4096);
        server.write_all(wire).await.unwrap();
        server.shutdown().await.unwrap();
        VmessStream::client(Box::new(client), header).unwrap()
    }

    #[tokio::test]
    async fn response_bounds_authentication_and_truncated_frames_are_terminal() {
        let request = header(Security::Aes128Gcm, 1);
        let (key, iv) = crypto::derive_response_key_iv(&request.body_key, &request.body_iv);
        let normal = seal_response(
            &request,
            &ResponseHeader {
                response_auth: request.response_auth,
                options: 0,
                command: None,
            },
        )
        .unwrap();
        let oversized =
            crypto::seal_response_header(&key, &iv, &vec![0; MAX_RESPONSE_PLAINTEXT + 1]).unwrap();
        let wrong_token = crypto::seal_response_header(&key, &iv, &[0, 0, 0, 0]).unwrap();
        let mut tampered = normal.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut encoder = BodyEncoder::new(
            request.security,
            request.options,
            BodyKeys::response(&request),
        )
        .unwrap();
        let frame = encoder.encode_frame(b"secret").unwrap();
        let mut truncated = normal.clone();
        truncated.extend_from_slice(&frame[..frame.len() - 1]);
        let mut corrupt_body = normal.clone();
        let mut invalid_frame = frame;
        invalid_frame[3] ^= 1;
        corrupt_body.extend(invalid_frame);
        for wire in [
            Vec::new(),
            normal[..17].to_vec(),
            normal.clone(),
            oversized[..18].to_vec(),
            wrong_token,
            tampered,
            truncated,
            corrupt_body,
        ] {
            let mut client = malformed_response_reader(&request, &wire).await;
            let mut output = [0; 64];
            assert!(client.read(&mut output).await.is_err());
            assert!(client.read(&mut output).await.is_err());
            assert!(client.write_all(b"after failure").await.is_err());
            assert!(client.flush().await.is_err());
            assert!(client.shutdown().await.is_err());
            assert!(client.read_wire.len() <= MAX_BODY_WIRE);
        }
    }

    #[tokio::test]
    async fn no_chunk_stream_flag_allows_transport_eof_only_at_complete_frame_boundary() {
        let request = header(Security::Aes128Gcm, 0);
        let mut wire = seal_response(
            &request,
            &ResponseHeader {
                response_auth: request.response_auth,
                options: 0,
                command: None,
            },
        )
        .unwrap();
        let mut encoder = BodyEncoder::new(
            request.security,
            request.options,
            BodyKeys::response(&request),
        )
        .unwrap();
        wire.extend(encoder.encode_frame(b"complete").unwrap());
        let mut client = malformed_response_reader(&request, &wire).await;
        let mut payload = Vec::new();
        client.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"complete");
        wire.pop();
        let mut client = malformed_response_reader(&request, &wire).await;
        assert!(client.read_to_end(&mut Vec::new()).await.is_err());
    }
}
