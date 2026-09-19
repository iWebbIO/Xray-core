//! Native Xray gRPC transport over an already connected byte stream.
//!
//! Wire and naming rules come from `transport/internet/grpc/{config,dial,hub}.go`
//! and `encoding/{stream.proto,hunkconn,multiconn,customSeviceName}.go`.
//! TLS, TCP socket options, reconnect policy, and destination-wide connection
//! pooling belong to the caller. TLS must negotiate `h2`. A cloneable [`Client`]
//! multiplexes tunnels on one HTTP/2 connection; [`Server`] accepts all streams
//! on one connection while its private driver continuously processes HTTP/2.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream, client::ResponseFuture};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
};

use super::BoxStream;
use crate::address::{Address, Destination};

// grpc-go's default maximum receive message size; emitted messages are much
// smaller so individual writes cannot queue an unbounded HTTP/2 send buffer.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const WRITE_CHUNK_BYTES: usize = 16 * 1024;
const ACCEPT_QUEUE: usize = 64;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub authority: String,
    #[serde(rename = "serviceName")]
    pub service_name: String,
    #[serde(rename = "multiMode")]
    pub multi_mode: bool,
    pub idle_timeout: i32,
    pub health_check_timeout: i32,
    pub permit_without_stream: bool,
    pub initial_windows_size: i32,
    pub user_agent: String,
}

impl Config {
    /// Negative values have the same disabled/default meaning as Go's Build.
    /// Configured keepalive must not silently degrade into no keepalive.
    pub fn validate(&self) -> io::Result<()> {
        if self.idle_timeout > 0 || self.health_check_timeout > 0 || self.permit_without_stream {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "gRPC HTTP/2 keepalive is not implemented; idle_timeout, health_check_timeout, and permit_without_stream must be disabled",
            ));
        }
        if !self.authority.is_empty() {
            validate_authority(&self.authority)?;
        }
        user_agent(self)?;
        Ok(())
    }

    pub fn paths(&self) -> Paths {
        Paths::new(&self.service_name)
    }

    /// Go dial.go authority precedence, including its default target endpoint
    /// when WithAuthority("") leaves grpc-go to choose an authority.
    pub fn authority_for(
        &self,
        destination: &Destination,
        tls_server_name: Option<&str>,
        reality: bool,
    ) -> String {
        if !self.authority.is_empty() {
            return self.authority.clone();
        }
        if let Some(name) = tls_server_name.filter(|name| !name.is_empty()) {
            return name.to_owned();
        }
        if !reality && let Address::Domain(name) = &destination.address {
            return name.clone();
        }
        destination.to_string()
    }
}

/// Escaped service/method names, not decoded URI paths. Empty service names are
/// valid in Xray and produce `//Tun`; do not normalize consecutive slashes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Paths {
    pub service: String,
    pub tun: String,
    pub tun_multi: String,
}

impl Paths {
    pub fn new(name: &str) -> Self {
        let (service, tun, tun_multi) = if name.starts_with('/') {
            let last = name.rfind('/').unwrap_or(0);
            let service = name[1..last.max(1)]
                .split('/')
                .map(path_escape)
                .collect::<Vec<_>>()
                .join("/");
            let mut endings = name[last + 1..].split('|');
            let tun = endings.next().unwrap_or_default();
            let multi = endings.next().unwrap_or(tun);
            (service, path_escape(tun), path_escape(multi))
        } else {
            (path_escape(name), "Tun".to_owned(), "TunMulti".to_owned())
        };
        Self {
            service,
            tun,
            tun_multi,
        }
    }

    pub fn path(&self, mode: Mode) -> String {
        let method = match mode {
            Mode::Tun => &self.tun,
            Mode::TunMulti => &self.tun_multi,
        };
        format!("/{}/{method}", self.service)
    }

    fn mode(&self, path: &str) -> Option<Mode> {
        // Go's service registration puts the latter descriptor into the method
        // map when custom Tun and TunMulti method names are equal.
        if path == self.path(Mode::TunMulti) {
            Some(Mode::TunMulti)
        } else if path == self.path(Mode::Tun) {
            Some(Mode::Tun)
        } else {
            None
        }
    }
}

/// Go net/url.PathEscape uses the path-segment safe set (not encodeURIComponent).
fn path_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 15) as usize]));
        }
    }
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Tun,
    TunMulti,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub code: u16,
    pub message: String,
}

impl Status {
    pub fn ok() -> Self {
        Self {
            code: 0,
            message: String::new(),
        }
    }

    pub fn new(code: u16, message: impl Into<String>) -> io::Result<Self> {
        if code > 16 {
            return Err(invalid("invalid gRPC status code"));
        }
        Ok(Self {
            code,
            message: message.into(),
        })
    }

    fn trailers(&self) -> io::Result<HeaderMap> {
        if self.code > 16 {
            return Err(invalid("invalid gRPC status code"));
        }
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "grpc-status",
            HeaderValue::from_str(&self.code.to_string()).map_err(invalid)?,
        );
        if !self.message.is_empty() {
            // Percent encoding all non-unreserved characters is valid grpc-message.
            trailers.insert(
                "grpc-message",
                HeaderValue::from_str(&path_escape(&self.message)).map_err(invalid)?,
            );
        }
        Ok(trailers)
    }

    fn result(&self) -> io::Result<()> {
        if self.code == 0 {
            return Ok(());
        }
        let kind = match self.code {
            1 => io::ErrorKind::Interrupted,
            4 => io::ErrorKind::TimedOut,
            7 | 16 => io::ErrorKind::PermissionDenied,
            8 => io::ErrorKind::OutOfMemory,
            12 => io::ErrorKind::Unsupported,
            14 => io::ErrorKind::ConnectionAborted,
            _ => io::ErrorKind::Other,
        };
        Err(io::Error::new(
            kind,
            format!("gRPC status {}: {}", self.code, self.message),
        ))
    }
}

fn read_status(headers: &HeaderMap) -> io::Result<Option<Status>> {
    let mut values = headers.get_all("grpc-status").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid("duplicate gRPC status"));
    }
    let value = value.to_str().map_err(invalid)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid gRPC status"));
    }
    let code: u16 = value.parse().map_err(invalid)?;
    let message = headers
        .get("grpc-message")
        .map(|v| unescape_message(v.as_bytes()))
        .unwrap_or_default();
    Status::new(code, message).map(Some)
}

fn unescape_message(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(a), Some(b)) = (
                char::from(bytes[i + 1]).to_digit(16),
                char::from(bytes[i + 2]).to_digit(16),
            )
        {
            out.push((a * 16 + b) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An established, reusable HTTP/2 client connection. The connection remains
/// alive until the final Client and Tunnel are dropped; no process-global pool.
#[derive(Clone)]
pub struct Client {
    sender: h2::client::SendRequest<Bytes>,
    config: Config,
    authority: String,
    driver: Arc<Driver>,
}

impl Client {
    pub async fn handshake(
        io: BoxStream,
        config: Config,
        fallback_authority: &str,
    ) -> io::Result<Self> {
        config.validate()?;
        let authority = if config.authority.is_empty() {
            fallback_authority.to_owned()
        } else {
            config.authority.clone()
        };
        validate_authority(&authority)?;
        let mut builder = h2::client::Builder::new();
        builder.max_send_buffer_size(WRITE_CHUNK_BYTES * 2);
        // grpc-go ignores initial stream window settings below its default.
        if config.initial_windows_size >= 65_535 {
            builder.initial_window_size(config.initial_windows_size as u32);
        }
        let (sender, connection) = builder.handshake(io).await.map_err(h2_error)?;
        let driver = Arc::new(Driver(tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "gRPC client HTTP/2 connection ended");
            }
        })));
        Ok(Self {
            sender,
            config,
            authority,
            driver,
        })
    }

    /// Returns before response headers arrive, as grpc-go NewStream does.
    pub async fn open(&self) -> io::Result<Tunnel> {
        let mode = if self.config.multi_mode {
            Mode::TunMulti
        } else {
            Mode::Tun
        };
        self.open_mode(mode).await
    }

    pub async fn open_mode(&self, mode: Mode) -> io::Result<Tunnel> {
        let mut sender = self.sender.clone().ready().await.map_err(h2_error)?;
        // Go performs TLS outside grpc-go and passes insecure credentials to
        // grpc.NewClient, so its HTTP/2 pseudo-header scheme remains "http".
        let uri = Uri::builder()
            .scheme("http")
            .authority(self.authority.as_str())
            .path_and_query(self.config.paths().path(mode))
            .build()
            .map_err(invalid)?;
        let mut request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        if let Some(agent) = user_agent(&self.config)? {
            request = request.header("user-agent", agent);
        }
        let (response, send) = sender
            .send_request(request.body(()).map_err(invalid)?, false)
            .map_err(h2_error)?;
        Ok(Tunnel::new(
            mode,
            Role::Client,
            send,
            None,
            Some(response),
            Some(self.driver.clone()),
        ))
    }
}

/// One inbound logical stream; authority and metadata remain available for
/// caller policy. Forwarded addresses must be interpreted using trusted-proxy
/// settings outside this byte transport.
pub struct Accepted {
    pub stream: Tunnel,
    pub mode: Mode,
    pub authority: String,
    pub metadata: HeaderMap,
}

pub struct Server {
    incoming: mpsc::Receiver<io::Result<Accepted>>,
    driver: Arc<Driver>,
}

impl Server {
    pub async fn handshake(io: BoxStream, config: Config) -> io::Result<Self> {
        config.validate()?;
        let mut builder = h2::server::Builder::new();
        builder
            .max_concurrent_streams(ACCEPT_QUEUE as u32)
            .max_send_buffer_size(WRITE_CHUNK_BYTES * 2);
        // Xray hub.go does not apply initial_windows_size on the server.
        let mut connection = builder.handshake::<_, Bytes>(io).await.map_err(h2_error)?;
        let (incoming_tx, incoming) = mpsc::channel(ACCEPT_QUEUE);
        let driver = Arc::new(Driver(tokio::spawn(async move {
            let mut closing = false;
            loop {
                let next = tokio::select! {
                    _ = incoming_tx.closed(), if !closing => {
                        closing = true;
                        connection.graceful_shutdown();
                        continue;
                    }
                    next = connection.accept() => next,
                };
                let Some(next) = next else {
                    break;
                };
                let (request, response) = match next {
                    Ok(next) => next,
                    Err(error) => {
                        let _ = incoming_tx.try_send(Err(h2_error(error)));
                        break;
                    }
                };
                match accept_request(request, response, &config) {
                    Ok(Some(accepted)) => {
                        // Never await application queue capacity in the HTTP/2
                        // driver: doing so stalls established tunnels as well.
                        if let Err(error) = incoming_tx.try_send(Ok(accepted))
                            && let Ok(mut accepted) = error.into_inner()
                        {
                            let status = Status {
                                code: 8,
                                message: "gRPC accept queue full or closed".into(),
                            };
                            let _ = accepted
                                .stream
                                .send
                                .send_trailers(status.trailers().expect("valid status"));
                            accepted.stream.write_closed = true;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(%error, "rejected gRPC stream");
                    }
                }
            }
        })));
        Ok(Self { incoming, driver })
    }

    pub async fn accept(&mut self) -> io::Result<Option<Accepted>> {
        match self.incoming.recv().await {
            Some(Ok(mut accepted)) => {
                accepted.stream.driver = Some(self.driver.clone());
                Ok(Some(accepted))
            }
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
}

fn accept_request(
    request: Request<RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    config: &Config,
) -> io::Result<Option<Accepted>> {
    if request.method() != Method::POST {
        response
            .send_response(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(())
                    .map_err(invalid)?,
                true,
            )
            .map_err(h2_error)?;
        return Ok(None);
    }
    if !is_grpc_content_type(request.headers()) {
        response
            .send_response(
                Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(())
                    .map_err(invalid)?,
                true,
            )
            .map_err(h2_error)?;
        return Ok(None);
    }
    let mode = config.paths().mode(request.uri().path());
    let encoding_supported = request
        .headers()
        .get("grpc-encoding")
        .is_none_or(|value| value == "identity");
    let rejection = if request.uri().query().is_some() || mode.is_none() {
        Some(Status {
            code: 12,
            message: "unknown gRPC service or method".into(),
        })
    } else if !encoding_supported {
        Some(Status {
            code: 12,
            message: "gRPC compression is not supported".into(),
        })
    } else {
        None
    };
    if let Some(status) = rejection {
        let mut reply = Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .map_err(invalid)?;
        reply.headers_mut().extend(status.trailers()?);
        response.send_response(reply, true).map_err(h2_error)?;
        return Ok(None);
    }
    let mode = mode.expect("validated method");
    let authority = request
        .uri()
        .authority()
        .map(ToString::to_string)
        .unwrap_or_default();
    let (parts, recv) = request.into_parts();
    let send = response
        .send_response(
            Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .map_err(invalid)?,
            false,
        )
        .map_err(h2_error)?;
    Ok(Some(Accepted {
        stream: Tunnel::new(mode, Role::Server, send, Some(recv), None, None),
        mode,
        authority,
        metadata: parts.headers,
    }))
}

fn validate_authority(authority: &str) -> io::Result<()> {
    let parsed: http::uri::Authority = authority.parse().map_err(invalid)?;
    if parsed.host().is_empty() || authority.contains('@') {
        return Err(invalid("invalid gRPC authority"));
    }
    Ok(())
}

fn user_agent(config: &Config) -> io::Result<Option<HeaderValue>> {
    let agent = match config.user_agent.as_str() {
        "golang" => return Ok(None),
        "" | "chrome" | "firefox" | "edge" => {
            let alias = if config.user_agent.is_empty() {
                "chrome"
            } else {
                &config.user_agent
            };
            let mut headers = BTreeMap::from([("User-Agent".into(), alias.to_owned())]);
            super::httpupgrade::apply_browser_headers(&mut headers);
            headers
                .remove("User-Agent")
                .expect("browser alias supplies UA")
        }
        literal => literal.to_owned(),
    };
    HeaderValue::from_str(&agent).map(Some).map_err(invalid)
}

fn is_grpc_content_type(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            matches!(
                value.split(';').next().unwrap_or_default().trim(),
                "application/grpc" | "application/grpc+proto"
            )
        })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Client,
    Server,
}

/// A bounded gRPC byte stream. shutdown() half-closes the client request or
/// sends the server's successful gRPC status. Dropping an unfinished tunnel
/// cancels only that HTTP/2 stream, leaving sibling streams usable.
pub struct Tunnel {
    mode: Mode,
    role: Role,
    send: SendStream<Bytes>,
    recv: Option<RecvStream>,
    response: Option<ResponseFuture>,
    decoder: Decoder,
    decoded: VecDeque<Bytes>,
    pending: Bytes,
    read_closed: bool,
    write_closed: bool,
    data_ended: bool,
    initial_status: Option<Status>,
    terminal_error: Option<(io::ErrorKind, String)>,
    // Drop after stream handles, keeping the HTTP/2 driver alive for I/O.
    driver: Option<Arc<Driver>>,
}

impl Tunnel {
    fn new(
        mode: Mode,
        role: Role,
        send: SendStream<Bytes>,
        recv: Option<RecvStream>,
        response: Option<ResponseFuture>,
        driver: Option<Arc<Driver>>,
    ) -> Self {
        Self {
            mode,
            role,
            send,
            recv,
            response,
            decoder: Decoder::new(mode),
            decoded: VecDeque::new(),
            pending: Bytes::new(),
            read_closed: false,
            write_closed: false,
            data_ended: false,
            initial_status: None,
            terminal_error: None,
            driver,
        }
    }

    pub fn boxed(self) -> BoxStream {
        Box::new(self)
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Finish a server response with a specific gRPC status. Pending data is
    /// drained first. Clients finish their request with AsyncWrite::shutdown.
    pub async fn finish(&mut self, status: Status) -> io::Result<()> {
        if self.role != Role::Server {
            return Err(invalid("only a gRPC server sends status trailers"));
        }
        if self.write_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC send side closed",
            ));
        }
        let trailers = status.trailers()?;
        std::future::poll_fn(|cx| self.poll_drain(cx)).await?;
        self.send.send_trailers(trailers).map_err(h2_error)?;
        self.write_closed = true;
        Ok(())
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            self.send.reserve_capacity(self.pending.len());
            let available = self.send.capacity();
            let capacity = if available > 0 {
                available
            } else {
                match ready!(self.send.poll_capacity(cx)) {
                    Some(Ok(capacity)) => capacity,
                    Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "gRPC HTTP/2 send stream closed",
                        )));
                    }
                }
            };
            let length = capacity.min(self.pending.len());
            if length == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let data = self.pending.split_to(length);
            self.send.send_data(data, false).map_err(h2_error)?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some((kind, message)) = &self.terminal_error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if buf.remaining() == 0 || self.read_closed {
            return Poll::Ready(Ok(()));
        }
        // A write may have accepted a bounded frame while HTTP/2 capacity was
        // exhausted. Reading must drive that frame too: a peer can wait for the
        // complete first message before returning response headers or data.
        if let Poll::Ready(Err(error)) = self.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(response) = &mut self.response {
            let response = ready!(Pin::new(response).poll(cx)).map_err(h2_error)?;
            self.response = None;
            if response.status() != StatusCode::OK {
                return Poll::Ready(Err(io::Error::other(format!(
                    "gRPC HTTP status {}",
                    response.status()
                ))));
            }
            if !is_grpc_content_type(response.headers()) {
                return Poll::Ready(Err(invalid("invalid gRPC response content-type")));
            }
            if response
                .headers()
                .get("grpc-encoding")
                .is_some_and(|v| v != "identity")
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "gRPC response compression is not supported",
                )));
            }
            self.initial_status = read_status(response.headers())?;
            if self.initial_status.is_some() && !response.body().is_end_stream() {
                return Poll::Ready(Err(invalid("gRPC status in non-final response headers")));
            }
            self.recv = Some(response.into_body());
        }
        // Yield cooperatively when receiving many zero-length protobuf messages.
        for _ in 0..64 {
            while let Some(data) = self.decoded.front_mut() {
                if data.is_empty() {
                    self.decoded.pop_front();
                    continue;
                }
                let amount = buf.remaining().min(data.len());
                buf.put_slice(&data.split_to(amount));
                return Poll::Ready(Ok(()));
            }
            if let Some(decoded) = self.decoder.next()? {
                self.decoded = decoded;
                continue;
            }
            let recv = self
                .recv
                .as_mut()
                .expect("response installs receive stream");
            if !self.data_ended {
                match ready!(recv.poll_data(cx)) {
                    Some(Ok(data)) => {
                        if self.initial_status.is_some() {
                            return Poll::Ready(Err(invalid("gRPC data follows final headers")));
                        }
                        // Release HTTP/2 capacity as bytes move into the bounded
                        // decoder, allowing messages larger than an H2 window.
                        self.decoder.wire.extend_from_slice(&data);
                        recv.flow_control()
                            .release_capacity(data.len())
                            .map_err(h2_error)?;
                        continue;
                    }
                    Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                    None => self.data_ended = true,
                }
            }
            if !self.decoder.wire.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated gRPC message",
                )));
            }
            let trailers = ready!(recv.poll_trailers(cx)).map_err(h2_error)?;
            if self.role == Role::Client {
                let status = match trailers.as_ref().map(read_status).transpose()?.flatten() {
                    Some(status) => status,
                    None => self
                        .initial_status
                        .take()
                        .ok_or_else(|| invalid("gRPC response ended without grpc-status"))?,
                };
                status.result()?;
            }
            self.read_closed = true;
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_write_parts(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC send side closed",
            )));
        }
        ready!(self.poll_drain(cx))?;
        let mut remaining = WRITE_CHUNK_BYTES;
        let mut parts = Vec::new();
        for buffer in buffers {
            let amount = remaining.min(buffer.len());
            if amount > 0 {
                parts.push(&buffer[..amount]);
                remaining -= amount;
            }
            if remaining == 0 {
                break;
            }
        }
        let written = WRITE_CHUNK_BYTES - remaining;
        if written > 0 {
            self.pending = encode_message(self.mode, &parts)?;
            // Queue immediately whenever capacity exists, without requiring an
            // extra write or flush for the common write-then-read exchange.
            if let Poll::Ready(Err(error)) = self.poll_drain(cx) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(written))
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = self.poll_read_inner(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.terminal_error = Some((error.kind(), error.to_string()));
            self.send.send_reset(h2::Reason::CANCEL);
        }
        result
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_parts(cx, &[io::IoSlice::new(data)])
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_parts(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_drain(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_drain(cx))?;
        if self.role == Role::Client {
            self.send.send_data(Bytes::new(), true).map_err(h2_error)?;
        } else {
            self.send
                .send_trailers(Status::ok().trailers()?)
                .map_err(h2_error)?;
        }
        self.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if !self.write_closed || (self.role == Role::Client && !self.read_closed) {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

#[derive(Clone, PartialEq, Message)]
struct Hunk {
    #[prost(bytes = "bytes", tag = "1")]
    data: Bytes,
}

#[derive(Clone, PartialEq, Message)]
struct MultiHunk {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    data: Vec<Bytes>,
}

fn encode_message(mode: Mode, parts: &[&[u8]]) -> io::Result<Bytes> {
    let payload = match mode {
        Mode::Tun => Hunk {
            data: parts.concat().into(),
        }
        .encode_to_vec(),
        Mode::TunMulti => MultiHunk {
            data: parts
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| Bytes::copy_from_slice(p))
                .collect(),
        }
        .encode_to_vec(),
    };
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("gRPC message exceeds 4 MiB receive limit"));
    }
    let mut frame = BytesMut::with_capacity(5 + payload.len());
    frame.extend_from_slice(&[0]); // uncompressed message
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame.freeze())
}

struct Decoder {
    mode: Mode,
    wire: BytesMut,
}
impl Decoder {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            wire: BytesMut::new(),
        }
    }
    fn next(&mut self) -> io::Result<Option<VecDeque<Bytes>>> {
        if self.wire.len() < 5 {
            return Ok(None);
        }
        if self.wire[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "compressed or invalid gRPC message flag",
            ));
        }
        let length = u32::from_be_bytes(self.wire[1..5].try_into().expect("four bytes")) as usize;
        if length > MAX_MESSAGE_BYTES {
            return Err(invalid("gRPC message exceeds 4 MiB receive limit"));
        }
        if self.wire.len() < length + 5 {
            return Ok(None);
        }
        self.wire.advance(5);
        let payload = self.wire.split_to(length).freeze();
        let pieces = match self.mode {
            Mode::Tun => VecDeque::from([Hunk::decode(payload).map_err(invalid)?.data]),
            Mode::TunMulti => MultiHunk::decode(payload).map_err(invalid)?.data.into(),
        };
        Ok(Some(pieces))
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn h2_error(error: h2::Error) -> io::Error {
    let kind = if error.is_io() {
        error
            .get_io()
            .map(io::Error::kind)
            .unwrap_or(io::ErrorKind::ConnectionAborted)
    } else if error.reason() == Some(h2::Reason::CANCEL) {
        io::ErrorKind::Interrupted
    } else {
        io::ErrorKind::ConnectionAborted
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config() -> Config {
        Config {
            service_name: "xray-test".into(),
            user_agent: "golang".into(),
            ..Config::default()
        }
    }

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(8), future)
            .await
            .expect("gRPC test timed out")
    }

    async fn pair() -> (Client, Server) {
        let (a, b) = tokio::io::duplex(4096);
        let (client, server) = tokio::join!(
            Client::handshake(Box::new(a), config(), "example.test"),
            Server::handshake(Box::new(b), config()),
        );
        (client.unwrap(), server.unwrap())
    }

    struct RawPeer {
        _client: Client,
        tunnel: Tunnel,
        request: Request<RecvStream>,
        response: h2::server::SendResponse<Bytes>,
        _driver: Driver,
    }

    async fn raw_peer(window: u32) -> RawPeer {
        let (a, b) = tokio::io::duplex(4096);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let driver = Driver(tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(window);
            let mut connection = builder
                .handshake::<_, Bytes>(Box::new(b) as BoxStream)
                .await
                .unwrap();
            let request = connection.accept().await.unwrap().unwrap();
            assert!(tx.send(request).is_ok());
            while connection.accept().await.is_some() {}
        }));
        let client = Client::handshake(Box::new(a), config(), "example.test")
            .await
            .unwrap();
        let tunnel = client.open().await.unwrap();
        let (request, response) = rx.await.unwrap();
        RawPeer {
            _client: client,
            tunnel,
            request,
            response,
            _driver: driver,
        }
    }

    fn response_headers() -> Response<()> {
        Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap()
    }

    #[test]
    fn go_service_path_fixtures() {
        let cases = [
            ("hello", "hello", "Tun", "TunMulti"),
            ("hello/world!", "hello%2Fworld%21", "Tun", "TunMulti"),
            ("/my/sample/path/a|b", "my/sample/path", "a", "b"),
            ("/hello /world!/a|b", "hello%20/world%21", "a", "b"),
            ("/foo", "", "foo", "foo"),
            (
                "/m y/sa !mple/pa\\th/tun\\_serv!ice",
                "m%20y/sa%20%21mple/pa%5Cth",
                "tun%5C_serv%21ice",
                "tun%5C_serv%21ice",
            ),
            (
                "/m y/sa !mple/pa\\th/mu%lti\\_serv!ice",
                "m%20y/sa%20%21mple/pa%5Cth",
                "mu%25lti%5C_serv%21ice",
                "mu%25lti%5C_serv%21ice",
            ),
            ("", "", "Tun", "TunMulti"),
            ("/", "", "", ""),
            ("/nested//a|b|ignored", "nested/", "a", "b"),
        ];
        for (name, service, tun, multi) in cases {
            let paths = Paths::new(name);
            assert_eq!(paths.service, service, "{name}");
            assert_eq!(paths.tun, tun, "{name}");
            assert_eq!(paths.tun_multi, multi, "{name}");
        }
        assert_eq!(Paths::new("").path(Mode::Tun), "//Tun");
        assert_eq!(
            path_escape("$&+:=@/;,? !%é"),
            "$&+:=@%2F%3B%2C%3F%20%21%25%C3%A9"
        );
    }

    #[test]
    fn go_authority_precedence_and_ipv6_fallback() {
        let mut c = config();
        let domain = Destination::new("host.test", 8443).unwrap();
        assert_eq!(c.authority_for(&domain, None, false), "host.test");
        assert_eq!(c.authority_for(&domain, None, true), "host.test:8443");
        assert_eq!(
            c.authority_for(&domain, Some("tls.test"), false),
            "tls.test"
        );
        c.authority = "configured.test:443".into();
        assert_eq!(
            c.authority_for(&domain, Some("tls.test"), false),
            "configured.test:443"
        );
        c.authority.clear();
        let ip = Destination::new("::1", 443).unwrap();
        assert_eq!(c.authority_for(&ip, None, false), "[::1]:443");
    }

    #[test]
    fn json_names_and_unsupported_keepalive_are_explicit() {
        let c: Config = serde_json::from_str(r#"{"serviceName":"service","multiMode":true,"initial_windows_size":-1,"idle_timeout":-3,"user_agent":"golang"}"#).unwrap();
        assert_eq!(c.service_name, "service");
        assert!(c.multi_mode);
        c.validate().unwrap();
        for field in [
            "idle_timeout",
            "health_check_timeout",
            "permit_without_stream",
        ] {
            let value = if field == "permit_without_stream" {
                "true"
            } else {
                "1"
            };
            let c: Config = serde_json::from_str(&format!("{{\"{field}\":{value}}}")).unwrap();
            assert_eq!(c.validate().unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        assert!(serde_json::from_str::<Config>(r#"{"unknown_socket_option":true}"#).is_err());
    }

    #[test]
    fn go_user_agent_aliases_and_literal_values() {
        for (alias, substring) in [
            ("", "Chrome/"),
            ("chrome", "Chrome/"),
            ("firefox", "Firefox/"),
            ("edge", "Edg/"),
        ] {
            let c = Config {
                user_agent: alias.into(),
                ..config()
            };
            assert!(
                user_agent(&c)
                    .unwrap()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains(substring)
            );
        }
        assert!(user_agent(&config()).unwrap().is_none());
        for literal in ["literal/1", "curl", "safari"] {
            let c = Config {
                user_agent: literal.into(),
                ..config()
            };
            assert_eq!(user_agent(&c).unwrap().unwrap(), literal);
        }
        let c = Config {
            user_agent: "bad\r\nheader".into(),
            ..config()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn source_protobuf_and_grpc_golden_frames() {
        assert_eq!(
            encode_message(Mode::Tun, &[b"hi"]).unwrap().as_ref(),
            &[0, 0, 0, 0, 4, 0x0a, 2, b'h', b'i']
        );
        assert_eq!(
            encode_message(Mode::TunMulti, &[b"A", b"", b"BC"])
                .unwrap()
                .as_ref(),
            &[0, 0, 0, 0, 7, 0x0a, 1, b'A', 0x0a, 2, b'B', b'C']
        );
        assert_eq!(
            encode_message(Mode::Tun, &[]).unwrap().as_ref(),
            &[0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_message(Mode::TunMulti, &[]).unwrap().as_ref(),
            &[0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn singular_hunk_uses_last_field_multi_hunk_keeps_all() {
        let frame = Bytes::from_static(&[0, 0, 0, 0, 8, 0x0a, 1, b'A', 0x10, 7, 0x0a, 1, b'B']);
        for (mode, expected) in [
            (Mode::Tun, b"B".as_slice()),
            (Mode::TunMulti, b"AB".as_slice()),
        ] {
            let mut decoder = Decoder::new(mode);
            decoder.wire.extend_from_slice(&frame);
            let actual: Vec<u8> = decoder
                .next()
                .unwrap()
                .unwrap()
                .into_iter()
                .flatten()
                .collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn grpc_frame_survives_every_http2_split_and_coalescing() {
        for mode in [Mode::Tun, Mode::TunMulti] {
            let frame = encode_message(mode, &[b"hello", b"world"]).unwrap();
            for split in 0..frame.len() {
                let mut decoder = Decoder::new(mode);
                decoder.wire.extend_from_slice(&frame[..split]);
                assert!(decoder.next().unwrap().is_none());
                decoder.wire.extend_from_slice(&frame[split..]);
                decoder.wire.extend_from_slice(&frame);
                for _ in 0..2 {
                    let actual: Vec<u8> = decoder
                        .next()
                        .unwrap()
                        .unwrap()
                        .into_iter()
                        .flatten()
                        .collect();
                    assert_eq!(actual, b"helloworld");
                }
                assert!(decoder.next().unwrap().is_none());
            }
        }
    }

    #[test]
    fn malformed_compressed_and_oversize_messages_are_rejected_early() {
        for frame in [
            vec![1, 0, 0, 0, 0],
            vec![2, 0, 0, 0, 0],
            vec![0, 0, 0x40, 0, 1],
            vec![0, 0, 0, 0, 1, 0x0a],
        ] {
            let mut decoder = Decoder::new(Mode::Tun);
            decoder.wire.extend_from_slice(&frame);
            assert!(decoder.next().is_err());
        }
    }

    #[test]
    fn status_roundtrip_preserves_utf8_and_rejects_invalid_codes() {
        let status = Status::new(7, "forbidden / café %").unwrap();
        assert_eq!(
            read_status(&status.trailers().unwrap()).unwrap(),
            Some(status)
        );
        let mut headers = HeaderMap::new();
        for value in ["", "-1", "+1", "17", "foo", "65536"] {
            headers.insert("grpc-status", HeaderValue::from_str(value).unwrap());
            assert!(read_status(&headers).is_err(), "{value}");
        }
        headers.insert("grpc-status", HeaderValue::from_static("0"));
        headers.append("grpc-status", HeaderValue::from_static("0"));
        assert!(read_status(&headers).is_err());
    }

    #[tokio::test]
    async fn both_modes_roundtrip_vectored_bytes_and_half_close() {
        bounded(async {
            let (client, mut server) = pair().await;
            for mode in [Mode::Tun, Mode::TunMulti] {
                let mut outbound = client.open_mode(mode).await.unwrap();
                let accepted = server.accept().await.unwrap().unwrap();
                assert_eq!(accepted.mode, mode);
                assert_eq!(accepted.authority, "example.test");
                assert_eq!(accepted.metadata["te"], "trailers");
                assert!(!accepted.metadata.contains_key("user-agent"));
                let mut inbound = accepted.stream;
                assert_eq!(
                    outbound
                        .write_vectored(&[io::IoSlice::new(b"hello"), io::IoSlice::new(b" world")])
                        .await
                        .unwrap(),
                    11
                );
                outbound.shutdown().await.unwrap();
                let mut request = Vec::new();
                inbound.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"hello world");
                inbound.write_all(b"reply").await.unwrap();
                inbound.shutdown().await.unwrap();
                let mut response = Vec::new();
                outbound.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"reply");
                assert_eq!(
                    outbound.write(b"closed").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
            }
        })
        .await;
    }

    #[tokio::test]
    async fn large_bidirectional_streams_cross_flow_control_windows() {
        bounded(async {
            let (client, mut server) = pair().await;
            let mut outbound = client.open().await.unwrap();
            let mut inbound = server.accept().await.unwrap().unwrap().stream;
            let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
            let ((), ()) = tokio::join!(
                async {
                    outbound.write_all(&payload).await.unwrap();
                    outbound.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    outbound.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(reply, payload);
                },
                async {
                    let mut request = Vec::new();
                    inbound.read_to_end(&mut request).await.unwrap();
                    assert_eq!(request, payload);
                    inbound.write_all(&request).await.unwrap();
                    inbound.shutdown().await.unwrap();
                }
            );
        })
        .await;
    }

    #[tokio::test]
    async fn cancel_one_pooled_stream_keeps_sibling_stream_alive() {
        bounded(async {
            let (client, mut server) = pair().await;
            let doomed = client.open().await.unwrap();
            let mut first = server.accept().await.unwrap().unwrap().stream;
            let mut survivor = client.clone().open().await.unwrap();
            let mut second = server.accept().await.unwrap().unwrap().stream;
            drop(doomed);
            let error = first.read(&mut [0u8; 1]).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            survivor.write_all(b"still alive").await.unwrap();
            survivor.shutdown().await.unwrap();
            let mut data = Vec::new();
            second.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"still alive");
            second.shutdown().await.unwrap();
            assert_eq!(survivor.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await;
    }

    #[tokio::test]
    async fn open_does_not_wait_for_peer_response_headers() {
        bounded(async {
            let mut peer = raw_peer(65_535).await;
            assert_eq!(peer.request.uri().scheme_str(), Some("http"));
            let mut receive = peer.request.into_body();
            peer.tunnel.write_all(b"first").await.unwrap();
            // A peer is permitted to wait for DATA before producing HEADERS.
            let data = receive.data().await.unwrap().unwrap();
            assert_eq!(data, encode_message(Mode::Tun, &[b"first"]).unwrap());
            receive.flow_control().release_capacity(data.len()).unwrap();
            let mut response = peer
                .response
                .send_response(response_headers(), false)
                .unwrap();
            response
                .send_data(encode_message(Mode::Tun, &[b"reply"]).unwrap(), false)
                .unwrap();
            response
                .send_trailers(Status::ok().trailers().unwrap())
                .unwrap();
            peer.tunnel.shutdown().await.unwrap();
            let mut reply = Vec::new();
            peer.tunnel.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply");
        })
        .await;
    }

    #[tokio::test]
    async fn canceled_read_preserves_partial_grpc_header() {
        bounded(async {
            let mut peer = raw_peer(65_535).await;
            let mut response = peer
                .response
                .send_response(response_headers(), false)
                .unwrap();
            let frame = encode_message(Mode::Tun, &[b"resumed"]).unwrap();
            response.send_data(frame.slice(..3), false).unwrap();
            let mut byte = [0u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), peer.tunnel.read(&mut byte))
                    .await
                    .is_err()
            );
            response.send_data(frame.slice(3..), false).unwrap();
            response
                .send_trailers(Status::ok().trailers().unwrap())
                .unwrap();
            peer.tunnel.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            peer.tunnel.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"resumed");
        })
        .await;
    }

    #[tokio::test]
    async fn canceled_pending_write_does_not_accept_or_duplicate_new_bytes() {
        bounded(async {
            let mut peer = raw_peer(64).await;
            let mut response = peer
                .response
                .send_response(response_headers(), false)
                .unwrap();
            // Read response headers first, ensuring peer SETTINGS were processed.
            assert!(
                tokio::time::timeout(Duration::from_millis(20), peer.tunnel.read(&mut [0u8; 1]))
                    .await
                    .is_err()
            );
            let data = vec![0x55; WRITE_CHUNK_BYTES];
            assert_eq!(peer.tunnel.write(&data).await.unwrap(), data.len());
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    peer.tunnel.write(b"not accepted")
                )
                .await
                .is_err()
            );
            let mut receive = peer.request.into_body();
            let ((), wire) = tokio::join!(
                async {
                    peer.tunnel.flush().await.unwrap();
                    peer.tunnel.shutdown().await.unwrap();
                },
                async {
                    let mut wire = Vec::new();
                    while let Some(chunk) = receive.data().await {
                        let chunk = chunk.unwrap();
                        wire.extend_from_slice(&chunk);
                        receive
                            .flow_control()
                            .release_capacity(chunk.len())
                            .unwrap();
                    }
                    wire
                }
            );
            assert_eq!(wire, encode_message(Mode::Tun, &[&data]).unwrap());
            response
                .send_trailers(Status::ok().trailers().unwrap())
                .unwrap();
            assert_eq!(peer.tunnel.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await;
    }

    #[tokio::test]
    async fn nonzero_status_is_reported_after_payload_and_is_sticky() {
        bounded(async {
            let (client, mut server) = pair().await;
            let mut outbound = client.open().await.unwrap();
            let mut inbound = server.accept().await.unwrap().unwrap().stream;
            outbound.shutdown().await.unwrap();
            inbound.write_all(b"partial").await.unwrap();
            inbound
                .finish(Status::new(7, "not permitted").unwrap())
                .await
                .unwrap();
            let mut data = Vec::new();
            let error = outbound.read_to_end(&mut data).await.unwrap_err();
            assert_eq!(data, b"partial");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("not permitted"));
            assert_eq!(
                outbound.read(&mut [0u8; 1]).await.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        })
        .await;
    }

    #[tokio::test]
    async fn missing_status_and_truncated_frames_never_become_clean_eof() {
        bounded(async {
            for partial in [false, true] {
                let mut peer = raw_peer(65_535).await;
                let mut response = peer
                    .response
                    .send_response(response_headers(), false)
                    .unwrap();
                if partial {
                    response
                        .send_data(Bytes::from_static(&[0, 0, 0, 0, 2, 0x0a]), false)
                        .unwrap();
                    response
                        .send_trailers(Status::ok().trailers().unwrap())
                        .unwrap();
                } else {
                    response.send_data(Bytes::new(), true).unwrap();
                }
                let error = peer.tunnel.read_to_end(&mut Vec::new()).await.unwrap_err();
                assert_eq!(
                    error.kind(),
                    if partial {
                        io::ErrorKind::UnexpectedEof
                    } else {
                        io::ErrorKind::InvalidData
                    }
                );
            }
        })
        .await;
    }

    #[tokio::test]
    async fn trailers_only_status_is_supported() {
        bounded(async {
            for code in [0, 12] {
                let mut peer = raw_peer(65_535).await;
                let mut headers = response_headers();
                headers.headers_mut().extend(
                    Status::new(code, "trailers only")
                        .unwrap()
                        .trailers()
                        .unwrap(),
                );
                peer.response.send_response(headers, true).unwrap();
                let result = peer.tunnel.read_to_end(&mut Vec::new()).await;
                if code == 0 {
                    assert_eq!(result.unwrap(), 0);
                } else {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn grpc_compression_and_http_errors_reach_the_caller() {
        bounded(async {
            for variant in 0..4 {
                let mut peer = raw_peer(65_535).await;
                let mut headers = response_headers();
                if variant == 0 {
                    *headers.status_mut() = StatusCode::BAD_GATEWAY;
                }
                if variant == 1 {
                    headers
                        .headers_mut()
                        .insert("content-type", HeaderValue::from_static("text/html"));
                }
                if variant == 2 {
                    headers
                        .headers_mut()
                        .insert("grpc-encoding", HeaderValue::from_static("gzip"));
                }
                let mut response = peer.response.send_response(headers, false).unwrap();
                if variant == 3 {
                    response
                        .send_data(Bytes::from_static(&[1, 0, 0, 0, 0]), false)
                        .unwrap();
                }
                response
                    .send_trailers(Status::ok().trailers().unwrap())
                    .unwrap();
                assert!(peer.tunnel.read_to_end(&mut Vec::new()).await.is_err());
            }
        })
        .await;
    }

    #[tokio::test]
    async fn peer_disconnect_is_an_error_not_eof() {
        bounded(async {
            let mut peer = raw_peer(65_535).await;
            peer._driver.0.abort();
            drop(peer.response);
            drop(peer.request);
            assert!(peer.tunnel.read(&mut [0u8; 1]).await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn dropping_client_handle_keeps_its_open_tunnel_alive() {
        bounded(async {
            let (client, mut server) = pair().await;
            let mut outbound = client.open().await.unwrap();
            let mut inbound = server.accept().await.unwrap().unwrap().stream;
            let weak = Arc::downgrade(&client.driver);
            drop(client);
            assert!(weak.upgrade().is_some());
            outbound.write_all(b"owned").await.unwrap();
            outbound.shutdown().await.unwrap();
            let mut received = Vec::new();
            inbound.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"owned");
            inbound.shutdown().await.unwrap();
            assert_eq!(outbound.read(&mut [0u8; 1]).await.unwrap(), 0);
            drop(outbound);
            assert!(weak.upgrade().is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn custom_server_accepts_both_escaped_methods() {
        bounded(async {
            let (a, b) = tokio::io::duplex(4096);
            let server_config = Config {
                service_name: "/my path/nested/tun!|multi!".into(),
                ..config()
            };
            let (client, server) = tokio::join!(
                Client::handshake(Box::new(a), server_config.clone(), "example.test"),
                Server::handshake(Box::new(b), server_config),
            );
            let client = client.unwrap();
            let mut server = server.unwrap();
            for mode in [Mode::Tun, Mode::TunMulti] {
                let mut outbound = client.open_mode(mode).await.unwrap();
                let mut accepted = server.accept().await.unwrap().unwrap();
                assert_eq!(accepted.mode, mode);
                outbound.shutdown().await.unwrap();
                accepted.stream.shutdown().await.unwrap();
                assert_eq!(outbound.read(&mut [0u8; 1]).await.unwrap(), 0);
            }
        })
        .await;
    }

    #[tokio::test]
    async fn unknown_service_gets_unimplemented_without_poisoning_connection() {
        bounded(async {
            let (client, mut server) = pair().await;
            let mut wrong = client.clone();
            wrong.config.service_name = "missing".into();
            let mut rejected = wrong.open().await.unwrap();
            assert_eq!(
                rejected.read(&mut [0u8; 1]).await.unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            let mut valid = client.open().await.unwrap();
            let mut accepted = server.accept().await.unwrap().unwrap();
            valid.shutdown().await.unwrap();
            accepted.stream.shutdown().await.unwrap();
            assert_eq!(valid.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await;
    }
}
