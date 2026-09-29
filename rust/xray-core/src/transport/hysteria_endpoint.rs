// P18 hysteria_endpoint: the QUIC endpoint glue, ported from Go
// transport/internet/hysteria/{hub,dialer,conn}.go. The server binds the UDP
// socket, accepts QUIC connections, performs the HTTP/3 authentication
// handshake (status 233) with the masquerade fallback, and yields the
// protocol's TCP streams (HTTP/3 extension frame 0x401) and UDP sessions;
// the client dialer wraps the tested Quinn helpers in transport/hysteria.rs.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail, ensure};
use bytes::{Buf, Bytes};
use http::{Method, Request, Response, StatusCode, header};
use rand::Rng;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
    time::interval_at,
};
use tokio_rustls::rustls;

use crate::{
    address::Destination,
    protocol::{
        hysteria::{MAX_UDP_PAYLOAD, UdpMessage},
        hysteria_runtime::HysteriaUser,
    },
    transport::hysteria::{
        self, AUTH_HOST, AUTH_PATH, AuthResponse, AuthenticatedConnection, CLOSE_OK, ClientOptions,
        CongestionMode, HEADER_AUTH, MAX_DATAGRAM_FRAME_SIZE, NativeCongestion,
        negotiate_congestion,
    },
};

/// Go's idle UDP session sweeper cadence (transport/internet/hysteria/config.go).
const UDP_CLEAN_INTERVAL: Duration = Duration::from_secs(1);
/// Go's per-session datagram queue depth (udpMessageChanSize).
const UDP_SESSION_QUEUE: usize = 1024;
/// The HTTP/3 extension frame type that opens a proxy TCP stream (0x401).
const TCP_REQUEST_FRAME: [u8; 2] = [0x44, 0x01];

// ---------------------------------------------------------------------------
// Masquerade and hysteriaSettings (Go infra/conf/transport_method.go)
// ---------------------------------------------------------------------------

/// Go's `Masquerade` JSON object inside `hysteriaSettings`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct MasqueradeSettings {
    #[serde(rename = "type")]
    pub kind: String,
    pub dir: String,
    pub url: String,
    pub rewrite_host: bool,
    pub x_forwarded: bool,
    pub insecure: bool,
    pub content: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub status_code: i32,
}

impl MasqueradeSettings {
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid hysteria masquerade settings")
    }

    /// The compiled masquerade handler. `"file"` and `"proxy"` fail explicitly:
    /// their Go file-server and reverse-proxy handlers are not ported, and a
    /// silent downgrade to 404 would change the observable server identity.
    pub fn compile(&self) -> Result<Masquerade> {
        match self.kind.to_ascii_lowercase().as_str() {
            "" | "404" => Ok(Masquerade::NotFound),
            "string" => Ok(Masquerade::String {
                content: self.content.clone(),
                headers: self.headers.clone(),
                status: if self.status_code == 0 {
                    StatusCode::OK
                } else {
                    StatusCode::from_u16(
                        u16::try_from(self.status_code)
                            .context("masquerade statusCode is not a valid HTTP status")?,
                    )?
                },
            }),
            "file" => bail!(
                "hysteria masquerade type \"file\" is not ported; serve static files with a real server"
            ),
            "proxy" => bail!(
                "hysteria masquerade type \"proxy\" is not ported; terminate masqueraded virtual hosts with a real server"
            ),
            other => bail!("unknown masquerade type {other:?}"),
        }
    }
}

/// The compiled masquerade, matching hub.go's handler selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Masquerade {
    /// Go's `http.NotFoundHandler()` (also the default for `""`).
    NotFound,
    /// Go's `masqType: "string"`: fixed headers, status and body.
    String {
        content: String,
        headers: std::collections::BTreeMap<String, String>,
        status: StatusCode,
    },
}

impl Masquerade {
    /// The masquerade response: the status/headers and the optional body Go
    /// writes for unauthenticated or non-auth requests.
    fn response(&self) -> (Response<()>, Option<Bytes>) {
        match self {
            Self::NotFound => (
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .expect("fixed 404 response"),
                None,
            ),
            Self::String {
                content,
                headers,
                status,
            } => {
                let mut builder = Response::builder().status(*status);
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                (
                    builder.body(()).expect("fixed masquerade response"),
                    Some(Bytes::copy_from_slice(content.as_bytes())),
                )
            }
        }
    }
}

/// Go's `hysteriaSettings` streamSettings object (infra/conf's
/// `HysteriaConfig`): `version` (must be 2), `auth`, `udpIdleTimeout`
/// (seconds; 0 selects 60, else 2..=600) and `masquerade`.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct HysteriaTransportSettings {
    pub version: i32,
    pub auth: String,
    pub udp_idle_timeout: i64,
    pub masquerade: MasqueradeSettings,
}

impl HysteriaTransportSettings {
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid hysteria transport settings")
    }

    /// Go `HysteriaConfig.Build`: version 2, the UDP idle timeout bounds and
    /// the masquerade handler are all validated before any socket opens.
    pub fn validate(&self) -> Result<&Self> {
        ensure!(self.version == 2, "hysteria transport version != 2");
        ensure!(
            self.udp_idle_timeout == 0 || (2..=600).contains(&self.udp_idle_timeout),
            "UdpIdleTimeout must be between 2 and 600"
        );
        self.masquerade.compile()?;
        Ok(self)
    }

    /// The effective UDP session idle timeout (Go: 0 becomes 60 seconds).
    pub fn udp_idle_timeout(&self) -> Duration {
        if self.udp_idle_timeout == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(self.udp_idle_timeout as u64)
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint options
// ---------------------------------------------------------------------------

/// The congestion mapping the integrator applies to Go's `quicParams`.
/// `reno` selects Quinn's NewReno; every Hysteria-native mode (BBR profiles,
/// Brutal, and the Auto/Brutal default) fails explicitly through the codec's
/// own negotiation instead of silently downgrading, exactly like
/// `NegotiatedCongestion::supported_native_controller`.
pub fn native_congestion(
    mode: CongestionMode,
    profile: hysteria::BbrProfile,
    local_tx: u64,
    peer_rx: u64,
    disable_loss_compensation: bool,
) -> Result<NativeCongestion> {
    negotiate_congestion(mode, profile, local_tx, peer_rx, disable_loss_compensation)
        .supported_native_controller()
}

/// The inbound QUIC listener's compiled options: the proxy-level users
/// (validator), the transport-level `auth` fallback, the masquerade handler,
/// the advertised receive bandwidth (`quicParams.brutalDown`), and the QUIC
/// tuning (`finalmask.quicParams`, or Go's nil defaults).
#[derive(Clone, Debug)]
pub struct HysteriaServerOptions {
    /// The proxy settings users; non-empty enables the UDP session manager
    /// (`ResponseHeaderUDPEnabled` is `validator != nil` in Go).
    pub users: Vec<HysteriaUser>,
    /// `hysteriaSettings.auth`: the single-secret fallback when no users are
    /// configured. An empty secret never authenticates.
    pub auth: String,
    pub masquerade: Masquerade,
    /// The UDP session idle timeout (Go default 60 seconds).
    pub udp_idle_timeout: Duration,
    /// The `Hysteria-CC-RX` value sent in the 233 auth response.
    pub receive_bytes_per_second: u64,
    /// The QUIC congestion controller; select through [`native_congestion`].
    pub congestion: NativeCongestion,
    /// The compiled `finalmask.quicParams` (Go's nil defaults when absent).
    pub quic: crate::transport::finalmask::QuicParams,
}

impl Default for HysteriaServerOptions {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            auth: String::new(),
            masquerade: Masquerade::NotFound,
            udp_idle_timeout: Duration::from_secs(60),
            receive_bytes_per_second: 0,
            congestion: NativeCongestion::QuinnNewReno,
            quic: crate::transport::finalmask::QuicParams::default(),
        }
    }
}

impl HysteriaServerOptions {
    /// Go hub.Listen's startup check: a validator (users) or a transport
    /// `auth` secret must exist, and the masquerade must compile.
    pub fn validate(&self) -> Result<&Self> {
        ensure!(
            !self.users.is_empty() || !self.auth.is_empty(),
            "hysteria inbound requires users or hysteriaSettings auth"
        );
        Ok(self)
    }

    fn udp_enabled(&self) -> bool {
        !self.users.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Routed HTTP/3 machinery
//
// The pinned protocol interleaves ordinary HTTP/3 request streams with raw
// bidirectional TCP-proxy streams whose first varint is frame 0x401 (Go's
// http3.Server StreamDispatcher hook). h3 owns every stream it can see, so the
// wrapper below intercepts `poll_accept_bidi`: streams headed by 0x401 are
// diverted to the endpoint's TCP queue, every other stream reaches h3 with
// its first two bytes replayed verbatim.
// ---------------------------------------------------------------------------

fn connection_error(error: quinn::ConnectionError) -> h3::quic::ConnectionErrorIncoming {
    use h3::quic::ConnectionErrorIncoming;
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: close.error_code.into_inner(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        error => ConnectionErrorIncoming::Undefined(Arc::new(error)),
    }
}

fn read_error(error: quinn::ReadError) -> h3::quic::StreamErrorIncoming {
    match error {
        quinn::ReadError::Reset(code) => h3::quic::StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(error) => {
            h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: connection_error(error),
            }
        }
        error => h3::quic::StreamErrorIncoming::Unknown(Box::new(error)),
    }
}

fn write_error(error: quinn::WriteError) -> h3::quic::StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => h3::quic::StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(error) => {
            h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: connection_error(error),
            }
        }
        error => h3::quic::StreamErrorIncoming::Unknown(Box::new(error)),
    }
}

fn stream_id(id: quinn::StreamId) -> h3::quic::StreamId {
    let value: u64 = id.into();
    value.try_into().expect("invalid stream id")
}

/// The receive half handed to h3, replaying the two routing bytes first.
struct RoutedRecv {
    prefix: Bytes,
    stream: quinn::RecvStream,
    buffer: Vec<u8>,
}

impl RoutedRecv {
    fn new(stream: quinn::RecvStream, prefix: Bytes) -> Self {
        Self {
            prefix,
            stream,
            buffer: vec![0; 4096],
        }
    }
}

impl h3::quic::RecvStream for RoutedRecv {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<Bytes>, h3::quic::StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            let chunk = self.prefix.clone();
            self.prefix.clear();
            return Poll::Ready(Ok(Some(chunk)));
        }
        let result = match self.stream.poll_read(cx, &mut self.buffer) {
            Poll::Ready(Ok(0)) => return Poll::Ready(Ok(None)),
            Poll::Ready(Ok(size)) => Ok(Some(Bytes::copy_from_slice(&self.buffer[..size]))),
            Poll::Ready(Err(error)) => Err(read_error(error)),
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(result)
    }

    fn stop_sending(&mut self, error_code: u64) {
        let _ = self
            .stream
            .stop(quinn::VarInt::from_u64(error_code).unwrap_or(quinn::VarInt::MAX));
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        stream_id(self.stream.id())
    }
}

/// The send half handed to h3; mirrors h3-quinn's buffered `WriteBuf` driver.
struct RoutedSend {
    stream: quinn::SendStream,
    writing: Option<h3::quic::WriteBuf<Bytes>>,
}

impl RoutedSend {
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

impl h3::quic::SendStream<Bytes> for RoutedSend {
    fn poll_ready(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        if let Some(data) = &mut self.writing {
            while data.has_remaining() {
                let written = match Pin::new(&mut self.stream).poll_write(cx, data.chunk()) {
                    Poll::Ready(Ok(size)) => size,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(write_error(error))),
                    Poll::Pending => return Poll::Pending,
                };
                data.advance(written);
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), h3::quic::StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: h3::quic::ConnectionErrorIncoming::InternalError(
                    "send_data called while the send stream is not ready".to_owned(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(
        &mut self,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|error| h3::quic::StreamErrorIncoming::Unknown(Box::new(error))),
        )
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(quinn::VarInt::from_u64(reset_code).unwrap_or(quinn::VarInt::MAX));
    }

    fn send_id(&self) -> h3::quic::StreamId {
        stream_id(self.stream.id())
    }
}

impl h3::quic::SendStreamUnframed<Bytes> for RoutedSend {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, h3::quic::StreamErrorIncoming>> {
        if self.writing.is_some() {
            return Poll::Ready(Err(
                h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: h3::quic::ConnectionErrorIncoming::InternalError(
                        "poll_send called while the send stream is not ready".to_owned(),
                    ),
                },
            ));
        }
        match Pin::new(&mut self.stream).poll_write(cx, buf.chunk()) {
            Poll::Ready(Ok(written)) => {
                buf.advance(written);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(write_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A bidirectional stream handed to h3 with the routing prefix replayed on
/// reads; writes pass straight to Quinn.
struct RoutedBidi {
    send: RoutedSend,
    recv: RoutedRecv,
}

impl RoutedBidi {
    fn new(streams: (quinn::SendStream, quinn::RecvStream), prefix: Bytes) -> Self {
        Self {
            send: RoutedSend::new(streams.0),
            recv: RoutedRecv::new(streams.1, prefix),
        }
    }
}

impl h3::quic::RecvStream for RoutedBidi {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<Bytes>, h3::quic::StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        self.recv.recv_id()
    }
}

impl h3::quic::SendStream<Bytes> for RoutedBidi {
    fn poll_ready(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), h3::quic::StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> h3::quic::StreamId {
        self.send.send_id()
    }
}

impl h3::quic::SendStreamUnframed<Bytes> for RoutedBidi {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut TaskContext<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, h3::quic::StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

impl h3::quic::BidiStream<Bytes> for RoutedBidi {
    type SendStream = RoutedSend;
    type RecvStream = RoutedRecv;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

type AcceptUni =
    Pin<Box<dyn Future<Output = Result<quinn::RecvStream, quinn::ConnectionError>> + Send>>;
type OpenBi = Pin<
    Box<
        dyn Future<Output = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>
            + Send,
    >,
>;
type OpenUni =
    Pin<Box<dyn Future<Output = Result<quinn::SendStream, quinn::ConnectionError>> + Send>>;

/// The stream opener h3 uses for its control streams. Cloning drops any
/// pending open future (h3 only clones for handle retention, exactly like
/// h3-quinn's manual Clone).
struct RoutedOpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<OpenBi>,
    opening_uni: Option<OpenUni>,
}

impl Clone for RoutedOpenStreams {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl RoutedOpenStreams {
    fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            opening_bi: None,
            opening_uni: None,
        }
    }
}
impl h3::quic::OpenStreams<Bytes> for RoutedOpenStreams {
    type BidiStream = RoutedBidi;
    type SendStream = RoutedSend;

    fn poll_open_bidi(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        if self.opening_bi.is_none() {
            let conn = self.conn.clone();
            self.opening_bi = Some(Box::pin(async move { conn.open_bi().await }));
        }
        let future = self.opening_bi.as_mut().expect("just created");
        let streams = match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.opening_bi = None;
                result.map_err(
                    |error| h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error: connection_error(error),
                    },
                )?
            }
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(Ok(RoutedBidi::new(streams, Bytes::new())))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        if self.opening_uni.is_none() {
            let conn = self.conn.clone();
            self.opening_uni = Some(Box::pin(async move { conn.open_uni().await }));
        }
        let future = self.opening_uni.as_mut().expect("just created");
        let stream = match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.opening_uni = None;
                result.map_err(
                    |error| h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error: connection_error(error),
                    },
                )?
            }
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(Ok(RoutedSend::new(stream)))
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.conn.close(
            quinn::VarInt::from_u64(code.value()).expect("error code varint"),
            reason,
        );
    }
}

/// The connection h3 drives: bidirectional streams arrive through the routing
/// pump (which diverts 0x401 TCP streams), unidirectional control streams
/// come straight from Quinn.
struct RoutedConnection {
    conn: quinn::Connection,
    accepting_uni: Option<AcceptUni>,
    opening_bi: Option<OpenBi>,
    opening_uni: Option<OpenUni>,
    h3_streams: mpsc::Receiver<RoutedBidi>,
}

impl RoutedConnection {
    fn new(conn: quinn::Connection, h3_streams: mpsc::Receiver<RoutedBidi>) -> Self {
        Self {
            conn,
            accepting_uni: None,
            opening_bi: None,
            opening_uni: None,
            h3_streams,
        }
    }
}

impl h3::quic::OpenStreams<Bytes> for RoutedConnection {
    type BidiStream = RoutedBidi;
    type SendStream = RoutedSend;

    fn poll_open_bidi(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        if self.opening_bi.is_none() {
            let conn = self.conn.clone();
            self.opening_bi = Some(Box::pin(async move { conn.open_bi().await }));
        }
        let future = self.opening_bi.as_mut().expect("just created");
        let streams = match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.opening_bi = None;
                result.map_err(
                    |error| h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error: connection_error(error),
                    },
                )?
            }
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(Ok(RoutedBidi::new(streams, Bytes::new())))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        if self.opening_uni.is_none() {
            let conn = self.conn.clone();
            self.opening_uni = Some(Box::pin(async move { conn.open_uni().await }));
        }
        let future = self.opening_uni.as_mut().expect("just created");
        let stream = match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.opening_uni = None;
                result.map_err(
                    |error| h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error: connection_error(error),
                    },
                )?
            }
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(Ok(RoutedSend::new(stream)))
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.conn.close(
            quinn::VarInt::from_u64(code.value()).expect("error code varint"),
            reason,
        );
    }
}

impl h3::quic::Connection<Bytes> for RoutedConnection {
    type RecvStream = RoutedRecv;
    type OpenStreams = RoutedOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::RecvStream, h3::quic::ConnectionErrorIncoming>> {
        if self.accepting_uni.is_none() {
            let conn = self.conn.clone();
            self.accepting_uni = Some(Box::pin(async move { conn.accept_uni().await }));
        }
        let future = self.accepting_uni.as_mut().expect("just created");
        let stream = match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.accepting_uni = None;
                result.map_err(connection_error)?
            }
            Poll::Pending => return Poll::Pending,
        };
        Poll::Ready(Ok(RoutedRecv::new(stream, Bytes::new())))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::ConnectionErrorIncoming>> {
        match self.h3_streams.poll_recv(cx) {
            Poll::Ready(Some(stream)) => Poll::Ready(Ok(stream)),
            Poll::Ready(None) => Poll::Ready(Err(h3::quic::ConnectionErrorIncoming::Timeout)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        RoutedOpenStreams::new(self.conn.clone())
    }
}

/// Diverts one accepted bidirectional stream: 0x401-headed streams go to the
/// endpoint's TCP queue (only after authentication), every other stream is
/// replayed to h3 with its first two bytes intact.
async fn route_one(
    streams: (quinn::SendStream, quinn::RecvStream),
    authenticated: Arc<AtomicBool>,
    tcp: mpsc::Sender<(quinn::SendStream, quinn::RecvStream)>,
    http: mpsc::Sender<RoutedBidi>,
) {
    let (mut send, mut recv) = streams;
    let mut head = [0u8; 2];
    if recv.read_exact(&mut head).await.is_err() {
        let _ = recv.stop(quinn::VarInt::from_u32(0));
        let _ = send.reset(quinn::VarInt::from_u32(0));
        return;
    }
    if head == TCP_REQUEST_FRAME {
        if !authenticated.load(Ordering::Relaxed) {
            // Go's StreamDispatcher ignores 0x401 before authentication and
            // lets the HTTP/3 layer fail the stream; reset it here.
            let _ = recv.stop(quinn::VarInt::from_u32(0));
            let _ = send.reset(quinn::VarInt::from_u32(0));
            return;
        }
        // Dropping on a full or closed queue resets the stream (Go's addConn
        // is unbounded goroutine spawning; the bounded queue throttles it).
        let _ = tcp.send((send, recv)).await;
        return;
    }
    let routed = RoutedBidi::new((send, recv), Bytes::copy_from_slice(&head));
    // When h3 is gone the whole connection is closing; dropping the stream
    // is the same outcome Go's exited ServeQUICConn produces.
    let _ = http.send(routed).await;
}

async fn route_bidi(
    conn: quinn::Connection,
    authenticated: Arc<AtomicBool>,
    tcp: mpsc::Sender<(quinn::SendStream, quinn::RecvStream)>,
    http: mpsc::Sender<RoutedBidi>,
) {
    loop {
        match conn.accept_bi().await {
            Ok(streams) => {
                let task_authenticated = authenticated.clone();
                let task_tcp = tcp.clone();
                let task_http = http.clone();
                tokio::spawn(async move {
                    route_one(streams, task_authenticated, task_tcp, task_http).await
                });
            }
            Err(_) => return,
        }
    }
}

// ---------------------------------------------------------------------------
// UDP sessions (Go conn.go's udpSessionManager and InterConn)
// ---------------------------------------------------------------------------

struct SessionEntry {
    sender: mpsc::Sender<Bytes>,
    last_active: Instant,
}

struct SessionRegistry {
    sessions: StdMutex<HashMap<u32, SessionEntry>>,
    udp_idle_timeout: Duration,
}

impl SessionRegistry {
    fn expire(&self) {
        let now = Instant::now();
        self.sessions
            .lock()
            .expect("UDP session registry")
            .retain(|_, entry| {
                now.saturating_duration_since(entry.last_active) < self.udp_idle_timeout
            });
    }

    fn close_all(&self) {
        self.sessions.lock().expect("UDP session registry").clear();
    }
}

/// One client UDP session on an authenticated QUIC connection — Go's
/// `InterConn`: raw wire datagrams flow in through a bounded queue, and
/// replies are written back with this session's id (Go's `InterConn.Write`
/// overwrites the first four bytes with the session id).
pub struct UdpSession {
    id: u32,
    conn: quinn::Connection,
    registry: Arc<SessionRegistry>,
    incoming: mpsc::Receiver<Bytes>,
}

impl UdpSession {
    pub fn id(&self) -> u32 {
        self.id
    }

    /// One raw wire datagram frame (session id included), or `None` when the
    /// session expired or the connection ended.
    pub async fn recv_raw(&mut self) -> Option<Bytes> {
        self.incoming.recv().await
    }

    /// The datagram size the peer negotiated, capped to Go's
    /// `MaxDatagramFrameSize`.
    pub fn max_datagram_size(&self) -> usize {
        self.conn
            .max_datagram_size()
            .unwrap_or(MAX_DATAGRAM_FRAME_SIZE)
            .min(MAX_DATAGRAM_FRAME_SIZE)
    }

    /// Send one complete message back to the client, fragmenting when the
    /// frame exceeds the negotiated datagram size (Go's `UDPWriter` retry
    /// with a random nonzero packet id). Returns the fragment count.
    pub fn send(&self, mut message: UdpMessage) -> io::Result<usize> {
        message.session_id = self.id;
        if message.payload.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::other("hysteria UDP payload is too large"));
        }
        let maximum = self.max_datagram_size();
        if message.header_size()? + message.payload.len() > maximum && message.packet_id == 0 {
            message.packet_id = rand::thread_rng().gen_range(1..=u16::MAX);
        }
        let fragments = message.fragment(maximum)?;
        for fragment in &fragments {
            self.conn
                .send_datagram(Bytes::from(fragment.encode()?))
                .map_err(io::Error::other)?;
        }
        if let Some(entry) = self
            .registry
            .sessions
            .lock()
            .expect("UDP session registry")
            .get_mut(&self.id)
        {
            entry.last_active = Instant::now();
        }
        Ok(fragments.len())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        // Go's InterConn close(): remove the session so the next datagram on
        // this id opens a fresh one.
        self.registry
            .sessions
            .lock()
            .expect("UDP session registry")
            .remove(&self.id);
    }
}

async fn receive_datagrams(
    conn: quinn::Connection,
    registry: Arc<SessionRegistry>,
    new_sessions: mpsc::Sender<UdpSession>,
    enabled: Arc<AtomicBool>,
) {
    loop {
        let datagram = match conn.read_datagram().await {
            Ok(datagram) => datagram,
            Err(_) => break,
        };
        // Go's udpSessionManager.run: frames shorter than a session id are
        // dropped, and no session manager exists before authentication.
        if datagram.len() < 4 || !enabled.load(Ordering::Relaxed) {
            continue;
        }
        let id = u32::from_be_bytes(datagram[..4].try_into().expect("four bytes"));
        // Decide under the lock and drop the guard before any await, so the
        // pump stays Send.
        let session = {
            let mut sessions = registry.sessions.lock().expect("UDP session registry");
            if let Some(entry) = sessions.get_mut(&id) {
                // Go feeds with a non-blocking channel send: a full queue drops.
                let _ = entry.sender.try_send(datagram);
                entry.last_active = Instant::now();
                None
            } else {
                let (sender, receiver) = mpsc::channel(UDP_SESSION_QUEUE);
                // Go's feed queues the creating datagram after addConn; the
                // channel buffers it until the runtime's session reads it.
                let _ = sender.try_send(datagram);
                sessions.insert(
                    id,
                    SessionEntry {
                        sender,
                        last_active: Instant::now(),
                    },
                );
                Some(UdpSession {
                    id,
                    conn: conn.clone(),
                    registry: registry.clone(),
                    incoming: receiver,
                })
            }
        };
        if let Some(session) = session
            && new_sessions.send(session).await.is_err()
        {
            break;
        }
    }
    // Go closes every session when the datagram loop ends.
    registry.close_all();
}

// ---------------------------------------------------------------------------
// Connection driver and listener
// ---------------------------------------------------------------------------

/// One accepted QUIC connection's protocol traffic.
pub enum HysteriaEvent {
    /// A 0x401 TCP proxy stream with the frame varint already consumed; the
    /// runtime reads the `TcpRequest`, answers with a `TcpResponse` and
    /// dispatches the stream.
    Tcp {
        user: Option<HysteriaUser>,
        stream: (quinn::SendStream, quinn::RecvStream),
    },
    /// A new client UDP session (its first datagram is already queued in
    /// [`UdpSession::recv_raw`]).
    Udp {
        user: Option<HysteriaUser>,
        session: UdpSession,
    },
}

/// A served QUIC connection. Dropping it closes the connection.
pub struct HysteriaConnection {
    source: SocketAddr,
    events: mpsc::Receiver<HysteriaEvent>,
    driver: JoinHandle<()>,
}

impl HysteriaConnection {
    pub fn remote_address(&self) -> SocketAddr {
        self.source
    }

    /// The next protocol event, or `None` when the connection ended.
    pub async fn next(&mut self) -> Option<HysteriaEvent> {
        self.events.recv().await
    }
}

impl Drop for HysteriaConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Per-connection authentication state (Go hub.go's httpHandler).
struct ConnectionAuth {
    options: Arc<HysteriaServerOptions>,
    authenticated: bool,
    user: Option<HysteriaUser>,
}

impl ConnectionAuth {
    fn new(options: Arc<HysteriaServerOptions>) -> Self {
        Self {
            options,
            authenticated: false,
            user: None,
        }
    }

    fn capabilities(&self) -> AuthResponse {
        AuthResponse {
            udp_enabled: self.options.udp_enabled(),
            receive_bytes_per_second: self.options.receive_bytes_per_second,
        }
    }

    /// Go's `AuthHTTP`: `Some(response)` authenticates (or re-confirms) the
    /// request; `None` falls through to the masquerade handler.
    fn handle(&mut self, request: &Request<()>) -> Option<Response<()>> {
        let host = request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                request
                    .headers()
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
            });
        if request.method() != Method::POST
            || host != Some(AUTH_HOST)
            || request.uri().path() != AUTH_PATH
        {
            return None;
        }
        if self.authenticated {
            return self.capabilities().to_http_response().ok();
        }
        let auth = request.headers().get(HEADER_AUTH)?.to_str().ok()?;
        let user = self
            .options
            .users
            .iter()
            .find(|user| {
                !user.auth.is_empty() && bool::from(auth.as_bytes().ct_eq(user.auth.as_bytes()))
            })
            .cloned();
        if let Some(user) = user {
            self.user = Some(user);
        } else if !self.options.auth.is_empty()
            && bool::from(auth.as_bytes().ct_eq(self.options.auth.as_bytes()))
        {
            self.user = None;
        } else {
            return None;
        }
        self.authenticated = true;
        self.capabilities().to_http_response().ok()
    }
}

#[allow(clippy::too_many_lines)]
async fn serve_connection(
    conn: quinn::Connection,
    options: Arc<HysteriaServerOptions>,
    events: mpsc::Sender<HysteriaEvent>,
) {
    let source = conn.remote_address();
    let authenticated = Arc::new(AtomicBool::new(false));
    let sessions_enabled = Arc::new(AtomicBool::new(false));
    let (tcp_tx, mut tcp_rx) = mpsc::channel::<(quinn::SendStream, quinn::RecvStream)>(64);
    let (http_tx, http_rx) = mpsc::channel::<RoutedBidi>(64);
    let registry = Arc::new(SessionRegistry {
        sessions: StdMutex::new(HashMap::new()),
        udp_idle_timeout: options.udp_idle_timeout,
    });
    let (session_tx, mut session_rx) = mpsc::channel::<UdpSession>(64);
    let routing = tokio::spawn(route_bidi(
        conn.clone(),
        authenticated.clone(),
        tcp_tx,
        http_tx,
    ));
    let datagrams = tokio::spawn(receive_datagrams(
        conn.clone(),
        registry.clone(),
        session_tx,
        sessions_enabled.clone(),
    ));
    let routed = RoutedConnection::new(conn.clone(), http_rx);
    let mut http = match h3::server::builder()
        .max_field_section_size(32 * 1024)
        .build(routed)
        .await
    {
        Ok(http) => http,
        Err(error) => {
            tracing::debug!(%source, %error, "hysteria HTTP/3 setup failed");
            conn.close(quinn::VarInt::from_u32(hysteria::CLOSE_PROTOCOL_ERROR), b"");
            return;
        }
    };
    let mut auth = ConnectionAuth::new(options.clone());
    let mut sweeper = interval_at(tokio::time::Instant::now(), UDP_CLEAN_INTERVAL);
    loop {
        tokio::select! {
            request = http.accept() => {
                match request {
                    Ok(Some(resolver)) => {
                        let (request, mut stream) = match resolver.resolve_request().await {
                            Ok(pair) => pair,
                            Err(error) => {
                                tracing::debug!(%source, %error, "hysteria HTTP/3 request failed");
                                break;
                            }
                        };
                        let (response, body) = match auth.handle(&request) {
                            Some(response) => {
                                if !authenticated.load(Ordering::Relaxed) {
                                    authenticated.store(true, Ordering::Relaxed);
                                    if auth.options.udp_enabled() {
                                        sessions_enabled.store(true, Ordering::Relaxed);
                                    }
                                }
                                (response, None)
                            }
                            None => auth.options.masquerade.response(),
                        };
                        let result = async {
                            stream.send_response(response).await?;
                            if let Some(body) = body {
                                stream.send_data(body).await?;
                            }
                            stream.finish().await
                        };
                        if let Err(error) = result.await {
                            tracing::debug!(%source, %error, "hysteria HTTP/3 response failed");
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(%source, %error, "hysteria HTTP/3 connection ended");
                        break;
                    }
                }
            }
            stream = tcp_rx.recv() => {
                let Some(stream) = stream else { continue };
                if events
                    .send(HysteriaEvent::Tcp {
                        user: auth.user.clone(),
                        stream,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            session = session_rx.recv() => {
                let Some(session) = session else { continue };
                if events
                    .send(HysteriaEvent::Udp {
                        user: auth.user.clone(),
                        session,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ = sweeper.tick() => registry.expire(),
        }
    }
    registry.close_all();
    routing.abort();
    datagrams.abort();
    conn.close(quinn::VarInt::from_u32(CLOSE_OK), b"");
}

/// The inbound QUIC listener: binds the UDP socket, accepts QUIC
/// connections, and yields authenticated connections whose protocol events
/// the runtime serves. Go's hysteria inbound has no TCP listener — this
/// endpoint IS the inbound listener.
pub struct HysteriaEndpointListener {
    endpoint: quinn::Endpoint,
    local: SocketAddr,
    incoming: mpsc::Receiver<HysteriaConnection>,
    accept_task: JoinHandle<()>,
}

impl HysteriaEndpointListener {
    /// Bind the QUIC listener. The TLS config needs no ALPN set: `h3` is
    /// forced here exactly like Go's `tls.WithNextProto("h3")`. The transport
    /// config applies `finalmask.quicParams` (Go's hub defaults when absent);
    /// stateless resets do not exist in quinn (PARITY_AUDIT.md).
    pub fn bind(
        address: SocketAddr,
        tls: rustls::ServerConfig,
        options: HysteriaServerOptions,
    ) -> Result<Self> {
        options.validate()?;
        let mut tls = tls;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        let quic = &options.quic;
        let mut transport = quinn::TransportConfig::default();
        // Go hub.go's receive-window defaults and datagram settings, with the
        // quicParams overrides compiled in.
        transport.stream_receive_window(quinn::VarInt::from_u64(
            quic.stream_receive_window.min(u32::MAX as u64),
        )?);
        transport.receive_window(quinn::VarInt::from_u64(
            quic.connection_receive_window.min(u32::MAX as u64),
        )?);
        transport.max_idle_timeout(Some(quic.max_idle_timeout.try_into()?));
        transport.datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE * 1024));
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u64(
            quic.max_incoming_streams.clamp(0, i64::from(u32::MAX)) as u64,
        )?);
        transport.keep_alive_interval(quic.keep_alive_period);
        if quic.disable_path_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        match options.congestion {
            NativeCongestion::QuinnNewReno => transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
            NativeCongestion::QuinnBbr => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
        };
        let mut server = server;
        server.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server, address)?;
        let local = endpoint.local_addr()?;
        let (connections, incoming) = mpsc::channel::<HysteriaConnection>(16);
        let options = Arc::new(options);
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), options, connections));
        Ok(Self {
            endpoint,
            local,
            incoming,
            accept_task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Accept one QUIC connection (authentication runs inside its driver), or
    /// `None` once the listener closed.
    pub async fn accept(&mut self) -> Option<HysteriaConnection> {
        self.incoming.recv().await
    }
}

impl Drop for HysteriaEndpointListener {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.endpoint
            .close(quinn::VarInt::from_u32(CLOSE_OK), b"listener closed");
    }
}

async fn accept_loop(
    endpoint: quinn::Endpoint,
    options: Arc<HysteriaServerOptions>,
    connections: mpsc::Sender<HysteriaConnection>,
) {
    loop {
        let incoming = match endpoint.accept().await {
            Some(incoming) => incoming,
            None => return,
        };
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::debug!(%error, "hysteria QUIC accept failed");
                continue;
            }
        };
        let source = conn.remote_address();
        let (events, event_queue) = mpsc::channel::<HysteriaEvent>(64);
        let task_options = options.clone();
        let driver = tokio::spawn(async move {
            serve_connection(conn, task_options, events).await;
        });
        let connection = HysteriaConnection {
            source,
            events: event_queue,
            driver,
        };
        if connections.send(connection).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Client dialer
// ---------------------------------------------------------------------------

/// The assembled outbound dial parameters: the proxy outbound's server
/// destination, the TLS client config, and the transport options
/// (authentication secret from `hysteriaSettings.auth`, congestion from
/// `quicParams.congestion` through [`native_congestion`]).
#[derive(Clone, Debug)]
pub struct HysteriaClientDialer {
    pub bind: SocketAddr,
    pub server: Destination,
    pub server_name: String,
    pub tls: rustls::ClientConfig,
    pub options: ClientOptions,
}
impl HysteriaClientDialer {
    pub fn new(
        bind: SocketAddr,
        server: Destination,
        server_name: String,
        tls: rustls::ClientConfig,
        options: ClientOptions,
    ) -> Self {
        Self {
            bind,
            server,
            server_name,
            tls,
            options,
        }
    }

    /// Fold one compiled `finalmask.quicParams` into the dial options (Go's
    /// dialer reads every QUIC knob from it).
    pub fn with_quic_params(mut self, quic: crate::transport::finalmask::QuicParams) -> Self {
        self.options = self.options.with_quic_params(quic);
        self
    }

    /// The dial candidates, resolved like the TCP transports resolve their
    /// destinations: an IP destination dials its literal, a domain resolves
    /// through `lookup_host`.
    pub async fn addresses(&self) -> Result<Vec<SocketAddr>> {
        let addresses = match self.server.address {
            crate::address::Address::Ip(ip) => {
                vec![SocketAddr::new(ip, self.server.port)]
            }
            crate::address::Address::Domain(ref host) => {
                tokio::net::lookup_host((host.as_str(), self.server.port))
                    .await?
                    .collect()
            }
        };
        ensure!(
            !addresses.is_empty(),
            "no address resolved for the hysteria server"
        );
        Ok(addresses)
    }

    /// Connect and authenticate to one resolved server address (the QUIC,
    /// HTTP/3 and status-233 handshake of the tested client helper).
    pub async fn connect_resolved(&self, address: &SocketAddr) -> Result<AuthenticatedConnection> {
        AuthenticatedConnection::connect(
            self.bind,
            *address,
            &self.server_name,
            &self.tls,
            self.options.clone(),
        )
        .await
    }

    /// Connect and authenticate, trying the resolved addresses in order —
    /// Go's cached `client.dial` (the first handshake that succeeds wins).
    pub async fn connect(&self) -> Result<AuthenticatedConnection> {
        let addresses = self.addresses().await?;
        let mut last = None;
        for address in &addresses {
            match self.connect_resolved(address).await {
                Ok(connection) => return Ok(connection),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no hysteria dial address")))
    }
}

// ---------------------------------------------------------------------------
// The proxy stream over one accepted 0x401 QUIC stream
// ---------------------------------------------------------------------------

/// A bidirectional proxy stream over Quinn, the server-side twin of
/// transport/hysteria.rs's client `HysteriaStream`.
pub struct QuicProxyStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicProxyStream {
    pub fn new(streams: (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self {
            send: streams.0,
            recv: streams.1,
        }
    }
}

impl AsyncRead for QuicProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for QuicProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn masquerade_compiles_go_types_and_rejects_unported_ones() {
        assert_eq!(
            MasqueradeSettings::from_value(&json!({"type": "404"}))
                .unwrap()
                .compile()
                .unwrap(),
            Masquerade::NotFound
        );
        assert_eq!(
            MasqueradeSettings::from_value(&json!({"type": "string", "content": "hi"}))
                .unwrap()
                .compile()
                .unwrap(),
            Masquerade::String {
                content: "hi".into(),
                headers: Default::default(),
                status: StatusCode::OK,
            }
        );
        let string = MasqueradeSettings::from_value(&json!({
            "type": "string", "content": "ok", "statusCode": 418,
            "headers": {"x-a": "b"}, "rewriteHost": true, "xForwarded": true, "insecure": true
        }))
        .unwrap()
        .compile()
        .unwrap();
        match string {
            Masquerade::String {
                content,
                headers,
                status,
            } => {
                assert_eq!(content, "ok");
                assert_eq!(status, StatusCode::IM_A_TEAPOT);
                assert_eq!(headers.get("x-a").map(String::as_str), Some("b"));
            }
            other => panic!("wrong masquerade {other:?}"),
        }
        for kind in ["file", "proxy"] {
            let error = MasqueradeSettings::from_value(&json!({"type": kind, "dir": "."}))
                .unwrap()
                .compile()
                .unwrap_err()
                .to_string();
            assert!(error.contains("not ported"), "{kind}: {error}");
        }
        assert!(
            MasqueradeSettings::from_value(&json!({"type": "unknown"}))
                .unwrap()
                .compile()
                .is_err()
        );
        assert!(MasqueradeSettings::from_value(&json!({"typo": "404"})).is_err());
    }

    #[test]
    fn transport_settings_match_go_keys_and_bounds() {
        let settings = HysteriaTransportSettings::from_value(&json!({
            "version": 2,
            "auth": "secret",
            "udpIdleTimeout": 30,
            "masquerade": {"type": "404"}
        }))
        .unwrap();
        settings.validate().unwrap();
        assert_eq!(settings.udp_idle_timeout(), Duration::from_secs(30));
        assert_eq!(
            HysteriaTransportSettings::from_value(&json!({"version": 2}))
                .unwrap()
                .udp_idle_timeout(),
            Duration::from_secs(60)
        );
        for bad in [
            json!({"version": 1}),
            json!({"version": 2, "udpIdleTimeout": 1}),
            json!({"version": 2, "udpIdleTimeout": 601}),
            json!({"version": 2, "masquerade": {"type": "proxy", "url": "http://x"}}),
        ] {
            let settings = HysteriaTransportSettings::from_value(&bad).unwrap();
            assert!(settings.validate().is_err(), "{bad}");
        }
        // Unknown keys fail at parse time (deny_unknown_fields).
        assert!(
            HysteriaTransportSettings::from_value(&json!({"version": 2, "unknown": true})).is_err()
        );
    }

    #[test]
    fn congestion_mapping_fails_hysteria_native_modes_explicitly() {
        let reno = native_congestion(
            CongestionMode::Reno,
            hysteria::BbrProfile::Standard,
            0,
            0,
            false,
        )
        .unwrap();
        assert_eq!(reno, NativeCongestion::QuinnNewReno);
        for (mode, name) in [
            (CongestionMode::Bbr, "bbr"),
            (CongestionMode::Auto, "auto"),
            (CongestionMode::Brutal, "brutal"),
            (CongestionMode::ForceBrutal, "force-brutal"),
        ] {
            let error = native_congestion(mode, hysteria::BbrProfile::Standard, 100, 100, false)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("not ported") || error.contains("not implemented"),
                "{name}: {error}"
            );
        }
    }
}
