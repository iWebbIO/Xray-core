//! Hysteria 2 HTTP/3 authentication and native Quinn client helpers.
//!
//! The wire handshake follows `transport/internet/hysteria/{config,dialer,hub}.go`.
//! Quinn's congestion controllers are explicit alternatives, not a port of the
//! pinned apernet/quic-go BBR profiles or Brutal controller. Listener stream
//! dispatch, masquerading, finalmask sockets and application routing are outside
//! this module. Merely establishing QUIC never produces an authenticated client.

use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use rand::{Rng, distributions::Alphanumeric};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};
use tokio_rustls::rustls;

use crate::protocol::hysteria::{TcpRequest, TcpResponse, UdpMessage};

pub const AUTH_HOST: &str = "hysteria";
pub const AUTH_PATH: &str = "/auth";
pub const AUTH_URI: &str = "https://hysteria/auth";
pub const HEADER_AUTH: &str = "hysteria-auth";
pub const HEADER_UDP: &str = "hysteria-udp";
pub const HEADER_CC_RX: &str = "hysteria-cc-rx";
pub const HEADER_PADDING: &str = "hysteria-padding";
pub const AUTH_STATUS: u16 = 233;
pub const CLOSE_OK: u32 = 0x100;
pub const CLOSE_PROTOCOL_ERROR: u32 = 0x101;
pub const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaddingKind {
    AuthRequest,
    AuthResponse,
    TcpRequest,
    TcpResponse,
}

/// Matches Go's half-open random-length ranges and alphanumeric alphabet.
pub fn random_padding(kind: PaddingKind) -> String {
    let (minimum, maximum) = match kind {
        PaddingKind::AuthRequest | PaddingKind::AuthResponse => (256, 2048),
        PaddingKind::TcpRequest => (64, 512),
        PaddingKind::TcpResponse => (128, 1024),
    };
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(minimum..maximum);
    (&mut rng)
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Values are bytes/second, not bits/second. Match Go's sequential
/// `strconv.ParseUint(..., 10, 64)` with the error discarded: invalid syntax
/// returns zero, but overflow returns u64::MAX before inspecting later bytes.
pub fn parse_receive_bandwidth(headers: &HeaderMap) -> u64 {
    let Some(value) = headers.get(HEADER_CC_RX) else {
        return 0;
    };
    let mut parsed = 0u64;
    for &byte in value.as_bytes() {
        if !byte.is_ascii_digit() {
            return 0;
        }
        let Some(next) = parsed
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(byte - b'0')))
        else {
            return u64::MAX;
        };
        parsed = next;
    }
    parsed
}

#[derive(Clone)]
pub struct AuthRequest {
    pub auth: String,
    pub receive_bytes_per_second: u64,
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthRequest")
            .field("auth", &"[redacted]")
            .field("receive_bytes_per_second", &self.receive_bytes_per_second)
            .finish()
    }
}

impl AuthRequest {
    pub fn to_http_request(&self) -> Result<Request<()>> {
        self.to_http_request_with_padding(&random_padding(PaddingKind::AuthRequest))
    }

    pub fn to_http_request_with_padding(&self, padding: &str) -> Result<Request<()>> {
        Ok(Request::builder()
            .method(Method::POST)
            .uri(AUTH_URI)
            .header(HEADER_AUTH, &self.auth)
            .header(HEADER_CC_RX, self.receive_bytes_per_second.to_string())
            .header(HEADER_PADDING, padding)
            .body(())?)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    pub receive_bytes_per_second: u64,
}

impl AuthResponse {
    pub fn from_http_response<B>(response: &Response<B>) -> Result<Self> {
        ensure!(
            response.status().as_u16() == AUTH_STATUS,
            "Hysteria authentication rejected with HTTP status {}",
            response.status().as_u16()
        );
        let udp_enabled = response
            .headers()
            .get(HEADER_UDP)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True"));
        Ok(Self {
            udp_enabled,
            receive_bytes_per_second: parse_receive_bandwidth(response.headers()),
        })
    }

    pub fn to_http_response(&self) -> Result<Response<()>> {
        self.to_http_response_with_padding(&random_padding(PaddingKind::AuthResponse))
    }

    pub fn to_http_response_with_padding(&self, padding: &str) -> Result<Response<()>> {
        Ok(Response::builder()
            .status(StatusCode::from_u16(AUTH_STATUS)?)
            .header(HEADER_UDP, if self.udp_enabled { "true" } else { "false" })
            .header(HEADER_CC_RX, self.receive_bytes_per_second.to_string())
            .header(HEADER_PADDING, padding)
            .body(())?)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthServerState {
    authenticated: bool,
    peer_receive_bytes_per_second: u64,
}

impl AuthServerState {
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
    pub fn peer_receive_bytes_per_second(&self) -> u64 {
        self.peer_receive_bytes_per_second
    }

    /// Per-QUIC-connection authentication state. `None` means the caller should
    /// use its masquerade handler. Credentials are checked only on first success,
    /// matching Go's repeated-auth behavior; an empty configured secret never
    /// authenticates. This helper does not implement HTTP/3 listener dispatch.
    pub fn handle<B>(
        &mut self,
        request: &Request<B>,
        expected_auth: &str,
        capabilities: AuthResponse,
    ) -> Result<Option<Response<()>>> {
        let host = request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
            });
        if request.method() != Method::POST
            || host != Some(AUTH_HOST)
            || request.uri().path() != AUTH_PATH
        {
            return Ok(None);
        }
        if !self.authenticated {
            let Some(auth) = request.headers().get(HEADER_AUTH) else {
                return Ok(None);
            };
            if expected_auth.is_empty()
                || !bool::from(auth.as_bytes().ct_eq(expected_auth.as_bytes()))
            {
                return Ok(None);
            }
            self.peer_receive_bytes_per_second = parse_receive_bandwidth(request.headers());
            self.authenticated = true;
        }
        Ok(Some(capabilities.to_http_response()?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionMode {
    Auto,
    Reno,
    Bbr,
    Brutal,
    ForceBrutal,
}

impl CongestionMode {
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "" => Ok(Self::Auto),
            "reno" => Ok(Self::Reno),
            "bbr" => Ok(Self::Bbr),
            "brutal" => Ok(Self::Brutal),
            "force-brutal" => Ok(Self::ForceBrutal),
            _ => bail!("unsupported Hysteria congestion mode {name:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

impl BbrProfile {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "" | "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            "aggressive" => Ok(Self::Aggressive),
            _ => bail!("unsupported Hysteria BBR profile {name:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiatedCongestion {
    Reno,
    Bbr(BbrProfile),
    Brutal {
        transmit_bytes_per_second: u64,
        disable_loss_compensation: bool,
    },
}

/// Exact pinned client/server policy: Auto/Brutal use min(local TX, peer RX)
/// unless either is zero, when BBR is selected. ForceBrutal ignores peer RX.
pub fn negotiate_congestion(
    mode: CongestionMode,
    profile: BbrProfile,
    local_tx: u64,
    peer_rx: u64,
    disable_loss_compensation: bool,
) -> NegotiatedCongestion {
    match mode {
        CongestionMode::Reno => NegotiatedCongestion::Reno,
        CongestionMode::Bbr => NegotiatedCongestion::Bbr(profile),
        CongestionMode::ForceBrutal => NegotiatedCongestion::Brutal {
            transmit_bytes_per_second: local_tx,
            disable_loss_compensation,
        },
        CongestionMode::Auto | CongestionMode::Brutal if local_tx == 0 || peer_rx == 0 => {
            NegotiatedCongestion::Bbr(profile)
        }
        CongestionMode::Auto | CongestionMode::Brutal => NegotiatedCongestion::Brutal {
            transmit_bytes_per_second: local_tx.min(peer_rx),
            disable_loss_compensation,
        },
    }
}

/// Explicit native controller choices. Quinn BBR has no equivalent of the
/// pinned Xray profile tuning. No implicit default hides that difference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCongestion {
    QuinnNewReno,
    QuinnBbr,
}

impl NegotiatedCongestion {
    pub fn supported_native_controller(self) -> Result<NativeCongestion> {
        match self {
            Self::Reno => Ok(NativeCongestion::QuinnNewReno),
            Self::Bbr(profile) => bail!(
                "the pinned Hysteria BBR profile {:?} is not ported (quinn's \
                 experimental BBR is a different controller); set \
                 finalmask.quicParams.congestion to \"reno\"",
                profile
            ),
            Self::Brutal { .. } => bail!(
                "Hysteria Brutal congestion control is not implemented; set \
                 finalmask.quicParams.congestion to \"reno\""
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub authentication: AuthRequest,
    pub congestion: NativeCongestion,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub keep_alive: Option<Duration>,
    pub disable_path_mtu_discovery: bool,
    /// The stream and connection receive windows (Go's dialer defaults).
    pub windows: (u64, u64),
    pub max_incoming_streams: i64,
}

impl ClientOptions {
    pub fn new(authentication: AuthRequest, congestion: NativeCongestion) -> Self {
        Self {
            authentication,
            congestion,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            keep_alive: None,
            disable_path_mtu_discovery: false,
            windows: (8_388_608, 8_388_608 * 5 / 2),
            max_incoming_streams: 1_024,
        }
    }

    /// Fold one compiled `finalmask.quicParams` in (Go's dialer reads every
    /// QUIC knob from it); the handshake timeout stays the transport's own.
    pub fn with_quic_params(mut self, quic: crate::transport::finalmask::QuicParams) -> Self {
        self.idle_timeout = quic.max_idle_timeout;
        self.keep_alive = quic.keep_alive_period;
        self.disable_path_mtu_discovery = quic.disable_path_mtu_discovery;
        self.windows = (quic.stream_receive_window, quic.connection_receive_window);
        self.max_incoming_streams = quic.max_incoming_streams;
        self
    }

    pub fn transport_config(&self) -> Result<quinn::TransportConfig> {
        ensure!(
            !self.handshake_timeout.is_zero(),
            "Hysteria handshake timeout must be positive"
        );
        ensure!(
            !self.idle_timeout.is_zero(),
            "Hysteria idle timeout must be positive"
        );
        let mut config = quinn::TransportConfig::default();
        config.stream_receive_window(quinn::VarInt::from_u64(
            self.windows.0.min(u32::MAX as u64),
        )?);
        config.receive_window(quinn::VarInt::from_u64(
            self.windows.1.min(u32::MAX as u64),
        )?);
        config.max_idle_timeout(Some(self.idle_timeout.try_into()?));
        config.keep_alive_interval(self.keep_alive);
        config.datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE * 1024));
        config.datagram_send_buffer_size(MAX_DATAGRAM_FRAME_SIZE * 1024);
        config.max_concurrent_bidi_streams(quinn::VarInt::from_u64(
            self.max_incoming_streams.clamp(0, i64::from(u32::MAX)) as u64,
        )?);
        if self.disable_path_mtu_discovery {
            config.mtu_discovery_config(None);
        }
        match self.congestion {
            NativeCongestion::QuinnNewReno => config.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
            NativeCongestion::QuinnBbr => config
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
        };
        Ok(config)
    }
}

/// Owns the endpoint and HTTP/3 driver for exactly one authenticated connection.
/// A live sender is retained because dropping h3's last SendRequest closes QUIC.
/// Clones and returned TCP streams share ownership of this session.
#[derive(Clone)]
pub struct AuthenticatedConnection {
    inner: Arc<ConnectionState>,
}

struct ConnectionState {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    http_sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: JoinHandle<()>,
    peer: AuthResponse,
    handshake_timeout: Duration,
}

impl AuthenticatedConnection {
    /// The supplied TLS config retains its certificate verifier and roots.
    /// Hysteria requires ALPN h3; early data is disabled to avoid replaying auth.
    pub async fn connect(
        bind: SocketAddr,
        remote: SocketAddr,
        server_name: &str,
        tls: &rustls::ClientConfig,
        options: ClientOptions,
    ) -> Result<Self> {
        let transport = options.transport_config()?;
        let request = options.authentication.to_http_request()?;
        let mut tls = tls.clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = false;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut quic_config = quinn::ClientConfig::new(Arc::new(crypto));
        quic_config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(quic_config);
        let connection = tokio::time::timeout(
            options.handshake_timeout,
            endpoint.connect(remote, server_name)?,
        )
        .await
        .context("Hysteria QUIC handshake timed out")??;
        let mut builder = h3::client::builder();
        builder.max_field_section_size(32 * 1024);
        let (mut driver, sender) = tokio::time::timeout(
            options.handshake_timeout,
            builder.build(h3_quinn::Connection::new(connection.clone())),
        )
        .await
        .context("Hysteria HTTP/3 setup timed out")??;
        let driver = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let mut client = ConnectionState {
            endpoint,
            connection,
            http_sender: sender,
            driver,
            peer: AuthResponse::default(),
            handshake_timeout: options.handshake_timeout,
        };
        let response = tokio::time::timeout(options.handshake_timeout, async {
            let mut stream = client.http_sender.send_request(request).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            AuthResponse::from_http_response(&response)
        })
        .await
        .context("Hysteria HTTP/3 authentication timed out")
        .and_then(|result| result);
        match response {
            Ok(response) => client.peer = response,
            Err(error) => {
                client
                    .connection
                    .close(quinn::VarInt::from_u32(CLOSE_PROTOCOL_ERROR), b"");
                return Err(error);
            }
        }
        Ok(Self {
            inner: Arc::new(client),
        })
    }

    pub fn peer_capabilities(&self) -> AuthResponse {
        self.inner.peer
    }
    pub fn local_address(&self) -> io::Result<SocketAddr> {
        self.inner.endpoint.local_addr()
    }
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.connection.remote_address()
    }

    /// Opens one independent proxy stream and validates its response. Application
    /// payload starts after this method returns; TCP Fast Open is not implemented.
    /// The returned stream retains the authenticated session even if this handle
    /// is dropped. Explicit `close()` still closes every stream on the session.
    pub async fn open_tcp(&self, address: &str) -> Result<HysteriaStream> {
        let header = TcpRequest {
            address: address.to_owned(),
            padding: random_padding(PaddingKind::TcpRequest).into_bytes(),
        }
        .encode_stream()?;
        tokio::time::timeout(self.inner.handshake_timeout, async {
            let (mut send, mut receive) = self.inner.connection.open_bi().await?;
            send.write_all(&header).await?;
            let response = TcpResponse::read(&mut receive).await?;
            ensure!(
                response.is_ok(),
                "Hysteria TCP request rejected: {}",
                String::from_utf8_lossy(&response.message)
            );
            Ok(HysteriaStream {
                send,
                receive,
                _connection: self.inner.clone(),
            })
        })
        .await
        .context("Hysteria TCP request timed out")?
    }

    /// Sends complete application datagrams. A zero packet ID is replaced with a
    /// random nonzero ID if fragmentation is needed. Session allocation and
    /// destination/source policy are the caller's responsibility.
    pub fn send_udp(&self, mut message: UdpMessage) -> Result<usize> {
        ensure!(self.inner.peer.udp_enabled, "Hysteria peer disabled UDP");
        let maximum = self
            .inner
            .connection
            .max_datagram_size()
            .context("Hysteria peer did not negotiate QUIC datagrams")?
            .min(MAX_DATAGRAM_FRAME_SIZE);
        if message.header_size()? + message.payload.len() > maximum && message.packet_id == 0 {
            message.packet_id = rand::thread_rng().gen_range(1..=u16::MAX);
        }
        let fragments = message.fragment(maximum)?;
        for fragment in &fragments {
            self.inner
                .connection
                .send_datagram(Bytes::from(fragment.encode()?))?;
        }
        Ok(fragments.len())
    }

    /// Returns one wire fragment; use the bounded protocol UdpReassembler and
    /// a session table above this layer. Only one receive loop should own this.
    pub async fn receive_udp_fragment(&self) -> Result<UdpMessage> {
        ensure!(self.inner.peer.udp_enabled, "Hysteria peer disabled UDP");
        let datagram = self.inner.connection.read_datagram().await?;
        ensure!(
            datagram.len() <= MAX_DATAGRAM_FRAME_SIZE,
            "oversized Hysteria datagram"
        );
        Ok(UdpMessage::decode(&datagram)?)
    }

    pub fn close(&self) {
        self.inner
            .connection
            .close(quinn::VarInt::from_u32(CLOSE_OK), b"");
    }
}

impl Drop for ConnectionState {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(CLOSE_OK), b"");
        self.driver.abort();
    }
}

pub struct HysteriaStream {
    send: quinn::SendStream,
    receive: quinn::RecvStream,
    _connection: Arc<ConnectionState>,
}

impl AsyncRead for HysteriaStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().receive), context, buffer)
    }
}

impl AsyncWrite for HysteriaStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), context, data)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn pinned_auth_headers_and_special_status() {
        let auth = AuthRequest {
            auth: "secret".into(),
            receive_bytes_per_second: 125_000,
        };
        let request = auth.to_http_request_with_padding("fixed").unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), AUTH_URI);
        assert_eq!(request.headers()[HEADER_AUTH], "secret");
        assert_eq!(request.headers()[HEADER_CC_RX], "125000");
        let expected = AuthResponse {
            udp_enabled: true,
            receive_bytes_per_second: 50_000,
        };
        let response = expected.to_http_response_with_padding("x").unwrap();
        assert_eq!(response.status().as_u16(), 233);
        assert_eq!(
            AuthResponse::from_http_response(&response).unwrap(),
            expected
        );
        assert!(AuthResponse::from_http_response(&Response::new(())).is_err());
        assert!(!format!("{auth:?}").contains("secret"));
    }

    #[test]
    fn server_auth_target_secret_and_connection_state() {
        let auth = AuthRequest {
            auth: "secret".into(),
            receive_bytes_per_second: 100,
        };
        let mut state = AuthServerState::default();
        let capabilities = AuthResponse {
            udp_enabled: true,
            receive_bytes_per_second: 200,
        };
        let request = auth.to_http_request_with_padding("").unwrap();
        assert!(
            state
                .handle(&request, "wrong", capabilities)
                .unwrap()
                .is_none()
        );
        assert!(!state.authenticated());
        assert!(state.handle(&request, "", capabilities).unwrap().is_none());
        let mut wrong = auth.to_http_request_with_padding("").unwrap();
        *wrong.uri_mut() = "https://elsewhere/auth".parse().unwrap();
        assert!(
            state
                .handle(&wrong, "secret", capabilities)
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .handle(&request, "secret", capabilities)
                .unwrap()
                .is_some()
        );
        assert!(state.authenticated());
        assert_eq!(state.peer_receive_bytes_per_second(), 100);
        let mut repeat = auth.to_http_request_with_padding("").unwrap();
        repeat.headers_mut().remove(HEADER_AUTH);
        assert!(
            state
                .handle(&repeat, "changed", capabilities)
                .unwrap()
                .is_some()
        );
        *repeat.method_mut() = Method::GET;
        assert!(
            state
                .handle(&repeat, "secret", capabilities)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bandwidth_parse_and_negotiation_match_go() {
        let cases: &[(&[u8], u64)] = &[
            (b"", 0),
            (b"0", 0),
            (b"125000", 125000),
            (b"00012", 12),
            (b"auto", 0),
            (b"+1", 0),
            (b"-1", 0),
            (b" 1", 0),
            (b"1 ", 0),
            (b"1_000", 0),
            (b"18446744073709551615", u64::MAX),
            (b"18446744073709551616", u64::MAX),
            (b"00018446744073709551615", u64::MAX),
            (b"00018446744073709551616", u64::MAX),
            (b"18446744073709551615x", 0),
            (b"18446744073709551616x", u64::MAX),
            (b"1844674407370955161x6", 0),
            (b"184467440737095516150x", u64::MAX),
            (b"+18446744073709551616", 0),
            (b"-18446744073709551616", 0),
            (b"\xff18446744073709551616", 0),
            (b"18446744073709551615\xff", 0),
            (b"18446744073709551616\xff", u64::MAX),
        ];
        assert_eq!(parse_receive_bandwidth(&HeaderMap::new()), 0);
        for &(value, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(HEADER_CC_RX, http::HeaderValue::from_bytes(value).unwrap());
            assert_eq!(parse_receive_bandwidth(&headers), expected, "{value:?}");
        }
        let profile = BbrProfile::Standard;
        for mode in [CongestionMode::Auto, CongestionMode::Brutal] {
            assert_eq!(
                negotiate_congestion(mode, profile, 100, 200, true),
                NegotiatedCongestion::Brutal {
                    transmit_bytes_per_second: 100,
                    disable_loss_compensation: true
                }
            );
            assert_eq!(
                negotiate_congestion(mode, profile, 200, 100, false),
                NegotiatedCongestion::Brutal {
                    transmit_bytes_per_second: 100,
                    disable_loss_compensation: false
                }
            );
            for (tx, rx) in [(0, 100), (100, 0)] {
                assert_eq!(
                    negotiate_congestion(mode, profile, tx, rx, false),
                    NegotiatedCongestion::Bbr(profile)
                );
            }
        }
        assert_eq!(
            negotiate_congestion(CongestionMode::ForceBrutal, profile, 100, 1, false),
            NegotiatedCongestion::Brutal {
                transmit_bytes_per_second: 100,
                disable_loss_compensation: false
            }
        );
        assert!(
            NegotiatedCongestion::Bbr(profile)
                .supported_native_controller()
                .is_err()
        );
        assert_eq!(
            NegotiatedCongestion::Reno
                .supported_native_controller()
                .unwrap(),
            NativeCongestion::QuinnNewReno
        );
    }

    #[test]
    fn padding_has_source_ranges_and_alphabet() {
        for (kind, range) in [
            (PaddingKind::AuthRequest, 256..2048),
            (PaddingKind::AuthResponse, 256..2048),
            (PaddingKind::TcpRequest, 64..512),
            (PaddingKind::TcpResponse, 128..1024),
        ] {
            for _ in 0..8 {
                let padding = random_padding(kind);
                assert!(range.contains(&padding.len()));
                assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            }
        }
    }

    fn loopback_tls() -> (quinn::ServerConfig, rustls::ClientConfig) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"h3".to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(1024 * 1024));
        server.transport_config(Arc::new(transport));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server, client)
    }

    /// Exercises actual TLS/QUIC/H3, then deliberately dispatches 0x401 outside
    /// h3's ordinary HTTP request parser, as the Go StreamDispatcher does.
    #[tokio::test]
    async fn native_http3_auth_tcp_and_udp_loopback() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (server_config, client_tls) = loopback_tls();
            let server =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = server.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                let mut http = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(
                    connection.clone(),
                ))
                .await
                .unwrap();
                let (request, mut stream) = http
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                let response = AuthServerState::default()
                    .handle(
                        &request,
                        "secret",
                        AuthResponse {
                            udp_enabled: true,
                            receive_bytes_per_second: 100_000,
                        },
                    )
                    .unwrap()
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream.finish().await.unwrap();
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                assert_eq!(
                    TcpRequest::read_stream(&mut receive).await.unwrap().address,
                    "example.com:443"
                );
                // Literal source-layout response, followed immediately by application bytes.
                send.write_all(b"\0\0\0hello").await.unwrap();
                let mut ping = [0; 4];
                receive.read_exact(&mut ping).await.unwrap();
                assert_eq!(&ping, b"ping");
                let datagram = connection.read_datagram().await.unwrap();
                let decoded = UdpMessage::decode(&datagram).unwrap();
                assert_eq!(decoded.session_id, 7);
                assert_eq!(decoded.payload, b"dns");
                connection.send_datagram(datagram).unwrap();
                let mut live = [0; 4];
                receive.read_exact(&mut live).await.unwrap();
                assert_eq!(&live, b"live");
                send.write_all(b"ok").await.unwrap();
                // Keep h3 control streams and endpoint alive until the client closes.
                connection.closed().await;
                drop(http);
            });
            let client = AuthenticatedConnection::connect(
                "127.0.0.1:0".parse().unwrap(),
                address,
                "localhost",
                &client_tls,
                ClientOptions::new(
                    AuthRequest {
                        auth: "secret".into(),
                        receive_bytes_per_second: 0,
                    },
                    NativeCongestion::QuinnNewReno,
                ),
            )
            .await
            .unwrap();
            assert!(client.peer_capabilities().udp_enabled);
            assert_eq!(client.peer_capabilities().receive_bytes_per_second, 100_000);
            let mut stream = client.open_tcp("example.com:443").await.unwrap();
            let mut hello = [0; 5];
            stream.read_exact(&mut hello).await.unwrap();
            assert_eq!(&hello, b"hello");
            stream.write_all(b"ping").await.unwrap();
            let message = UdpMessage {
                session_id: 7,
                packet_id: 0,
                fragment_id: 0,
                fragment_count: 1,
                address: "dns.example:53".into(),
                payload: b"dns".to_vec(),
            };
            assert_eq!(client.send_udp(message.clone()).unwrap(), 1);
            assert_eq!(client.receive_udp_fragment().await.unwrap(), message);
            drop(client);
            // A dispatched TCP stream must keep the authenticated session alive.
            stream.write_all(b"live").await.unwrap();
            let mut ok = [0; 2];
            stream.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"ok");
            drop(stream);
            task.await.unwrap();
        })
        .await
        .expect("Hysteria loopback timed out");
    }

    #[tokio::test]
    async fn native_client_rejects_http_success_without_hysteria_auth_status() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (server_config, client_tls) = loopback_tls();
            let server =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = server.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                let mut http = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(
                    connection.clone(),
                ))
                .await
                .unwrap();
                let (_, mut stream) = http
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
                match connection.closed().await {
                    quinn::ConnectionError::ApplicationClosed(close) => assert_eq!(
                        close.error_code,
                        quinn::VarInt::from_u32(CLOSE_PROTOCOL_ERROR)
                    ),
                    other => panic!("expected protocol close, got {other:?}"),
                }
            });
            let result = AuthenticatedConnection::connect(
                "127.0.0.1:0".parse().unwrap(),
                address,
                "localhost",
                &client_tls,
                ClientOptions::new(
                    AuthRequest {
                        auth: "secret".into(),
                        receive_bytes_per_second: 0,
                    },
                    NativeCongestion::QuinnNewReno,
                ),
            )
            .await;
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("HTTP status 200")
            );
            task.await.unwrap();
        })
        .await
        .expect("Hysteria rejection loopback timed out");
    }
}
