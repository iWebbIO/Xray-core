// P16 masque_transport: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]
//! MASQUE transport stream settings: HTTP/2 extended CONNECT (RFC 8441) with
//! the `connect-ip` protocol (RFC 9484) over TLS.
//!
//! Go reference: transport/internet/masque/{dialer,conn,config}.go, http2.go,
//! and connectip/{client,request,http2}.go. Go dials either HTTP/3 (quic-go)
//! or HTTP/2 depending on the TLS `nextProtocol` list; this port implements
//! the HTTP/2 branch only (`usesHTTP2` in dialer.go): a TLS stream
//! negotiated with ALPN `h2` carrying one extended-CONNECT tunnel per
//! connection target. HTTP/3-only options (QUIC congestion control,
//! datagram frames, BBR...) are parsed and rejected with explicit errors,
//! never silently ignored.
//!
//! Deviation required by the per-target stream-settings model: Go's
//! CONNECT-IP tunnel forwards raw IP flows and carries no per-connection
//! target, while an Xray streamSettings dial is per destination. Each
//! extended-CONNECT request therefore encodes its target in the configured
//! path template: the first `*` captures `host:port` and the second `*`
//! captures the network (`tcp` or `udp`). The Go default template
//! `/.well-known/masque/ip/*/*/` keeps this shape. TCP targets bridge the
//! CONNECT stream directly; UDP targets carry RFC 9484 datagram capsules
//! (CONTRACT-CAPSULE, `masque_connectip::capsule`) in the stream body,
//! matching Go's connectip HTTP/2 body handling.
//!
//! Not ported (see the batch report notes): HTTP/3, the address
//! assignment/reassignment dance (`RequestAddresses`/
//! `ReceiveAddressAssignment` needs capsule encodings outside the shared
//! capsule contract), and finalmask/cnc transport wrapping, which belongs to
//! the runtime.

use std::{
    collections::BTreeMap,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use anyhow::{Result, bail};
use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream, client::ResponseFuture, ext::Protocol as ConnectProtocol};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::transport::{
    BoxStream,
    masque_connectip::capsule::{self, Capsule},
    tls::TlsSettings,
};

/// `protocolName` in config.go.
pub const PROTOCOL_NAME: &str = "masque";
/// `DefaultPath` in config.go.
pub const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
/// `MinPacketSize` in dialer.go: the smallest payload a usable tunnel carries.
pub const MIN_PACKET_SIZE: usize = 1280;
/// Largest UDP payload this implementation accepts for one capsule; HTTP/2
/// framing has no negotiated UDP payload limit, so a u16-sized bound is used.
pub const MAX_PACKET_SIZE: usize = 65_535;

/// `requestProtocol` in connectip/request.go.
const CONNECT_IP_PROTOCOL: &str = "connect-ip";
/// `capsuleProtocolHeaderValue` in connectip/request.go; the header name is
/// `http3.CapsuleProtocolHeader` ("capsule-protocol").
const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_VALUE: &str = "?1";

// http2.go client constants reproduced through the h2 builder.
const HTTP2_STREAM_WINDOW: u32 = 6 << 20;
const HTTP2_CONNECTION_WINDOW: u32 = 15 << 20;
const HTTP2_MAX_HEADER_LIST_SIZE: u32 = 256 << 10;
const DEFAULT_USER_AGENT: &str = "Go-http-client/2.0";

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_CHUNK: usize = 16 * 1024;
const ACCEPT_QUEUE: usize = 64;
/// Capsules are unbounded in RFC 9484; a fixed bound keeps a malformed peer
/// from growing the receive buffer indefinitely.
const MAX_CAPSULE_BUFFER: usize = 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

fn h2_error(error: h2::Error) -> io::Error {
    let kind = if let Some(error) = error.get_io() {
        error.kind()
    } else if error.reason() == Some(h2::Reason::CANCEL) {
        io::ErrorKind::Interrupted
    } else {
        io::ErrorKind::ConnectionAborted
    };
    io::Error::new(kind, error)
}

/// The network of a dialed target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One per-connection dial target, encoded into the request path template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub network: Network,
}

impl Target {
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            network: Network::Tcp,
        }
    }

    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            network: Network::Udp,
        }
    }

    /// `host:port` with IPv6 literals bracketed, as in net.JoinHostPort.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{host}]:{port}", host = self.host, port = self.port)
        } else {
            format!("{host}:{port}", host = self.host, port = self.port)
        }
    }
}

/// `masque.Config` (config.proto): `host`, `path`, `headers`.
///
/// The JSON loader must reject anything the Go config does not carry. The
/// path is a template whose first `*` is the target slot and whose second `*`
/// is the network slot, so a template without `*` cannot express the
/// per-target model and is rejected here rather than misdialed later.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// Client-side `:authority` override; server-side Host restriction.
    pub host: String,
    /// URL path template. Defaults to [DEFAULT_PATH] like the registered Go
    /// protocol creator.
    #[serde(default = "default_path")]
    pub path: String,
    /// Extra request headers. Header spelling is preserved, as with Go's
    /// `http.Header`.
    #[serde(deserialize_with = "optional_headers")]
    pub headers: BTreeMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: DEFAULT_PATH.to_owned(),
            headers: BTreeMap::new(),
        }
    }
}

fn default_path() -> String {
    DEFAULT_PATH.to_owned()
}

// encoding/json decodes a null map[string]string as a nil (empty) map.
fn optional_headers<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Headers {
        Map(BTreeMap<String, String>),
        Null,
    }
    Ok(match Headers::deserialize(deserializer)? {
        Headers::Map(map) => map,
        Headers::Null => BTreeMap::new(),
    })
}

/// HTTP/3-only options that never belong in `masqueSettings`; they arrive from
/// the QUIC layer (`streamSettings.QuicParams`) in Go and are rejected with a
/// message that names them instead of the generic unknown-field error.
const HTTP3_ONLY_KEYS: &[&str] = &[
    "congestion",
    "bbrProfile",
    "brutalUp",
    "brutalDown",
    "disableGso",
    "disablePathMtuDiscovery",
    "initStreamReceiveWindow",
    "maxStreamReceiveWindow",
    "initConnReceiveWindow",
    "maxConnReceiveWindow",
    "keepAlivePeriod",
    "maxIdleTimeout",
];

impl Settings {
    /// The single config-layer entry point. `null` yields the Go creator's
    /// defaults (config.go `RegisterProtocolConfigCreator`).
    pub fn from_value(value: &Value) -> Result<Self> {
        if value.is_null() {
            return Ok(Self::default());
        }
        let object = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("MASQUE settings must be a JSON object"))?;
        for key in object.keys() {
            if HTTP3_ONLY_KEYS
                .iter()
                .any(|option| option.eq_ignore_ascii_case(key))
            {
                bail!(
                    "MASQUE option \"{key}\" is HTTP/3-only (QUIC); \
                     HTTP/2 MASQUE does not support it"
                );
            }
        }
        let mut settings: Settings = serde_json::from_value(value.clone())
            .map_err(|error| anyhow::anyhow!("invalid MASQUE settings: {error}"))?;
        if settings.path.is_empty() {
            settings.path = DEFAULT_PATH.to_owned();
        }
        settings.validate()?;
        Ok(settings)
    }

    /// Go's `NewRequest` validations plus the template requirements above.
    fn validate(&self) -> Result<()> {
        if !self.path.starts_with('/') {
            bail!("MASQUE path must start with '/': {:?}", self.path);
        }
        if self.path.contains("{}") {
            // connectip.NewRequest: an unexpanded URI Template expression.
            bail!(
                "MASQUE IP flow forwarding not supported: \
                 path contains a URI Template expression"
            );
        }
        if !self.path.contains('*') {
            bail!("MASQUE path template must contain a '*' target placeholder");
        }
        for (name, value) in &self.headers {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            {
                bail!("invalid MASQUE header name {:?}", name);
            }
            if value
                .bytes()
                .any(|byte| byte < b' ' && byte != b'\t' || byte == 127)
            {
                bail!("invalid MASQUE header value for {:?}", name);
            }
        }
        if !self.host.is_empty()
            && self
                .host
                .bytes()
                .any(|byte| byte <= b' ' || byte >= 127 || b"/\\?#@".contains(&byte))
        {
            bail!("invalid MASQUE host; use an ASCII DNS name or IP address");
        }
        Ok(())
    }

    /// `authority` in dialer.go: an explicit `host` wins; otherwise the TLS
    /// server name (brackets stripped), without a port when it is 443.
    pub fn authority(&self, server_name: &str, port: u16) -> String {
        if !self.host.is_empty() {
            return self.host.clone();
        }
        let host = server_name
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(server_name);
        let bracketed = host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_ipv6());
        match (port == 443, bracketed) {
            (true, true) => format!("[{host}]"),
            (true, false) => host.to_owned(),
            (false, true) => format!("[{host}]:{port}"),
            (false, false) => format!("{host}:{port}"),
        }
    }

    /// Substitutes the target and network into the path template. The first
    /// `*` becomes the percent-encoded `host:port` and every later `*` is the
    /// network name; a template with a single `*` cannot carry a network and
    /// therefore only dials TCP.
    fn request_path(&self, target: &Target) -> Result<String> {
        self.validate()?;
        if target.host.is_empty() {
            bail!("MASQUE target host is empty");
        }
        let target_text = escape_segment(&target.authority());
        let mut star = 0;
        let segments: Vec<String> = self
            .path
            .split('/')
            .map(|segment| {
                if segment == "*" {
                    star += 1;
                    match star {
                        1 => target_text.clone(),
                        _ => target.network.as_str().to_owned(),
                    }
                } else {
                    segment.to_owned()
                }
            })
            .collect();
        if star == 1 && target.network == Network::Udp {
            bail!(
                "MASQUE path template needs a second '*' for UDP targets; \
                 the network cannot be encoded"
            );
        }
        Ok(segments.join("/"))
    }

    /// The inverse of [Settings::request_path] for the server: every literal
    /// template segment must match and each `*` captures one path segment.
    /// Returns `None` when the request path is not this template.
    fn parse_target(&self, path: &str) -> Option<Target> {
        let template: Vec<_> = self.path.split('/').collect();
        let request: Vec<_> = path.split('/').collect();
        if template.len() != request.len() {
            return None;
        }
        let mut captures = Vec::new();
        for (pattern, segment) in template.iter().zip(request.iter()) {
            if *pattern == "*" {
                captures.push((*segment).to_owned());
            } else if pattern != segment {
                return None;
            }
        }
        let target = percent_decode(captures.first()?)?;
        let network = match captures.get(1).map(String::as_str) {
            Some("tcp") => Network::Tcp,
            Some("udp") => Network::Udp,
            // A single-star template encodes a TCP target only.
            None => Network::Tcp,
            _ => return None,
        };
        let (host, port) = split_host_port(&target)?;
        if host.is_empty() {
            return None;
        }
        Some(Target {
            host,
            port,
            network,
        })
    }

    /// The request headers after Go's `establish` User-Agent mapping, minus
    /// the fields its HTTP/2 writer excludes (http2.go `writeHeaders`).
    /// Matching `http.Header.Get`, the User-Agent lookup is canonical, i.e.
    /// case-insensitive over the configured header names.
    fn request_headers(&self) -> BTreeMap<String, String> {
        let user_agent = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.clone());
        let mut headers: BTreeMap<String, String> = self
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("user-agent"))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        match user_agent.as_deref() {
            // Go: an empty value sends no user-agent at all (the key remains
            // present for the default check in `open`).
            Some("") => {}
            // Go: header.Set("User-Agent", utils.ChromeUA) and friends; the
            // browser profiles are shared with the neighboring transports.
            Some("chrome" | "edge" | "firefox" | "safari" | "curl") => {
                let mut profile = BTreeMap::from([(
                    "User-Agent".to_owned(),
                    user_agent.clone().unwrap_or_default(),
                )]);
                crate::transport::httpupgrade::apply_browser_headers(&mut profile);
                if let Some(agent) = profile.get("User-Agent") {
                    headers.insert("User-Agent".to_owned(), agent.clone());
                }
            }
            // Go: header.Del("User-Agent")
            Some("golang") => {}
            // Literal values and an absent header keep the configured value.
            Some(literal) => {
                headers.insert("User-Agent".to_owned(), literal.to_owned());
            }
            None => {}
        }
        headers.retain(|name, _| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                ":protocol"
                    | "host"
                    | "connection"
                    | "proxy-connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
            )
        });
        headers
    }

    /// Whether the configured headers name a User-Agent at all; Go's
    /// writeHeaders only adds its default when the key is absent.
    fn has_user_agent(&self) -> bool {
        self.headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("user-agent"))
    }
}

/// Percent-encode one path segment, escaping everything outside RFC 3986
/// pchar (unreserved, sub-delims, `:`, `@`).
fn escape_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~$&+,;=:@!'()*".contains(&byte) {
            result.push(char::from(byte));
        } else {
            result.push('%');
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    result
}

/// Percent-decode a path segment; `None` on a bad escape.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hi = (index + 1 < bytes.len())
                    .then(|| bytes[index + 1])
                    .and_then(|byte| char::from(byte).to_digit(16))?;
                let lo = (index + 2 < bytes.len())
                    .then(|| bytes[index + 2])
                    .and_then(|byte| char::from(byte).to_digit(16))?;
                result.push(((hi << 4) | lo) as u8);
                index += 3;
            }
            byte => {
                result.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(result).ok()
}

/// Split `host:port`, tolerating bracketed IPv6 literals. A missing port is 0.
fn split_host_port(value: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = value
        .strip_prefix('[')
        .and_then(|inner| inner.split_once("]:"))
    {
        return Some((host.to_owned(), port.parse().ok()?));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_owned(), port.parse().ok()?)),
        Some(_) | None => Some((value.to_owned(), 0)),
    }
}

/// `usesHTTP2` in dialer.go: HTTP/2 only when `h2` is offered and `h3` is
/// not. Every other combination means the Go dialer would take the QUIC
/// branch, which this port does not implement.
pub fn uses_http2(next_protocol: &[String]) -> bool {
    next_protocol.iter().any(|value| value == "h2")
        && !next_protocol.iter().any(|value| value == "h3")
}

/// The dial-side ALPN policy: reject the HTTP/3 branch explicitly.
fn require_http2(tls: &TlsSettings) -> io::Result<()> {
    if uses_http2(&tls.alpn) {
        return Ok(());
    }
    if tls.alpn.iter().any(|value| value == "h3") {
        return Err(unsupported(
            "MASQUE over HTTP/3 (h3/QUIC) is not implemented; \
             use HTTP/2 by removing h3 from the TLS ALPN nextProtocol list",
        ));
    }
    Err(unsupported(
        "MASQUE requires HTTP/2: add \"h2\" to the TLS ALPN nextProtocol list",
    ))
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A reusable HTTP/2 MASQUE client connection, the Rust analogue of Go's
/// `dialHTTP2` plus its `http2ClientConn`. Created by [MasqueClient::dial];
/// each target then opens its own extended-CONNECT stream (RFC 8441
/// `:protocol = connect-ip`).
pub struct MasqueClient {
    sender: h2::client::SendRequest<Bytes>,
    settings: Arc<Settings>,
    /// The `:authority` for every request, computed once like Go's
    /// `authority(config, serverName, port)`.
    authority: String,
    _driver: Arc<Driver>,
}

impl MasqueClient {
    /// Establishes the TLS + HTTP/2 connection: TCP connect, `h2` ALPN check
    /// (Go: "the server negotiated ... instead of h2"), then the H2 handshake
    /// with the window/header settings from http2.go.
    pub async fn dial(
        address: SocketAddr,
        host: &str,
        settings: &Settings,
        tls: &TlsSettings,
    ) -> io::Result<Self> {
        require_http2(tls)?;
        settings
            .validate()
            .map_err(|error| unsupported(error.to_string()))?;
        let config = tls
            .build_client_config()
            .map_err(|error| unsupported(error.to_string()))?;
        let tcp = tokio::net::TcpStream::connect(address).await?;
        let connector = TlsConnector::from(config);
        let tls_stream = connector
            .connect(
                tls.server_name(host)
                    .map_err(|error| unsupported(error.to_string()))?,
                tcp,
            )
            .await?;
        match tls_stream.get_ref().1.alpn_protocol() {
            Some(b"h2") => {}
            Some(other) => {
                return Err(invalid(format!(
                    "the server negotiated {} instead of h2",
                    strconv_quote(other)
                )));
            }
            None => return Err(invalid("the server negotiated \"\" instead of h2")),
        }
        let mut builder = h2::client::Builder::new();
        builder
            .max_header_list_size(HTTP2_MAX_HEADER_LIST_SIZE)
            .initial_window_size(HTTP2_STREAM_WINDOW)
            .initial_connection_window_size(HTTP2_CONNECTION_WINDOW)
            .enable_push(false);
        let (sender, connection) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, builder.handshake(tls_stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MASQUE handshake timed out"))?
                .map_err(h2_error)?;
        let driver = Arc::new(Driver(tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "MASQUE client connection ended");
            }
        })));
        // h2's client handshake resolves before the server's SETTINGS are
        // processed, but extended CONNECT needs the server's enable flag from
        // them (Go's http2 transport gates connection readiness on the
        // initial SETTINGS). Yield until the driver has consumed them.
        let settings_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        while !sender.is_extended_connect_protocol_enabled() {
            if tokio::time::Instant::now() >= settings_deadline {
                return Err(unsupported(
                    "http2: the server did not enable extended CONNECT",
                ));
            }
            tokio::task::yield_now().await;
        }
        let server_name = if tls.server_name.is_empty() {
            host.to_owned()
        } else {
            tls.server_name.clone()
        };
        Ok(Self {
            sender,
            settings: Arc::new(settings.clone()),
            authority: settings.authority(&server_name, address.port()),
            _driver: driver,
        })
    }

    /// Opens one extended-CONNECT stream and returns the raw tunnel halves
    /// plus the capsule context id derived from the stream id.
    async fn open(&self, target: &Target) -> io::Result<(SendStream<Bytes>, ResponseFuture, u32)> {
        let path = self
            .settings
            .request_path(target)
            .map_err(|error| unsupported(error.to_string()))?;
        let mut sender = self.sender.clone().ready().await.map_err(h2_error)?;
        if !sender.is_extended_connect_protocol_enabled() {
            // errHTTP2NoExtendedConnect
            return Err(unsupported(
                "http2: the server did not enable extended CONNECT",
            ));
        }
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.authority.as_str())
            .path_and_query(path)
            .build()
            .map_err(|error| invalid(error.to_string()))?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(uri)
            .body(())
            .map_err(|error| invalid(error.to_string()))?;
        request
            .extensions_mut()
            .insert(ConnectProtocol::from_static(CONNECT_IP_PROTOCOL));
        let headers = request.headers_mut();
        headers.insert(
            HeaderName::from_static(CAPSULE_PROTOCOL_HEADER),
            HeaderValue::from_static(CAPSULE_PROTOCOL_VALUE),
        );
        let mut request_headers = self.settings.request_headers();
        if !self.settings.has_user_agent() {
            request_headers.insert("User-Agent".to_owned(), DEFAULT_USER_AGENT.to_owned());
        }
        for (name, value) in &request_headers {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| invalid(error.to_string()))?,
                HeaderValue::from_str(value).map_err(|error| invalid(error.to_string()))?,
            );
        }
        let (response, send) = sender.send_request(request, false).map_err(h2_error)?;
        let context_id = DatagramTunnel::context_id_of(&send);
        Ok((send, response, context_id))
    }

    /// Bridges one TCP target over a new extended-CONNECT stream.
    pub async fn connect_stream(&self, target: &Target) -> io::Result<BoxStream> {
        let (send, response, _) = self.open(target).await?;
        let response = Self::await_response(response).await?;
        let recv = response.into_body();
        Ok(Box::new(H2Stream::client(send, recv)))
    }

    /// Opens a UDP target: a capsule-framed tunnel over one extended-CONNECT
    /// stream, as Go's connectip HTTP/2 body does.
    pub async fn connect_datagram(&self, target: &Target) -> io::Result<DatagramTunnel> {
        let (send, response, context_id) = self.open(target).await?;
        let response = Self::await_response(response).await?;
        let recv = response.into_body();
        Ok(DatagramTunnel::new(
            H2Stream::client(send, recv),
            context_id,
        ))
    }

    async fn await_response(response: ResponseFuture) -> io::Result<http::Response<RecvStream>> {
        let response = tokio::time::timeout(HANDSHAKE_TIMEOUT, response)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "MASQUE CONNECT response timed out")
            })?
            .map_err(h2_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(invalid(format!(
                "connect-ip: server responded with {status}"
            )));
        }
        Ok(response)
    }
}

/// Go's strconv.Quote for a short negotiated-protocol blob.
fn strconv_quote(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(*byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}

/// One HTTP/2 stream adapted to [BoxStream]: at most one received DATA frame
/// is retained, capacity is released only as bytes are consumed, and writes
/// reserve capacity before copying at most [WRITE_CHUNK] bytes. Extended
/// CONNECT streams are bidirectional after the 2xx response, so both roles
/// share this adapter.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    received: Bytes,
    read_closed: bool,
    write_closed: bool,
    data_ended: bool,
    terminal_error: Option<(io::ErrorKind, String)>,
}

impl H2Stream {
    fn client(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self::plain(send, recv)
    }

    fn plain(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            received: Bytes::new(),
            read_closed: false,
            write_closed: false,
            data_ended: false,
            terminal_error: None,
        }
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some((kind, message)) = &self.terminal_error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if self.read_closed || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..64 {
            if !self.received.is_empty() {
                let length = self.received.len().min(buf.remaining());
                buf.put_slice(&self.received[..length]);
                self.received.advance(length);
                self.recv
                    .flow_control()
                    .release_capacity(length)
                    .map_err(h2_error)?;
                return Poll::Ready(Ok(()));
            }
            if !self.data_ended {
                match ready!(self.recv.poll_data(cx)) {
                    Some(Ok(bytes)) => {
                        self.received = bytes;
                        continue;
                    }
                    Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                    None => self.data_ended = true,
                }
            }
            let _ = ready!(self.recv.poll_trailers(cx)).map_err(h2_error)?;
            self.read_closed = true;
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_capacity(&mut self, cx: &mut Context<'_>, desired: usize) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MASQUE HTTP/2 write side closed",
            )));
        }
        if let Poll::Ready(reset) = self.send.poll_reset(cx) {
            return Poll::Ready(Err(match reset {
                Ok(reason) => h2_error(reason.into()),
                Err(error) => h2_error(error),
            }));
        }
        if desired == 0 {
            return Poll::Ready(Ok(0));
        }
        self.send.reserve_capacity(desired.min(WRITE_CHUNK));
        if self.send.capacity() > 0 {
            return Poll::Ready(Ok(self.send.capacity().min(desired).min(WRITE_CHUNK)));
        }
        match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(capacity)) if capacity > 0 => {
                Poll::Ready(Ok(capacity.min(desired).min(WRITE_CHUNK)))
            }
            Some(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Err(error)) => Poll::Ready(Err(h2_error(error))),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MASQUE HTTP/2 stream closed",
            ))),
        }
    }
}

impl AsyncRead for H2Stream {
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

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let length = ready!(self.poll_capacity(cx, bytes.len()))?;
        if length > 0 {
            self.send
                .send_data(Bytes::copy_from_slice(&bytes[..length]), false)
                .map_err(h2_error)?;
        }
        Poll::Ready(Ok(length))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.poll_capacity(cx, 0).map_ok(|_| ())
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.send.send_data(Bytes::new(), true).map_err(h2_error)?;
        self.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if !self.write_closed {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

/// A UDP tunnel over one extended-CONNECT stream: every datagram is one
/// RFC 9484 DATAGRAM capsule (CONTRACT-CAPSULE) in the stream body, and a
/// CLOSE capsule ends the tunnel. The capsule context id follows the
/// quarter-stream-id rule, derived identically on both ends from the stream
/// the tunnel rides.
pub struct DatagramTunnel {
    stream: H2Stream,
    context_id: u32,
    receive: BytesMut,
}

impl DatagramTunnel {
    fn new(stream: H2Stream, context_id: u32) -> Self {
        Self {
            stream,
            context_id,
            receive: BytesMut::new(),
        }
    }

    fn context_id_of(send: &SendStream<Bytes>) -> u32 {
        (u32::from(send.stream_id()) - 1) / 4
    }

    /// Sends one datagram as a DATAGRAM capsule. Go's `Conn.Write` rejects
    /// oversized payloads ("packet too big for the tunnel"); empty payloads
    /// cannot be a capsule datagram and are rejected the same way.
    pub async fn send_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_PACKET_SIZE {
            return Err(invalid(format!(
                "packet too big for the tunnel: {} bytes",
                payload.len()
            )));
        }
        let mut out = Vec::with_capacity(payload.len() + 16);
        capsule::encode(
            &Capsule::Datagram {
                context_id: self.context_id,
                payload: payload.to_vec(),
            },
            &mut out,
        );
        tokio::io::AsyncWriteExt::write_all(&mut self.stream, &out).await
    }

    /// Receives one datagram into `buf` (replacing its contents), returning
    /// the payload length. `Ok(0)` means the peer sent a CLOSE capsule or
    /// ended the stream. Non-datagram capsules (address assignments, route
    /// advertisements, unknown types) are consumed and ignored, like Go's
    /// capsule body demuxer keeping only DATAGRAM for the IP layer.
    pub async fn recv_datagram(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        loop {
            match capsule::decode(&self.receive) {
                Ok((capsule, consumed)) => {
                    self.receive.advance(consumed);
                    match capsule {
                        Capsule::Datagram { payload, .. } => {
                            if payload.is_empty() {
                                continue;
                            }
                            let length = payload.len();
                            buf.clear();
                            buf.extend_from_slice(&payload);
                            return Ok(length);
                        }
                        Capsule::Close => {
                            self.receive.clear();
                            return Ok(0);
                        }
                        // ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT and unknown
                        // capsules carry no datagrams for this transport.
                        Capsule::AddressAssigned { .. }
                        | Capsule::RouteAdvertisement { .. }
                        | Capsule::Unknown { .. } => continue,
                    }
                }
                Err(_) if self.receive.len() < MAX_CAPSULE_BUFFER => {
                    // A partial capsule: read more of the stream body. A
                    // genuinely malformed capsule surfaces only when the
                    // buffer reaches the cap or the stream ends mid-capsule.
                    let mut chunk = [0_u8; WRITE_CHUNK];
                    let read = tokio::io::AsyncReadExt::read(&mut self.stream, &mut chunk).await?;
                    if read == 0 {
                        if self.receive.is_empty() {
                            return Ok(0);
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "MASQUE capsule stream ended mid-capsule",
                        ));
                    }
                    self.receive.extend_from_slice(&chunk[..read]);
                }
                Err(_) => return Err(invalid("MASQUE capsule exceeds the maximum buffered size")),
            }
        }
    }

    /// Sends a CLOSE capsule and ends the stream, the graceful shutdown of
    /// Go's `Conn.Close` for the capsule body.
    pub async fn close(&mut self) -> io::Result<()> {
        let mut out = Vec::new();
        capsule::encode(&Capsule::Close, &mut out);
        tokio::io::AsyncWriteExt::write_all(&mut self.stream, &out).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut self.stream).await
    }
}

/// The handle a [Hub] hands the runtime for one accepted extended CONNECT.
pub enum RequestHandle {
    /// A TCP target: the bridged CONNECT stream, ready for raw bytes.
    Stream(BoxStream),
    /// A UDP target: the capsule datagram tunnel.
    Datagram(DatagramTunnel),
}

/// One accepted extended-CONNECT request: the parsed target plus its handle.
pub struct MasqueRequest {
    pub target: Target,
    pub handle: RequestHandle,
}

/// The server hub: a TLS + HTTP/2 listener that validates every extended
/// CONNECT against the configured path template, answers it with 2xx, and
/// yields the bridged [MasqueRequest] through [Hub::accept]. The validations
/// mirror connectip's `ParseProxyRequest` (method CONNECT,
/// `:protocol = connect-ip`, `capsule-protocol: ?1`) plus this port's
/// per-target path template.
pub struct Hub {
    address: SocketAddr,
    incoming: mpsc::Receiver<io::Result<MasqueRequest>>,
    _driver: Arc<Driver>,
}

impl Hub {
    pub async fn bind(
        address: impl tokio::net::ToSocketAddrs,
        settings: &Settings,
        tls: &TlsSettings,
    ) -> io::Result<Self> {
        settings
            .validate()
            .map_err(|error| unsupported(error.to_string()))?;
        let listener = TcpListener::bind(address).await?;
        let bound = listener.local_addr()?;
        let config = tls
            .build_server_config()
            .map_err(|error| unsupported(error.to_string()))?;
        let (sender, incoming) = mpsc::channel(ACCEPT_QUEUE);
        let state = Arc::new((listener, TlsAcceptor::from(config), settings.clone()));
        let driver = Arc::new(Driver(tokio::spawn(serve(state, sender))));
        Ok(Self {
            address: bound,
            incoming,
            _driver: driver,
        })
    }

    /// The bound loopback address clients dial.
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Accepts one MASQUE request across all connections. Each accepted
    /// request owns its stream; the H2 connection stays open for more.
    pub async fn accept(&mut self) -> io::Result<MasqueRequest> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE hub closed"))?
    }
}

/// Per-connection accept loop. Every request is validated inline; rejected
/// requests get the status connectip's `ProxyRequestParseError` prescribes
/// (405 non-CONNECT, 501 wrong protocol, 400 bad capsule-protocol header) or
/// 404 for an unparsable path, matching the HTTP shape a Go proxy sends.
async fn serve(
    state: Arc<(TcpListener, TlsAcceptor, Settings)>,
    sender: mpsc::Sender<io::Result<MasqueRequest>>,
) {
    loop {
        let (tcp, _) = tokio::select! {
            _ = sender.closed() => return,
            accept = state.0.accept() => match accept {
                Ok(accept) => accept,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
            },
        };
        let acceptor = state.1.clone();
        let settings = state.2.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(%error, "MASQUE TLS accept failed");
                    return;
                }
            };
            let mut builder = h2::server::Builder::new();
            builder
                .max_header_list_size(HTTP2_MAX_HEADER_LIST_SIZE)
                .initial_window_size(HTTP2_STREAM_WINDOW)
                .initial_connection_window_size(HTTP2_CONNECTION_WINDOW)
                .max_concurrent_streams(ACCEPT_QUEUE as u32)
                .enable_connect_protocol();
            let mut connection = match builder.handshake::<_, Bytes>(tls_stream).await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!(%error, "MASQUE H2 server handshake failed");
                    return;
                }
            };
            loop {
                let next = tokio::select! {
                    _ = sender.closed() => break,
                    next = connection.accept() => next,
                };
                let Some(next) = next else { break };
                let (request, responder) = match next {
                    Ok(next) => next,
                    Err(error) => {
                        tracing::debug!(%error, "MASQUE H2 accept failed");
                        break;
                    }
                };
                match handle_request(request, responder, &settings) {
                    Ok(Some(message)) => {
                        if sender.send(Ok(message)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => tracing::debug!(%error, "MASQUE request rejected"),
                }
            }
            // Let already-accepted streams drain before the connection drops.
            connection.graceful_shutdown();
            while connection.accept().await.is_some() {}
        });
    }
}

/// Validates one request and, when accepted, answers 200 and builds the
/// handle. `Ok(None)` means the request was answered with an error status.
fn handle_request(
    request: Request<RecvStream>,
    mut responder: h2::server::SendResponse<Bytes>,
    settings: &Settings,
) -> io::Result<Option<MasqueRequest>> {
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|path| path.path().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let protocol = parts
        .extensions
        .get::<ConnectProtocol>()
        .map(ConnectProtocol::as_str);
    let target = match validate_request(&parts.method, protocol, &parts.headers, &path, settings) {
        Ok(target) => target,
        Err(status) => {
            let response = Response::builder()
                .status(status)
                .version(Version::HTTP_2)
                .body(())
                .map_err(|error| invalid(error.to_string()))?;
            responder.send_response(response, true).map_err(h2_error)?;
            return Ok(None);
        }
    };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|error| invalid(error.to_string()))?;
    response.headers_mut().insert(
        HeaderName::from_static(CAPSULE_PROTOCOL_HEADER),
        HeaderValue::from_static(CAPSULE_PROTOCOL_VALUE),
    );
    let send = responder.send_response(response, false).map_err(h2_error)?;
    let context_id = DatagramTunnel::context_id_of(&send);
    let handle = match target.network {
        Network::Tcp => RequestHandle::Stream(Box::new(H2Stream::plain(send, body))),
        Network::Udp => {
            RequestHandle::Datagram(DatagramTunnel::new(H2Stream::plain(send, body), context_id))
        }
    };
    Ok(Some(MasqueRequest { target, handle }))
}

/// connectip's `ParseProxyRequest` plus the per-target path template. The
/// returned `StatusCode` is what a Go proxy answers with.
fn validate_request(
    method: &Method,
    protocol: Option<&str>,
    headers: &HeaderMap,
    path: &str,
    settings: &Settings,
) -> std::result::Result<Target, StatusCode> {
    if method != Method::CONNECT {
        // ProxyRequestParseError: StatusMethodNotAllowed
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if protocol != Some(CONNECT_IP_PROTOCOL) {
        // ProxyRequestParseError: StatusNotImplemented
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    // ProxyRequestParseError: StatusBadRequest for the capsule-protocol field.
    let capsule = headers
        .get(CAPSULE_PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if capsule != CAPSULE_PROTOCOL_VALUE && !capsule.starts_with("?1;") {
        return Err(StatusCode::BAD_REQUEST);
    }
    settings.parse_target(path).ok_or(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("MASQUE test timed out")
    }

    fn tls_pair() -> (TlsSettings, TlsSettings, String) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["masque.test".into()]).unwrap();
        let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
        let server = TlsSettings {
            alpn: vec!["h2".into()],
            certificates: vec![crate::transport::tls::TlsCertificate {
                certificate: certificate.clone(),
                key: signing_key
                    .serialize_pem()
                    .lines()
                    .map(str::to_owned)
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client = TlsSettings {
            disable_system_root: true,
            alpn: vec!["h2".into()],
            certificates: vec![crate::transport::tls::TlsCertificate {
                certificate,
                usage: "verify".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        (server, client, "masque.test".to_owned())
    }

    #[test]
    fn settings_defaults_match_go_creator() {
        for value in [Value::Null, json!({})] {
            let settings = Settings::from_value(&value).unwrap();
            assert_eq!(settings.host, "");
            assert_eq!(settings.path, DEFAULT_PATH);
            assert!(settings.headers.is_empty());
        }
        let settings = Settings::from_value(&json!({
            "host": "proxy.example", "path": "/tun/*/*",
            "headers": {"x-a": "b"}
        }))
        .unwrap();
        assert_eq!(settings.host, "proxy.example");
        assert_eq!(settings.path, "/tun/*/*");
        assert_eq!(settings.headers["x-a"], "b");
        // encoding/json decodes a null map as empty.
        assert!(
            Settings::from_value(&json!({"headers": null}))
                .unwrap()
                .headers
                .is_empty()
        );
    }

    #[test]
    fn settings_rejection_matrix() {
        for settings in [
            json!("masque"),
            json!({"host": 1}),
            json!({"path": []}),
            json!({"headers": "x"}),
            json!({"headers": {"x": 1}}),
            json!({"unknown": true}),
            json!({"path": "no-slash/*"}),
            json!({"path": "/no-star"}),
            json!({"path": "/tpl/{}/*"}),
            json!({"headers": {"Bad Header": "v"}}),
            json!({"headers": {"x-a": "line\r\nbreak"}}),
            json!({"host": "a b"}),
        ] {
            assert!(Settings::from_value(&settings).is_err(), "{settings}");
        }
        // HTTP/3-only options are named explicitly.
        for key in ["congestion", "bbrProfile", "brutalUp"] {
            let error = Settings::from_value(&json!({ key: "bbr" }))
                .unwrap_err()
                .to_string();
            assert!(error.contains("HTTP/3"), "{error}");
        }
    }

    #[test]
    fn authority_matches_go_dialer() {
        let override_host = Settings {
            host: "set.example".into(),
            ..Default::default()
        };
        assert_eq!(override_host.authority("tls.example", 443), "set.example");
        let settings = Settings::default();
        assert_eq!(settings.authority("example.com", 443), "example.com");
        assert_eq!(settings.authority("example.com", 8443), "example.com:8443");
        assert_eq!(settings.authority("2001:db8::1", 443), "[2001:db8::1]");
        assert_eq!(
            settings.authority("[2001:db8::1]", 8443),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn path_template_round_trips_targets() {
        let settings = Settings::default();
        assert_eq!(
            settings
                .request_path(&Target::tcp("example.com", 443))
                .unwrap(),
            "/.well-known/masque/ip/example.com:443/tcp/"
        );
        assert_eq!(
            settings
                .request_path(&Target::udp("dns.example", 53))
                .unwrap(),
            "/.well-known/masque/ip/dns.example:53/udp/"
        );
        assert_eq!(
            settings
                .parse_target("/.well-known/masque/ip/example.com:443/tcp/")
                .unwrap(),
            Target::tcp("example.com", 443)
        );
        assert_eq!(
            settings
                .parse_target("/.well-known/masque/ip/dns.example:53/udp/")
                .unwrap(),
            Target::udp("dns.example", 53)
        );
        // An escaped IPv6 literal round trips.
        let ipv6 = Target::tcp("2001:db8::1", 443);
        let path = settings.request_path(&ipv6).unwrap();
        assert_eq!(path, "/.well-known/masque/ip/%5B2001:db8::1%5D:443/tcp/");
        assert_eq!(settings.parse_target(&path).unwrap(), ipv6);
        // Custom and single-star (TCP-only) templates.
        let custom = Settings::from_value(&json!({"path": "/m/*/*"})).unwrap();
        assert_eq!(
            custom.request_path(&Target::tcp("a.example", 80)).unwrap(),
            "/m/a.example:80/tcp"
        );
        let single = Settings::from_value(&json!({"path": "/m/*"})).unwrap();
        assert_eq!(
            single.request_path(&Target::tcp("a.example", 80)).unwrap(),
            "/m/a.example:80"
        );
        assert_eq!(
            single.parse_target("/m/a.example:80").unwrap(),
            Target::tcp("a.example", 80)
        );
        assert!(single.request_path(&Target::udp("a.example", 53)).is_err());
        // Unparsable or foreign paths yield None.
        assert!(settings.parse_target("/other/path").is_none());
        assert!(
            settings
                .parse_target("/.well-known/masque/ip/x:443/sctp")
                .is_none()
        );
        assert!(
            settings
                .parse_target("/.well-known/masque/ip/x:443/tcp/extra")
                .is_none()
        );
        assert!(
            settings
                .parse_target("/.well-known/masque/ip/%ZZ/tcp")
                .is_none()
        );
    }

    #[test]
    fn user_agent_matches_go_establish() {
        fn headers(agent: &str) -> BTreeMap<String, String> {
            let value = if agent.is_empty() {
                json!({})
            } else {
                json!({"headers": {"User-Agent": agent}})
            };
            Settings::from_value(&value).unwrap().request_headers()
        }
        assert!(!headers("").contains_key("User-Agent"));
        assert!(!headers("golang").contains_key("User-Agent"));
        let chrome = headers("chrome");
        assert!(chrome["User-Agent"].contains("Chrome/"));
        assert!(!chrome.contains_key("Sec-Fetch-Mode"));
        for (alias, marker) in [
            ("edge", "Edg/"),
            ("firefox", "Firefox/"),
            ("safari", "Version/"),
            ("curl", "curl/"),
        ] {
            assert!(headers(alias)["User-Agent"].contains(marker), "{alias}");
        }
        assert_eq!(headers("literal-agent")["User-Agent"], "literal-agent");
        // Go's writeHeaders drops the hop-by-hop fields it names.
        let excluded = Settings::from_value(&json!({
            "headers": {"Connection": "close", "Content-Length": "5", "x-keep": "1"}
        }))
        .unwrap()
        .request_headers();
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded["x-keep"], "1");
        // An absent User-Agent keeps the map empty; the dialer adds the
        // Go-http-client/2.0 default there.
        assert!(!headers("").contains_key("User-Agent"));
    }

    #[test]
    fn alpn_policy_rejects_http3_branch() {
        assert!(uses_http2(&["h2".to_owned()]));
        assert!(!uses_http2(&["h2".to_owned(), "h3".to_owned()]));
        assert!(!uses_http2(&["h3".to_owned()]));
        assert!(!uses_http2(&[] as &[String]));
        let h3 = TlsSettings {
            alpn: vec!["h3".to_owned()],
            ..Default::default()
        };
        assert!(
            require_http2(&h3)
                .unwrap_err()
                .to_string()
                .contains("HTTP/3")
        );
        let both = TlsSettings {
            alpn: vec!["h2".to_owned(), "h3".to_owned()],
            ..Default::default()
        };
        assert!(
            require_http2(&both)
                .unwrap_err()
                .to_string()
                .contains("HTTP/3")
        );
        let none = TlsSettings::default();
        assert!(require_http2(&none).unwrap_err().to_string().contains("h2"));
    }

    #[test]
    fn request_validation_statuses_match_connectip() {
        let settings = Settings::default();
        let mut request = http::Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        *request.headers_mut() = HeaderMap::from_iter([(
            HeaderName::from_static(CAPSULE_PROTOCOL_HEADER),
            HeaderValue::from_static(CAPSULE_PROTOCOL_VALUE),
        )]);
        let parts = request.into_parts().0;
        let target = Target::tcp("example.com", 443);
        let path = settings.request_path(&target).unwrap();
        assert_eq!(
            validate_request(
                &parts.method,
                Some(CONNECT_IP_PROTOCOL),
                &parts.headers,
                &path,
                &settings
            )
            .unwrap(),
            target
        );
        // Non-CONNECT: 405.
        let mut get = parts.clone();
        get.method = Method::GET;
        assert_eq!(
            validate_request(
                &get.method,
                Some(CONNECT_IP_PROTOCOL),
                &get.headers,
                &path,
                &settings
            )
            .unwrap_err(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        // Wrong :protocol: 501; extended CONNECT without a protocol is the
        // ordinary CONNECT shape connectip also refuses.
        for protocol in [None, Some("connect-udp"), Some("")] {
            assert_eq!(
                validate_request(&parts.method, protocol, &parts.headers, &path, &settings)
                    .unwrap_err(),
                StatusCode::NOT_IMPLEMENTED
            );
        }
        // Missing/invalid capsule-protocol: 400.
        let mut no_capsule = parts.clone();
        no_capsule.headers.remove(CAPSULE_PROTOCOL_HEADER);
        assert_eq!(
            validate_request(
                &no_capsule.method,
                Some(CONNECT_IP_PROTOCOL),
                &no_capsule.headers,
                &path,
                &settings
            )
            .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        let mut bad_capsule = parts.clone();
        bad_capsule.headers.insert(
            HeaderName::from_static(CAPSULE_PROTOCOL_HEADER),
            HeaderValue::from_static("?0"),
        );
        assert_eq!(
            validate_request(
                &bad_capsule.method,
                Some(CONNECT_IP_PROTOCOL),
                &bad_capsule.headers,
                &path,
                &settings
            )
            .unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        // Unparsable path: 404.
        assert_eq!(
            validate_request(
                &parts.method,
                Some(CONNECT_IP_PROTOCOL),
                &parts.headers,
                "/x",
                &settings
            )
            .unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn extended_connect_tcp_bridge_echoes_over_tls() {
        let (server_tls, client_tls, host) = tls_pair();
        let mut hub = Hub::bind("127.0.0.1:0", &Settings::default(), &server_tls)
            .await
            .unwrap();
        let address = hub.local_addr();
        let server = tokio::spawn(async move {
            let request = bounded(hub.accept()).await.expect("hub accept");
            assert_eq!(request.target, Target::tcp("dest.example", 1234));
            let RequestHandle::Stream(mut stream) = request.handle else {
                panic!("a TCP target must bridge a stream");
            };
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, b"bridge me");
            stream.write_all(b"echoed").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let client = bounded(MasqueClient::dial(
            address,
            &host,
            &Settings::default(),
            &client_tls,
        ))
        .await
        .expect("dial");
        let mut stream = bounded(client.connect_stream(&Target::tcp("dest.example", 1234)))
            .await
            .expect("connect stream");
        stream.write_all(b"bridge me").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"echoed");
        bounded(server).await.expect("server task");
    }

    #[tokio::test]
    async fn capsule_datagram_tunnel_round_trips_over_tls() {
        let (server_tls, client_tls, host) = tls_pair();
        let mut hub = Hub::bind("127.0.0.1:0", &Settings::default(), &server_tls)
            .await
            .unwrap();
        let address = hub.local_addr();
        let server = tokio::spawn(async move {
            let request = bounded(hub.accept()).await.expect("hub accept");
            assert_eq!(request.target, Target::udp("dns.example", 53));
            let RequestHandle::Datagram(mut tunnel) = request.handle else {
                panic!("a UDP target must bridge a datagram tunnel");
            };
            let mut payload = Vec::new();
            assert_eq!(
                bounded(tunnel.recv_datagram(&mut payload)).await.unwrap(),
                b"first query".len()
            );
            assert_eq!(payload, b"first query");
            assert_eq!(
                bounded(tunnel.recv_datagram(&mut payload)).await.unwrap(),
                b"second query".len()
            );
            assert_eq!(payload, b"second query");
            tunnel.send_datagram(b"answer").await.unwrap();
            tunnel.close().await.unwrap();
        });
        let client = bounded(MasqueClient::dial(
            address,
            &host,
            &Settings::default(),
            &client_tls,
        ))
        .await
        .expect("dial");
        let mut tunnel = bounded(client.connect_datagram(&Target::udp("dns.example", 53)))
            .await
            .expect("datagram");
        tunnel.send_datagram(b"first query").await.unwrap();
        tunnel.send_datagram(b"second query").await.unwrap();
        let mut payload = Vec::new();
        assert_eq!(
            bounded(tunnel.recv_datagram(&mut payload)).await.unwrap(),
            b"answer".len()
        );
        assert_eq!(payload, b"answer");
        // The peer's CLOSE capsule ends the tunnel.
        assert_eq!(
            bounded(tunnel.recv_datagram(&mut payload)).await.unwrap(),
            0
        );
        // Oversized and empty payloads are rejected like Go's PacketTooBigError.
        assert!(tunnel.send_datagram(&[]).await.is_err());
        let oversized = vec![0_u8; MAX_PACKET_SIZE + 1];
        assert!(tunnel.send_datagram(&oversized).await.is_err());
        bounded(server).await.expect("server task");
    }

    #[tokio::test]
    async fn dial_rejects_http3_and_requires_h2_alpn_before_connecting() {
        let (server_tls, client_tls, host) = tls_pair();
        let hub = Hub::bind("127.0.0.1:0", &Settings::default(), &server_tls)
            .await
            .unwrap();
        let address = hub.local_addr();
        let mut h3 = client_tls.clone();
        h3.alpn = vec!["h3".into()];
        let Err(error) = bounded(MasqueClient::dial(
            address,
            &host,
            &Settings::default(),
            &h3,
        ))
        .await
        else {
            panic!("an h3-only ALPN must not dial");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("HTTP/3"));
        let mut no_alpn = client_tls.clone();
        no_alpn.alpn = vec![];
        let Err(error) = bounded(MasqueClient::dial(
            address,
            &host,
            &Settings::default(),
            &no_alpn,
        ))
        .await
        else {
            panic!("an empty ALPN must not dial");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("h2"));
    }
}
