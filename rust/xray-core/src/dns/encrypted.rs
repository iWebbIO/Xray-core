//! Native HTTP/2 DNS-over-HTTPS and DNS-over-TLS exchanges.
//!
//! This transport layer returns validated DNS messages; the parent resolver
//! still owns caching, address selection and server fallback. Source DoH uses
//! HTTP/2 with ID zero. DoT is a standards-based extension: the inspected Go
//! `app/dns/nameserver.go` has no DoT branch. No query bypasses certificate/name
//! verification, silently invokes the OS resolver, or falls back to cleartext.

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri, header};
use rand::{Rng, distributions::Alphanumeric};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, rustls::pki_types::ServerName};
use tokio_util::sync::CancellationToken;

use super::{
    DnsError, read_tcp_message,
    wire::{self, MAX_MESSAGE_SIZE, Message, Question},
    write_tcp_message,
};
use crate::transport::{BoxStream, tls::TlsSettings};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: u32 = 16 * 1024;
const DNS_MEDIA_TYPE: &str = "application/dns-message";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedProtocol {
    Https,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialMode {
    Routed,
    Local,
}

#[derive(Debug, Clone)]
pub struct EncryptedEndpoint {
    protocol: EncryptedProtocol,
    mode: DialMode,
    host: String,
    port: u16,
    /// An absolute HTTPS URI, preserving the original encoded path/query.
    request_uri: Option<Uri>,
}

impl EncryptedEndpoint {
    /// `https` / `https+local` mirror the Go routed/local distinction. `tls`
    /// and `tls+local` explicitly select the new DoT transport. Empty HTTPS
    /// paths become `/`, as in Go net/http; `/dns-query` is never invented.
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            !value.contains('#'),
            "encrypted DNS URL fragments are not supported"
        );
        let uri: Uri = value.parse().context("invalid encrypted DNS URL")?;
        let (protocol, mode, default_port) = match uri
            .scheme_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "https" => (EncryptedProtocol::Https, DialMode::Routed, 443),
            "https+local" => (EncryptedProtocol::Https, DialMode::Local, 443),
            "tls" => (EncryptedProtocol::Tls, DialMode::Routed, 853),
            "tls+local" => (EncryptedProtocol::Tls, DialMode::Local, 853),
            _ => bail!(
                "unsupported encrypted DNS scheme; expected https, https+local, tls or tls+local"
            ),
        };
        let authority = uri
            .authority()
            .context("encrypted DNS URL requires an authority")?;
        ensure!(
            !authority.as_str().contains('@'),
            "encrypted DNS URL userinfo is not supported"
        );
        let host = uri.host().context("encrypted DNS URL requires a host")?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        ensure!(
            !host.is_empty() && !host.contains('%'),
            "invalid encrypted DNS host; scoped IP addresses are unsupported"
        );
        // Authority::port_u16 returns None for both missing and invalid ports;
        // distinguish them so a typo cannot silently select the default port.
        let port_text = if authority.as_str().starts_with('[') {
            let end = authority
                .as_str()
                .find(']')
                .context("invalid bracketed DNS host")?;
            let suffix = &authority.as_str()[end + 1..];
            if suffix.is_empty() {
                None
            } else {
                Some(
                    suffix
                        .strip_prefix(':')
                        .context("invalid encrypted DNS authority")?,
                )
            }
        } else {
            authority.as_str().rsplit_once(':').map(|(_, port)| port)
        };
        let port = match port_text {
            Some(port) => port.parse::<u16>().context("invalid encrypted DNS port")?,
            None => default_port,
        };
        ensure!(port != 0, "encrypted DNS endpoint port must be nonzero");
        ensure!(
            protocol != EncryptedProtocol::Tls || port != 53,
            "DNS-over-TLS must not use the cleartext DNS port 53"
        );
        let path = uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/");
        let request_uri = if protocol == EncryptedProtocol::Https {
            Some(
                Uri::builder()
                    .scheme("https")
                    .authority(authority.clone())
                    .path_and_query(if path.is_empty() { "/" } else { path })
                    .build()?,
            )
        } else {
            ensure!(
                path.is_empty() || path == "/",
                "DNS-over-TLS endpoint cannot have a path or query"
            );
            None
        };
        // Validate the destination's verification identity without DNS lookup.
        ServerName::try_from(host.clone()).context("invalid encrypted DNS verification name")?;
        Ok(Self {
            protocol,
            mode,
            host,
            port,
            request_uri,
        })
    }

    pub fn protocol(&self) -> EncryptedProtocol {
        self.protocol
    }
    pub fn mode(&self) -> DialMode {
        self.mode
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn request_uri(&self) -> Option<&Uri> {
        self.request_uri.as_ref()
    }
}

/// The runtime receives an owned target when supplying a routed dialer. It may
/// apply its own DNS/bootstrap policy, outbound routing and socket settings.
/// Returned bytes must be a raw TCP stream; this module performs TLS itself.
#[derive(Debug, Clone)]
pub struct DialTarget {
    pub host: String,
    pub port: u16,
    pub mode: DialMode,
    pub bootstrap: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct EncryptedConfig {
    pub endpoint: EncryptedEndpoint,
    /// Dial these IPs at the URL port without changing certificate identity or
    /// HTTP authority. Numeric URL hosts bootstrap themselves when this is empty.
    pub bootstrap: Vec<IpAddr>,
    pub tls: TlsSettings,
    /// One budget covers dial, TLS handshake, protocol exchange and response.
    pub timeout: Duration,
    pub client_ip: Option<IpAddr>,
}

impl EncryptedConfig {
    pub fn new(endpoint: EncryptedEndpoint) -> Self {
        Self {
            endpoint,
            bootstrap: Vec::new(),
            tls: TlsSettings::default(),
            timeout: DEFAULT_TIMEOUT,
            client_ip: None,
        }
    }
}

/// A clonable transport client. Each exchange owns one connection and its
/// protocol driver; dropping/cancelling the exchange drops both. Connection
/// pooling, cross-query HTTP/2 multiplexing and resolver cache wiring are not
/// implemented here.
#[derive(Clone)]
pub struct EncryptedClient {
    config: EncryptedConfig,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    next_id: Arc<AtomicU16>,
}

impl EncryptedClient {
    pub fn new(mut config: EncryptedConfig) -> Result<Self> {
        ensure!(
            !config.timeout.is_zero(),
            "encrypted DNS timeout must be nonzero"
        );
        let protocol_name = match config.endpoint.protocol {
            EncryptedProtocol::Https => "h2",
            EncryptedProtocol::Tls => "dot",
        };
        ensure!(
            config.tls.alpn.is_empty() || config.tls.alpn == [protocol_name],
            "encrypted DNS TLS ALPN does not match its protocol"
        );
        config.tls.alpn = vec![protocol_name.to_owned()];
        let server_name = config.tls.server_name(&config.endpoint.host)?;
        let connector = TlsConnector::from(config.tls.build_client_config()?);
        Ok(Self {
            config,
            connector,
            server_name,
            next_id: Arc::new(AtomicU16::new(0)),
        })
    }

    pub fn endpoint(&self) -> &EncryptedEndpoint {
        &self.config.endpoint
    }

    pub fn dial_target(&self) -> DialTarget {
        let mut bootstrap: Vec<_> = self
            .config
            .bootstrap
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.config.endpoint.port))
            .collect();
        if bootstrap.is_empty()
            && let Ok(ip) = self.config.endpoint.host.parse::<IpAddr>()
        {
            bootstrap.push(SocketAddr::new(ip, self.config.endpoint.port));
        }
        DialTarget {
            host: self.config.endpoint.host.clone(),
            port: self.config.endpoint.port,
            mode: self.config.endpoint.mode,
            bootstrap,
        }
    }

    /// Query a `+local` endpoint, using explicit bootstrap IPs. Routed endpoints
    /// require query_with_dialer so an HTTPS URL cannot silently bypass routing.
    pub async fn query(&self, question: &Question, cancel: &CancellationToken) -> Result<Message> {
        let query = self.make_query(question)?;
        wire::decode(&self.exchange(&query, cancel).await?).map_err(Into::into)
    }

    pub async fn query_with_dialer<F, Fut>(
        &self,
        question: &Question,
        cancel: &CancellationToken,
        dialer: F,
    ) -> Result<Message>
    where
        F: FnOnce(DialTarget) -> Fut,
        Fut: Future<Output = Result<BoxStream>>,
    {
        let query = self.make_query(question)?;
        wire::decode(&self.exchange_with_dialer(&query, cancel, dialer).await?).map_err(Into::into)
    }

    /// Exchange an existing single-question DNS wire message. HTTPS sends ID
    /// zero, validates a zero-ID reply, then restores the caller's original ID.
    /// DoT preserves the wire ID. Flags, ECS and other query options are retained.
    pub async fn exchange(&self, query: &[u8], cancel: &CancellationToken) -> Result<Vec<u8>> {
        ensure!(
            self.config.endpoint.mode == DialMode::Local,
            "routed encrypted DNS requires exchange_with_dialer"
        );
        self.exchange_with_dialer(query, cancel, connect_bootstrap)
            .await
    }

    pub async fn exchange_with_dialer<F, Fut>(
        &self,
        query: &[u8],
        cancel: &CancellationToken,
        dialer: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce(DialTarget) -> Fut,
        Fut: Future<Output = Result<BoxStream>>,
    {
        let request = wire::decode(query)?;
        ensure!(
            !request.header.is_response()
                && request.header.opcode() == 0
                && request.questions.len() == 1,
            "encrypted DNS requires a standard single-question query"
        );
        let original_id = request.header.id;
        let wire_id = if self.config.endpoint.protocol == EncryptedProtocol::Https {
            0
        } else {
            original_id
        };
        let mut query = query.to_vec();
        query[..2].copy_from_slice(&wire_id.to_be_bytes());
        let operation = async {
            let stream = dialer(self.dial_target())
                .await
                .context("encrypted DNS dial failed")?;
            let mut stream = self
                .connector
                .connect(self.server_name.clone(), stream)
                .await
                .context("encrypted DNS TLS handshake failed")?;
            let negotiated = stream.get_ref().1.alpn_protocol();
            let response = match self.config.endpoint.protocol {
                EncryptedProtocol::Https => {
                    ensure!(
                        negotiated == Some(b"h2".as_slice()),
                        "DNS-over-HTTPS server did not negotiate h2"
                    );
                    exchange_https(
                        stream,
                        self.config
                            .endpoint
                            .request_uri
                            .as_ref()
                            .expect("HTTPS URI validated"),
                        &query,
                    )
                    .await?
                }
                EncryptedProtocol::Tls => {
                    ensure!(
                        negotiated.is_none() || negotiated == Some(b"dot".as_slice()),
                        "DNS-over-TLS server negotiated an unexpected protocol"
                    );
                    write_tcp_message(&mut stream, &query).await?;
                    read_tcp_message(&mut stream)
                        .await?
                        .ok_or(DnsError::Malformed("EOF before DNS-over-TLS response"))?
                }
            };
            let message = wire::decode(&response)?;
            validate_response(&message, wire_id, &request.questions[0])?;
            let mut response = response;
            response[..2].copy_from_slice(&original_id.to_be_bytes());
            Ok(response)
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(DnsError::Io(io::Error::new(io::ErrorKind::Interrupted, "encrypted DNS query cancelled")).into()),
            result = tokio::time::timeout(self.config.timeout, operation) => result.map_err(|_| DnsError::Timeout)?,
        }
    }

    fn make_query(&self, question: &Question) -> Result<Vec<u8>> {
        // Avoid asking a routed DoH resolver to bootstrap its own hostname.
        if self.config.endpoint.mode == DialMode::Routed
            && self.config.bootstrap.is_empty()
            && question
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&self.config.endpoint.host)
        {
            bail!(
                "encrypted DNS resolver cannot resolve its own hostname without bootstrap addresses"
            );
        }
        let id = if self.config.endpoint.protocol == EncryptedProtocol::Https {
            0
        } else {
            self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
        };
        let mut bytes = wire::encode_query(id, question, self.config.client_ip)?;
        if self.config.endpoint.protocol == EncryptedProtocol::Https {
            let padding = rand::thread_rng().gen_range(100..=300);
            add_query_padding(&mut bytes, self.config.client_ip, padding)?;
        }
        Ok(bytes)
    }
}

/// Numeric/bootstrap-only local dialing. This never recurses into the resolver
/// being queried or leaks endpoint bootstrap to an implicit system DNS lookup.
pub async fn connect_bootstrap(target: DialTarget) -> Result<BoxStream> {
    ensure!(
        !target.bootstrap.is_empty(),
        "encrypted DNS hostname needs explicit bootstrap addresses or a runtime dialer"
    );
    let mut last_error = None;
    for address in target.bootstrap {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(Box::new(stream));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("nonempty bootstrap addresses").into())
}

fn validate_response(message: &Message, id: u16, question: &Question) -> Result<()> {
    if message.header.id != id
        || !message.header.is_response()
        || message.header.opcode() != 0
        || message.questions.len() != 1
    {
        return Err(DnsError::MismatchedResponse.into());
    }
    let actual = &message.questions[0];
    if !actual.name.eq_ignore_ascii_case(&question.name)
        || actual.record_type != question.record_type
        || actual.class != question.class
    {
        return Err(DnsError::MismatchedResponse.into());
    }
    if message.header.is_truncated() {
        return Err(DnsError::Truncated.into());
    }
    Ok(())
}

/// Called only for the exact encode_query layout above, whose optional OPT is
/// last and contains a single ECS option. Never rewrites arbitrary caller input.
fn add_query_padding(bytes: &mut Vec<u8>, client_ip: Option<IpAddr>, padding: u16) -> Result<()> {
    let extra = usize::from(padding) + 4;
    ensure!(
        bytes.len() + extra + 11 <= MAX_MESSAGE_SIZE,
        "padded DNS query exceeds wire limit"
    );
    if let Some(ip) = client_ip {
        let option_length = if ip.is_ipv4() { 11 } else { 20 };
        let offset = bytes
            .len()
            .checked_sub(option_length + 2)
            .context("invalid generated ECS layout")?;
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        bytes[offset..offset + 2].copy_from_slice(&(length + padding + 4).to_be_bytes());
    } else {
        bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 41]);
        bytes.extend_from_slice(&1350u16.to_be_bytes());
        bytes.extend_from_slice(&0xe000_8000u32.to_be_bytes());
        bytes.extend_from_slice(&(padding + 4).to_be_bytes());
    }
    bytes.extend_from_slice(&12u16.to_be_bytes());
    bytes.extend_from_slice(&padding.to_be_bytes());
    bytes.resize(bytes.len() + usize::from(padding), 0);
    Ok(())
}

async fn exchange_https<S>(stream: S, uri: &Uri, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .max_header_list_size(MAX_HEADER_BYTES)
        .max_send_buffer_size(MAX_MESSAGE_SIZE)
        .handshake::<_, Bytes>(stream)
        .await
        .context("DNS-over-HTTPS HTTP/2 handshake failed")?;
    let operation = async {
        // Match common/utils.H2Base62Pad's compensation for HPACK Huffman
        // encoding: the source samples a desired encoded length of 100..1000.
        let padding_length =
            (rand::thread_rng().gen_range(100..=1000) as f64 * 1.2493702770780857) as usize;
        let padding: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(padding_length)
            .map(char::from)
            .collect();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri.clone())
            .header(header::ACCEPT, DNS_MEDIA_TYPE)
            .header(header::CONTENT_TYPE, DNS_MEDIA_TYPE)
            .header(header::CONTENT_LENGTH, query.len())
            .header(header::ACCEPT_ENCODING, "identity")
            .header("x-padding", padding)
            .body(())?;
        let mut sender = sender
            .ready()
            .await
            .context("DNS-over-HTTPS stream unavailable")?;
        let (response, mut send) = sender.send_request(request, false)?;
        send.send_data(Bytes::copy_from_slice(query), true)?;
        let response = response
            .await
            .context("DNS-over-HTTPS response headers failed")?;
        ensure!(
            response.status() == StatusCode::OK,
            "DNS-over-HTTPS returned HTTP {}",
            response.status()
        );
        let headers = response.headers();
        let content_types: Vec<_> = headers.get_all(header::CONTENT_TYPE).iter().collect();
        ensure!(
            content_types.len() == 1,
            "DNS-over-HTTPS response requires one Content-Type"
        );
        let media_type = content_types[0]
            .to_str()?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        ensure!(
            media_type.eq_ignore_ascii_case(DNS_MEDIA_TYPE),
            "DNS-over-HTTPS returned an unexpected media type"
        );
        for encoding in headers.get_all(header::CONTENT_ENCODING) {
            ensure!(
                encoding.to_str()?.eq_ignore_ascii_case("identity"),
                "compressed DNS-over-HTTPS responses are unsupported"
            );
        }
        let content_lengths: Vec<_> = headers.get_all(header::CONTENT_LENGTH).iter().collect();
        ensure!(
            content_lengths.len() <= 1,
            "duplicate DNS-over-HTTPS Content-Length"
        );
        let expected_length = content_lengths
            .first()
            .map(|value| {
                value
                    .to_str()?
                    .parse::<usize>()
                    .context("invalid DNS-over-HTTPS Content-Length")
            })
            .transpose()?;
        if let Some(length) = expected_length {
            ensure!(
                (12..=MAX_MESSAGE_SIZE).contains(&length),
                "DNS-over-HTTPS body length outside DNS wire bounds"
            );
        }
        let mut body = response.into_body();
        let mut output = Vec::with_capacity(expected_length.unwrap_or(512));
        while let Some(chunk) = body.data().await {
            let chunk = chunk.context("DNS-over-HTTPS response body failed")?;
            ensure!(
                chunk.len() <= MAX_MESSAGE_SIZE.saturating_sub(output.len()),
                "DNS-over-HTTPS body exceeds DNS wire limit"
            );
            output.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len())?;
        }
        let _trailers = body.trailers().await?;
        ensure!(
            output.len() >= 12,
            "DNS-over-HTTPS body shorter than DNS header"
        );
        if let Some(length) = expected_length {
            ensure!(
                output.len() == length,
                "DNS-over-HTTPS Content-Length mismatch"
            );
        }
        Ok(output)
    };
    tokio::pin!(operation, connection);
    // Both futures are owned here. A cancellation/timeout drops the connection
    // driver immediately instead of leaving a detached query running.
    tokio::select! {
        biased;
        result = &mut operation => result,
        result = &mut connection => {
            result.context("DNS-over-HTTPS HTTP/2 connection failed")?;
            operation.await
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls::TlsCertificate;
    use std::sync::atomic::AtomicBool;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::{JoinHandle, JoinSet},
    };
    use tokio_rustls::TlsAcceptor;

    fn tls_pair(alpn: &str) -> (TlsSettings, TlsSettings) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["resolver.example".into()]).unwrap();
        let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
        let server = TlsSettings {
            alpn: vec![alpn.into()],
            certificates: vec![TlsCertificate {
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
            certificates: vec![TlsCertificate {
                certificate,
                usage: "verify".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        (server, client)
    }

    fn question() -> Question {
        Question::new("Example.COM", wire::RecordType::A).unwrap()
    }

    fn dns_reply(query: &[u8]) -> Vec<u8> {
        let request = wire::decode(query).unwrap();
        wire::encode_response(
            request.header.id,
            &request.questions[0],
            &["192.0.2.17".parse().unwrap()],
            123,
            0,
            None,
            MAX_MESSAGE_SIZE,
        )
        .unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum Behavior {
        Good,
        Status,
        MissingType,
        WrongType,
        Oversize,
        AdvertisedOversize,
        WrongId,
        WrongQuestion,
        QueryInsteadOfResponse,
        Truncated,
        WrongLength,
        Compressed,
        Stall,
    }

    #[derive(Debug)]
    struct Observed {
        method: Method,
        uri: Uri,
        headers: http::HeaderMap,
        query: Vec<u8>,
        sni: Option<String>,
    }

    async fn https_fixture(
        behavior: Behavior,
    ) -> (EncryptedConfig, JoinHandle<()>, oneshot::Receiver<Observed>) {
        let (server_tls, client_tls) = tls_pair("h2");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = EncryptedEndpoint::parse(&format!(
            "https+local://resolver.example:{port}/custom%2Fquery?token=fixture"
        ))
        .unwrap();
        let mut config = EncryptedConfig::new(endpoint);
        config.bootstrap = vec!["127.0.0.1".parse().unwrap()];
        config.tls = client_tls;
        config.timeout = Duration::from_secs(2);
        let (observed, receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_tls.build_server_config().unwrap());
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            let sni = stream.get_ref().1.server_name().map(str::to_owned);
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            let mut tasks = JoinSet::new();
            let mut observed = Some(observed);
            while let Some(request) = connection.accept().await {
                let Ok((request, mut respond)) = request else {
                    break;
                };
                let observed = observed.take().expect("one request per fixture connection");
                let sni = sni.clone();
                tasks.spawn(async move {
                    let (parts, mut body) = request.into_parts();
                    let mut query = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        query.extend_from_slice(&chunk);
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                    }
                    let _ = observed.send(Observed {
                        method: parts.method,
                        uri: parts.uri,
                        headers: parts.headers,
                        query: query.clone(),
                        sni,
                    });
                    if matches!(behavior, Behavior::Stall) {
                        std::future::pending::<()>().await;
                    }
                    let mut payload = dns_reply(&query);
                    match behavior {
                        Behavior::WrongId => payload[1] ^= 1,
                        Behavior::WrongQuestion => payload[13] = b'Z',
                        Behavior::QueryInsteadOfResponse => payload[2] &= 0x7f,
                        Behavior::Truncated => payload[2] |= 2,
                        Behavior::Oversize => payload = vec![0; MAX_MESSAGE_SIZE + 1],
                        _ => (),
                    }
                    let status = if matches!(behavior, Behavior::Status) {
                        503
                    } else {
                        200
                    };
                    let mut response = http::Response::builder().status(status);
                    if !matches!(behavior, Behavior::MissingType) {
                        response = response.header(
                            header::CONTENT_TYPE,
                            if matches!(behavior, Behavior::WrongType) {
                                "text/html"
                            } else {
                                "Application/DNS-Message; fixture=yes"
                            },
                        );
                    }
                    if matches!(behavior, Behavior::AdvertisedOversize) {
                        response = response.header(header::CONTENT_LENGTH, MAX_MESSAGE_SIZE + 1);
                    } else if matches!(behavior, Behavior::WrongLength) {
                        response = response.header(header::CONTENT_LENGTH, payload.len() + 1);
                    } else if !matches!(behavior, Behavior::Oversize) {
                        response = response.header(header::CONTENT_LENGTH, payload.len());
                    }
                    if matches!(behavior, Behavior::Compressed) {
                        response = response.header(header::CONTENT_ENCODING, "gzip");
                    }
                    if let Ok(mut send) = respond.send_response(response.body(()).unwrap(), false) {
                        let _ = send.send_data(Bytes::from(payload), true);
                    }
                });
            }
            // Also aborts any deliberately stalled mock handler after the
            // client drops its connection, making cancellation testable.
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        (config, server, receiver)
    }

    async fn finish(server: JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("query driver left its connection open")
            .unwrap();
    }

    #[test]
    fn parses_source_doh_urls_and_explicit_dot_extension() {
        let endpoint =
            EncryptedEndpoint::parse("https+local://[2001:db8::1]:5443/a%2Fb?x=1").unwrap();
        assert_eq!(endpoint.host(), "2001:db8::1");
        assert_eq!(endpoint.port(), 5443);
        assert_eq!(endpoint.mode(), DialMode::Local);
        assert_eq!(
            endpoint.request_uri().unwrap().to_string(),
            "https://[2001:db8::1]:5443/a%2Fb?x=1"
        );
        let endpoint = EncryptedEndpoint::parse("https://dns.example").unwrap();
        assert_eq!(endpoint.request_uri().unwrap().path(), "/");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(endpoint.mode(), DialMode::Routed);
        let endpoint = EncryptedEndpoint::parse("tls+local://dns.example").unwrap();
        assert_eq!(endpoint.protocol(), EncryptedProtocol::Tls);
        assert_eq!(endpoint.port(), 853);
        for bad in [
            "http://example.com",
            "h2c://example.com",
            "https://user@example.com/path",
            "https://example.com:0",
            "https://example.com:65536",
            "https://example.com:abc",
            "https://example.com:",
            "https://example.com/#fragment",
            "tls://example.com/dns-query",
            "tls://example.com:53",
            "tls://example.com/?q=1",
            "https://example.com/\r\ninjected",
        ] {
            assert!(EncryptedEndpoint::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn generated_doh_queries_include_source_padding_and_optional_ecs() {
        for client_ip in [
            None,
            Some("192.0.2.99".parse().unwrap()),
            Some("2001:db8::99".parse().unwrap()),
        ] {
            let mut config = EncryptedConfig::new(
                EncryptedEndpoint::parse("https+local://resolver.example/dns-query").unwrap(),
            );
            config.client_ip = client_ip;
            let client = EncryptedClient::new(config).unwrap();
            let query = wire::decode(&client.make_query(&question()).unwrap()).unwrap();
            assert_eq!(query.header.id, 0);
            assert_eq!(query.additionals.len(), 1);
            let opt = &query.additionals[0];
            assert_eq!(opt.record_type, wire::RecordType::OPT);
            assert_eq!(opt.class, 1350);
            assert_eq!(opt.ttl, 0xe000_8000);
            let wire::RecordData::Other(data) = &opt.data else {
                panic!("OPT is opaque data")
            };
            let mut cursor = 0;
            if client_ip.is_some() {
                assert_eq!(&data[..2], &8u16.to_be_bytes());
                let length = u16::from_be_bytes([data[2], data[3]]) as usize;
                cursor = 4 + length;
            }
            assert_eq!(&data[cursor..cursor + 2], &12u16.to_be_bytes());
            let padding = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
            assert!((100..=300).contains(&padding));
            assert_eq!(data.len(), cursor + 4 + padding);
            assert!(data[cursor + 4..].iter().all(|byte| *byte == 0));
        }
    }

    #[tokio::test]
    async fn actual_https_h2_uses_verified_name_path_zero_id_and_restores_caller_id() {
        let (config, server, observed) = https_fixture(Behavior::Good).await;
        let client = EncryptedClient::new(config).unwrap();
        let query = wire::encode_query(0xbeef, &question(), None).unwrap();
        let reply = client
            .exchange(&query, &CancellationToken::new())
            .await
            .unwrap();
        let response = wire::decode(&reply).unwrap();
        assert_eq!(response.header.id, 0xbeef);
        assert_eq!(response.questions[0], question());
        assert_eq!(response.answers[0].ttl, 123);
        let observed = observed.await.unwrap();
        assert_eq!(observed.method, Method::POST);
        assert_eq!(
            observed.uri.path_and_query().unwrap().as_str(),
            "/custom%2Fquery?token=fixture"
        );
        assert_eq!(observed.uri.host(), Some("resolver.example"));
        assert_eq!(observed.sni.as_deref(), Some("resolver.example"));
        assert_eq!(observed.headers[header::ACCEPT], DNS_MEDIA_TYPE);
        assert_eq!(observed.headers[header::CONTENT_TYPE], DNS_MEDIA_TYPE);
        let padding = observed.headers["x-padding"].to_str().unwrap();
        assert!((124..=1249).contains(&padding.len()));
        assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(&observed.query[..2], &[0, 0]);
        assert_eq!(&observed.query[2..], &query[2..]);
        finish(server).await;
    }

    #[tokio::test]
    async fn http_and_dns_failures_never_become_successful_answers() {
        for behavior in [
            Behavior::Status,
            Behavior::MissingType,
            Behavior::WrongType,
            Behavior::Oversize,
            Behavior::AdvertisedOversize,
            Behavior::WrongId,
            Behavior::WrongQuestion,
            Behavior::QueryInsteadOfResponse,
            Behavior::Truncated,
            Behavior::WrongLength,
            Behavior::Compressed,
        ] {
            let (config, server, _) = https_fixture(behavior).await;
            let client = EncryptedClient::new(config).unwrap();
            let result = client.query(&question(), &CancellationToken::new()).await;
            assert!(result.is_err(), "accepted {behavior:?}");
            finish(server).await;
        }
    }

    #[tokio::test]
    async fn tls_rejects_wrong_server_name_and_untrusted_root() {
        for wrong_name in [true, false] {
            let (mut config, server, _) = https_fixture(Behavior::Good).await;
            if wrong_name {
                config.tls.server_name = "different.example".into();
            } else {
                let (_, other_roots) = tls_pair("h2");
                config.tls = other_roots;
            }
            let client = EncryptedClient::new(config).unwrap();
            assert!(
                client
                    .query(&question(), &CancellationToken::new())
                    .await
                    .is_err()
            );
            finish(server).await;
        }
    }

    #[tokio::test]
    async fn dot_exchanges_real_tls_frames_preserving_ids_and_accepts_no_alpn() {
        for no_alpn in [false, true] {
            let (server_settings, client_settings) = tls_pair("dot");
            let mut server_config = server_settings.build_server_config().unwrap();
            if no_alpn {
                // The shared TLS helper's empty setting defaults to HTTP ALPN;
                // this fixture intentionally models a legacy DoT TLS server.
                Arc::make_mut(&mut server_config).alpn_protocols.clear();
            }
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = TlsAcceptor::from(server_config)
                    .accept(stream)
                    .await
                    .unwrap();
                assert_eq!(stream.get_ref().1.server_name(), Some("resolver.example"));
                let query = read_tcp_message(&mut stream).await.unwrap().unwrap();
                assert_eq!(wire::decode(&query).unwrap().header.id, 0x4567);
                let reply = dns_reply(&query);
                // A split length prefix exercises TLS/frame short-read handling.
                let length = (reply.len() as u16).to_be_bytes();
                stream.write_all(&length[..1]).await.unwrap();
                stream.flush().await.unwrap();
                stream.write_all(&length[1..]).await.unwrap();
                stream.write_all(&reply).await.unwrap();
                stream.flush().await.unwrap();
                let mut closed = [0];
                let _ = stream.read(&mut closed).await;
            });
            let mut config = EncryptedConfig::new(
                EncryptedEndpoint::parse(&format!("tls+local://127.0.0.1:{}", address.port()))
                    .unwrap(),
            );
            config.tls = client_settings;
            config.tls.server_name = "resolver.example".into();
            let client = EncryptedClient::new(config).unwrap();
            let query = wire::encode_query(0x4567, &question(), None).unwrap();
            let reply = client
                .exchange(&query, &CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(wire::decode(&reply).unwrap().header.id, 0x4567);
            finish(server).await;
        }
    }

    #[tokio::test]
    async fn cancellation_drops_h2_connection_and_pending_response() {
        let (config, server, observed) = https_fixture(Behavior::Stall).await;
        let client = EncryptedClient::new(config).unwrap();
        let cancel = CancellationToken::new();
        let query_cancel = cancel.clone();
        let pending = tokio::spawn(async move { client.query(&question(), &query_cancel).await });
        tokio::time::timeout(Duration::from_secs(2), observed)
            .await
            .unwrap()
            .unwrap();
        cancel.cancel();
        let error = pending.await.unwrap().unwrap_err();
        assert!(
            matches!(error.downcast_ref::<DnsError>(), Some(DnsError::Io(error)) if error.kind() == io::ErrorKind::Interrupted)
        );
        finish(server).await;
    }

    #[tokio::test]
    async fn timeout_covers_dial_and_drops_dial_future() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let mut config =
            EncryptedConfig::new(EncryptedEndpoint::parse("tls://resolver.example").unwrap());
        config.timeout = Duration::from_millis(20);
        let client = EncryptedClient::new(config).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&dropped));
        let query = wire::encode_query(7, &question(), None).unwrap();
        let error = client
            .exchange_with_dialer(&query, &CancellationToken::new(), move |_| async move {
                let _guard = guard;
                std::future::pending::<Result<BoxStream>>().await
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<DnsError>(),
            Some(DnsError::Timeout)
        ));
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn no_implicit_system_bootstrap_or_routing_bypass_and_precancel_avoids_dial() {
        let local = EncryptedClient::new(EncryptedConfig::new(
            EncryptedEndpoint::parse("https+local://resolver.invalid/dns-query").unwrap(),
        ))
        .unwrap();
        assert!(
            local
                .query(&question(), &CancellationToken::new())
                .await
                .unwrap_err()
                .to_string()
                .contains("dial failed")
        );
        let routed = EncryptedClient::new(EncryptedConfig::new(
            EncryptedEndpoint::parse("https://127.0.0.1/dns-query").unwrap(),
        ))
        .unwrap();
        assert!(
            routed
                .query(&question(), &CancellationToken::new())
                .await
                .unwrap_err()
                .to_string()
                .contains("requires exchange_with_dialer")
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let query = wire::encode_query(7, &question(), None).unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let called_copy = Arc::clone(&called);
        let error = routed
            .exchange_with_dialer(&query, &cancel, move |_| async move {
                called_copy.store(true, Ordering::Relaxed);
                bail!("cancelled query must not reach dialer")
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(!called.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn routed_dialer_receives_original_host_and_keeps_tls_verification() {
        let (mut config, server, observed) = https_fixture(Behavior::Good).await;
        let endpoint = config.endpoint.request_uri().unwrap().to_string();
        config.endpoint = EncryptedEndpoint::parse(&endpoint).unwrap();
        let client = EncryptedClient::new(config).unwrap();
        let answer = client
            .query_with_dialer(
                &question(),
                &CancellationToken::new(),
                |target| async move {
                    assert_eq!(target.mode, DialMode::Routed);
                    assert_eq!(target.host, "resolver.example");
                    connect_bootstrap(target).await
                },
            )
            .await
            .unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            observed.await.unwrap().sni.as_deref(),
            Some("resolver.example")
        );
        finish(server).await;
    }

    #[test]
    fn invalid_tls_policy_zero_timeout_and_recursive_bootstrap_are_rejected() {
        let endpoint = EncryptedEndpoint::parse("https://resolver.example/dns-query").unwrap();
        let mut config = EncryptedConfig::new(endpoint.clone());
        config.timeout = Duration::ZERO;
        assert!(EncryptedClient::new(config).is_err());
        let mut config = EncryptedConfig::new(endpoint.clone());
        config.tls.allow_insecure = true;
        assert!(EncryptedClient::new(config).is_err());
        let mut config = EncryptedConfig::new(endpoint.clone());
        config.tls.alpn = vec!["http/1.1".into()];
        assert!(EncryptedClient::new(config).is_err());
        let client = EncryptedClient::new(EncryptedConfig::new(endpoint)).unwrap();
        assert!(
            client
                .make_query(&Question::new("resolver.example", wire::RecordType::A).unwrap())
                .is_err()
        );
    }
}
