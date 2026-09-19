//! Native Xray WebSocket byte streams.
//!
//! The caller establishes TCP/TLS (with HTTP/1.1 ALPN) before passing the stream.
//! Listener PROXY protocol handling and trusted forwarded-address processing
//! belong to that caller. Message boundaries are deliberately hidden, as in
//! `transport/internet/websocket/connection.go`.

use std::{
    collections::BTreeMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use base64::{
    Engine, alphabet,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use rand::{RngCore, rngs::OsRng};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use super::BoxStream;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEADER_BYTES: usize = 8192;
const MAX_HEADERS: usize = 128;
const READ_CHUNK: usize = 16 * 1024;
const WRITE_CHUNK: usize = 64 * 1024;
const QUEUE_DEPTH: usize = 8;
const GO_RAW_URL_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);
const GO_STANDARD_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

/// Settings after Xray's JSON `?ed=` extraction and deprecated Host migration.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub early_data_limit: usize,
    pub heartbeat_period: Duration,
}

impl Config {
    pub fn normalized_path(&self) -> String {
        if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        }
    }

    /// Parse `wsSettings`, including Xray's `?ed=N` convention. A listener must
    /// handle PROXY protocol itself, so this helper rejects that setting rather
    /// than accidentally treating the PROXY preface as an HTTP request.
    pub fn from_json(value: &serde_json::Value) -> io::Result<Self> {
        #[derive(Default, serde::Deserialize)]
        #[serde(default, rename_all = "camelCase")]
        struct JsonConfig {
            host: String,
            path: String,
            headers: BTreeMap<String, String>,
            heartbeat_period: u32,
            accept_proxy_protocol: bool,
        }
        let raw: JsonConfig = serde_json::from_value(value.clone()).map_err(invalid_input)?;
        if raw.accept_proxy_protocol {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WebSocket acceptProxyProtocol must be handled by the outer listener",
            ));
        }
        let (path, early_data_limit) = extract_early_data(&raw.path)?;
        let mut config = Self {
            host: raw.host,
            path,
            headers: raw.headers,
            early_data_limit,
            heartbeat_period: Duration::from_secs(raw.heartbeat_period.into()),
        };
        let legacy_host = config
            .headers
            .keys()
            .find(|k| k.eq_ignore_ascii_case("host"))
            .cloned();
        if let Some(key) = legacy_host {
            let host = config.headers.remove(&key).unwrap_or_default();
            if config.host.is_empty() {
                config.host = host;
            }
        }
        config
            .headers
            .retain(|k, _| !k.eq_ignore_ascii_case("host"));
        Ok(config)
    }
}

/// HTTP metadata is untrusted. In particular `X-Forwarded-For` must only be
/// applied by a caller that also knows the socket peer and trusted proxy list.
#[derive(Clone, Debug)]
pub struct RequestMetadata {
    pub host: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub early_data_len: usize,
}

pub struct Accepted {
    pub stream: BoxStream,
    pub request: RequestMetadata,
}

/// Upgrade an already-connected stream. With early data enabled the HTTP
/// handshake starts on the first nonempty write, matching Go's delayed dial.
/// The destination argument is the address alone, without its port; Go uses
/// that address for Host after the configured host and TLS server name.
pub async fn client(
    stream: BoxStream,
    destination_host: &str,
    tls_server_name: Option<&str>,
    config: Config,
) -> io::Result<BoxStream> {
    let host = if !config.host.is_empty() {
        config.host.clone()
    } else if let Some(name) = tls_server_name.filter(|name| !name.is_empty()) {
        name.to_owned()
    } else {
        destination_host.to_owned()
    };
    validate_config(&config, &host)?;
    if config.early_data_limit == 0 {
        client_handshake(stream, host, config, None).await
    } else {
        Ok(Box::new(DelayedClient::new(stream, host, config)))
    }
}

pub async fn server(stream: BoxStream, config: Config) -> io::Result<BoxStream> {
    Ok(server_with_metadata(stream, config).await?.stream)
}

pub async fn server_with_metadata(mut stream: BoxStream, config: Config) -> io::Result<Accepted> {
    if config.heartbeat_period.as_secs() > u64::from(u32::MAX) {
        return Err(invalid_input(
            "WebSocket heartbeat period exceeds uint32 seconds",
        ));
    }
    let result = tokio::time::timeout(Duration::from_secs(4), async {
        let (head, tail) = read_head(&mut stream).await?;
        match check_request(&head, &config) {
            Ok((request, key, early, protocol)) => {
                let mut response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n", accept_key(&key));
                if let Some(protocol) = protocol { response.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n")); }
                response.push_str("\r\n");
                stream.write_all(response.as_bytes()).await?;
                stream.flush().await?;
                Ok((request, tail, early))
            }
            Err((status, error)) => {
                let reason = match status { 404 => "Not Found", 405 => "Method Not Allowed", 426 => "Upgrade Required", _ => "Bad Request" };
                let extra = if status == 426 { "Sec-WebSocket-Version: 13\r\n" } else { "" };
                let response = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n{extra}\r\n");
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                Err(error)
            }
        }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket server handshake timed out"))??;
    let (request, tail, early) = result;
    let stream = WebSocketStream::new(
        prefixed(stream, tail),
        Role::Server,
        early,
        config.heartbeat_period,
    );
    Ok(Accepted {
        stream: Box::new(stream),
        request,
    })
}

async fn client_handshake(
    mut stream: BoxStream,
    host: String,
    config: Config,
    early: Option<Vec<u8>>,
) -> io::Result<BoxStream> {
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    let key = STANDARD.encode(nonce);
    let request = build_request(&host, &config, &key, early.as_deref())?;
    let tail = tokio::time::timeout(Duration::from_secs(8), async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let (head, tail) = read_head(&mut stream).await?;
        check_response(&head, &key)?;
        Ok::<_, io::Error>(tail)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "WebSocket client handshake timed out",
        )
    })??;
    Ok(Box::new(WebSocketStream::new(
        prefixed(stream, tail),
        Role::Client,
        Vec::new(),
        config.heartbeat_period,
    )))
}

fn validate_config(config: &Config, host: &str) -> io::Result<()> {
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 127) {
        return Err(invalid_input("invalid WebSocket Host"));
    }
    request_target(&config.normalized_path())?;
    if config.heartbeat_period.as_secs() > u64::from(u32::MAX) {
        return Err(invalid_input(
            "WebSocket heartbeat period exceeds uint32 seconds",
        ));
    }
    for (name, value) in &config.headers {
        if name.is_empty()
            || !name.bytes().all(is_token)
            || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127)
        {
            return Err(invalid_input("invalid WebSocket HTTP header"));
        }
        if [
            "upgrade",
            "connection",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "content-length",
            "transfer-encoding",
        ]
        .iter()
        .any(|key| name.eq_ignore_ascii_case(key))
        {
            return Err(invalid_input(format!("reserved WebSocket header: {name}")));
        }
    }
    Ok(())
}

fn build_request(
    host: &str,
    config: &Config,
    key: &str,
    early: Option<&[u8]>,
) -> io::Result<String> {
    validate_config(config, host)?;
    let target = request_target(&config.normalized_path())?;
    let mut headers = BTreeMap::new();
    let mut extra_values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in &config.headers {
        let key = canonical_header_name(name);
        match headers.entry(key.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(value.clone());
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                extra_values.entry(key).or_default().push(value.clone());
            }
        }
    }
    let original_headers = headers.clone();
    apply_browser_headers(&mut headers);
    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || (early.is_some() && name.eq_ignore_ascii_case("sec-websocket-protocol"))
        {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
        // http.Header.Add preserves separate values after canonicalization.
        // A masquerade helper's Set replaces all configured values for a key.
        if original_headers.get(&name) == Some(&value) {
            for extra in extra_values.get(&name).into_iter().flatten() {
                request.push_str(&format!("{name}: {extra}\r\n"));
            }
        }
    }
    if let Some(early) = early {
        request.push_str(&format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            URL_SAFE_NO_PAD.encode(early)
        ));
    }
    request.push_str("\r\n");
    if request.len() > MAX_HEADER_BYTES {
        return Err(invalid_input("WebSocket request headers exceed 8192 bytes"));
    }
    Ok(request)
}

fn apply_browser_headers(headers: &mut BTreeMap<String, String>) {
    super::httpupgrade::apply_browser_headers(headers);
}

fn canonical_header_name(name: &str) -> String {
    let mut first = true;
    name.chars()
        .map(|ch| {
            let result = if first {
                ch.to_ascii_uppercase()
            } else {
                ch.to_ascii_lowercase()
            };
            first = ch == '-';
            result
        })
        .collect()
}

fn accept_key(key: &str) -> String {
    let mut hash = Sha1::new();
    hash.update(key);
    hash.update(GUID);
    STANDARD.encode(hash.finalize())
}

async fn read_head(stream: &mut BoxStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::with_capacity(1024);
    loop {
        if let Some(end) = data
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
        {
            if end > MAX_HEADER_BYTES {
                return Err(invalid_data("WebSocket HTTP headers exceed 8192 bytes"));
            }
            let tail = data.split_off(end);
            return Ok((data, tail));
        }
        if data.len() >= MAX_HEADER_BYTES {
            return Err(invalid_data("WebSocket HTTP headers exceed 8192 bytes"));
        }
        let mut block = [0; 1024];
        let n = stream.read(&mut block).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF during WebSocket handshake",
            ));
        }
        data.extend_from_slice(&block[..n]);
    }
}

fn header<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

fn has_token(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .any(|h| {
            h.value
                .split(|b| *b == b',')
                .any(|v| std::str::from_utf8(v).is_ok_and(|v| v.trim().eq_ignore_ascii_case(token)))
        })
}

fn check_response(head: &[u8], key: &str) -> io::Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    if !response.parse(head).map_err(invalid_data)?.is_complete()
        || response.code != Some(101)
        || !has_token(response.headers, "Upgrade", "websocket")
        || !has_token(response.headers, "Connection", "upgrade")
        || header(response.headers, "Sec-WebSocket-Accept") != Some(accept_key(key).as_str())
    {
        return Err(invalid_data("invalid WebSocket upgrade response"));
    }
    if header(response.headers, "Sec-WebSocket-Extensions").is_some_and(|v| !v.is_empty()) {
        return Err(invalid_data("unsolicited WebSocket extensions"));
    }
    Ok(())
}

type CheckedRequest = (RequestMetadata, String, Vec<u8>, Option<String>);
fn check_request(head: &[u8], config: &Config) -> Result<CheckedRequest, (u16, io::Error)> {
    let bad = |status, message| (status, invalid_data(message));
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    if !request
        .parse(head)
        .map_err(|e| (400, invalid_data(e)))?
        .is_complete()
    {
        return Err(bad(400, "incomplete WebSocket request"));
    }
    let target = request
        .path
        .ok_or_else(|| bad(400, "missing WebSocket request target"))?;
    let host = header(request.headers, "Host").ok_or_else(|| bad(400, "missing WebSocket Host"))?;
    if request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"))
        .count()
        != 1
    {
        return Err(bad(400, "duplicate WebSocket Host"));
    }
    let path = target.split('?').next().unwrap_or(target);
    let decoded = percent_decode(path, false).map_err(|e| (400, e))?;
    if (!config.host.is_empty() && !valid_host(host, &config.host))
        || decoded != config.normalized_path().as_bytes()
    {
        return Err(bad(404, "WebSocket host or path mismatch"));
    }
    if request.method != Some("GET") {
        return Err(bad(405, "WebSocket upgrade requires GET"));
    }
    if request.version != Some(1) {
        return Err(bad(400, "WebSocket upgrade requires HTTP/1.1"));
    }
    if !has_token(request.headers, "Connection", "upgrade")
        || !has_token(request.headers, "Upgrade", "websocket")
    {
        return Err(bad(400, "missing WebSocket upgrade headers"));
    }
    if !has_token(request.headers, "Sec-WebSocket-Version", "13") {
        return Err(bad(426, "unsupported WebSocket version"));
    }
    let key = header(request.headers, "Sec-WebSocket-Key")
        .ok_or_else(|| bad(400, "missing WebSocket key"))?;
    if !GO_STANDARD_BASE64
        .decode(key)
        .is_ok_and(|key| key.len() == 16)
    {
        return Err(bad(400, "invalid WebSocket key"));
    }
    if header(request.headers, "Transfer-Encoding").is_some()
        || header(request.headers, "Content-Length").is_some_and(|v| v != "0")
    {
        return Err(bad(
            400,
            "WebSocket handshake cannot have an HTTP request body",
        ));
    }
    let protocol = header(request.headers, "Sec-WebSocket-Protocol");
    let early = protocol.and_then(decode_early_data).unwrap_or_default();
    let echoed = if early.is_empty() {
        None
    } else {
        protocol.map(str::to_owned)
    };
    let request_metadata = RequestMetadata {
        host: host.to_owned(),
        target: target.to_owned(),
        early_data_len: early.len(),
        headers: request
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_owned(),
                    String::from_utf8_lossy(h.value).into_owned(),
                )
            })
            .collect(),
    };
    Ok((request_metadata, key.to_owned(), early, echoed))
}

fn decode_early_data(protocol: &str) -> Option<Vec<u8>> {
    // Go strings.NewReplacer("+", "-", "/", "_", "=", "") accepts both encodings.
    let normalized = protocol
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    GO_RAW_URL_BASE64
        .decode(normalized)
        .ok()
        .filter(|bytes| !bytes.is_empty())
}

fn valid_host(request: &str, configured: &str) -> bool {
    let request = request.to_ascii_lowercase();
    let host = if request.contains(':') {
        if let Some(bracketed) = request.strip_prefix('[') {
            let Some((host, port)) = bracketed.split_once("]:") else {
                return false;
            };
            if port.contains(':') {
                return false;
            }
            host
        } else {
            let Some((host, port)) = request.split_once(':') else {
                return false;
            };
            if port.contains(':') {
                return false;
            }
            host
        }
    } else {
        &request
    };
    host.eq_ignore_ascii_case(configured)
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn percent_decode(input: &str, form: bool) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let hi = bytes.next().and_then(|b| (b as char).to_digit(16));
                let lo = bytes.next().and_then(|b| (b as char).to_digit(16));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
                    _ => return Err(invalid_input("invalid URL escape")),
                }
            }
            b'+' if form => out.push(b' '),
            _ => out.push(byte),
        }
    }
    Ok(out)
}

fn form_escape(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            output.push(byte as char);
        } else if byte == b' ' {
            output.push('+');
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn extract_early_data(path: &str) -> io::Result<(String, usize)> {
    let (url, fragment) = path
        .split_once('#')
        .map_or((path, None), |(p, f)| (p, Some(f)));
    let Some((base, query)) = url.split_once('?') else {
        return Ok((path.to_owned(), 0));
    };
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pair in query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.contains(';'))
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Ok(key), Ok(value)) = (percent_decode(key, true), percent_decode(value, true)) else {
            continue;
        };
        let (Ok(key), Ok(value)) = (String::from_utf8(key), String::from_utf8(value)) else {
            continue;
        };
        fields.entry(key).or_default().push(value);
    }
    let Some(ed) = fields
        .get("ed")
        .and_then(|v| v.first())
        .filter(|v| !v.is_empty())
    else {
        return Ok((path.to_owned(), 0));
    };
    let limit = ed.parse::<i64>().unwrap_or(0) as u32 as usize;
    fields.remove("ed");
    let query = fields
        .into_iter()
        .flat_map(|(key, values)| {
            values
                .into_iter()
                .map(move |value| format!("{}={}", form_escape(&key), form_escape(&value)))
        })
        .collect::<Vec<_>>()
        .join("&");
    let mut result = base.to_owned();
    if !query.is_empty() {
        result.push('?');
        result.push_str(&query);
    }
    if let Some(fragment) = fragment {
        result.push('#');
        result.push_str(fragment);
    }
    Ok((result, limit))
}

fn request_target(path: &str) -> io::Result<String> {
    if path.bytes().any(|byte| byte < 32 || byte == 127) {
        return Err(invalid_input("control character in WebSocket path"));
    }
    let path = path.split('#').next().unwrap_or(path);
    percent_decode(path, false)?;
    let mut result = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte <= 32
            || byte >= 127
            || matches!(
                byte,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            )
        {
            result.push_str(&format!("%{byte:02X}"));
        } else {
            result.push(byte as char);
        }
    }
    Ok(result)
}

struct PrefixedStream {
    inner: BoxStream,
    prefix: Vec<u8>,
    offset: usize,
}
fn prefixed(inner: BoxStream, prefix: Vec<u8>) -> BoxStream {
    Box::new(PrefixedStream {
        inner,
        prefix,
        offset: 0,
    })
}
impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = buf.remaining().min(self.prefix.len() - self.offset);
            buf.put_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

#[derive(Clone)]
struct SavedError {
    kind: io::ErrorKind,
    message: String,
}
impl SavedError {
    fn new(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

#[derive(Default)]
struct SharedState {
    error: Option<SavedError>,
    write_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}
type State = Arc<Mutex<SharedState>>;
fn fail(state: &State, error: &io::Error) {
    let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
    if state.error.is_none() {
        state.error = Some(SavedError::new(error));
    }
    if let Some(waker) = state.read_waker.take() {
        waker.wake();
    }
    if let Some(waker) = state.write_waker.take() {
        waker.wake();
    }
}

fn finish_writing(state: &State) {
    let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
    state.write_closed = true;
    if let Some(waker) = state.write_waker.take() {
        waker.wake();
    }
}

enum Command {
    Binary(Vec<u8>),
    Pong(Vec<u8>),
    Flush(oneshot::Sender<io::Result<()>>),
    Close(Vec<u8>, Option<oneshot::Sender<io::Result<()>>>),
}
type Reservation = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Command>, mpsc::error::SendError<()>>> + Send>,
>;

struct WebSocketStream {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Command>,
    reservation: Option<Reservation>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    flush: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown_started: bool,
    shutdown_complete: bool,
    state: State,
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

impl WebSocketStream {
    fn new(stream: BoxStream, role: Role, early: Vec<u8>, heartbeat: Duration) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let (incoming_tx, incoming) = mpsc::channel(QUEUE_DEPTH);
        let (outgoing, outgoing_rx) = mpsc::channel(QUEUE_DEPTH);
        let state = Arc::new(Mutex::new(SharedState::default()));
        let reader_state = state.clone();
        let controls = outgoing.clone();
        let reader_task = tokio::spawn(async move {
            if let Err(error) =
                read_frames(reader, role, early, incoming_tx.clone(), controls.clone()).await
            {
                fail(&reader_state, &error);
                // Protocol errors get a best-effort 1002 response. Never wait
                // on a full queue when reporting the error to the application.
                if error.kind() == io::ErrorKind::InvalidData {
                    let _ = controls.try_send(Command::Close(1002u16.to_be_bytes().to_vec(), None));
                }
            }
            // Keep the sender alive until the error has been stored. Otherwise
            // another executor thread could observe a clean EOF first.
            drop(incoming_tx);
        });
        let writer_state = state.clone();
        let writer_task = tokio::spawn(async move {
            if let Err(error) =
                write_frames(writer, role, heartbeat, outgoing_rx, &writer_state).await
            {
                fail(&writer_state, &error);
            }
        });
        Self {
            incoming,
            outgoing,
            reservation: None,
            read_buffer: Vec::new(),
            read_offset: 0,
            flush: None,
            shutdown: None,
            shutdown_started: false,
            shutdown_complete: false,
            state,
            reader_task,
            writer_task,
        }
    }

    fn poll_permit(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<mpsc::OwnedPermit<Command>>> {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(error) = &state.error {
                return Poll::Ready(Err(error.error()));
            }
            if state.write_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WebSocket writer closed",
                )));
            }
            state.write_waker = Some(cx.waker().clone());
        }
        if self.reservation.is_none() {
            self.reservation = Some(Box::pin(self.outgoing.clone().reserve_owned()));
        }
        match self
            .reservation
            .as_mut()
            .expect("reservation initialized")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.reservation = None;
                Poll::Ready(result.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket writer closed")
                }))
            }
        }
    }
}

impl WebSocketStream {
    fn write_status(&self) -> io::Result<bool> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match &state.error {
            Some(error) => Err(error.error()),
            None => Ok(state.write_closed),
        }
    }
}

impl Drop for WebSocketStream {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

impl AsyncRead for WebSocketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.read_waker = Some(cx.waker().clone());
        }
        if self.read_offset == self.read_buffer.len() {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    self.read_buffer = data;
                    self.read_offset = 0;
                }
                result => {
                    let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(error) = &state.error {
                        return Poll::Ready(Err(error.error()));
                    }
                    return match result {
                        Poll::Ready(None) => Poll::Ready(Ok(())),
                        _ => Poll::Pending,
                    };
                }
            }
        }
        let n = buf
            .remaining()
            .min(self.read_buffer.len() - self.read_offset);
        buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + n]);
        self.read_offset += n;
        Poll::Ready(Ok(()))
    }
}

fn poll_ack(
    receiver: &mut oneshot::Receiver<io::Result<()>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    match Pin::new(receiver).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(result)) => Poll::Ready(result),
        Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "WebSocket writer stopped",
        ))),
    }
}

impl AsyncWrite for WebSocketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket is closing",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let permit = match self.poll_permit(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        let n = buf.len().min(WRITE_CHUNK);
        // A canceled flush followed by another write needs a new barrier.
        self.flush = None;
        permit.send(Command::Binary(buf[..n].to_vec()));
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown_started {
            return self.poll_shutdown(cx);
        }
        if self.write_status()? {
            return Poll::Ready(Ok(()));
        }
        if self.flush.is_none() {
            let permit = match self.poll_permit(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(if self.write_status()? {
                        Ok(())
                    } else {
                        Err(error)
                    });
                }
            };
            let (tx, rx) = oneshot::channel();
            self.flush = Some(rx);
            permit.send(Command::Flush(tx));
        }
        let mut result = poll_ack(self.flush.as_mut().expect("flush initialized"), cx);
        if matches!(&result, Poll::Ready(Err(_))) && self.write_status()? {
            result = Poll::Ready(Ok(()));
        }
        if result.is_ready() {
            self.flush = None;
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown.is_none() {
            if self.write_status()? {
                self.shutdown_started = true;
                self.shutdown_complete = true;
                return Poll::Ready(Ok(()));
            }
            let permit = match self.poll_permit(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(if self.write_status()? {
                        Ok(())
                    } else {
                        Err(error)
                    });
                }
            };
            let (tx, rx) = oneshot::channel();
            self.shutdown = Some(rx);
            self.shutdown_started = true;
            permit.send(Command::Close(1000u16.to_be_bytes().to_vec(), Some(tx)));
        }
        // Once the close is queued, its write acknowledgement is authoritative.
        // A peer can close its transport immediately after receiving our close,
        // racing an UnexpectedEof into the shared read error before this poll.
        // Preserve that error for reads without losing a successful shutdown.
        let mut result = poll_ack(self.shutdown.as_mut().expect("shutdown initialized"), cx);
        if matches!(&result, Poll::Ready(Err(_))) && self.write_status()? {
            result = Poll::Ready(Ok(()));
        }
        if result.is_ready() {
            self.shutdown_complete = matches!(&result, Poll::Ready(Ok(())));
            self.shutdown = None;
        }
        result
    }
}

async fn write_frames<W: AsyncWrite + Unpin>(
    mut writer: W,
    role: Role,
    heartbeat: Duration,
    mut receiver: mpsc::Receiver<Command>,
    state: &State,
) -> io::Result<()> {
    let period = if heartbeat.is_zero() {
        Duration::from_secs(3600)
    } else {
        heartbeat
    };
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let command = tokio::select! {
            command = receiver.recv() => match command { Some(command) => command, None => return Ok(()) },
            _ = ticks.tick(), if !heartbeat.is_zero() => { write_frame(&mut writer, role, 9, &[]).await?; continue; }
        };
        match command {
            Command::Binary(data) => write_frame(&mut writer, role, 2, &data).await?,
            Command::Pong(data) => write_frame(&mut writer, role, 10, &data).await?,
            Command::Flush(done) => {
                let result = writer.flush().await;
                let saved = result.as_ref().err().map(SavedError::new);
                let _ = done.send(result);
                if let Some(error) = saved {
                    return Err(error.error());
                }
            }
            Command::Close(data, done) => {
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    write_frame(&mut writer, role, 8, &data).await?;
                    writer.shutdown().await
                })
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "WebSocket close timed out",
                    ))
                });
                let saved = result.as_ref().err().map(SavedError::new);
                // Publish completion before acknowledging or dropping the
                // queue. EOF readers can then flush/shutdown idempotently.
                match &result {
                    Ok(()) => finish_writing(state),
                    Err(error) => fail(state, error),
                }
                if let Some(done) = done {
                    let _ = done.send(result);
                }
                return saved.map_or(Ok(()), |error| Err(error.error()));
            }
        }
    }
}

fn frame_bytes(role: Role, opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    let masked = if role == Role::Client { 0x80 } else { 0 };
    match payload.len() {
        n @ 0..=125 => frame.push(masked | n as u8),
        n @ 126..=65535 => {
            frame.push(masked | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(masked | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if role == Role::Client {
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    } else {
        frame.extend_from_slice(payload);
    }
    frame
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    role: Role,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    let mut mask = [0; 4];
    if role == Role::Client {
        OsRng.fill_bytes(&mut mask);
    }
    writer
        .write_all(&frame_bytes(role, opcode, payload, mask))
        .await?;
    writer.flush().await
}

async fn read_frames<R: AsyncRead + Unpin>(
    mut reader: R,
    role: Role,
    early: Vec<u8>,
    incoming: mpsc::Sender<Vec<u8>>,
    outgoing: mpsc::Sender<Command>,
) -> io::Result<()> {
    if !early.is_empty() && incoming.send(early).await.is_err() {
        return Ok(());
    }
    let mut fragmented = false;
    loop {
        let mut head = [0; 2];
        reader.read_exact(&mut head).await?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        if head[0] & 0x70 != 0 || masked != (role == Role::Server) {
            return Err(invalid_data(
                "invalid WebSocket reserved bits or mask direction",
            ));
        }
        let short = head[1] & 0x7f;
        let mut len = u64::from(short);
        if short == 126 {
            let mut bytes = [0; 2];
            reader.read_exact(&mut bytes).await?;
            len = u16::from_be_bytes(bytes).into();
            if len < 126 {
                return Err(invalid_data("nonminimal WebSocket length"));
            }
        } else if short == 127 {
            let mut bytes = [0; 8];
            reader.read_exact(&mut bytes).await?;
            len = u64::from_be_bytes(bytes);
            if len < 65536 || len > i64::MAX as u64 {
                return Err(invalid_data("invalid WebSocket 64-bit length"));
            }
        }
        match opcode {
            0 if fragmented => fragmented = !fin,
            1 | 2 if !fragmented => fragmented = !fin,
            8..=10 if fin && len <= 125 => {}
            _ => {
                return Err(invalid_data(
                    "invalid WebSocket opcode, continuation, or control frame",
                ));
            }
        }
        let mut mask = [0; 4];
        if masked {
            reader.read_exact(&mut mask).await?;
        }
        if opcode >= 8 {
            let mut data = vec![0; len as usize];
            reader.read_exact(&mut data).await?;
            if masked {
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }
            match opcode {
                8 => {
                    let code = validate_close(&data)?;
                    let (tx, rx) = oneshot::channel();
                    tokio::time::timeout(Duration::from_secs(5), async {
                        if outgoing.send(Command::Close(data, Some(tx))).await.is_ok() {
                            let _ = rx.await;
                        }
                    })
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "WebSocket close reply blocked")
                    })?;
                    return if code.is_none_or(|code| code == 1000 || code == 1001) {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("WebSocket peer closed with status {}", code.unwrap_or(1005)),
                        ))
                    };
                }
                9 => {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        outgoing.send(Command::Pong(data)),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "WebSocket pong queue blocked")
                    })?
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket writer closed")
                    })?;
                }
                _ => {}
            }
        } else {
            let mut offset = 0usize;
            while len != 0 {
                let n = len.min(READ_CHUNK as u64) as usize;
                let mut data = vec![0; n];
                let n = reader.read(&mut data).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF inside WebSocket frame",
                    ));
                }
                data.truncate(n);
                if masked {
                    for (i, b) in data.iter_mut().enumerate() {
                        *b ^= mask[(offset + i) % 4];
                    }
                }
                offset = (offset + n) % 4;
                len -= n as u64;
                if incoming.send(data).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

fn validate_close(data: &[u8]) -> io::Result<Option<u16>> {
    if data.is_empty() {
        return Ok(None);
    }
    if data.len() == 1 {
        return Err(invalid_data("one-byte WebSocket close payload"));
    }
    let code = u16::from_be_bytes([data[0], data[1]]);
    if !(matches!(code, 1000..=1003 | 1007..=1014) || (3000..=4999).contains(&code)) || code == 1015
    {
        return Err(invalid_data("invalid WebSocket close status"));
    }
    std::str::from_utf8(&data[2..]).map_err(invalid_data)?;
    Ok(Some(code))
}

struct DeferredArgs {
    stream: BoxStream,
    host: String,
    config: Config,
}
enum DeferredState {
    Waiting(Option<DeferredArgs>),
    Connecting(oneshot::Receiver<io::Result<BoxStream>>),
    Ready(BoxStream),
    Failed(SavedError),
    Closed,
}
struct DelayedClient {
    state: DeferredState,
    wake: State,
    task: Option<JoinHandle<()>>,
}
impl DelayedClient {
    fn new(stream: BoxStream, host: String, config: Config) -> Self {
        Self {
            state: DeferredState::Waiting(Some(DeferredArgs {
                stream,
                host,
                config,
            })),
            wake: Arc::new(Mutex::new(SharedState::default())),
            task: None,
        }
    }
    fn poll_connected(&mut self, cx: &mut Context<'_>, read: bool) -> Poll<io::Result<()>> {
        {
            let mut wake = self.wake.lock().unwrap_or_else(|p| p.into_inner());
            if read {
                wake.read_waker = Some(cx.waker().clone());
            } else {
                wake.write_waker = Some(cx.waker().clone());
            }
        }
        match &mut self.state {
            DeferredState::Waiting(_) => Poll::Pending,
            DeferredState::Connecting(receiver) => match Pin::new(receiver).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    match result.unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "WebSocket handshake task stopped",
                        ))
                    }) {
                        Ok(stream) => {
                            self.state = DeferredState::Ready(stream);
                            Poll::Ready(Ok(()))
                        }
                        Err(error) => {
                            self.state = DeferredState::Failed(SavedError::new(&error));
                            Poll::Ready(Err(error))
                        }
                    }
                }
            },
            DeferredState::Ready(_) => Poll::Ready(Ok(())),
            DeferredState::Failed(error) => Poll::Ready(Err(error.error())),
            DeferredState::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket stream closed",
            ))),
        }
    }
}
impl Drop for DelayedClient {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl AsyncRead for DelayedClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_connected(cx, true) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        match &mut self.state {
            DeferredState::Ready(stream) => Pin::new(stream).poll_read(cx, buf),
            _ => unreachable!(),
        }
    }
}
impl AsyncWrite for DelayedClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let DeferredState::Waiting(args) = &mut self.state {
            if args
                .as_ref()
                .is_some_and(|args| buf.len() <= args.config.early_data_limit)
                && buf.len() > MAX_HEADER_BYTES
            {
                return Poll::Ready(Err(invalid_input(
                    "WebSocket early data exceeds HTTP header limit",
                )));
            }
            let args = args.take().expect("deferred connection arguments");
            let use_early = buf.len() <= args.config.early_data_limit;
            let n = if use_early {
                buf.len()
            } else {
                buf.len().min(WRITE_CHUNK)
            };
            let data = buf[..n].to_vec();
            let (tx, rx) = oneshot::channel();
            let wake = self.wake.clone();
            self.task = Some(tokio::spawn(async move {
                let result = async {
                    let early = if use_early { Some(data.clone()) } else { None };
                    let mut stream =
                        client_handshake(args.stream, args.host, args.config, early).await?;
                    if !use_early {
                        stream.write_all(&data).await?;
                        stream.flush().await?;
                    }
                    Ok(stream)
                }
                .await;
                let _ = tx.send(result);
                let mut wake = wake.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(waker) = wake.read_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = wake.write_waker.take() {
                    waker.wake();
                }
            }));
            self.state = DeferredState::Connecting(rx);
            return Poll::Ready(Ok(n));
        }
        match self.poll_connected(cx, false) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        match &mut self.state {
            DeferredState::Ready(stream) => Pin::new(stream).poll_write(cx, buf),
            _ => unreachable!(),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.state, DeferredState::Waiting(_)) {
            return Poll::Ready(Ok(()));
        }
        match self.poll_connected(cx, false) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        match &mut self.state {
            DeferredState::Ready(stream) => Pin::new(stream).poll_flush(cx),
            _ => unreachable!(),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(
            self.state,
            DeferredState::Waiting(_) | DeferredState::Closed
        ) {
            self.state = DeferredState::Closed;
            let mut wake = self.wake.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(waker) = wake.read_waker.take() {
                waker.wake();
            }
            return Poll::Ready(Ok(()));
        }
        match self.poll_connected(cx, false) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        match &mut self.state {
            DeferredState::Ready(stream) => Pin::new(stream).poll_shutdown(cx),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn config() -> Config {
        Config {
            host: "example.test".into(),
            path: "/tunnel".into(),
            headers: BTreeMap::from([("User-Agent".into(), "fixture".into())]),
            ..Config::default()
        }
    }

    fn request(target: &str, host: &str, protocol: Option<&str>) -> Vec<u8> {
        let mut data = format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {RFC_KEY}\r\n"
        );
        if let Some(protocol) = protocol {
            data.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
        }
        data.push_str("\r\n");
        data.into_bytes()
    }

    async fn read_wire_frame(stream: &mut DuplexStream) -> (u8, bool, Vec<u8>) {
        let mut head = [0; 2];
        stream.read_exact(&mut head).await.unwrap();
        let mut len = (head[1] & 127) as usize;
        if len == 126 {
            let mut bytes = [0; 2];
            stream.read_exact(&mut bytes).await.unwrap();
            len = u16::from_be_bytes(bytes) as usize;
        } else if len == 127 {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            len = u64::from_be_bytes(bytes) as usize;
        }
        assert!(len <= 100_000);
        let masked = head[1] & 128 != 0;
        let mut mask = [0; 4];
        if masked {
            stream.read_exact(&mut mask).await.unwrap();
        }
        let mut payload = vec![0; len];
        stream.read_exact(&mut payload).await.unwrap();
        if masked {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        (head[0] & 15, masked, payload)
    }

    #[test]
    fn rfc6455_accept_and_masked_hello_fixtures() {
        assert_eq!(accept_key(RFC_KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(
            frame_bytes(Role::Client, 1, b"Hello", [0x37, 0xfa, 0x21, 0x3d]),
            [
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
        assert_eq!(
            frame_bytes(Role::Server, 2, b"Hi", [0; 4]),
            [0x82, 2, b'H', b'i']
        );
    }

    #[test]
    fn config_matches_go_early_data_and_legacy_host_conversion() {
        let parsed = Config::from_json(&serde_json::json!({
            "path": "tunnel?z=last&ed=2048&a=hello%20world&ed=1",
            "headers": {"Host":"example.test", "X-Token":"value"}, "heartbeatPeriod": 17
        }))
        .unwrap();
        assert_eq!(parsed.path, "tunnel?a=hello+world&z=last");
        assert_eq!(parsed.normalized_path(), "/tunnel?a=hello+world&z=last");
        assert_eq!(parsed.host, "example.test");
        assert_eq!(parsed.early_data_limit, 2048);
        assert_eq!(parsed.heartbeat_period, Duration::from_secs(17));
        assert!(!parsed.headers.contains_key("Host"));
        assert_eq!(Config::default().normalized_path(), "/");
        assert_eq!(
            extract_early_data("/x?ed=bogus&b=2").unwrap(),
            ("/x?b=2".into(), 0)
        );
        assert_eq!(
            extract_early_data("/x?ed=&b=2").unwrap(),
            ("/x?ed=&b=2".into(), 0)
        );
        assert_eq!(extract_early_data("/x?ed=-1").unwrap().1, u32::MAX as usize);
        assert_eq!(
            Config::from_json(&serde_json::json!({"acceptProxyProtocol":true}))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn host_and_decoded_path_follow_go_listener_rules() {
        assert!(valid_host("EXAMPLE.test:8443", "example.test"));
        assert!(valid_host("[::1]:8443", "::1"));
        assert!(!valid_host("example.test:8443", "example.test:8443"));
        assert!(!valid_host("::1", "::1"));
        let cfg = config();
        assert!(
            check_request(
                &request("/%74unnel?arbitrary=query", "EXAMPLE.test:443", None),
                &cfg
            )
            .is_ok()
        );
        assert_eq!(
            check_request(&request("/other", "example.test", None), &cfg)
                .unwrap_err()
                .0,
            404
        );
        assert_eq!(
            check_request(&request("/tunnel", "other.test", None), &cfg)
                .unwrap_err()
                .0,
            404
        );
        // Go compares URL.Path with its literal configured path, not RawQuery.
        let mut with_query = cfg;
        with_query.path = "/tunnel?x=1".into();
        assert_eq!(
            check_request(&request("/tunnel?x=1", "example.test", None), &with_query)
                .unwrap_err()
                .0,
            404
        );
    }

    #[test]
    fn go_early_data_accepts_both_alphabets_padding_and_noncanonical_bits() {
        for encoded in ["+/8=", "-_8", "-_=8="] {
            assert_eq!(decode_early_data(encoded), Some(vec![251, 255]));
        }
        // encoding/base64.RawURLEncoding is not its Strict variant.
        assert_eq!(decode_early_data("Zh"), Some(b"f".to_vec()));
        for encoded in ["", "=", "a", "abc,def", "not base64"] {
            assert!(decode_early_data(encoded).is_none());
        }
        let (metadata, _, early, echo) =
            check_request(&request("/tunnel", "example.test", Some("+/8=")), &config()).unwrap();
        assert_eq!(early, [251, 255]);
        assert_eq!(metadata.early_data_len, 2);
        assert_eq!(echo.as_deref(), Some("+/8="));
        let (_, _, early, echo) = check_request(
            &request("/tunnel", "example.test", Some("invalid!")),
            &config(),
        )
        .unwrap();
        assert!(early.is_empty());
        assert!(echo.is_none());
    }

    #[test]
    fn client_headers_prevent_injection_and_preserve_early_data_override() {
        let mut cfg = config();
        cfg.headers.remove("User-Agent");
        cfg.headers
            .insert("user-agent".into(), "literal-custom-agent".into());
        cfg.headers
            .insert("Sec-WebSocket-Protocol".into(), "ordinary".into());
        cfg.headers.insert("X-Token".into(), "secret".into());
        let request = build_request("example.test", &cfg, RFC_KEY, Some(&[251, 255])).unwrap();
        assert!(request.contains("Sec-WebSocket-Protocol: -_8\r\n"));
        assert!(!request.contains("ordinary"));
        assert!(request.contains("User-Agent: literal-custom-agent\r\n"));
        assert!(!request.contains("Mozilla/5.0"));
        assert!(request.contains("X-Token: secret\r\n"));
        cfg.headers
            .insert("X-Bad".into(), "ok\r\nInjected: yes".into());
        assert!(build_request("example.test", &cfg, RFC_KEY, None).is_err());
        cfg.headers.remove("X-Bad");
        cfg.headers.insert("connection".into(), "close".into());
        assert!(build_request("example.test", &cfg, RFC_KEY, None).is_err());
        assert!(request_target("/x\r\nGET /other").is_err());
        assert!(request_target("/x%GG").is_err());
        assert_eq!(
            request_target("/snow/雪 and%20ice#fragment").unwrap(),
            "/snow/%E9%9B%AA%20and%20ice"
        );
    }

    #[test]
    fn handshake_rejects_bad_keys_versions_and_response_accepts() {
        let valid = request("/tunnel", "example.test", None);
        let wrong_version = String::from_utf8(valid.clone())
            .unwrap()
            .replace("Version: 13", "Version: 12");
        assert_eq!(
            check_request(wrong_version.as_bytes(), &config())
                .unwrap_err()
                .0,
            426
        );
        let bad_key = String::from_utf8(valid).unwrap().replace(RFC_KEY, "b2s=");
        assert_eq!(
            check_request(bad_key.as_bytes(), &config()).unwrap_err().0,
            400
        );
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(RFC_KEY)
        );
        assert!(check_response(response.as_bytes(), RFC_KEY).is_ok());
        assert!(check_response(response.as_bytes(), "different-key").is_err());
        assert!(check_response(response.replace("101", "200").as_bytes(), RFC_KEY).is_err());
    }

    #[tokio::test]
    async fn native_client_server_exchange_and_clean_close() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (a, b) = tokio::io::duplex(1024);
            let (client, server) = tokio::join!(
                client(Box::new(a), "ignored", None, config()),
                server(Box::new(b), config())
            );
            let mut client = client.unwrap();
            let mut server = server.unwrap();
            client.write_all(b"request").await.unwrap();
            let mut request = [0; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            server.write_all(b"response").await.unwrap();
            let mut response = [0; 8];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"response");
            client.shutdown().await.unwrap();
            assert_eq!(server.read(&mut [0; 1]).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    async fn early_data_case(limit: usize, first: &[u8], expected_early: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (a, b) = tokio::io::duplex(1024);
            let expected = first.to_vec();
            let accepted = tokio::spawn(async move {
                let mut accepted = server_with_metadata(Box::new(b), config()).await.unwrap();
                assert_eq!(accepted.request.early_data_len, expected_early);
                let mut data = vec![0; expected.len()];
                accepted.stream.read_exact(&mut data).await.unwrap();
                assert_eq!(data, expected);
                accepted.stream.write_all(b"ok").await.unwrap();
                accepted.stream.flush().await.unwrap();
                // Wait for the client to close so buffered response is not dropped.
                let _ = accepted.stream.read(&mut [0; 1]).await;
            });
            let mut cfg = config();
            cfg.early_data_limit = limit;
            let mut client = client(Box::new(a), "example.test", None, cfg)
                .await
                .unwrap();
            client.write_all(first).await.unwrap();
            let mut response = [0; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ok");
            client.shutdown().await.unwrap();
            accepted.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delayed_handshake_uses_whole_first_write_or_no_early_data() {
        early_data_case(4, b"abcd", 4).await;
        early_data_case(3, b"abcd", 0).await;
    }

    #[tokio::test]
    async fn deferred_read_waits_for_first_write_and_zero_length_reads_are_ready() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (a, mut peer) = tokio::io::duplex(1024);
            let mut cfg = config();
            cfg.early_data_limit = 100;
            let mut client = client(Box::new(a), "example.test", None, cfg)
                .await
                .unwrap();
            assert_eq!(client.read(&mut []).await.unwrap(), 0);
            let mut byte = [0; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), peer.read(&mut byte))
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                    .await
                    .is_err()
            );
            client.shutdown().await.unwrap();
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handshake_preserves_coalesced_frames_and_early_data_order() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(4096);
            let server = tokio::spawn(server_with_metadata(Box::new(stream), config()));
            let mut request = request("/tunnel?ignored=yes", "example.test", Some("ZWFybHk="));
            request.extend(frame_bytes(Role::Client, 2, b"frame", [1, 2, 3, 4]));
            peer.write_all(&request).await.unwrap();
            let mut accepted = server.await.unwrap().unwrap();
            let mut data = [0; 10];
            accepted.stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"earlyframe");
            let mut peer: BoxStream = Box::new(peer);
            let (response, _) = read_head(&mut peer).await.unwrap();
            assert!(
                String::from_utf8(response)
                    .unwrap()
                    .contains("Sec-WebSocket-Protocol: ZWFybHk=\r\n")
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn client_preserves_frame_coalesced_with_upgrade_response() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (a, b) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut b: BoxStream = Box::new(b);
                let (head, _) = read_head(&mut b).await.unwrap();
                let (_, key, _, _) = check_request(&head, &config()).unwrap();
                let mut response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept_key(&key)).into_bytes();
                response.extend(frame_bytes(Role::Server, 2, b"first", [0; 4]));
                b.write_all(&response).await.unwrap();
                let _ = b.read(&mut [0; 1]).await;
            });
            let mut client = client(Box::new(a), "example.test", None, config()).await.unwrap();
            let mut data = [0; 5]; client.read_exact(&mut data).await.unwrap(); assert_eq!(&data, b"first");
            drop(client); peer.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn fragments_text_binary_ping_and_empty_messages_form_one_byte_stream() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(4096);
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Server, Vec::new(), Duration::ZERO);
            let mut frames = frame_bytes(Role::Client, 1, b"hel", [3, 1, 4, 1]);
            frames[0] &= 0x7f;
            frames.extend(frame_bytes(Role::Client, 9, b"ping", [2, 7, 1, 8]));
            frames.extend(frame_bytes(Role::Client, 0, b"lo", [1, 6, 1, 8]));
            frames.extend(frame_bytes(Role::Client, 2, b"", [0; 4]));
            frames.extend(frame_bytes(Role::Client, 2, &[255, 0], [5, 7, 7, 2]));
            peer.write_all(&frames).await.unwrap();
            let mut data = [0; 7];
            ws.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"hello\xff\0");
            assert_eq!(
                read_wire_frame(&mut peer).await,
                (10, false, b"ping".to_vec())
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ping_replies_and_heartbeat_do_not_require_application_reads() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(4096);
            let _ws = WebSocketStream::new(
                Box::new(stream),
                Role::Client,
                Vec::new(),
                Duration::from_millis(30),
            );
            peer.write_all(&frame_bytes(Role::Server, 9, b"p", [0; 4]))
                .await
                .unwrap();
            assert_eq!(read_wire_frame(&mut peer).await, (10, true, b"p".to_vec()));
            assert_eq!(read_wire_frame(&mut peer).await, (9, true, Vec::new()));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn extended_payloads_stream_across_small_reads_without_losing_mask_alignment() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let payload: Vec<u8> = (0..70_000).map(|n| (n % 251) as u8).collect();
            let expected = payload.clone();
            let (mut peer, stream) = tokio::io::duplex(137);
            let send = tokio::spawn(async move {
                peer.write_all(&frame_bytes(Role::Client, 2, &payload, [7, 9, 3, 5]))
                    .await
                    .unwrap();
                peer.write_all(&frame_bytes(
                    Role::Client,
                    8,
                    &1000u16.to_be_bytes(),
                    [1; 4],
                ))
                .await
                .unwrap();
                assert_eq!(read_wire_frame(&mut peer).await.0, 8);
            });
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Server, Vec::new(), Duration::ZERO);
            let mut received = Vec::new();
            ws.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
            send.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn write_flush_shutdown_preserve_order_and_client_masking() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(32);
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Client, Vec::new(), Duration::ZERO);
            let read = tokio::spawn(async move {
                assert_eq!(
                    read_wire_frame(&mut peer).await,
                    (2, true, b"data".to_vec())
                );
                assert_eq!(
                    read_wire_frame(&mut peer).await,
                    (8, true, 1000u16.to_be_bytes().to_vec())
                );
                assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            });
            ws.write_all(b"data").await.unwrap();
            ws.flush().await.unwrap();
            ws.shutdown().await.unwrap();
            read.await.unwrap();
            // Bare transport EOF remains an error on reads, but must not undo
            // the successful, independently acknowledged write-side close.
            assert_eq!(
                ws.read(&mut [0; 1]).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            ws.shutdown().await.unwrap();
            ws.flush().await.unwrap();
            assert_eq!(
                ws.write(b"after").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn role_masking_fragmentation_and_control_violations_are_errors() {
        let cases = vec![
            (Role::Server, vec![0x82, 0]),           // unmasked client
            (Role::Client, vec![0x82, 0x80]),        // masked server
            (Role::Client, vec![0xc2, 0]),           // RSV1 without extension
            (Role::Client, vec![0x80, 0]),           // orphan continuation
            (Role::Client, vec![0x09, 0]),           // fragmented ping
            (Role::Client, vec![0x83, 0]),           // reserved opcode
            (Role::Client, vec![0x82, 126, 0, 1]),   // nonminimal length
            (Role::Client, vec![0x89, 126, 0, 126]), // oversized ping
            (Role::Client, vec![0x88, 1, 0]),        // malformed close
            (Role::Client, vec![0x01, 0, 0x82, 0]),  // data before continuation
            (Role::Client, vec![0x82, 127, 128, 0, 0, 0, 0, 0, 0, 0]),
        ];
        for (role, bytes) in cases {
            tokio::time::timeout(Duration::from_secs(1), async {
                let (mut peer, stream) = tokio::io::duplex(4096);
                let mut ws =
                    WebSocketStream::new(Box::new(stream), role, Vec::new(), Duration::ZERO);
                peer.write_all(&bytes).await.unwrap();
                assert_eq!(
                    ws.read(&mut [0; 1]).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData,
                    "{bytes:?}"
                );
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn bare_transport_eof_is_not_a_clean_websocket_close() {
        let (peer, stream) = tokio::io::duplex(16);
        let mut ws =
            WebSocketStream::new(Box::new(stream), Role::Server, Vec::new(), Duration::ZERO);
        assert_eq!(ws.read(&mut []).await.unwrap(), 0);
        drop(peer);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), ws.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn normal_peer_close_allows_idempotent_flush_and_shutdown() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(4096);
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Server, Vec::new(), Duration::ZERO);
            peer.write_all(&frame_bytes(
                Role::Client,
                8,
                &1000u16.to_be_bytes(),
                [1; 4],
            ))
            .await
            .unwrap();
            assert_eq!(ws.read(&mut [0; 1]).await.unwrap(), 0);
            assert_eq!(
                read_wire_frame(&mut peer).await,
                (8, false, 1000u16.to_be_bytes().to_vec())
            );
            ws.flush().await.unwrap();
            ws.shutdown().await.unwrap();
            ws.flush().await.unwrap();
            ws.shutdown().await.unwrap();
            assert_eq!(
                ws.write(b"after-close").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn copy_bidirectional_finishes_cleanly_after_websocket_peer_close() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(4096);
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Server, Vec::new(), Duration::ZERO);
            let (mut application, mut forwarded) = tokio::io::duplex(4096);
            let relay = tokio::spawn(async move {
                tokio::io::copy_bidirectional(&mut ws, &mut forwarded).await
            });
            let mut wire = frame_bytes(Role::Client, 2, b"relayed", [3; 4]);
            wire.extend(frame_bytes(Role::Client, 8, &1000u16.to_be_bytes(), [7; 4]));
            peer.write_all(&wire).await.unwrap();
            let mut data = Vec::new();
            application.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"relayed");
            application.shutdown().await.unwrap();
            assert_eq!(relay.await.unwrap().unwrap(), (7, 0));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn canceled_reads_and_flushes_do_not_discard_errors() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut peer, stream) = tokio::io::duplex(4096);
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Server, Vec::new(), Duration::ZERO);
            let mut byte = [0; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(10), ws.read(&mut byte))
                    .await
                    .is_err()
            );
            peer.write_all(&[0x82, 0]).await.unwrap();
            for _ in 0..2 {
                assert_eq!(
                    ws.read(&mut byte).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }

            let (peer, stream) = tokio::io::duplex(8);
            let mut ws =
                WebSocketStream::new(Box::new(stream), Role::Client, Vec::new(), Duration::ZERO);
            ws.write_all(&[0; 1024]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), ws.flush())
                    .await
                    .is_err()
            );
            drop(peer);
            assert!(ws.flush().await.is_err());
            assert!(ws.flush().await.is_err());
            assert!(ws.shutdown().await.is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn oversized_http_headers_are_rejected_without_unbounded_allocation() {
        let (mut peer, stream) = tokio::io::duplex(MAX_HEADER_BYTES * 2);
        peer.write_all(&vec![b'x'; MAX_HEADER_BYTES]).await.unwrap();
        let mut stream: BoxStream = Box::new(stream);
        assert_eq!(
            read_head(&mut stream).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn close_status_and_utf8_are_validated() {
        for code in [1000u16, 1001, 1002, 1011, 1012, 1013, 1014, 3000, 4999] {
            assert_eq!(validate_close(&code.to_be_bytes()).unwrap(), Some(code));
        }
        for code in [999u16, 1004, 1005, 1006, 1015, 2000, 5000] {
            assert!(validate_close(&code.to_be_bytes()).is_err());
        }
        assert!(validate_close(&[3, 232, 255]).is_err());
        assert!(validate_close(&[0]).is_err());
        assert_eq!(validate_close(&[]).unwrap(), None);
    }
}
