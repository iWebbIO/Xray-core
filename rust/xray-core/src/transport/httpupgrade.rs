//! Xray's HTTP Upgrade transport: an HTTP/1 handshake followed by raw bytes.
//!
//! This is deliberately not a WebSocket codec. In Go's
//! `transport/internet/httpupgrade/dialer.go`, `ed > 0` only postpones reading
//! the response; the first application write is sent unchanged. TCP, TLS
//! (with HTTP/1.1 ALPN), PROXY protocol and socket options belong to the caller.

use std::{
    collections::BTreeMap,
    io,
    net::IpAddr,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::Rng;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::transport::BoxStream;

/// The Go listener's complete request-header budget.
pub const MAX_REQUEST_HEADER_BYTES: usize = 12_288;
/// A defensive bound on a peer response, which Go does not explicitly limit.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 65_536;
pub const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

const RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn bad_config(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Transport settings after the Go JSON loader's `?ed=N` transformation.
#[derive(Clone, Debug, Default)]
pub struct HttpUpgradeConfig {
    /// Client Host override, and optional server Host restriction.
    pub host: String,
    /// A literal URL path. Even remaining `?query` text is escaped as path text.
    pub path: String,
    /// Header spelling is retained, as with Go's `AddHeader`.
    pub headers: BTreeMap<String, String>,
    /// Any nonzero value enables writes before response validation. No byte cap
    /// or WebSocket early-data header is applied by the Go HTTP Upgrade dialer.
    pub early_data: u32,
}

impl HttpUpgradeConfig {
    /// Parses `httpupgradeSettings`, including the loader's `?ed=` convention.
    /// A listener must implement PROXY protocol before passing its stream here.
    pub fn from_json(value: &Value) -> io::Result<Self> {
        let mut config = Self::default();
        if value.is_null() {
            return Ok(config);
        }
        let object = value
            .as_object()
            .ok_or_else(|| bad_config("HTTP Upgrade settings must be an object"))?;
        for (key, dest) in [("host", &mut config.host), ("path", &mut config.path)] {
            if let Some(value) = object.get(key).filter(|value| !value.is_null()) {
                *dest = value
                    .as_str()
                    .ok_or_else(|| bad_config(format!("HTTP Upgrade {key} must be a string")))?
                    .to_owned();
            }
        }
        if let Some(value) = object.get("headers").filter(|value| !value.is_null()) {
            for (key, value) in value
                .as_object()
                .ok_or_else(|| bad_config("HTTP Upgrade headers must be an object"))?
            {
                // encoding/json decodes a null map[string]string value as "".
                let value = if value.is_null() {
                    ""
                } else {
                    value
                        .as_str()
                        .ok_or_else(|| bad_config("HTTP Upgrade header values must be strings"))?
                };
                config.headers.insert(key.clone(), value.to_owned());
            }
        }
        if let Some(value) = object
            .get("acceptProxyProtocol")
            .filter(|value| !value.is_null())
            && value
                .as_bool()
                .ok_or_else(|| bad_config("acceptProxyProtocol must be a boolean"))?
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTP Upgrade acceptProxyProtocol requires a PROXY-aware listener; consume this setting before transport configuration",
            ));
        }
        (config.path, config.early_data) = extract_early_data(&config.path);
        config.validate()?;
        Ok(config)
    }

    pub fn normalized_path(&self) -> String {
        if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        }
    }

    fn validate(&self) -> io::Result<()> {
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("host") {
                return Err(bad_config(
                    "HTTP Upgrade headers cannot contain Host; use host",
                ));
            }
            if name.is_empty() || !name.bytes().all(is_token) {
                return Err(bad_config("invalid HTTP Upgrade header name"));
            }
            if value
                .bytes()
                .any(|byte| (byte < b' ' && !matches!(byte, b'\t' | b'\r' | b'\n')) || byte == 127)
            {
                return Err(bad_config("invalid HTTP Upgrade header value"));
            }
        }
        Ok(())
    }
}

/// Sends the upgrade request over an already connected stream. `fallback_host`
/// is TLS serverName when configured, otherwise the destination address (not
/// its port), matching the Go dialer. Explicit `config.host` takes precedence.
pub async fn client_upgrade(
    mut stream: BoxStream,
    config: &HttpUpgradeConfig,
    fallback_host: &str,
) -> io::Result<BoxStream> {
    let request = request_bytes(config, fallback_host)?;
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut stream = UpgradeStream::new(stream, true, Vec::new());
    if config.early_data == 0 {
        std::future::poll_fn(|cx| stream.poll_response(cx)).await?;
    }
    Ok(Box::new(stream))
}

/// Request information for access logging and trusted X-Forwarded-For policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestMetadata {
    pub method: String,
    pub host: String,
    /// The percent-decoded URL path, excluding an actual request-target query.
    pub path: String,
    /// Ordered fields, including duplicates. Values can contain non-UTF8 bytes.
    pub headers: Vec<(String, Vec<u8>)>,
}

impl RequestMetadata {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        first_header(&self.headers, name)
    }

    /// Mirrors common/protocol/http/headers.go: trust X-Forwarded-For only if
    /// at least one configured trusted header is present. Use port 0 for the
    /// returned address; retain the actual peer address on None.
    pub fn trusted_forwarded_ip(&self, trusted_headers: &[String]) -> Option<IpAddr> {
        if !trusted_headers
            .iter()
            .any(|name| self.header(name).is_some())
        {
            return None;
        }
        let value = std::str::from_utf8(self.header("X-Forwarded-For")?).ok()?;
        let first = value.split(',').next()?;
        let first = first
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(first)
            .trim();
        first.parse().ok()
    }
}

pub async fn server_upgrade(
    stream: BoxStream,
    config: &HttpUpgradeConfig,
) -> io::Result<BoxStream> {
    let (stream, _) = server_upgrade_with_metadata(stream, config).await?;
    Ok(stream)
}

/// Validates Host/path and the exact Connection/Upgrade values, sends the Go
/// 101 response and preserves application bytes coalesced with the request.
/// No Sec-WebSocket-Key, version, masking, frame or subprotocol is required.
pub async fn server_upgrade_with_metadata(
    stream: BoxStream,
    config: &HttpUpgradeConfig,
) -> io::Result<(BoxStream, RequestMetadata)> {
    server_handshake(stream, config, SERVER_HANDSHAKE_TIMEOUT).await
}

async fn server_handshake(
    mut stream: BoxStream,
    config: &HttpUpgradeConfig,
    timeout: Duration,
) -> io::Result<(BoxStream, RequestMetadata)> {
    config.validate()?;
    let bytes = tokio::time::timeout(timeout, read_head(&mut stream, MAX_REQUEST_HEADER_BYTES))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP Upgrade request timed out"))??;
    let end = head_end(&bytes).ok_or_else(|| invalid("incomplete HTTP Upgrade request"))?;
    let metadata = parse_request(&bytes[..end], config)?;
    stream.write_all(RESPONSE).await?;
    stream.flush().await?;
    let stream = UpgradeStream::new(stream, false, bytes[end..].to_vec());
    Ok((Box::new(stream), metadata))
}

/// State is held inside the stream, making a cancelled first read safe to retry.
struct UpgradeStream {
    inner: BoxStream,
    pending_response: bool,
    buffered: Vec<u8>,
    offset: usize,
    scanned: usize,
    failure: Option<(io::ErrorKind, String)>,
}

impl UpgradeStream {
    fn new(inner: BoxStream, pending_response: bool, buffered: Vec<u8>) -> Self {
        Self {
            inner,
            pending_response,
            buffered,
            offset: 0,
            scanned: 0,
            failure: None,
        }
    }

    fn failed(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn fail(&mut self, error: io::Error) -> Poll<io::Result<()>> {
        self.failure = Some((error.kind(), error.to_string()));
        self.buffered.clear();
        Poll::Ready(Err(error))
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.failed() {
            return Poll::Ready(Err(error));
        }
        while self.pending_response {
            if let Some(end) = head_end_after(&self.buffered, self.scanned) {
                if let Err(error) = validate_response(&self.buffered[..end]) {
                    return self.fail(error);
                }
                self.pending_response = false;
                self.offset = end;
                return Poll::Ready(Ok(()));
            }
            self.scanned = self.buffered.len();
            let remaining = MAX_RESPONSE_HEADER_BYTES - self.buffered.len();
            if remaining == 0 {
                return self.fail(invalid("HTTP Upgrade response headers exceed 65536 bytes"));
            }
            let mut chunk = [0_u8; 4096];
            let capacity = remaining.min(chunk.len());
            let mut buf = ReadBuf::new(&mut chunk[..capacity]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return self.fail(error),
                Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                    return self.fail(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed before HTTP Upgrade response completed",
                    ));
                }
                Poll::Ready(Ok(())) => self.buffered.extend_from_slice(buf.filled()),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for UpgradeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_response(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        if self.offset < self.buffered.len() {
            let amount = buf.remaining().min(self.buffered.len() - self.offset);
            buf.put_slice(&self.buffered[self.offset..self.offset + amount]);
            self.offset += amount;
            return Poll::Ready(Ok(()));
        }
        self.buffered.clear();
        self.offset = 0;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UpgradeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.failed() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.failed() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn read_head(stream: &mut BoxStream, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut scanned = 0;
    loop {
        if head_end_after(&bytes, scanned).is_some() {
            return Ok(bytes);
        }
        scanned = bytes.len();
        if bytes.len() == limit {
            return Err(invalid("HTTP Upgrade request headers exceed 12288 bytes"));
        }
        let mut chunk = [0_u8; 4096];
        let capacity = chunk.len().min(limit - bytes.len());
        let amount = stream.read(&mut chunk[..capacity]).await?;
        if amount == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed before HTTP Upgrade request completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..amount]);
    }
}

// net/textproto accepts either CRLF or LF line endings, including mixed ones.
fn head_end(bytes: &[u8]) -> Option<usize> {
    head_end_after(bytes, 0)
}

// Only rescan the two-byte overlap when a fragmented header gains more bytes.
fn head_end_after(bytes: &[u8], scanned: usize) -> Option<usize> {
    for (index, byte) in bytes.iter().enumerate().skip(scanned.saturating_sub(2)) {
        if *byte == b'\n'
            && (index == 0
                || bytes[index - 1] == b'\n'
                || (bytes[index - 1] == b'\r' && (index == 1 || bytes[index - 2] == b'\n')))
        {
            return Some(index + 1);
        }
    }
    None
}

type Headers = Vec<(String, Vec<u8>)>;

fn parse_head(bytes: &[u8]) -> io::Result<(&str, Headers)> {
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let first = lines
        .next()
        .ok_or_else(|| invalid("missing HTTP start line"))?;
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    let first = std::str::from_utf8(first).map_err(|_| invalid("invalid HTTP start line"))?;
    if first.is_empty() || first.bytes().any(|byte| byte < b' ' || byte == 127) {
        return Err(invalid("invalid HTTP start line"));
    }
    let mut headers: Headers = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return Ok((first, headers));
        }
        if line
            .iter()
            .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 127)
        {
            return Err(invalid("invalid HTTP header value"));
        }
        if matches!(line[0], b' ' | b'\t') {
            let (_, value) = headers
                .last_mut()
                .ok_or_else(|| invalid("HTTP header continuation without a field"))?;
            value.push(b' ');
            value.extend_from_slice(trim_ows(line));
            continue;
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| invalid("HTTP header without colon"))?;
        if colon == 0 || !line[..colon].iter().copied().all(is_token) {
            return Err(invalid("invalid HTTP header name"));
        }
        let name =
            std::str::from_utf8(&line[..colon]).map_err(|_| invalid("invalid HTTP header name"))?;
        headers.push((name.to_owned(), trim_ows(&line[colon + 1..]).to_vec()));
    }
    Err(invalid("incomplete HTTP header block"))
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn valid_http_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    bytes.len() == 8
        && &bytes[..5] == b"HTTP/"
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'.'
        && bytes[7].is_ascii_digit()
}

fn first_header<'a>(headers: &'a Headers, name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}

fn valid_upgrade_headers(headers: &Headers) -> bool {
    first_header(headers, "Connection").is_some_and(|value| value.eq_ignore_ascii_case(b"upgrade"))
        && first_header(headers, "Upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"))
}

fn validate_response(bytes: &[u8]) -> io::Result<()> {
    let (line, headers) = parse_head(bytes)?;
    let (version, status) = line
        .split_once(' ')
        .ok_or_else(|| invalid("malformed HTTP Upgrade response"))?;
    if !valid_http_version(version)
        || status.trim_start_matches(' ') != "101 Switching Protocols"
        || !valid_upgrade_headers(&headers)
    {
        return Err(invalid("unrecognized HTTP Upgrade response"));
    }
    validate_transfer_headers(&headers)?;
    Ok(())
}

fn parse_request(bytes: &[u8], config: &HttpUpgradeConfig) -> io::Result<RequestMetadata> {
    let (line, headers) = parse_head(bytes)?;
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts
        .next()
        .ok_or_else(|| invalid("missing HTTP request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| invalid("missing HTTP version"))?;
    if method.is_empty()
        || !method.bytes().all(is_token)
        || !valid_http_version(version)
        || parts.next().is_some()
    {
        return Err(invalid("invalid HTTP Upgrade request line"));
    }
    if headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Host"))
        .count()
        > 1
    {
        return Err(invalid("multiple HTTP Host headers"));
    }
    let header_host = std::str::from_utf8(first_header(&headers, "Host").unwrap_or_default())
        .map_err(|_| invalid("invalid HTTP Host"))?;
    let (host, path) = target_host_path(method, target, header_host)?;
    if !config.host.is_empty() && !valid_host(&host, &config.host) {
        return Err(invalid("HTTP Upgrade Host does not match configured host"));
    }
    if path != config.normalized_path() {
        return Err(invalid("HTTP Upgrade path does not match configured path"));
    }
    if !valid_upgrade_headers(&headers) {
        return Err(invalid("unrecognized HTTP Upgrade request"));
    }
    validate_transfer_headers(&headers)?;
    Ok(RequestMetadata {
        method: method.to_owned(),
        host,
        path,
        headers,
    })
}

// Validate the framing fields net/http parses even though the upgraded stream
// never reads an HTTP body. Identical duplicate Content-Length fields are legal.
fn validate_transfer_headers(headers: &Headers) -> io::Result<()> {
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, value)| value.as_slice())
        .collect();
    if let Some(first) = lengths.first()
        && (first.is_empty()
            || !first.iter().all(u8::is_ascii_digit)
            || lengths.iter().any(|value| value != first)
            || std::str::from_utf8(first)
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .is_none())
    {
        return Err(invalid("invalid or conflicting HTTP Content-Length"));
    }
    let encodings: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Transfer-Encoding"))
        .map(|(_, value)| value.as_slice())
        .collect();
    if encodings.len() > 1
        || encodings
            .first()
            .is_some_and(|value| !value.eq_ignore_ascii_case(b"chunked"))
    {
        return Err(invalid("unsupported HTTP Transfer-Encoding"));
    }
    Ok(())
}

fn target_host_path(method: &str, target: &str, header_host: &str) -> io::Result<(String, String)> {
    let (host, rest) = if target.starts_with('/') || target == "*" {
        (header_host, target)
    } else if let Some((scheme, authority)) = target.split_once("://") {
        if !scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+.-".contains(&byte))
        {
            return Err(invalid("invalid HTTP request-target scheme"));
        }
        let end = authority.find(['/', '?']).unwrap_or(authority.len());
        let authority_host = authority[..end].rsplit('@').next().unwrap_or_default();
        (authority_host, &authority[end..])
    } else if method == "CONNECT" {
        (target, "")
    } else {
        return Err(invalid("invalid HTTP request target"));
    };
    let raw_path = rest.split('?').next().unwrap_or_default();
    let path = String::from_utf8(percent_decode(raw_path.as_bytes(), false)?)
        .map_err(|_| invalid("HTTP Upgrade path is not UTF-8"))?;
    Ok((host.to_owned(), path))
}

/// Matches internet.IsValidHTTPHost: case-insensitive host, strip a request
/// port only when net.SplitHostPort would succeed; config must not contain one.
fn valid_host(request: &str, configured: &str) -> bool {
    let host = if request.contains(':') {
        if let Some(bracketed) = request.strip_prefix('[') {
            match bracketed.split_once("]:") {
                Some((host, port)) if !port.contains(':') && !host.contains(['[', ']']) => host,
                _ => return false,
            }
        } else {
            match request.split_once(':') {
                Some((host, port)) if !port.contains(':') && !host.contains(['[', ']']) => host,
                _ => return false,
            }
        }
    } else {
        request
    };
    host.eq_ignore_ascii_case(configured)
}

fn request_bytes(config: &HttpUpgradeConfig, fallback_host: &str) -> io::Result<Vec<u8>> {
    config.validate()?;
    let host = if config.host.is_empty() {
        fallback_host
    } else {
        &config.host
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte <= b' ' || byte >= 127 || b"/\\?#@".contains(&byte))
    {
        return Err(bad_config(
            "invalid HTTP Upgrade Host; use an ASCII DNS name or IP address",
        ));
    }
    let mut headers = config.headers.clone();
    apply_browser_headers(&mut headers);
    headers.insert("Connection".into(), "Upgrade".into());
    headers.insert("Upgrade".into(), "websocket".into());
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n",
        escape_path(&config.normalized_path(), false),
        host
    );
    let user_agent = headers
        .get("User-Agent")
        .map(String::as_str)
        .unwrap_or("Go-http-client/1.1");
    if !user_agent.is_empty() {
        request.push_str(&format!(
            "User-Agent: {}\r\n",
            clean_header_value(user_agent)
        ));
    }
    // Go's Request.Write emits User-Agent separately and sorts the remaining
    // map keys without changing their spelling. These exclusions are exact.
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "Host" | "User-Agent" | "Content-Length" | "Transfer-Encoding" | "Trailer"
        ) {
            continue;
        }
        request.push_str(&name);
        request.push_str(": ");
        request.push_str(&clean_header_value(&value));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    if request.len() > MAX_REQUEST_HEADER_BYTES {
        return Err(bad_config(
            "HTTP Upgrade request exceeds the Go listener's 12288-byte limit",
        ));
    }
    Ok(request.into_bytes())
}

fn clean_header_value(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .trim_matches([' ', '\t'])
        .to_owned()
}

fn escape_path(path: &str, preserve_percent: bool) -> String {
    let mut result = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric()
            || b"-_.~$&+,/:;=@".contains(&byte)
            || (preserve_percent && byte == b'%')
        {
            result.push(char::from(byte));
        } else {
            push_escape(&mut result, byte);
        }
    }
    result
}

fn push_escape(result: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    result.push('%');
    result.push(char::from(HEX[usize::from(byte >> 4)]));
    result.push(char::from(HEX[usize::from(byte & 15)]));
}

fn percent_decode(input: &[u8], plus_as_space: bool) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' => {
                let hi = input
                    .get(index + 1)
                    .and_then(|byte| char::from(*byte).to_digit(16));
                let lo = input
                    .get(index + 2)
                    .and_then(|byte| char::from(*byte).to_digit(16));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => output.push(((hi << 4) | lo) as u8),
                    _ => return Err(invalid("invalid percent-escape in HTTP path")),
                }
                index += 3;
            }
            b'+' if plus_as_space => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    Ok(output)
}

fn query_escape(input: &[u8]) -> String {
    let mut result = String::new();
    for byte in input {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(byte) {
            result.push(char::from(*byte));
        } else if *byte == b' ' {
            result.push('+');
        } else {
            push_escape(&mut result, *byte);
        }
    }
    result
}

fn extract_early_data(path: &str) -> (String, u32) {
    let (without_fragment, fragment) = path
        .split_once('#')
        .map_or((path, None), |(path, fragment)| (path, Some(fragment)));
    let Some((base, query)) = without_fragment.split_once('?') else {
        return (path.to_owned(), 0);
    };
    // url.Parse fails before Query if the path or fragment contains bad escapes
    // or the URL contains a control character. Go then leaves the input intact.
    if path.bytes().any(|byte| byte < b' ' || byte == 127)
        || percent_decode(base.as_bytes(), false).is_err()
        || fragment.is_some_and(|fragment| percent_decode(fragment.as_bytes(), false).is_err())
    {
        return (path.to_owned(), 0);
    }
    let mut values: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    for pair in query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.contains(';'))
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Ok(key), Ok(value)) = (
            percent_decode(key.as_bytes(), true),
            percent_decode(value.as_bytes(), true),
        ) {
            values.entry(key).or_default().push(value);
        }
    }
    let Some(ed) = values
        .get(b"ed".as_slice())
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
    else {
        return (path.to_owned(), 0);
    };
    let early_data = std::str::from_utf8(ed)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0) as u32;
    values.remove(b"ed".as_slice());
    let query: Vec<_> = values
        .into_iter()
        .flat_map(|(key, values)| {
            values
                .into_iter()
                .map(move |value| format!("{}={}", query_escape(&key), query_escape(&value)))
        })
        .collect();
    let mut result = escape_path(base, true);
    if !query.is_empty() {
        result.push('?');
        result.push_str(&query.join("&"));
    }
    if let Some(fragment) = fragment.filter(|fragment| !fragment.is_empty()) {
        result.push('#');
        for byte in fragment.bytes() {
            if byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@%?!()*".contains(&byte) {
                result.push(char::from(byte));
            } else {
                push_escape(&mut result, byte);
            }
        }
    }
    (result, early_data)
}

struct BrowserProfiles {
    chrome: String,
    chrome_hints: String,
    edge: String,
    edge_hints: String,
    firefox: String,
    safari: String,
    curl: String,
}

fn browser_profiles() -> &'static BrowserProfiles {
    static PROFILES: OnceLock<BrowserProfiles> = OnceLock::new();
    PROFILES.get_or_init(|| {
        let days = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64 / 86_400;
        let mut rng = rand::thread_rng();
        // Formulae and epoch dates are from common/utils/browser.go. Go seeds
        // its process-wide generator from CPU metadata; this implementation
        // uses the existing OS-seeded Rust RNG and caches the selected profile.
        let curl_minor = (days - civil_days(2023, 3, 20) - 60 - (rng.r#gen::<f64>().powi(2) * 165.0).floor() as i64) / 57;
        let firefox_version = (days - civil_days(2024, 7, 29) - 25 - (rng.r#gen::<f64>().powi(2) * 50.0).floor() as i64) / 30 + 128;
        let mut year = 1970 + (days / 365) as i32;
        while civil_days(year, 1, 1) > days { year -= 1; }
        while civil_days(year + 1, 1, 1) <= days { year += 1; }
        let delay = (rng.r#gen::<f64>().powi(3) * 75.0).floor() as i64;
        if days < civil_days(year, 9, 23) + delay { year -= 1; }
        const SAFARI_MINOR: [u8; 25] = [0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6];
        let minor_index = ((days - civil_days(year, 9, 23) - delay) / 15).clamp(0, 24) as usize;
        let chrome_version = 144 + (days - civil_days(2026, 1, 13) - 35 - (rng.r#gen::<f64>().powi(2) * 105.0).floor() as i64) / 35;
        let chrome = format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36");
        BrowserProfiles {
            edge: format!("{chrome}Edg/{chrome_version}.0.0.0"),
            chrome,
            chrome_hints: chrome_hints(chrome_version, "Google Chrome"),
            edge_hints: chrome_hints(chrome_version, "Microsoft Edge"),
            firefox: format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{firefox_version}.0) Gecko/20100101 Firefox/{firefox_version}.0"),
            safari: format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{}.{} Safari/605.1.15", year - 1999, SAFARI_MINOR[minor_index]),
            curl: format!("curl/8.{curl_minor}.0"),
        }
    })
}

fn civil_days(year: i32, month: i32, day: i32) -> i64 {
    let year = i64::from(year - i32::from(month <= 2));
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month + if month > 2 { -3 } else { 9 });
    let day_of_year = (153 * month + 2) / 5 + i64::from(day) - 1;
    era * 146_097 + year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year - 719_468
}

fn chrome_hints(version: i64, browser: &str) -> String {
    const SEPARATORS: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let seed = version.max(0) as usize;
    let source = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            SEPARATORS[seed % 11],
            SEPARATORS[(seed + 1) % 11],
            VERSIONS[seed % 3]
        ),
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"{browser}\";v=\"{version}\""),
    ];
    let mut result = ["", "", ""];
    for (index, destination) in ORDERS[seed % 6].iter().enumerate() {
        result[*destination] = &source[index];
    }
    result.join(", ")
}

/// Shared with the WebSocket transport: Go's TryDefaultHeadersWith("ws").
/// Keys deliberately retain their input case, matching http.Header map access.
pub(crate) fn apply_browser_headers(headers: &mut BTreeMap<String, String>) {
    let browser = headers
        .get("User-Agent")
        .map(String::as_str)
        .unwrap_or("chrome")
        .to_owned();
    if browser == "golang" {
        headers.remove("User-Agent");
        return;
    }
    if !matches!(
        browser.as_str(),
        "chrome" | "edge" | "firefox" | "safari" | "curl"
    ) {
        return;
    }
    let profiles = browser_profiles();
    if browser == "curl" {
        headers.insert("User-Agent".into(), profiles.curl.clone());
        return;
    }
    match browser.as_str() {
        "chrome" | "edge" => {
            let (ua, hints) = if browser == "chrome" {
                (&profiles.chrome, &profiles.chrome_hints)
            } else {
                (&profiles.edge, &profiles.edge_hints)
            };
            headers.insert("User-Agent".into(), ua.clone());
            headers.insert("Sec-CH-UA".into(), hints.clone());
            headers.insert("Sec-CH-UA-Mobile".into(), "?0".into());
            headers.insert("Sec-CH-UA-Platform".into(), "\"Windows\"".into());
            headers.insert("DNT".into(), "1".into());
            headers.insert("Accept-Language".into(), "en-US,en;q=0.9".into());
        }
        "firefox" => {
            headers.insert("User-Agent".into(), profiles.firefox.clone());
            headers.insert("DNT".into(), "1".into());
            headers.insert("Accept-Language".into(), "en-US,en;q=0.5".into());
        }
        "safari" => {
            headers.insert("User-Agent".into(), profiles.safari.clone());
            headers.insert("Accept-Language".into(), "en-US,en;q=0.9".into());
        }
        _ => unreachable!(),
    }
    headers.insert("Sec-Fetch-Mode".into(), "websocket".into());
    headers.insert(
        "Sec-Fetch-Dest".into(),
        if browser == "safari" {
            "websocket"
        } else {
            "empty"
        }
        .into(),
    );
    headers.insert("Sec-Fetch-Site".into(), "same-origin".into());
    for (name, value) in [
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Accept", "*/*"),
    ] {
        if headers.get(name).is_none_or(String::is_empty) {
            headers.insert(name.into(), value.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HttpUpgradeConfig {
        HttpUpgradeConfig {
            host: "example.com".into(),
            path: "tunnel".into(),
            headers: BTreeMap::from([("User-Agent".into(), "golang".into())]),
            early_data: 0,
        }
    }

    fn request(path: &str, host: &str, additional: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{additional}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn go_request_write_golden_keeps_header_case_and_escapes_literal_path() {
        let mut config = config();
        config.path = "route?x=1#two %".into();
        config
            .headers
            .insert("x-Custom".into(), " a\r\nb \t".into());
        config.headers.insert("Connection".into(), "close".into());
        config.headers.insert("Upgrade".into(), "other".into());
        config.headers.insert("Content-Length".into(), "100".into());
        assert_eq!(
            request_bytes(&config, "unused.example").unwrap(),
            b"GET /route%3Fx=1%23two%20%25 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nx-Custom: a  b\r\n\r\n"
        );
        config.host.clear();
        let bytes = request_bytes(&config, "fallback.example").unwrap();
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("Host: fallback.example\r\n")
        );
        assert!(
            !request_bytes(&config, "fallback.example")
                .unwrap()
                .windows(18)
                .any(|part| part == b"Sec-WebSocket-Key:")
        );
    }

    #[test]
    fn json_loader_removes_ed_and_sorts_remaining_query_before_path_escaping() {
        let config = HttpUpgradeConfig::from_json(&serde_json::json!({
            "path": "/tunnel?b=two+words&ed=4096&a=1&a=2",
            "headers": {"User-Agent": "golang"}
        }))
        .unwrap();
        assert_eq!(config.early_data, 4096);
        assert_eq!(config.path, "/tunnel?a=1&a=2&b=two+words");
        assert!(
            request_bytes(&config, "example.com")
                .unwrap()
                .starts_with(b"GET /tunnel%3Fa=1&a=2&b=two+words HTTP/1.1\r\n")
        );
        for (input, expected_path, expected_ed) in [
            ("/%20?ed=-1", "/%20", u32::MAX),
            ("/a?ed=invalid&z=1", "/a?z=1", 0),
            ("/a?ed=&z=1", "/a?ed=&z=1", 0),
            ("/a?ed=0", "/a", 0),
            ("/a b?ed=2", "/a%20b", 2),
            ("/%XX?ed=2", "/%XX?ed=2", 0),
            ("/a?ed=2#fragment", "/a#fragment", 2),
        ] {
            assert_eq!(
                extract_early_data(input),
                (expected_path.into(), expected_ed)
            );
        }
        assert_eq!(HttpUpgradeConfig::default().normalized_path(), "/");
        assert_eq!(config.normalized_path(), config.path);
    }

    #[test]
    fn invalid_configuration_is_explicit() {
        for settings in [
            serde_json::json!({"headers":{"hOsT":"override"}}),
            serde_json::json!({"headers":{"Bad Header":"value"}}),
            serde_json::json!({"headers":{"x-test":123}}),
            serde_json::json!({"path":123}),
            serde_json::json!({"acceptProxyProtocol":"true"}),
        ] {
            assert!(HttpUpgradeConfig::from_json(&settings).is_err());
        }
        assert_eq!(
            HttpUpgradeConfig::from_json(&serde_json::json!({"acceptProxyProtocol":true}))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert!(request_bytes(&config(), "unused").is_ok());
        let mut invalid_host = config();
        invalid_host.host = "host\r\nInjected: header".into();
        assert!(request_bytes(&invalid_host, "unused").is_err());
    }

    #[test]
    fn browser_aliases_match_source_headers_and_preserve_literal_user_agents() {
        assert_eq!(civil_days(1970, 1, 1), 0);
        assert_eq!(civil_days(2026, 1, 13), 20_466);
        let mut headers = BTreeMap::new();
        apply_browser_headers(&mut headers);
        assert!(headers["User-Agent"].contains("Chrome/"));
        assert_eq!(headers["Sec-Fetch-Mode"], "websocket");
        assert_eq!(headers["Sec-Fetch-Dest"], "empty");
        assert_eq!(headers["Sec-CH-UA-Platform"], "\"Windows\"");
        assert_eq!(headers["Accept"], "*/*");
        assert!(headers["Sec-CH-UA"].contains("\"Google Chrome\""));
        let first_ua = headers["User-Agent"].clone();
        let mut again = BTreeMap::new();
        apply_browser_headers(&mut again);
        assert_eq!(first_ua, again["User-Agent"]);
        for (alias, marker) in [
            ("edge", "Edg/"),
            ("firefox", "Firefox/"),
            ("safari", "Version/"),
            ("curl", "curl/"),
        ] {
            let mut headers = BTreeMap::from([
                ("User-Agent".into(), alias.into()),
                ("Accept".into(), "custom/accept".into()),
            ]);
            apply_browser_headers(&mut headers);
            assert!(headers["User-Agent"].contains(marker));
            assert_eq!(headers["Accept"], "custom/accept");
            if alias == "safari" {
                assert_eq!(headers["Sec-Fetch-Dest"], "websocket");
            }
            if alias == "curl" {
                assert!(!headers.contains_key("Sec-Fetch-Mode"));
            }
        }
        for user_agent in ["literal-agent", ""] {
            let mut headers = BTreeMap::from([("User-Agent".into(), user_agent.into())]);
            let original = headers.clone();
            apply_browser_headers(&mut headers);
            assert_eq!(headers, original);
        }
        let mut headers = BTreeMap::from([("user-agent".into(), "lower-case".into())]);
        apply_browser_headers(&mut headers);
        assert_eq!(headers["user-agent"], "lower-case");
        assert!(headers["User-Agent"].contains("Chrome/"));
    }

    #[test]
    fn response_requires_exact_go_status_and_header_values() {
        assert!(validate_response(RESPONSE).is_ok());
        assert!(
            validate_response(
                b"HTTP/1.0   101 Switching Protocols\nconnection: uPgRaDe\nupgrade: WebSocket\n\n"
            )
            .is_ok()
        );
        for response in [
            b"HTTP/1.1 101 switching protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
        ] {
            assert!(validate_response(response).is_err());
        }
        // Header.Get sees the first duplicate field, rather than joining it.
        assert!(validate_response(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n"
        )
        .is_ok());
    }

    #[test]
    fn request_validates_host_path_and_go_first_header_semantics() {
        let config = config();
        let valid = request(
            "/tunnel?ignored=1",
            "EXAMPLE.COM:443",
            "X-Fold: one\r\n\ttwo\r\n",
        );
        let metadata = parse_request(&valid, &config).unwrap();
        assert_eq!(metadata.path, "/tunnel");
        assert_eq!(metadata.header("x-fold"), Some(b"one two".as_slice()));
        for (path, host, additional) in [
            ("/other", "example.com", ""),
            ("/tunnel", "other.example", ""),
            ("/tunnel", "example.com", "Host: example.com\r\n"),
            ("/%XX", "example.com", ""),
        ] {
            assert!(parse_request(&request(path, host, additional), &config).is_err());
        }
        // hub.go does not insist on GET or Sec-WebSocket-* headers.
        let post = String::from_utf8(request("/tunnel", "example.com", ""))
            .unwrap()
            .replacen("GET ", "POST ", 1);
        assert_eq!(
            parse_request(post.as_bytes(), &config).unwrap().method,
            "POST"
        );
        let absolute = request("http://EXAMPLE.com/tunnel", "ignored.invalid", "");
        assert_eq!(
            parse_request(&absolute, &config).unwrap().host,
            "EXAMPLE.com"
        );
        let bad_tokens = String::from_utf8(request("/tunnel", "example.com", ""))
            .unwrap()
            .replace("Connection: Upgrade", "Connection: keep-alive, Upgrade");
        assert!(parse_request(bad_tokens.as_bytes(), &config).is_err());
        let literal = HttpUpgradeConfig {
            path: "/tunnel?a=1".into(),
            ..config
        };
        assert!(parse_request(&request("/tunnel%3Fa=1", "example.com", ""), &literal).is_ok());
    }

    #[test]
    fn host_matching_follows_split_host_port_including_ipv6() {
        for (request, configured, expected) in [
            ("EXAMPLE.com", "example.COM", true),
            ("example.com:443", "EXAMPLE.com", true),
            ("example.com:", "example.com", true),
            ("example.com:service", "example.com", true),
            ("example.com:443", "example.com:443", false),
            ("[2001:db8::1]:443", "2001:DB8::1", true),
            ("[2001:db8::1]", "2001:db8::1", false),
            ("2001:db8::1", "2001:db8::1", false),
            ("[2001:db8::1]:443", "[2001:db8::1]", false),
            ("other.example", "example.com", false),
        ] {
            assert_eq!(
                valid_host(request, configured),
                expected,
                "{request} / {configured}"
            );
        }
    }

    #[test]
    fn trusted_xff_requires_presence_of_a_configured_header() {
        let metadata = parse_request(
            &request(
                "/tunnel",
                "example.com",
                "X-Forwarded-For: 198.51.100.7, 10.0.0.1\r\nX-Trusted-CDN: yes\r\n",
            ),
            &config(),
        )
        .unwrap();
        assert_eq!(metadata.trusted_forwarded_ip(&[]), None);
        assert_eq!(metadata.trusted_forwarded_ip(&["Not-Present".into()]), None);
        assert_eq!(
            metadata.trusted_forwarded_ip(&["x-trusted-cdn".into()]),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            metadata.trusted_forwarded_ip(&["X-Forwarded-For".into()]),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn server_preserves_raw_payload_coalesced_with_headers() {
        let (mut peer, server) = tokio::io::duplex(65_536);
        let payload = b"\x00\xff\x81\x03abc\r\n\r\nunframed";
        let mut bytes = request("/tunnel", "example.com", "");
        bytes.extend_from_slice(payload);
        peer.write_all(&bytes).await.unwrap();
        let (mut stream, metadata) = server_upgrade_with_metadata(Box::new(server), &config())
            .await
            .unwrap();
        assert_eq!(metadata.method, "GET");
        let mut response = vec![0; RESPONSE.len()];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, RESPONSE);
        let mut read = vec![0; payload.len()];
        stream.read_exact(&mut read).await.unwrap();
        assert_eq!(read, payload);
        peer.write_all(b"later").await.unwrap();
        let mut later = [0; 5];
        stream.read_exact(&mut later).await.unwrap();
        assert_eq!(&later, b"later");
        stream.write_all(b"reply").await.unwrap();
        peer.read_exact(&mut later).await.unwrap();
        assert_eq!(&later, b"reply");
    }

    #[tokio::test]
    async fn early_data_is_raw_write_before_response_not_a_header_or_frame() {
        let (client, server) = tokio::io::duplex(65_536);
        let mut server: BoxStream = Box::new(server);
        let config = HttpUpgradeConfig {
            early_data: 1,
            ..config()
        };
        let mut client = client_upgrade(Box::new(client), &config, "unused")
            .await
            .unwrap();
        let sent = read_head(&mut server, MAX_REQUEST_HEADER_BYTES)
            .await
            .unwrap();
        assert_eq!(sent, request_bytes(&config, "unused").unwrap());
        // The configured value 1 is an enable flag, not an early-write byte cap.
        let payload = b"\x00\x01\x82not-websocket-masked";
        client.write_all(payload).await.unwrap();
        let mut early = vec![0; payload.len()];
        server.read_exact(&mut early).await.unwrap();
        assert_eq!(early, payload);
        let mut response = RESPONSE.to_vec();
        response.extend_from_slice(b"accepted");
        server.write_all(&response).await.unwrap();
        let mut output = Vec::new();
        for _ in 0..8 {
            output.push(client.read_u8().await.unwrap());
        }
        assert_eq!(output, b"accepted");
    }

    #[tokio::test]
    async fn eager_client_waits_for_fragmented_response_and_preserves_tail() {
        let (client, server) = tokio::io::duplex(65_536);
        let server_task = tokio::spawn(async move {
            let mut server: BoxStream = Box::new(server);
            read_head(&mut server, MAX_REQUEST_HEADER_BYTES)
                .await
                .unwrap();
            for byte in RESPONSE {
                server.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            server.write_all(b"payload").await.unwrap();
        });
        let mut client = client_upgrade(Box::new(client), &config(), "unused")
            .await
            .unwrap();
        let mut payload = [0; 7];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_during_deferred_header_read_retains_progress() {
        let (client, server) = tokio::io::duplex(65_536);
        let mut server: BoxStream = Box::new(server);
        let config = HttpUpgradeConfig {
            early_data: 4,
            ..config()
        };
        let mut client = client_upgrade(Box::new(client), &config, "unused")
            .await
            .unwrap();
        read_head(&mut server, MAX_REQUEST_HEADER_BYTES)
            .await
            .unwrap();
        server.write_all(&RESPONSE[..20]).await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err()
        );
        let mut remaining = RESPONSE[20..].to_vec();
        remaining.extend_from_slice(b"x");
        server.write_all(&remaining).await.unwrap();
        client.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
    }

    #[tokio::test]
    async fn failed_deferred_handshake_never_becomes_an_unchecked_raw_stream() {
        let (client, server) = tokio::io::duplex(65_536);
        let mut server: BoxStream = Box::new(server);
        let config = HttpUpgradeConfig {
            early_data: 1,
            ..config()
        };
        let mut client = client_upgrade(Box::new(client), &config, "unused")
            .await
            .unwrap();
        read_head(&mut server, MAX_REQUEST_HEADER_BYTES)
            .await
            .unwrap();
        server
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nnot tunnel data")
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            client.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            client.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            client.write(b"late write").await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn incomplete_oversize_and_slow_handshakes_fail_explicitly() {
        let (peer, server) = tokio::io::duplex(1024);
        let error = server_handshake(Box::new(server), &config(), Duration::from_millis(10))
            .await
            .err()
            .expect("idle handshake must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(peer);

        let (mut peer, server) = tokio::io::duplex(MAX_REQUEST_HEADER_BYTES * 2);
        let mut oversized = request("/tunnel", "example.com", "");
        oversized.truncate(oversized.len() - 2);
        oversized.extend_from_slice(b"X-Fill: ");
        oversized.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEADER_BYTES));
        peer.write_all(&oversized).await.unwrap();
        let error = server_upgrade(Box::new(server), &config())
            .await
            .err()
            .expect("oversized request must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let (mut peer, server) = tokio::io::duplex(1024);
        peer.write_all(b"GET /tunnel HTTP/1.1\r\n").await.unwrap();
        peer.shutdown().await.unwrap();
        let error = server_upgrade(Box::new(server), &config())
            .await
            .err()
            .expect("incomplete request must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn client_response_headers_are_bounded() {
        let (client, server) = tokio::io::duplex(MAX_RESPONSE_HEADER_BYTES * 2);
        let mut server: BoxStream = Box::new(server);
        let config = HttpUpgradeConfig {
            early_data: 1,
            ..config()
        };
        let mut client = client_upgrade(Box::new(client), &config, "unused")
            .await
            .unwrap();
        read_head(&mut server, MAX_REQUEST_HEADER_BYTES)
            .await
            .unwrap();
        let mut response = b"HTTP/1.1 101 Switching Protocols\r\nX-Fill: ".to_vec();
        response.resize(MAX_RESPONSE_HEADER_BYTES, b'a');
        server.write_all(&response).await.unwrap();
        let error = client.read(&mut [0]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn native_loopback_tcp_transfers_all_byte_values_and_half_closes() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = server_upgrade(Box::new(tcp), &config()).await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, (0_u8..=255).collect::<Vec<_>>());
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = client_upgrade(Box::new(tcp), &config(), "unused")
            .await
            .unwrap();
        let payload: Vec<_> = (0_u8..=255).collect();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        server.await.unwrap();
    }
}
