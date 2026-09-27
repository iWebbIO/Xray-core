//! Native XHTTP HTTP/1.1 packet-up, stream-up, and stream-one transport.
//!
//! Wire behavior follows transport/internet/splithttp/{config,client,hub,
//! upload_queue,xpadding}.go. Packet-up and stream-up split a GET downlink from
//! numbered or streaming uploads; stream-one uses one full-duplex request.
//! The main facade uses HTTP/1.1. The separate [`http2`] module provides native
//! HTTP/2 stream-one sessions; runtime HTTP/2 selection, HTTP/3 and Xmux remain
//! separate integration work. A TLS stream supplied to this HTTP/1.1 facade
//! must negotiate HTTP/1.1.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde_json::Value;
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader, DuplexStream, ReadBuf,
    },
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::transport::BoxStream;

pub type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;
/// Opens a fresh connection to the same XHTTP endpoint for each HTTP request.
pub type Connector = Arc<dyn Fn() -> ConnectFuture + Send + Sync>;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

#[derive(Clone, Copy, Debug)]
struct Range {
    from: usize,
    to: usize,
}

#[derive(Clone, Copy, Debug)]
struct SecondsRange {
    from: i32,
    to: i32,
}

impl SecondsRange {
    fn delay(self) -> Duration {
        // Go time.Sleep returns immediately for non-positive durations.
        Duration::from_secs(rand::thread_rng().gen_range(self.from..=self.to).max(0) as u64)
    }
}

impl Range {
    fn choose(self) -> usize {
        rand::thread_rng().gen_range(self.from..=self.to)
    }

    fn parse(value: Option<&Value>, default: Self) -> io::Result<Self> {
        let Some(value) = value.filter(|v| !v.is_null()) else {
            return Ok(default);
        };
        let parsed = if let Some(n) = value.as_u64() {
            Self {
                from: n.try_into().map_err(|_| invalid("range is too large"))?,
                to: n.try_into().map_err(|_| invalid("range is too large"))?,
            }
        } else if let Some(s) = value.as_str() {
            let (a, b) = s.split_once('-').unwrap_or((s, s));
            Self {
                from: a.parse().map_err(|_| invalid("invalid XHTTP range"))?,
                to: b.parse().map_err(|_| invalid("invalid XHTTP range"))?,
            }
        } else {
            return Err(invalid("XHTTP ranges must be numbers or from-to strings"));
        };
        if parsed.from == 0 && parsed.to == 0 {
            return Ok(default);
        }
        if parsed.from > parsed.to {
            return Err(invalid("XHTTP range is reversed"));
        }
        Ok(parsed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Auto,
    QueryInHeader,
}

impl Placement {
    fn parse(s: &str) -> io::Result<Self> {
        match s {
            "path" => Ok(Self::Path),
            "query" => Ok(Self::Query),
            "header" => Ok(Self::Header),
            "cookie" => Ok(Self::Cookie),
            "body" => Ok(Self::Body),
            "auto" => Ok(Self::Auto),
            "queryInHeader" => Ok(Self::QueryInHeader),
            _ => Err(invalid(format!("invalid XHTTP placement: {s}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

impl Mode {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "packet-up" => Ok(Self::PacketUp),
            "stream-up" => Ok(Self::StreamUp),
            "stream-one" => Ok(Self::StreamOne),
            _ => Err(unsupported(format!("unsupported XHTTP mode: {value}"))),
        }
    }

    fn allows_packet(self) -> bool {
        matches!(self, Self::Auto | Self::PacketUp)
    }

    fn allows_stream_up(self) -> bool {
        matches!(self, Self::Auto | Self::StreamUp)
    }

    fn allows_stream_one(self) -> bool {
        // The pinned Go listener also permits stream-one under stream-up.
        matches!(self, Self::Auto | Self::StreamUp | Self::StreamOne)
    }
}

/// Validated settings for the implemented HTTP/1.1 modes.
#[derive(Clone, Debug)]
pub struct Config {
    /// Configured Host header. Set the destination fallback with `with_authority`.
    pub host: String,
    mode: Mode,
    scheme: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    method: String,
    session_placement: Placement,
    session_key: String,
    seq_placement: Placement,
    seq_key: String,
    data_placement: Placement,
    data_key: String,
    chunk_size: Range,
    padding: Range,
    obfs: bool,
    padding_placement: Placement,
    padding_key: String,
    padding_header: String,
    max_post: Range,
    interval_ms: Range,
    max_buffered: usize,
    max_header: usize,
    no_sse: bool,
    no_grpc: bool,
    stream_up_keepalive: Option<SecondsRange>,
}

impl Config {
    pub fn from_json(value: &Value) -> io::Result<Self> {
        let empty = serde_json::Map::new();
        let outer = if value.is_null() {
            &empty
        } else {
            value
                .as_object()
                .ok_or_else(|| invalid("XHTTP settings must be an object"))?
        };
        // Go replaces the settings with extra, retaining only host/path/mode.
        let mut settings = if let Some(extra) = outer.get("extra").filter(|v| !v.is_null()) {
            extra
                .as_object()
                .ok_or_else(|| invalid("XHTTP extra must be an object"))?
                .clone()
        } else {
            outer.clone()
        };
        if outer.get("extra").is_some_and(|v| !v.is_null()) {
            for key in ["host", "path", "mode"] {
                settings.insert(
                    key.into(),
                    outer
                        .get(key)
                        .cloned()
                        .unwrap_or(Value::String(String::new())),
                );
            }
        }
        let string = |key: &str, default: &str| -> io::Result<String> {
            match settings.get(key).filter(|v| !v.is_null()) {
                None => Ok(default.into()),
                Some(Value::String(s)) if s.is_empty() => Ok(default.into()),
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(invalid(format!("{key} must be a string"))),
            }
        };
        let boolean = |key: &str| -> io::Result<bool> {
            settings
                .get(key)
                .filter(|v| !v.is_null())
                .map_or(Ok(false), |v| {
                    v.as_bool()
                        .ok_or_else(|| invalid(format!("{key} must be boolean")))
                })
        };
        let mode = Mode::parse(&string("mode", "auto")?)?;
        for key in [
            "xmux",
            "downloadSettings",
            "sessionIDTable",
            "sessionIDLength",
        ] {
            if settings.get(key).is_some_and(|v| {
                !v.is_null()
                    && v != ""
                    && v != &Value::Object(serde_json::Map::new())
                    && v != &Value::from(0)
            }) {
                return Err(unsupported(format!(
                    "native XHTTP {key} is not implemented"
                )));
            }
        }
        if string("xPaddingMethod", "repeat-x")? != "repeat-x" {
            return Err(unsupported(
                "native XHTTP tokenish HPACK padding is not implemented",
            ));
        }
        let session_placement = Placement::parse(&string("sessionIDPlacement", "path")?)?;
        let seq_placement = Placement::parse(&string("seqPlacement", "path")?)?;
        for placement in [session_placement, seq_placement] {
            if !matches!(
                placement,
                Placement::Path | Placement::Query | Placement::Header | Placement::Cookie
            ) {
                return Err(invalid("invalid XHTTP metadata placement"));
            }
        }
        let default_key = |placement, header, other| {
            if placement == Placement::Header {
                header
            } else {
                other
            }
        };
        let session_key = string(
            "sessionIDKey",
            default_key(session_placement, "X-Session", "x_session"),
        )?;
        let seq_key = string("seqKey", default_key(seq_placement, "X-Seq", "x_seq"))?;
        let data_placement = Placement::parse(&string("uplinkDataPlacement", "auto")?)?;
        if !matches!(
            data_placement,
            Placement::Body | Placement::Auto | Placement::Header | Placement::Cookie
        ) {
            return Err(invalid("invalid XHTTP uplink data placement"));
        }
        if matches!(data_placement, Placement::Header | Placement::Cookie) && mode != Mode::PacketUp
        {
            return Err(invalid(
                "header/cookie payloads require explicit packet-up mode",
            ));
        }
        let path_and_query = string("path", "/")?;
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((&path_and_query, ""));
        let mut path: String = if path.starts_with('/') {
            path.into()
        } else {
            format!("/{path}")
        };
        if (session_placement == Placement::Path || seq_placement == Placement::Path)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        let mut headers = Vec::new();
        if let Some(h) = settings.get("headers").filter(|v| !v.is_null()) {
            for (key, value) in h
                .as_object()
                .ok_or_else(|| invalid("XHTTP headers must be an object"))?
            {
                let value = value
                    .as_str()
                    .ok_or_else(|| invalid("XHTTP header values must be strings"))?;
                validate_header(key, value)?;
                if ["host", "content-length", "transfer-encoding", "connection"]
                    .iter()
                    .any(|reserved| key.eq_ignore_ascii_case(reserved))
                {
                    return Err(invalid(format!("XHTTP headers cannot override {key}")));
                }
                if key.eq_ignore_ascii_case("accept-encoding")
                    && !value.eq_ignore_ascii_case("identity")
                {
                    return Err(unsupported(
                        "XHTTP compressed HTTP response bodies are not implemented",
                    ));
                }
                headers.push((key.clone(), value.into()));
            }
        }
        let padding = Range::parse(
            settings.get("xPaddingBytes"),
            Range {
                from: 100,
                to: 1000,
            },
        )?;
        if padding.from == 0 || padding.to > 1024 * 1024 {
            return Err(invalid("XHTTP padding must be positive and at most 1 MiB"));
        }
        let max_post = Range::parse(
            settings.get("scMaxEachPostBytes"),
            Range {
                from: 1_000_000,
                to: 1_000_000,
            },
        )?;
        if max_post.from == 0 || max_post.to > 64 * 1024 * 1024 {
            return Err(invalid(
                "XHTTP post size must be positive and at most 64 MiB",
            ));
        }
        let chunk_default = match data_placement {
            Placement::Header => Range {
                from: 3000,
                to: 4000,
            },
            Placement::Cookie => Range {
                from: 2048,
                to: 3072,
            },
            _ => max_post,
        };
        let mut chunk_size = Range::parse(settings.get("uplinkChunkSize"), chunk_default)?;
        chunk_size.from = chunk_size.from.max(64);
        chunk_size.to = chunk_size.to.max(64);
        let padding_placement = Placement::parse(&string("xPaddingPlacement", "queryInHeader")?)?;
        if !matches!(
            padding_placement,
            Placement::Query | Placement::Header | Placement::Cookie | Placement::QueryInHeader
        ) {
            return Err(invalid("invalid XHTTP padding placement"));
        }
        let method = string("uplinkHTTPMethod", "POST")?.to_ascii_uppercase();
        if !is_token(&method) || method == "CONNECT" || method == "HEAD" || method == "OPTIONS" {
            return Err(invalid("unsupported XHTTP upload HTTP method"));
        }
        if method == "GET" && mode != Mode::PacketUp {
            return Err(invalid("GET uploads require explicit packet-up mode"));
        }
        let integer = |key: &str, default: usize| -> io::Result<usize> {
            match settings.get(key).filter(|v| !v.is_null()) {
                None => Ok(default),
                Some(v) => {
                    let n = v
                        .as_u64()
                        .ok_or_else(|| invalid(format!("invalid {key}")))?;
                    if n == 0 {
                        Ok(default)
                    } else {
                        usize::try_from(n).map_err(|_| invalid(format!("{key} is too large")))
                    }
                }
            }
        };
        let max_buffered = integer("scMaxBufferedPosts", 30)?;
        let max_header = integer("serverMaxHeaderBytes", 8192)?;
        if max_buffered > 65536 || !(1024..=16 * 1024 * 1024).contains(&max_header) {
            return Err(invalid("XHTTP queue or header limit is out of range"));
        }
        let config = Self {
            host: string("host", "")?,
            mode,
            scheme: "http".into(),
            path,
            query: parse_query(query)?,
            headers,
            method,
            session_placement,
            session_key,
            seq_placement,
            seq_key,
            data_placement,
            data_key: string(
                "uplinkDataKey",
                if data_placement == Placement::Cookie {
                    "x_data"
                } else {
                    "X-Data"
                },
            )?,
            chunk_size,
            padding,
            obfs: boolean("xPaddingObfsMode")?,
            padding_placement,
            padding_key: string("xPaddingKey", "x_padding")?,
            padding_header: string("xPaddingHeader", "X-Padding")?,
            max_post,
            interval_ms: Range::parse(
                settings.get("scMinPostsIntervalMs"),
                Range { from: 30, to: 30 },
            )?,
            max_buffered,
            max_header,
            no_sse: boolean("noSSEHeader")?,
            no_grpc: boolean("noGRPCHeader")?,
            stream_up_keepalive: stream_up_keepalive(settings.get("scStreamUpServerSecs"))?,
        };
        validate_header("Host", &config.host)?;
        for key in [
            &config.session_key,
            &config.seq_key,
            &config.data_key,
            &config.padding_key,
            &config.padding_header,
        ] {
            if !is_token(key) {
                return Err(invalid("XHTTP metadata keys must be HTTP tokens"));
            }
        }
        Ok(config)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Apply the destination/serverName fallback without replacing an explicit host.
    pub fn with_authority(
        mut self,
        authority: impl Into<String>,
        secure: bool,
    ) -> io::Result<Self> {
        if self.host.is_empty() {
            self.host = authority.into();
        }
        validate_header("Host", &self.host)?;
        if self.host.is_empty()
            || self
                .host
                .bytes()
                .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'?' | b'#' | b'@'))
        {
            return Err(invalid("invalid XHTTP authority"));
        }
        self.scheme = if secure { "https" } else { "http" }.into();
        Ok(self)
    }

    fn request(&self, session: &str, sequence: Option<u64>, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.request_inner(session, sequence, payload, false)
    }

    fn stream_request(&self, session: &str) -> io::Result<Vec<u8>> {
        self.request_inner(session, None, &[], true)
    }

    fn request_inner(
        &self,
        session: &str,
        sequence: Option<u64>,
        payload: &[u8],
        streaming: bool,
    ) -> io::Result<Vec<u8>> {
        let mut target = Target {
            path: self.path.clone(),
            query: self.query.clone(),
            headers: self.headers.clone(),
            cookies: Vec::new(),
        };
        target.set_header("Host", self.host.clone());
        target.set_header("Connection", "close".into());
        target.set_header("Accept-Encoding", "identity".into());
        let padding = "X".repeat(self.padding.choose());
        if !self.obfs {
            let mut query = Vec::new();
            set_query(&mut query, "x_padding", padding);
            target.set_header(
                "Referer",
                format!(
                    "{}://{}{}?{}",
                    self.scheme,
                    self.host,
                    encode_path(&self.path),
                    encode_query(&query)
                ),
            );
        } else {
            match self.padding_placement {
                Placement::Query => set_query(&mut target.query, &self.padding_key, padding),
                Placement::Cookie => target.cookies.push((self.padding_key.clone(), padding)),
                Placement::Header => target.set_header(&self.padding_header, padding),
                Placement::QueryInHeader => {
                    let mut query = Vec::new();
                    set_query(&mut query, &self.padding_key, padding);
                    target.set_header(
                        &self.padding_header,
                        format!(
                            "{}://{}{}?{}",
                            self.scheme,
                            self.host,
                            encode_path(&self.path),
                            encode_query(&query)
                        ),
                    );
                }
                _ => unreachable!(),
            }
        }
        if !session.is_empty() {
            target.meta(self.session_placement, &self.session_key, session);
        }
        if let Some(seq) = sequence {
            target.meta(self.seq_placement, &self.seq_key, &seq.to_string());
        }
        let body = if sequence.is_some()
            && matches!(self.data_placement, Placement::Header | Placement::Cookie)
        {
            let encoded = URL_SAFE_NO_PAD.encode(payload);
            let mut offset = 0;
            let mut index = 0;
            while offset < encoded.len() {
                let end = encoded.len().min(offset + self.chunk_size.choose());
                if self.data_placement == Placement::Header {
                    target.set_header(
                        &format!("{}-{index}", self.data_key),
                        encoded[offset..end].into(),
                    );
                } else {
                    target.cookies.push((
                        format!("{}_{index}", self.data_key),
                        encoded[offset..end].into(),
                    ));
                }
                offset = end;
                index += 1;
            }
            &[][..]
        } else {
            payload
        };
        if !target.cookies.is_empty() {
            let mut cookie = target
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| format!("{v}; "))
                .unwrap_or_default();
            cookie.push_str(
                &target
                    .cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            target.set_header("Cookie", cookie);
        }
        if streaming {
            target.set_header("Transfer-Encoding", "chunked".into());
            if !self.no_grpc {
                target.set_header("Content-Type", "application/grpc".into());
            }
        } else if sequence.is_some() {
            target.set_header("Content-Length", body.len().to_string());
        }
        let path = target.url_path();
        let method = if sequence.is_some() || streaming {
            &self.method
        } else {
            "GET"
        };
        let mut request = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
        for (key, value) in target.headers {
            validate_header(&key, &value)?;
            request.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(body);
        Ok(request)
    }

    fn metadata(&self, request: &Head) -> io::Result<(String, String)> {
        let (raw_path, query) = request
            .target
            .split_once('?')
            .unwrap_or((&request.target, ""));
        let path = percent_decode(raw_path, false)?;
        let subpath = path
            .strip_prefix(&self.path)
            .ok_or_else(|| invalid("XHTTP path mismatch"))?;
        let mut segments = subpath.split('/');
        let query = parse_query(query)?;
        let mut extract = |placement, key: &str| -> String {
            match placement {
                Placement::Path => segments.next().unwrap_or("").into(),
                Placement::Header => request.get(key).into(),
                Placement::Cookie => request.cookie(key),
                Placement::Query => query
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
                _ => String::new(),
            }
        };
        let session = extract(self.session_placement, &self.session_key);
        let seq = extract(self.seq_placement, &self.seq_key);
        Ok((session, seq))
    }

    fn valid_padding(&self, request: &Head) -> bool {
        let query_value = |uri: &str, key: &str| -> String {
            uri.split_once('?')
                .and_then(|(_, q)| parse_query(q).ok())
                .and_then(|q| q.into_iter().find(|(k, _)| k == key).map(|(_, v)| v))
                .unwrap_or_default()
        };
        let padding = if !self.obfs {
            if request.get("Referer").is_empty() {
                query_value(&request.target, "x_padding")
            } else {
                query_value(request.get("Referer"), "x_padding")
            }
        } else {
            let cookie = request.cookie(&self.padding_key);
            let header = request.get(&self.padding_header);
            if !cookie.is_empty() {
                cookie
            } else if !header.is_empty() {
                if self.padding_placement == Placement::Header {
                    header.into()
                } else {
                    query_value(header, &self.padding_key)
                }
            } else {
                query_value(&request.target, &self.padding_key)
            }
        };
        // Repeat-x validation in Go deliberately validates length, not alphabet.
        !padding.is_empty() && (self.padding.from..=self.padding.to).contains(&padding.len())
    }

    fn response(&self, request: &Head, status: u16, streaming: bool) -> Vec<u8> {
        self.response_inner(request, status, streaming, true)
    }

    fn response_inner(&self, request: &Head, status: u16, streaming: bool, sse: bool) -> Vec<u8> {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            413 => "Content Too Large",
            _ => "Internal Server Error",
        };
        let connection =
            if status == 200 && !streaming && request.method != "OPTIONS" && request.keep_alive() {
                "keep-alive"
            } else {
                "close"
            };
        let mut out = format!("HTTP/1.1 {status} {reason}\r\nConnection: {connection}\r\n");
        let origin = if request.get("Origin").is_empty() {
            "*"
        } else {
            request.get("Origin")
        };
        out.push_str(&format!("Access-Control-Allow-Origin: {origin}\r\n"));
        if [
            self.session_placement,
            self.seq_placement,
            self.padding_placement,
            self.data_placement,
        ]
        .contains(&Placement::Cookie)
        {
            out.push_str("Access-Control-Allow-Credentials: true\r\n");
        }
        if request.method == "OPTIONS" {
            for (response, request_key) in [
                (
                    "Access-Control-Allow-Methods",
                    "Access-Control-Request-Method",
                ),
                (
                    "Access-Control-Allow-Headers",
                    "Access-Control-Request-Headers",
                ),
            ] {
                let value = request.get(request_key);
                out.push_str(&format!(
                    "{response}: {}\r\n",
                    if value.is_empty() { "*" } else { value }
                ));
            }
        }
        let padding = "X".repeat(self.padding.choose());
        if !self.obfs {
            out.push_str(&format!("X-Padding: {padding}\r\n"));
        } else {
            match self.padding_placement {
                Placement::Header => {
                    out.push_str(&format!("{}: {padding}\r\n", self.padding_header))
                }
                Placement::QueryInHeader => out.push_str(&format!(
                    "{}: ?{}={}\r\n",
                    self.padding_header,
                    percent_encode(&self.padding_key),
                    padding
                )),
                Placement::Cookie => {
                    out.push_str(&format!("Set-Cookie: {}={padding}\r\n", self.padding_key))
                }
                _ => (),
            }
        }
        if streaming {
            out.push_str("Transfer-Encoding: chunked\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\n");
            if sse && !self.no_sse {
                out.push_str("Content-Type: text/event-stream\r\n");
            }
        } else {
            out.push_str("Content-Length: 0\r\nCache-Control: no-store\r\n");
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

fn stream_up_keepalive(value: Option<&Value>) -> io::Result<Option<SecondsRange>> {
    let default = SecondsRange { from: 20, to: 80 };
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Some(default));
    };
    let (from, to) = if let Some(number) = value.as_i64() {
        let number = i32::try_from(number)
            .map_err(|_| invalid("scStreamUpServerSecs exceeds int32 range"))?;
        (number, number)
    } else if let Some(value) = value.as_str() {
        if value.is_empty() {
            return Ok(Some(default));
        }
        if let Ok(number) = value.parse::<i32>() {
            (number, number)
        } else {
            let separator = value
                .char_indices()
                .skip(1)
                .find(|(_, ch)| *ch == '-')
                .map(|(index, _)| index)
                .ok_or_else(|| invalid("invalid scStreamUpServerSecs range"))?;
            let from = value[..separator]
                .parse::<i32>()
                .map_err(|_| invalid("invalid scStreamUpServerSecs range"))?;
            let to = value[separator + 1..]
                .parse::<i32>()
                .map_err(|_| invalid("invalid scStreamUpServerSecs range"))?;
            (from, to)
        }
    } else {
        return Err(invalid(
            "scStreamUpServerSecs must be an integer or range string",
        ));
    };
    let range = SecondsRange {
        from: from.min(to),
        to: from.max(to),
    };
    Ok(if range.to == 0 {
        Some(default)
    } else if range.to < 0 {
        None
    } else {
        Some(range)
    })
}

struct Target {
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
}
impl Target {
    fn set_header(&mut self, key: &str, value: String) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
        self.headers.push((key.into(), value));
    }
    fn meta(&mut self, placement: Placement, key: &str, value: &str) {
        match placement {
            Placement::Path => {
                if !self.path.ends_with('/') {
                    self.path.push('/');
                }
                self.path.push_str(value);
            }
            Placement::Query => set_query(&mut self.query, key, value.into()),
            Placement::Header => self.set_header(key, value.into()),
            Placement::Cookie => self.cookies.push((key.into(), value.into())),
            _ => (),
        }
    }
    fn url_path(&self) -> String {
        if self.query.is_empty() {
            encode_path(&self.path)
        } else {
            format!("{}?{}", encode_path(&self.path), encode_query(&self.query))
        }
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
fn validate_header(key: &str, value: &str) -> io::Result<()> {
    if !is_token(key) || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
        return Err(invalid("invalid HTTP header"));
    }
    Ok(())
}
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}
fn percent_decode(s: &str, query: bool) -> io::Result<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(invalid("truncated URL escape"));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| invalid("invalid URL escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| invalid("invalid URL escape"))?);
            index += 3;
        } else {
            out.push(if query && bytes[index] == b'+' {
                b' '
            } else {
                bytes[index]
            });
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| invalid("XHTTP URL is not UTF-8"))
}
fn parse_query(q: &str) -> io::Result<Vec<(String, String)>> {
    q.split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            Ok((percent_decode(key, true)?, percent_decode(value, true)?))
        })
        .collect()
}
fn set_query(q: &mut Vec<(String, String)>, key: &str, value: String) {
    q.retain(|(k, _)| k != key);
    q.push((key.into(), value));
}
fn encode_query(q: &[(String, String)]) -> String {
    let mut q = q.to_vec();
    q.sort_by(|a, b| a.0.cmp(&b.0));
    q.iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[derive(Debug)]
struct Head {
    method: String,
    target: String,
    status: u16,
    headers: Vec<(String, String)>,
}
impl Head {
    fn keep_alive(&self) -> bool {
        !self
            .get("Connection")
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("close"))
    }
    fn get(&self, key: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
    fn cookie(&self, key: &str) -> String {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .flat_map(|(_, v)| v.split(';'))
            .find_map(|part| {
                let (k, v) = part.trim().split_once('=')?;
                (k == key).then(|| v.trim_matches('"').into())
            })
            .unwrap_or_default()
    }
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete HTTP line",
            ));
        }
        let length = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |n| n + 1);
        if line.len() + length > limit {
            return Err(invalid("HTTP header/chunk line exceeds limit"));
        }
        line.extend_from_slice(&buf[..length]);
        reader.consume(length);
        if line.ends_with(b"\n") {
            if !line.ends_with(b"\r\n") {
                return Err(invalid("HTTP requires CRLF"));
            }
            return Ok(line);
        }
    }
}

async fn read_head<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    request: bool,
    limit: usize,
) -> io::Result<Head> {
    let mut bytes = Vec::new();
    loop {
        let line = read_line(reader, limit.saturating_sub(bytes.len())).await?;
        let end = line == b"\r\n";
        bytes.extend_from_slice(&line);
        if end {
            break;
        }
    }
    let mut headers = vec![httparse::EMPTY_HEADER; (limit / 4).min(4096)];
    let (method, target, status, parsed_headers) = if request {
        let mut req = httparse::Request::new(&mut headers);
        if !req
            .parse(&bytes)
            .map_err(|e| invalid(e.to_string()))?
            .is_complete()
            || req.version != Some(1)
        {
            return Err(invalid("XHTTP requires HTTP/1.1"));
        }
        (
            req.method.unwrap_or("").into(),
            req.path.unwrap_or("").into(),
            0,
            req.headers,
        )
    } else {
        let mut response = httparse::Response::new(&mut headers);
        if !response
            .parse(&bytes)
            .map_err(|e| invalid(e.to_string()))?
            .is_complete()
        {
            return Err(invalid("incomplete HTTP response"));
        }
        (
            String::new(),
            String::new(),
            response.code.unwrap_or(0),
            response.headers,
        )
    };
    let headers: io::Result<Vec<_>> = parsed_headers
        .iter()
        .map(|h| {
            let value = std::str::from_utf8(h.value)
                .map_err(|_| invalid("HTTP header value is not UTF-8"))?
                .to_string();
            validate_header(h.name, &value)?;
            Ok((h.name.into(), value))
        })
        .collect();
    let head = Head {
        method,
        target,
        status,
        headers: headers?,
    };
    if request
        && (head.get("Host").is_empty()
            || head
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .count()
                != 1)
    {
        return Err(invalid("HTTP/1.1 requires exactly one Host"));
    }
    Ok(head)
}

enum Body {
    Length(u64),
    Chunked {
        remaining: u64,
        delimiter: bool,
        done: bool,
    },
    Eof,
}
impl Body {
    fn from_head(head: &Head, request: bool) -> io::Result<Self> {
        let lengths: Vec<_> = head
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .collect();
        let transfers: Vec<_> = head
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
            .collect();
        if lengths.len() > 1 || transfers.len() > 1 || !lengths.is_empty() && !transfers.is_empty()
        {
            return Err(invalid("ambiguous HTTP body framing"));
        }
        if let Some((_, v)) = transfers.first() {
            if !v.eq_ignore_ascii_case("chunked") {
                return Err(unsupported("unsupported HTTP transfer coding"));
            }
            Ok(Self::Chunked {
                remaining: 0,
                delimiter: false,
                done: false,
            })
        } else if let Some((_, v)) = lengths.first() {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("invalid Content-Length"));
            }
            Ok(Self::Length(
                v.parse().map_err(|_| invalid("Content-Length overflow"))?,
            ))
        } else if request {
            Ok(Self::Length(0))
        } else {
            Ok(Self::Eof)
        }
    }
    async fn read<R: AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = match self {
            Self::Eof => return reader.read(buf).await,
            Self::Length(remaining) => remaining,
            Self::Chunked {
                remaining,
                delimiter,
                done,
            } => {
                if *done {
                    return Ok(0);
                }
                if *remaining == 0 {
                    if *delimiter {
                        let mut crlf = [0; 2];
                        reader.read_exact(&mut crlf).await?;
                        if crlf != *b"\r\n" {
                            return Err(invalid("invalid HTTP chunk delimiter"));
                        }
                    }
                    let line = read_line(reader, 8192).await?;
                    let line = std::str::from_utf8(&line[..line.len() - 2])
                        .map_err(|_| invalid("invalid chunk size"))?;
                    let size = line.split(';').next().unwrap_or("");
                    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(invalid("invalid chunk size"));
                    }
                    *remaining = u64::from_str_radix(size, 16)
                        .map_err(|_| invalid("HTTP chunk size overflow"))?;
                    *delimiter = true;
                    if *remaining == 0 {
                        let mut trailer_bytes = 0;
                        loop {
                            let line =
                                read_line(reader, 8192usize.saturating_sub(trailer_bytes)).await?;
                            trailer_bytes += line.len();
                            if line == b"\r\n" {
                                break;
                            }
                        }
                        *done = true;
                        return Ok(0);
                    }
                }
                remaining
            }
        };
        if *remaining == 0 {
            return Ok(0);
        }
        let length = (*remaining).min(buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..length]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated HTTP body",
            ));
        }
        *remaining -= n as u64;
        Ok(n)
    }
}

async fn body_bytes<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    body: &mut Body,
    max: usize,
) -> io::Result<Vec<u8>> {
    if matches!(body, Body::Length(n) if *n > max as u64) {
        return Err(invalid("XHTTP packet exceeds scMaxEachPostBytes"));
    }
    let mut result = Vec::new();
    let mut buf = [0; 16384];
    loop {
        let n = body.read(reader, &mut buf).await?;
        if n == 0 {
            return Ok(result);
        }
        if result.len() + n > max {
            return Err(invalid("XHTTP packet exceeds scMaxEachPostBytes"));
        }
        result.extend_from_slice(&buf[..n]);
    }
}

type Failure = Arc<StdMutex<Option<(io::ErrorKind, String)>>>;
struct TaskStream {
    inner: DuplexStream,
    task: JoinHandle<()>,
    failure: Failure,
    write_done: Option<oneshot::Receiver<io::Result<()>>>,
    write_result: Option<Result<(), (io::ErrorKind, String)>>,
}
impl Drop for TaskStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TaskStream {
    fn error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn poll_write_done(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(done) = &mut self.write_done {
            let result = match Pin::new(done).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result.unwrap_or_else(|_| {
                    Err(self.error().unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "XHTTP connection closed before writes completed",
                        )
                    }))
                }),
            };
            self.write_done = None;
            self.write_result = Some(result.map_err(|error| (error.kind(), error.to_string())));
        }
        Poll::Ready(match &self.write_result {
            Some(Err((kind, message))) => Err(io::Error::new(*kind, message.clone())),
            _ => Ok(()),
        })
    }
}
impl AsyncRead for TaskStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let capacity = buf.remaining();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if capacity > 0 && buf.filled().len() == before => {
                Poll::Ready(self.error().map_or(Ok(()), Err))
            }
            other => other,
        }
    }
}
impl AsyncWrite for TaskStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        // Register this writer's waker on completion even if the bounded pipe
        // is full. A peer can close an upload response while the GET remains
        // usable; the read half must not fail, and parked writes must wake.
        if let Poll::Ready(result) = self.poll_write_done(cx) {
            return Poll::Ready(Err(result.err().unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP writes are complete")
            })));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.error() {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(result) = self.poll_write_done(cx) {
            return Poll::Ready(result);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => (),
            other => return other,
        }
        self.poll_write_done(cx)
    }
}

type WriteDone = oneshot::Sender<io::Result<()>>;

fn notify_write_done(done: WriteDone, result: &io::Result<()>) {
    let result = result
        .as_ref()
        .map(|_| ())
        .map_err(|error| io::Error::new(error.kind(), error.to_string()));
    let _ = done.send(result);
}

async fn write_notified<F: Future<Output = io::Result<()>>>(
    future: F,
    done: WriteDone,
) -> io::Result<()> {
    let result = future.await;
    notify_write_done(done, &result);
    result
}
fn save_failure(failure: &Failure, result: io::Result<()>) {
    if let Err(error) = result {
        failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_or_insert_with(|| (error.kind(), error.to_string()));
    }
}

async fn response_body<R: AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> io::Result<Body> {
    // Go's HTTP client transparently handles informational responses too.
    for _ in 0..16 {
        let head = read_head(reader, false, limit.max(65536)).await?;
        if (100..200).contains(&head.status) && head.status != 101 {
            continue;
        }
        if head.status != 200 {
            return Err(invalid(format!("XHTTP returned HTTP {}", head.status)));
        }
        if !head.get("Content-Encoding").is_empty()
            && !head
                .get("Content-Encoding")
                .eq_ignore_ascii_case("identity")
        {
            return Err(unsupported("compressed XHTTP response"));
        }
        return Body::from_head(&head, false);
    }
    Err(invalid("too many informational XHTTP responses"))
}

async fn copy_body<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    body: &mut Body,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    let mut buf = [0; 16384];
    loop {
        let n = body.read(reader, &mut buf).await?;
        if n == 0 {
            return writer.shutdown().await;
        }
        writer.write_all(&buf[..n]).await?;
    }
}

/// Wait for the response after an application write-half shutdown; a completed
/// response or either I/O failure terminates the connection and its other half.
async fn relay<U, D>(up: U, down: D) -> io::Result<()>
where
    U: Future<Output = io::Result<()>>,
    D: Future<Output = io::Result<()>>,
{
    tokio::pin!(up, down);
    tokio::select! {
        result = &mut up => { result?; down.await },
        result = &mut down => result,
    }
}

/// Connect a tunnel. `auto` uses packet-up on HTTP/1.1; the connector must
/// return HTTP/1.1 byte streams. Streaming headers use Connection: close so
/// Go net/http does not drain the upload before flushing the response.
pub async fn connect(config: Config, connector: Connector) -> io::Result<BoxStream> {
    if config.host.is_empty() {
        return Err(invalid("XHTTP client needs an authority"));
    }
    if config.mode == Mode::StreamOne {
        return connect_stream_one(config, connector).await;
    }
    let session = uuid::Uuid::new_v4().to_string();
    let mut network = BufReader::new(connector().await?);
    network
        .get_mut()
        .write_all(&config.request(&session, None, &[])?)
        .await?;
    network.get_mut().flush().await?;
    let mut body = response_body(&mut network, config.max_header).await?;
    let upload_stream = if config.mode == Mode::StreamUp {
        let mut upload = connector().await?;
        send_response(&mut upload, &config.stream_request(&session)?).await?;
        Some(upload)
    } else {
        None
    };
    let (app, bridge) = tokio::io::duplex(65536);
    let (mut upstream, mut downstream) = tokio::io::split(bridge);
    let failure: Failure = Arc::new(StdMutex::new(None));
    let task_failure = failure.clone();
    let (write_done, write_completed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let down = copy_body(&mut body, &mut network, &mut downstream);
        let up = async {
            match upload_stream {
                Some(stream) => {
                    upload_stream_body(&mut upstream, stream, config.max_header, write_done).await
                }
                None => {
                    write_notified(
                        upload_packets(&mut upstream, &config, &session, &connector),
                        write_done,
                    )
                    .await
                }
            }
        };
        save_failure(&task_failure, relay(up, down).await);
    });
    Ok(Box::new(TaskStream {
        inner: app,
        task,
        failure,
        write_done: Some(write_completed),
        write_result: None,
    }))
}

async fn connect_stream_one(config: Config, connector: Connector) -> io::Result<BoxStream> {
    let mut network = connector().await?;
    send_response(&mut network, &config.stream_request("")?).await?;
    let (app, bridge) = tokio::io::duplex(65536);
    let (mut upstream, mut downstream) = tokio::io::split(bridge);
    let (network_reader, mut network_writer) = tokio::io::split(network);
    let mut network_reader = BufReader::new(network_reader);
    let failure: Failure = Arc::new(StdMutex::new(None));
    let task_failure = failure.clone();
    let (write_done, write_completed) = oneshot::channel();
    // Do not wait for the response here: some HTTP peers wait for the first
    // request-body bytes before producing headers, and the caller must write.
    let task = tokio::spawn(async move {
        let up = write_notified(
            write_chunked(&mut upstream, &mut network_writer, false),
            write_done,
        );
        let down = async {
            let mut body = response_body(&mut network_reader, config.max_header).await?;
            copy_body(&mut body, &mut network_reader, &mut downstream).await
        };
        save_failure(&task_failure, relay(up, down).await);
    });
    Ok(Box::new(TaskStream {
        inner: app,
        task,
        failure,
        write_done: Some(write_completed),
        write_result: None,
    }))
}

async fn upload_stream_body<R: AsyncRead + Unpin>(
    reader: &mut R,
    network: BoxStream,
    header_limit: usize,
    write_done: WriteDone,
) -> io::Result<()> {
    let (network_reader, mut network_writer) = tokio::io::split(network);
    let mut network_reader = BufReader::new(network_reader);
    let upload = write_notified(
        write_chunked(reader, &mut network_writer, false),
        write_done,
    );
    let response = async {
        let mut body = response_body(&mut network_reader, header_limit).await?;
        let mut discard = [0; 16384];
        while body.read(&mut network_reader, &mut discard).await? != 0 {}
        Ok(())
    };
    tokio::pin!(upload, response);
    tokio::select! {
        result = &mut upload => { result?; response.await },
        // An upload-only response is independent of the GET. Go closes the
        // upload writer on a completed response but continues consuming the
        // download; don't turn a clean response EOF into a download failure.
        result = &mut response => result,
    }
}

async fn upload_packets<R: AsyncRead + Unpin>(
    reader: &mut R,
    config: &Config,
    session: &str,
    connector: &Connector,
) -> io::Result<()> {
    let mut sequence = 0u64;
    // Keep writes bounded while honoring a configured smaller packet size.
    let mut buf = vec![0; config.max_post.choose().min(65536)];
    let mut previous = None;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        if let Some(previous) = previous {
            tokio::time::sleep_until(
                previous + Duration::from_millis(config.interval_ms.choose() as u64),
            )
            .await;
        }
        previous = Some(tokio::time::Instant::now());
        let mut upload = BufReader::new(connector().await?);
        upload
            .get_mut()
            .write_all(&config.request(session, Some(sequence), &buf[..n])?)
            .await?;
        upload.get_mut().flush().await?;
        let response = read_head(&mut upload, false, config.max_header.max(65536)).await?;
        if response.status != 200 {
            return Err(invalid(format!(
                "XHTTP upload returned HTTP {}",
                response.status
            )));
        }
        let mut body = Body::from_head(&response, false)?;
        let _ = body_bytes(&mut upload, &mut body, 1024 * 1024).await?;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("XHTTP upload sequence exhausted"))?;
    }
}

struct Packet {
    sequence: u64,
    bytes: Vec<u8>,
}
enum Upload {
    Packet(Packet),
    Stream(DuplexStream),
}
impl From<Packet> for Upload {
    fn from(packet: Packet) -> Self {
        Self::Packet(packet)
    }
}
struct Session {
    sender: mpsc::Sender<Upload>,
    receiver: Mutex<Option<mpsc::Receiver<Upload>>>,
    connected: std::sync::atomic::AtomicBool,
    stream_claimed: std::sync::atomic::AtomicBool,
    cancelled: CancellationToken,
    failure: Failure,
}
struct ServerInner {
    config: Config,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

// A tunnel can be dropped while its worker awaits I/O. Cleanup must also run
// when the JoinHandle is aborted, not only on its normal completion path.
struct SessionGuard {
    inner: std::sync::Weak<ServerInner>,
    id: String,
    session: Arc<Session>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.session.cancelled.cancel();
        if let (Some(inner), Ok(runtime)) =
            (self.inner.upgrade(), tokio::runtime::Handle::try_current())
        {
            let id = self.id.clone();
            let session = self.session.clone();
            runtime.spawn(async move {
                let mut sessions = inner.sessions.lock().await;
                if sessions.get(&id).is_some_and(|s| Arc::ptr_eq(s, &session)) {
                    sessions.remove(&id);
                }
            });
        }
    }
}

/// Clone once per accepted socket; session state must be shared by all sockets.
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}
impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            inner: Arc::new(ServerInner {
                config,
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    async fn session(&self, id: &str) -> Arc<Session> {
        let mut sessions = self.inner.sessions.lock().await;
        if let Some(session) = sessions.get(id) {
            return session.clone();
        }
        let (sender, receiver) = mpsc::channel(self.inner.config.max_buffered);
        let session = Arc::new(Session {
            sender,
            receiver: Mutex::new(Some(receiver)),
            connected: std::sync::atomic::AtomicBool::new(false),
            stream_claimed: std::sync::atomic::AtomicBool::new(false),
            cancelled: CancellationToken::new(),
            failure: Arc::new(StdMutex::new(None)),
        });
        sessions.insert(id.into(), session.clone());
        let weak = Arc::downgrade(&self.inner);
        let id = id.to_string();
        let expiring = session.clone();
        tokio::spawn(async move {
            tokio::select! { _ = tokio::time::sleep(Duration::from_secs(30)) => (), _ = expiring.cancelled.cancelled() => return }
            if expiring
                .connected
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            if let Some(inner) = weak.upgrade() {
                let mut sessions = inner.sessions.lock().await;
                if !expiring
                    .connected
                    .load(std::sync::atomic::Ordering::Acquire)
                    && sessions.get(&id).is_some_and(|s| Arc::ptr_eq(s, &expiring))
                {
                    sessions.remove(&id);
                    expiring.cancelled.cancel();
                }
            }
        });
        session
    }

    /// Serve one HTTP connection. A downlink GET or a stream-one request yields
    /// the logical tunnel. Packet requests, stream-up uploads, and preflights
    /// are handled here and yield `None` after their response has completed.
    pub async fn accept(&self, stream: BoxStream) -> io::Result<Option<BoxStream>> {
        let config = &self.inner.config;
        let mut network = BufReader::new(stream);
        let mut served_packet = false;
        loop {
            let request = match tokio::time::timeout(
                Duration::from_secs(4),
                read_head(&mut network, true, config.max_header),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "XHTTP request header timed out")
            })? {
                Ok(request) => request,
                Err(error) if served_packet && error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let reject = |status| config.response(&request, status, false);
            let request_host = request.get("Host");
            let host_matches = config.host.is_empty() || valid_host(request_host, &config.host);
            let metadata = config.metadata(&request);
            if !host_matches || metadata.is_err() {
                send_response(network.get_mut(), &reject(404)).await?;
                return Ok(None);
            }
            if request.method == "OPTIONS" {
                send_response(network.get_mut(), &reject(200)).await?;
                return Ok(None);
            }
            if !config.valid_padding(&request) {
                send_response(network.get_mut(), &reject(400)).await?;
                return Ok(None);
            }
            let (id, sequence) = metadata?;
            if id.len() > 1024 {
                send_response(network.get_mut(), &reject(400)).await?;
                return Ok(None);
            }
            let mut body = match Body::from_head(&request, true) {
                Ok(body) => body,
                Err(_) => {
                    send_response(network.get_mut(), &reject(400)).await?;
                    return Ok(None);
                }
            };
            if id.is_empty() {
                if !config.mode.allows_stream_one() {
                    send_response(network.get_mut(), &reject(400)).await?;
                    return Ok(None);
                }
                send_continue(&mut network, &request).await?;
                return self
                    .accept_stream_one(network, request, body)
                    .await
                    .map(Some);
            }
            if !sequence.is_empty() {
                if !config.mode.allows_packet() {
                    send_response(network.get_mut(), &reject(400)).await?;
                    return Ok(None);
                }
                let sequence = match sequence.parse::<u64>() {
                    Ok(seq) => seq,
                    Err(_) => {
                        send_response(network.get_mut(), &reject(500)).await?;
                        return Ok(None);
                    }
                };
                let session = self.session(&id).await;
                if session
                    .stream_claimed
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    send_response(network.get_mut(), &reject(409)).await?;
                    return Ok(None);
                }
                // Reserve queue capacity before allocating or consuming a packet
                // body. Blocked uploads therefore do not each buffer a full post.
                let permit = tokio::select! {
                    result = session.sender.reserve() => result.map_err(|_| invalid("XHTTP upload queue closed"))?,
                    _ = session.cancelled.cancelled() => {
                        send_response(network.get_mut(), &reject(409)).await?;
                        return Ok(None);
                    }
                };
                send_continue(&mut network, &request).await?;
                let mut payload = Vec::new();
                if matches!(config.data_placement, Placement::Header | Placement::Auto)
                    && append_payload(&request, &config.data_key, false, &mut payload).is_err()
                {
                    send_response(network.get_mut(), &reject(400)).await?;
                    return Ok(None);
                }
                if matches!(config.data_placement, Placement::Cookie | Placement::Auto)
                    && append_payload(&request, &config.data_key, true, &mut payload).is_err()
                {
                    send_response(network.get_mut(), &reject(400)).await?;
                    return Ok(None);
                }
                let uploaded = tokio::select! {
                    result = body_bytes(&mut network, &mut body, config.max_post.to) => result,
                    _ = session.cancelled.cancelled() => {
                        send_response(network.get_mut(), &reject(409)).await?;
                        return Ok(None);
                    }
                };
                match uploaded {
                    Ok(bytes) => {
                        if matches!(config.data_placement, Placement::Body | Placement::Auto) {
                            payload.extend_from_slice(&bytes);
                        }
                    }
                    Err(_) => {
                        send_response(network.get_mut(), &reject(413)).await?;
                        return Ok(None);
                    }
                }
                if payload.len() > config.max_post.to {
                    send_response(network.get_mut(), &reject(413)).await?;
                    return Ok(None);
                }
                if session.cancelled.is_cancelled()
                    || session
                        .stream_claimed
                        .load(std::sync::atomic::Ordering::Acquire)
                {
                    send_response(network.get_mut(), &reject(409)).await?;
                    return Ok(None);
                }
                permit.send(Upload::Packet(Packet {
                    sequence,
                    bytes: payload,
                }));
                send_response(network.get_mut(), &reject(200)).await?;
                if request.keep_alive() {
                    served_packet = true;
                    continue;
                }
                return Ok(None);
            }
            if request.method != "GET" {
                if !config.mode.allows_stream_up() {
                    send_response(network.get_mut(), &reject(400)).await?;
                    return Ok(None);
                }
                send_continue(&mut network, &request).await?;
                return self.accept_stream_up(network, request, body, id).await;
            }
            if !matches!(body, Body::Length(0)) {
                send_response(network.get_mut(), &reject(400)).await?;
                return Ok(None);
            }
            let session = self.session(&id).await;
            let Some(receiver) = session.receiver.lock().await.take() else {
                send_response(network.get_mut(), &reject(409)).await?;
                return Ok(None);
            };
            session
                .connected
                .store(true, std::sync::atomic::Ordering::Release);
            let cleanup = SessionGuard {
                inner: Arc::downgrade(&self.inner),
                id: id.clone(),
                session: session.clone(),
            };
            network
                .get_mut()
                .write_all(&config.response(&request, 200, true))
                .await?;
            network.get_mut().flush().await?;
            let (app, bridge) = tokio::io::duplex(65536);
            let (mut downstream, mut upstream) = tokio::io::split(bridge);
            // Split the BufReader itself; it may already contain request bytes.
            let (mut probe_reader, mut response_writer) = tokio::io::split(network);
            let failure = session.failure.clone();
            let task_failure = failure.clone();
            let (write_done, write_completed) = oneshot::channel();
            let inner = self.inner.clone();
            let max_buffered = config.max_buffered;
            let task = tokio::spawn(async move {
                let _cleanup = cleanup;
                let mut probe = [0; 1];
                let result = tokio::select! {
                    result = relay(reassemble(receiver, max_buffered, &mut upstream), write_notified(write_chunks(&mut downstream, &mut response_writer), write_done)) => result,
                    result = probe_reader.read(&mut probe) => result.map(|_| ()),
                    _ = session.cancelled.cancelled() => Ok(()),
                };
                save_failure(&task_failure, result);
                session.cancelled.cancel();
                let mut sessions = inner.sessions.lock().await;
                if sessions.get(&id).is_some_and(|s| Arc::ptr_eq(s, &session)) {
                    sessions.remove(&id);
                }
            });
            return Ok(Some(Box::new(TaskStream {
                inner: app,
                task,
                failure,
                write_done: Some(write_completed),
                write_result: None,
            })));
        }
    }

    async fn accept_stream_one(
        &self,
        mut network: BufReader<BoxStream>,
        request: Head,
        mut body: Body,
    ) -> io::Result<BoxStream> {
        send_response(
            network.get_mut(),
            &self.inner.config.response(&request, 200, true),
        )
        .await?;
        let (app, bridge) = tokio::io::duplex(65536);
        let (mut downstream, mut upstream) = tokio::io::split(bridge);
        // Keep any body bytes read together with the request headers.
        let (network_reader, mut network_writer) = tokio::io::split(network);
        let mut network_reader = BufReader::new(network_reader);
        let failure: Failure = Arc::new(StdMutex::new(None));
        let task_failure = failure.clone();
        let (write_done, write_completed) = oneshot::channel();
        let task = tokio::spawn(async move {
            let up = receive_body_then_disconnect(&mut body, &mut network_reader, &mut upstream);
            let down = write_notified(
                write_chunks(&mut downstream, &mut network_writer),
                write_done,
            );
            tokio::pin!(up, down);
            let result = tokio::select! {
                result = &mut up => result,
                result = &mut down => result,
            };
            save_failure(&task_failure, result);
        });
        Ok(Box::new(TaskStream {
            inner: app,
            task,
            failure,
            write_done: Some(write_completed),
            write_result: None,
        }))
    }

    async fn accept_stream_up(
        &self,
        mut network: BufReader<BoxStream>,
        request: Head,
        mut body: Body,
        id: String,
    ) -> io::Result<Option<BoxStream>> {
        let config = &self.inner.config;
        let session = self.session(&id).await;
        if session
            .stream_claimed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
            || session.cancelled.is_cancelled()
        {
            send_response(network.get_mut(), &config.response(&request, 409, false)).await?;
            return Ok(None);
        }
        // An aborted accept future must release the GET and other uploads too.
        let _cleanup = SessionGuard {
            inner: Arc::downgrade(&self.inner),
            id,
            session: session.clone(),
        };
        let (stream_reader, mut stream_writer) = tokio::io::duplex(65536);
        let queued = tokio::select! {
            result = session.sender.send(Upload::Stream(stream_reader)) => result.is_ok(),
            _ = session.cancelled.cancelled() => false,
        };
        if !queued {
            send_response(network.get_mut(), &config.response(&request, 409, false)).await?;
            return Ok(None);
        }
        // Stream-up responses carry only keepalive padding, never application
        // bytes and never SSE Content-Type; application data uses the GET.
        send_response(
            network.get_mut(),
            &config.response_inner(&request, 200, true, false),
        )
        .await?;
        let heartbeat = if !request.get("Referer").is_empty() || config.obfs {
            config.stream_up_keepalive
        } else {
            None
        };
        let (network_reader, mut response_writer) = tokio::io::split(network);
        let mut network_reader = BufReader::new(network_reader);
        let (result, finish_response) = {
            let upload =
                receive_body_then_disconnect(&mut body, &mut network_reader, &mut stream_writer);
            tokio::pin!(upload);
            let mut next_padding = tokio::time::Instant::now();
            loop {
                if let Some(interval) = heartbeat {
                    tokio::select! {
                        result = &mut upload => break (result, true),
                        _ = session.cancelled.cancelled() => break (Ok(()), true),
                        _ = tokio::time::sleep_until(next_padding) => (),
                    }
                    let padding = vec![b'X'; config.padding.choose()];
                    // A peer that stops reading its response cannot prevent
                    // dropping/cancelling the logical session. If cancellation
                    // interrupts a chunk, close the socket rather than append a
                    // terminator to an incompletely written chunk.
                    tokio::select! {
                        result = write_chunk(&mut response_writer, &padding) => {
                            if let Err(error) = result { break (Err(error), false); }
                        },
                        result = &mut upload => break (result, false),
                        _ = session.cancelled.cancelled() => break (Ok(()), false),
                    }
                    next_padding = tokio::time::Instant::now() + interval.delay();
                } else {
                    tokio::select! {
                        result = &mut upload => break (result, true),
                        _ = session.cancelled.cancelled() => break (Ok(()), true),
                    }
                }
            }
        };
        save_failure(&session.failure, result);
        if finish_response {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                finish_chunks(&mut response_writer, true),
            )
            .await;
        }
        Ok(None)
    }
}

async fn send_continue(network: &mut BufReader<BoxStream>, request: &Head) -> io::Result<()> {
    if request.get("Expect").eq_ignore_ascii_case("100-continue") {
        send_response(network.get_mut(), b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    } else if !request.get("Expect").is_empty() {
        return Err(unsupported("unsupported XHTTP expectation"));
    }
    Ok(())
}

/// Publish body EOF to the application while keeping the HTTP response alive.
/// Once EOF is delivered, observe peer closure so an abandoned response cannot
/// retain a session indefinitely. Connection: close forbids another request.
async fn receive_body_then_disconnect<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    body: &mut Body,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    copy_body(body, reader, writer).await?;
    let mut probe = [0; 1];
    if reader.read(&mut probe).await? != 0 {
        return Err(invalid(
            "unexpected bytes following XHTTP streaming request body",
        ));
    }
    Ok(())
}

fn valid_host(request: &str, configured: &str) -> bool {
    // Same normalization as transport/internet.IsValidHTTPHost: strip an
    // optional request port, preserving unbracketed IPv6 as the hostname.
    let host = if request.contains(':') {
        if let Some(rest) = request.strip_prefix('[') {
            match rest.split_once("]:") {
                Some((host, _)) => host,
                None => return false,
            }
        } else {
            match request.split_once(':') {
                Some((host, port)) if !port.contains(':') => host,
                _ => return false,
            }
        }
    } else {
        request
    };
    host.eq_ignore_ascii_case(configured)
}

async fn send_response<W: AsyncWrite + Unpin>(writer: &mut W, response: &[u8]) -> io::Result<()> {
    writer.write_all(response).await?;
    writer.flush().await
}

fn append_payload(request: &Head, key: &str, cookie: bool, result: &mut Vec<u8>) -> io::Result<()> {
    let mut encoded = String::new();
    for index in 0..=4096 {
        let value = if cookie {
            request.cookie(&format!("{key}_{index}"))
        } else {
            request.get(&format!("{key}-{index}")).into()
        };
        if value.is_empty() {
            break;
        }
        encoded.push_str(&value);
    }
    result.extend_from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| invalid("invalid XHTTP base64url payload"))?,
    );
    Ok(())
}

async fn reassemble<T: Into<Upload>, W: AsyncWrite + Unpin>(
    mut receiver: mpsc::Receiver<T>,
    max_buffered: usize,
    writer: &mut W,
) -> io::Result<()> {
    let mut next = 0u64;
    let mut pending = BTreeMap::new();
    while let Some(upload) = receiver.recv().await {
        let packet = match upload.into() {
            Upload::Packet(packet) => packet,
            Upload::Stream(mut reader) => {
                // A stream claim permanently switches the source upload queue
                // to its request reader; there can only be one such reader.
                tokio::io::copy(&mut reader, writer).await?;
                return writer.shutdown().await;
            }
        };
        // A retried HTTP upload may already have been delivered.
        if packet.sequence < next {
            continue;
        }
        pending.entry(packet.sequence).or_insert(packet.bytes);
        while let Some(bytes) = pending.remove(&next) {
            writer.write_all(&bytes).await?;
            next = next
                .checked_add(1)
                .ok_or_else(|| invalid("XHTTP sequence exhausted"))?;
        }
        if pending.len() > max_buffered {
            return Err(invalid("XHTTP reassembly queue is too large"));
        }
    }
    if !pending.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "XHTTP upload sequence has a gap",
        ));
    }
    writer.shutdown().await
}

async fn write_chunks<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    write_chunked(reader, writer, true).await
}

async fn write_chunk<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    debug_assert!(!bytes.is_empty());
    writer
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await?;
    writer.write_all(bytes).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await
}

async fn finish_chunks<W: AsyncWrite + Unpin>(writer: &mut W, close: bool) -> io::Result<()> {
    writer.write_all(b"0\r\n\r\n").await?;
    writer.flush().await?;
    if close {
        writer.shutdown().await
    } else {
        Ok(())
    }
}

async fn write_chunked<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    close: bool,
) -> io::Result<()> {
    let mut buf = [0; 16384];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // For request bodies a terminating chunk is sufficient. Closing
            // the transport write-half here can cancel Go's request context
            // before its final application response has been produced.
            return finish_chunks(writer, close).await;
        }
        write_chunk(writer, &buf[..n]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(value: Value) -> Config {
        Config::from_json(&value)
            .unwrap()
            .with_authority("example.test", false)
            .unwrap()
    }

    #[test]
    fn go_normalized_defaults_and_extra_replacement() {
        let c = config(
            json!({"path":"split?ed=1", "xPaddingBytes": 999, "extra": {"xPaddingBytes": "100-100"}}),
        );
        assert_eq!(c.path, "/split/");
        assert_eq!(c.padding.from, 100);
        assert_eq!(c.max_post.to, 1_000_000);
        assert_eq!(c.max_buffered, 30);
        assert_eq!(c.interval_ms.from, 30);
        assert_eq!(c.query, [("ed".into(), "1".into())]);
    }

    #[tokio::test]
    async fn reference_packet_fixture_uses_referer_before_session_metadata() {
        let c = config(json!({"path":"/split?ed=1", "xPaddingBytes":100}));
        let bytes = c.request("session", Some(42), b"\x00\xffhello").unwrap();
        let mut reader = BufReader::new(bytes.as_slice());
        let head = read_head(&mut reader, true, 8192).await.unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/split/session/42?ed=1");
        assert_eq!(
            head.get("Referer"),
            format!("http://example.test/split/?x_padding={}", "X".repeat(100))
        );
        assert!(c.valid_padding(&head));
        assert_eq!(c.metadata(&head).unwrap(), ("session".into(), "42".into()));
        assert_eq!(
            body_bytes(&mut reader, &mut Body::from_head(&head, true).unwrap(), 32)
                .await
                .unwrap(),
            b"\x00\xffhello"
        );
    }

    #[tokio::test]
    async fn reference_header_cookie_payload_and_metadata() {
        for placement in ["header", "cookie"] {
            let c = config(
                json!({"mode":"packet-up", "path":"/s", "sessionIDPlacement":"cookie", "seqPlacement":"query", "uplinkDataPlacement":placement, "uplinkDataKey":"data", "uplinkChunkSize":64, "xPaddingObfsMode":true, "xPaddingPlacement":"header", "xPaddingBytes":100}),
            );
            let data: Vec<_> = (0..=255).collect();
            let request = c.request("abc", Some(7), &data).unwrap();
            let head = read_head(&mut BufReader::new(request.as_slice()), true, 8192)
                .await
                .unwrap();
            assert_eq!(head.target, "/s?x_seq=7");
            assert_eq!(c.metadata(&head).unwrap(), ("abc".into(), "7".into()));
            assert!(c.valid_padding(&head));
            let mut payload = Vec::new();
            append_payload(&head, "data", placement == "cookie", &mut payload).unwrap();
            assert_eq!(payload, data);
            assert_eq!(head.get("Content-Length"), "0");
        }
    }

    #[tokio::test]
    async fn go_url_path_escaping_preserves_literal_percent_and_unicode() {
        let c = config(json!({"path": "/a b/é/%2f", "xPaddingBytes": 100}));
        let bytes = c.request("session", Some(0), b"data").unwrap();
        let head = read_head(&mut BufReader::new(bytes.as_slice()), true, 8192)
            .await
            .unwrap();
        assert_eq!(head.target, "/a%20b/%C3%A9/%252f/session/0");
        assert_eq!(c.metadata(&head).unwrap(), ("session".into(), "0".into()));
        assert!(
            head.get("Referer")
                .starts_with("http://example.test/a%20b/%C3%A9/%252f/?x_padding=")
        );
    }

    #[tokio::test]
    async fn persistent_uploads_match_go_pool_and_drop_cleans_session() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let c = config(json!({"path":"/split", "xPaddingBytes":100}));
            let server = Server::new(c.clone());
            let (mut down_client, down_socket) = tokio::io::duplex(8192);
            down_client
                .write_all(&c.request("session", None, &[]).unwrap())
                .await
                .unwrap();
            let mut tunnel = server.accept(Box::new(down_socket)).await.unwrap().unwrap();
            let mut down_client = BufReader::new(down_client);
            assert_eq!(
                read_head(&mut down_client, false, 8192)
                    .await
                    .unwrap()
                    .status,
                200
            );
            let (upload_client, upload_socket) = tokio::io::duplex(8192);
            let upload_server = server.clone();
            let worker =
                tokio::spawn(async move { upload_server.accept(Box::new(upload_socket)).await });
            let mut upload_client = BufReader::new(upload_client);
            for (sequence, payload) in [(1, "b"), (0, "a")] {
                let request = String::from_utf8(
                    c.request("session", Some(sequence), payload.as_bytes())
                        .unwrap(),
                )
                .unwrap()
                .replace("Connection: close", "Connection: keep-alive");
                upload_client
                    .get_mut()
                    .write_all(request.as_bytes())
                    .await
                    .unwrap();
                let head = read_head(&mut upload_client, false, 8192).await.unwrap();
                assert_eq!(head.status, 200);
                assert!(head.keep_alive());
            }
            let mut data = [0; 2];
            tunnel.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ab");
            drop(upload_client);
            assert!(worker.await.unwrap().unwrap().is_none());
            drop(tunnel);
            loop {
                if server.inner.sessions.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn unsupported_features_and_header_injection_are_rejected() {
        for value in [
            json!({"mode":"invalid-mode"}),
            json!({"xmux":{"maxConnections":2}}),
            json!({"xPaddingMethod":"tokenish"}),
            json!({"downloadSettings":{ "network":"tcp" }}),
        ] {
            assert_eq!(
                Config::from_json(&value).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
        assert!(Config::from_json(&json!({"headers":{"x-test":"a\r\nb: c"}})).is_err());
        assert!(Config::from_json(&json!({"headers":{"Host":"other"}})).is_err());
        assert!(Config::from_json(&json!({"xPaddingBytes":"0-100"})).is_err());
    }

    #[tokio::test]
    async fn chunked_body_reference_vector_preserves_buffered_bytes_and_trailers() {
        let bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;name=value\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: ignored\r\n\r\nnext";
        let mut reader = BufReader::new(bytes.as_slice());
        let head = read_head(&mut reader, false, 8192).await.unwrap();
        let data = body_bytes(&mut reader, &mut Body::from_head(&head, false).unwrap(), 32)
            .await
            .unwrap();
        assert_eq!(data, b"Wikipedia");
        let mut tail = String::new();
        reader.read_to_string(&mut tail).await.unwrap();
        assert_eq!(tail, "next");
    }

    #[tokio::test]
    async fn rejects_smuggled_or_truncated_http_bodies() {
        for bytes in [b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(), b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n".as_slice()] { let head = read_head(&mut BufReader::new(bytes), true, 8192).await.unwrap(); assert!(Body::from_head(&head, true).is_err()); }
        let mut body = Body::Length(5);
        let mut reader = BufReader::new(b"abc".as_slice());
        assert_eq!(
            body_bytes(&mut reader, &mut body, 10)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn sequence_queue_reorders_and_ignores_retries() {
        let (sender, receiver) = mpsc::channel(8);
        for (sequence, bytes) in [
            (2, b"c".to_vec()),
            (0, b"a".to_vec()),
            (0, b"duplicate".to_vec()),
            (1, b"b".to_vec()),
        ] {
            sender.send(Packet { sequence, bytes }).await.unwrap();
        }
        drop(sender);
        let (mut output, mut input) = tokio::io::duplex(32);
        reassemble(receiver, 8, &mut output).await.unwrap();
        let mut result = Vec::new();
        input.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, b"abc");
    }

    #[tokio::test]
    async fn packet_up_client_server_full_duplex_round_trip() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let address = listener.local_addr().unwrap();
            let c = config(json!({"mode":"packet-up", "path":"/xhttp", "scMaxEachPostBytes":4096, "scMinPostsIntervalMs":1}));
            let server = Server::new(c.clone());
            let acceptor = tokio::spawn(async move { loop { let (socket, _) = listener.accept().await.unwrap(); let server = server.clone(); tokio::spawn(async move { if let Some(mut tunnel) = server.accept(Box::new(socket)).await.unwrap() { let mut buf = [0; 8192]; loop { let n = tunnel.read(&mut buf).await.unwrap(); if n == 0 { break; } tunnel.write_all(&buf[..n]).await.unwrap(); } } }); } });
            let connector: Connector = Arc::new(move || Box::pin(async move { Ok(Box::new(tokio::net::TcpStream::connect(address).await?) as BoxStream) }));
            let tunnel = connect(c, connector).await.unwrap(); let (mut reader, mut writer) = tokio::io::split(tunnel);
            let payload: Vec<u8> = (0..150_000).map(|n| (n % 251) as u8).collect(); let expected = payload.clone();
            let sending = tokio::spawn(async move { writer.write_all(&payload).await.unwrap(); writer });
            let mut output = vec![0; expected.len()]; reader.read_exact(&mut output).await.unwrap(); assert_eq!(output, expected); drop(sending.await.unwrap()); drop(reader); acceptor.abort();
        }).await.unwrap();
    }
}

pub mod download;
pub mod http2;
pub mod xmux;
#[cfg(test)]
mod streaming_tests;
