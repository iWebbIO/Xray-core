// P23 tcp_headers: TCP header obfuscation codecs (http camouflage + noop).
#![allow(dead_code)]

//! TCP header obfuscation (`tcpSettings.header`): the HTTP request/response
//! camouflage of Go's `transport/internet/headers/http` and the identity
//! codec of `transport/internet/headers/noop`.
//!
//! Go wraps the connection in both directions. The outbound side writes the
//! configured request header before the first payload byte and skips the
//! peer's first header block on its first read (`Authenticator.Client`). The
//! inbound side validates the peer's request header (its percent-decoded
//! path must be one of the configured URIs), writes the configured response
//! header before its first write, and emits a camouflage 400/404 error
//! response when it closes before ever writing (`Authenticator.Server` plus
//! `Conn.Close`). Everything after the header block is relayed verbatim;
//! the first read never loses body bytes that arrived with the header.
//!
//! Requests are validated like Go's linked `net/http.readRequest`: a
//! malformed request line or header line fails fast while the header is
//! still arriving, an unterminated header fails after Go's 8192-byte budget
//! (`ErrHeaderToLong`), and a valid request with an unconfigured path fails
//! with `ErrHeaderMisMatch`. The outbound side skips the peer's terminated
//! header block without parsing it.

use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use rand::Rng;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::transport::BoxStream;

/// Go's `http.ENDING`: the boundary between header block and body.
const ENDING: &[u8] = b"\r\n\r\n";
/// Go's `http.maxHeaderLength`; the terminator may extend four bytes past it.
const MAX_HEADER_LENGTH: usize = 8192;

/// The codec selected by the `type` field of `tcpSettings.header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderKind {
    /// `""` and `"none"`: bytes pass through untouched (Go's noop codec).
    Noop,
    /// `"http"`: HTTP request/response camouflage.
    Http,
}

/// The `tcpSettings.header` JSON: `{"type": "...", "settings": {...}}`.
///
/// Go's loader (`infra/conf/transport_method.go`) reads `type` from the
/// whole header object and unmarshals that same object into the http
/// `Authenticator`, so `request`/`response` sit beside `type`; the
/// `settings` nesting of the integration contract is accepted as well and
/// top-level keys win. The type lookup is case-insensitive, unknown types
/// fail with Go's `unknown config id` error, and a missing `type` key fails
/// like Go's `type not found in JSON context`.
#[derive(Clone, Debug)]
pub struct HeaderSettings {
    kind: HeaderKind,
    request: RequestSettings,
    response: ResponseSettings,
}

/// Raw `request` overrides; empty fields keep Go's defaults at compile time.
#[derive(Clone, Debug, Default)]
struct RequestSettings {
    version: String,
    method: String,
    path: Vec<String>,
    headers: Option<BTreeMap<String, Option<Vec<String>>>>,
}

/// Raw `response` overrides; empty fields keep Go's defaults at compile time.
#[derive(Clone, Debug, Default)]
struct ResponseSettings {
    version: String,
    status: String,
    reason: String,
    headers: Option<BTreeMap<String, Option<Vec<String>>>>,
}

impl HeaderSettings {
    /// Parses the `tcpSettings.header` value. Only called for a present,
    /// non-null `header` key; an absent key means plain TCP.
    pub fn from_value(value: &Value) -> Result<Self> {
        let object = match value {
            // encoding/json decodes JSON null into a nil map, so Go fails
            // with the missing-type error rather than a syntax error.
            Value::Null => bail!("invalid TCP header config: type not found in JSON context"),
            Value::Object(object) => object,
            _ => bail!("invalid TCP header config: header settings must be a JSON object"),
        };
        let kind = match object.get("type") {
            None => bail!("invalid TCP header config: type not found in JSON context"),
            Some(Value::Null) => HeaderKind::Noop,
            Some(Value::String(name)) => match name.to_ascii_lowercase().as_str() {
                "" | "none" => HeaderKind::Noop,
                "http" => HeaderKind::Http,
                other => bail!("invalid TCP header config: unknown config id: {other}"),
            },
            Some(_) => bail!("invalid TCP header config: header type must be a string"),
        };
        if kind == HeaderKind::Noop {
            // Go's `none` creator has no fields, so the rest of the object
            // is silently ignored by encoding/json.
            return Ok(Self {
                kind,
                request: RequestSettings::default(),
                response: ResponseSettings::default(),
            });
        }
        Ok(Self {
            kind,
            request: parse_request_settings(field(object, "request"))?,
            response: parse_response_settings(field(object, "response"))?,
        })
    }

    pub fn kind(&self) -> HeaderKind {
        self.kind
    }
}

/// Reads a top-level http key, falling back to the `settings` object of the
/// integration contract (Go has no such key and would ignore it).
fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).or_else(|| {
        object
            .get("settings")
            .and_then(Value::as_object)
            .and_then(|settings| settings.get(key))
    })
}

fn parse_request_settings(value: Option<&Value>) -> Result<RequestSettings> {
    match value {
        None | Some(Value::Null) => Ok(RequestSettings::default()),
        Some(Value::Object(object)) => Ok(RequestSettings {
            version: string_setting(object, "version", "request.version")?,
            method: string_setting(object, "method", "request.method")?,
            path: string_list(object.get("path"))?,
            headers: header_map(object.get("headers"), "request.headers")?,
        }),
        Some(_) => bail!("invalid TCP header config: request header settings must be an object"),
    }
}

fn parse_response_settings(value: Option<&Value>) -> Result<ResponseSettings> {
    match value {
        None | Some(Value::Null) => Ok(ResponseSettings::default()),
        Some(Value::Object(object)) => Ok(ResponseSettings {
            version: string_setting(object, "version", "response.version")?,
            status: string_setting(object, "status", "response.status")?,
            reason: string_setting(object, "reason", "response.reason")?,
            headers: header_map(object.get("headers"), "response.headers")?,
        }),
        Some(_) => bail!("invalid TCP header config: response header settings must be an object"),
    }
}

/// A JSON string field; JSON null decodes as Go's empty string.
fn string_setting(object: &Map<String, Value>, key: &str, context: &str) -> Result<String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => bail!("invalid TCP header config: {context} must be a string"),
    }
}

/// Go's `StringList`: an array of strings, or one string split on commas.
/// JSON null decodes to an empty list (no override).
fn string_list(value: Option<&Value>) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                let Value::String(item) = item else {
                    bail!("invalid TCP header config: unknown format of a string list: {value}");
                };
                values.push(item.clone());
            }
            Ok(values)
        }
        Value::String(text) => Ok(text.split(',').map(str::to_owned).collect()),
        _ => bail!("invalid TCP header config: unknown format of a string list: {value}"),
    }
}

/// Go's `map[string]*StringList`: JSON null values decode to a nil pointer,
/// which `Build` rejects as an empty header value.
fn header_map(
    value: Option<&Value>,
    context: &str,
) -> Result<Option<BTreeMap<String, Option<Vec<String>>>>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => {
            let mut headers = BTreeMap::new();
            for (name, value) in object {
                let values = match value {
                    Value::Null => None,
                    Value::Array(_) | Value::String(_) => Some(string_list(Some(value))?),
                    _ => {
                        bail!("invalid TCP header config: unknown format of a string list: {value}")
                    }
                };
                headers.insert(name.clone(), values);
            }
            Ok(Some(headers))
        }
        Some(_) => bail!("invalid TCP header config: {context} must be an object"),
    }
}

/// One compiled codec pair: the accept-side and the dial-side of the
/// obfuscation over one stream.
pub struct HeaderCodec {
    kind: HeaderKind,
    request: RequestSpec,
    response: ResponseSpec,
}

/// The compiled request camouflage: Go's `http.RequestConfig` after
/// `infra/conf`'s `AuthenticatorRequest.Build` (defaults resolved).
#[derive(Clone, Debug, Default)]
struct RequestSpec {
    method: String,
    version: String,
    uris: Vec<String>,
    headers: Vec<(String, Vec<String>)>,
}

/// The compiled response camouflage: Go's `http.ResponseConfig` after
/// `AuthenticatorResponse.Build`. The zero value renders as
/// "HTTP/1.1 200 OK", matching Go's nil-handling in `formResponseHeader`.
#[derive(Clone, Debug, Default)]
struct ResponseSpec {
    version: String,
    code: String,
    reason: String,
    headers: Vec<(String, Vec<String>)>,
}

impl HeaderCodec {
    /// Compiles from the decoded settings, validating like Go's `Build`.
    pub fn compile(settings: &HeaderSettings) -> Result<Self> {
        if settings.kind == HeaderKind::Noop {
            return Ok(Self {
                kind: HeaderKind::Noop,
                request: RequestSpec::default(),
                response: ResponseSpec::default(),
            });
        }
        Ok(Self {
            kind: HeaderKind::Http,
            request: build_request_spec(&settings.request)?,
            response: build_response_spec(&settings.response)?,
        })
    }

    pub fn kind(&self) -> HeaderKind {
        self.kind
    }
}

/// `AuthenticatorRequest.Build`: defaults for everything left empty; a
/// non-empty `headers` map replaces the entire default set (sorted keys,
/// which a `BTreeMap` iteration provides).
fn build_request_spec(settings: &RequestSettings) -> Result<RequestSpec> {
    let mut headers = default_request_headers();
    if let Some(configured) = &settings.headers
        && !configured.is_empty()
    {
        headers = Vec::with_capacity(configured.len());
        for (name, values) in configured {
            let Some(values) = values else {
                bail!("invalid TCP header config: empty HTTP header value: {name}");
            };
            headers.push((name.clone(), values.clone()));
        }
    }
    Ok(RequestSpec {
        method: if settings.method.is_empty() {
            "GET".to_owned()
        } else {
            settings.method.clone()
        },
        version: if settings.version.is_empty() {
            "1.1".to_owned()
        } else {
            settings.version.clone()
        },
        uris: if settings.path.is_empty() {
            vec!["/".to_owned()]
        } else {
            settings.path.clone()
        },
        headers,
    })
}

/// `AuthenticatorResponse.Build`.
fn build_response_spec(settings: &ResponseSettings) -> Result<ResponseSpec> {
    let mut headers = default_response_headers();
    if let Some(configured) = &settings.headers
        && !configured.is_empty()
    {
        headers = Vec::with_capacity(configured.len());
        for (name, values) in configured {
            let Some(values) = values else {
                bail!("invalid TCP header config: empty HTTP header value: {name}");
            };
            headers.push((name.clone(), values.clone()));
        }
    }
    Ok(ResponseSpec {
        version: if settings.version.is_empty() {
            "1.1".to_owned()
        } else {
            settings.version.clone()
        },
        code: if settings.status.is_empty() {
            "200".to_owned()
        } else {
            settings.status.clone()
        },
        reason: if settings.reason.is_empty() {
            "OK".to_owned()
        } else {
            settings.reason.clone()
        },
        headers,
    })
}

/// The default request headers, in `AuthenticatorRequest.Build`'s exact order.
fn default_request_headers() -> Vec<(String, Vec<String>)> {
    let chrome = chrome_profile();
    vec![
        (
            "Host".to_owned(),
            vec!["www.baidu.com".to_owned(), "www.bing.com".to_owned()],
        ),
        ("User-Agent".to_owned(), vec![chrome.user_agent.clone()]),
        ("Sec-CH-UA".to_owned(), vec![chrome.ch_ua.clone()]),
        ("Sec-CH-UA-Mobile".to_owned(), vec!["?0".to_owned()]),
        ("Sec-CH-UA-Platform".to_owned(), vec!["Windows".to_owned()]),
        (
            "Sec-Fetch-Mode".to_owned(),
            vec![
                "no-cors".to_owned(),
                "cors".to_owned(),
                "same-origin".to_owned(),
            ],
        ),
        ("Sec-Fetch-Dest".to_owned(), vec!["empty".to_owned()]),
        ("Sec-Fetch-Site".to_owned(), vec!["none".to_owned()]),
        ("Sec-Fetch-User".to_owned(), vec!["?1".to_owned()]),
        (
            "Accept-Encoding".to_owned(),
            vec!["gzip, deflate".to_owned()],
        ),
        ("Connection".to_owned(), vec!["keep-alive".to_owned()]),
        ("Pragma".to_owned(), vec!["no-cache".to_owned()]),
    ]
}

/// The default response headers, in `AuthenticatorResponse.Build`'s order.
fn default_response_headers() -> Vec<(String, Vec<String>)> {
    vec![
        (
            "Content-Type".to_owned(),
            vec![
                "application/octet-stream".to_owned(),
                "video/mpeg".to_owned(),
            ],
        ),
        ("Transfer-Encoding".to_owned(), vec!["chunked".to_owned()]),
        ("Connection".to_owned(), vec!["keep-alive".to_owned()]),
        ("Pragma".to_owned(), vec!["no-cache".to_owned()]),
        (
            "Cache-Control".to_owned(),
            vec!["private".to_owned(), "no-cache".to_owned()],
        ),
    ]
}

/// Go's `resp400`/`resp404` camouflage responses from `resp.go`.
fn error_response_spec(code: &str, reason: &str) -> ResponseSpec {
    ResponseSpec {
        version: "1.1".to_owned(),
        code: code.to_owned(),
        reason: reason.to_owned(),
        headers: vec![
            ("Connection".to_owned(), vec!["close".to_owned()]),
            ("Cache-Control".to_owned(), vec!["private".to_owned()]),
            ("Content-Length".to_owned(), vec!["0".to_owned()]),
        ],
    }
}

struct ChromeProfile {
    version: i64,
    user_agent: String,
    ch_ua: String,
}

/// `common/utils`'s `ChromeUA`/`ChromeUACH`: the version derives from the
/// current date and a squared-random delay, and the brand list is
/// GREASE-shuffled with the version as seed. Computed once per process,
/// like Go's package-level var.
fn chrome_profile() -> &'static ChromeProfile {
    static PROFILE: OnceLock<ChromeProfile> = OnceLock::new();
    PROFILE.get_or_init(|| {
        let mut rng = rand::thread_rng();
        // Chrome 144 was released on 2026-01-13, day 20466 of the epoch.
        let days = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            / 86_400;
        let delay = (rng.r#gen::<f64>().powi(2) * 105.0).floor() as i64;
        let version = 144 + (days - 20_466 - 35 - delay) / 35;
        let user_agent = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/{version}.0.0.0 Safari/537.36"
        );
        ChromeProfile {
            version,
            user_agent,
            ch_ua: greased_ch_ua(version),
        }
    })
}

/// `utils.getGreasedChUa(version, "chrome")`.
fn greased_ch_ua(version: i64) -> String {
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
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            SEPARATORS[seed % 11],
            SEPARATORS[(seed + 1) % 11],
            VERSIONS[seed % 3]
        ),
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"Google Chrome\";v=\"{version}\""),
    ];
    let mut shuffled = [String::new(), String::new(), String::new()];
    for (index, destination) in ORDERS[seed % 6].iter().enumerate() {
        shuffled[*destination] = brands[index].clone();
    }
    shuffled.join(", ")
}

/// `pickString`: a random entry when several are configured.
fn pick_string(values: &[String]) -> &str {
    match values.len() {
        0 => "",
        1 => &values[0],
        count => &values[rand::thread_rng().gen_range(0..count)],
    }
}

/// `Authenticator.GetClientWriter`: the request line plus picked headers.
fn render_request_header(request: &RequestSpec) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&request.method);
    out.push(' ');
    out.push_str(pick_string(&request.uris));
    out.push_str(" HTTP/");
    out.push_str(&request.version);
    out.push_str("\r\n");
    for (name, values) in &request.headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(pick_string(values));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// `formResponseHeader`: the status line, picked headers, and Go's automatic
/// `Date` header (http.TimeFormat) unless a Date header is configured.
fn render_response_header(response: &ResponseSpec) -> Vec<u8> {
    let mut out = format!(
        "HTTP/{} {} {}\r\n",
        response.version, response.code, response.reason
    );
    for (name, values) in &response.headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(pick_string(values));
        out.push_str("\r\n");
    }
    if !has_header(&response.headers, "Date") {
        out.push_str("Date: ");
        out.push_str(&http_date_now());
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// `ResponseConfig.HasHeader`, case-insensitive on the configured names.
fn has_header(headers: &[(String, Vec<String>)], name: &str) -> bool {
    headers
        .iter()
        .any(|(header, _)| header.eq_ignore_ascii_case(name))
}

/// Go's `http.TimeFormat`: "Mon, 02 Jan 2006 15:04:05 GMT".
fn http_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Why a header block was rejected; each variant also selects the error
/// response Go's `Conn.Close` writes.
#[derive(Debug)]
enum ScanFailure {
    /// `ErrHeaderMisMatch`: the request path is not configured.
    Mismatch,
    /// `ErrHeaderToLong`.
    TooLong,
    /// net/http's parse errors ("malformed ..."/"invalid ...").
    Malformed(String),
    /// A failure of the underlying stream, including unexpected EOF.
    Io(io::Error),
}

impl ScanFailure {
    fn message(&self) -> String {
        match self {
            Self::Mismatch => "Header Mismatch.".to_owned(),
            Self::TooLong => "Header too long.".to_owned(),
            Self::Malformed(text) => text.clone(),
            Self::Io(error) => error.to_string(),
        }
    }

    fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::Io(error) => error.kind(),
            _ => io::ErrorKind::InvalidData,
        }
    }

    fn into_io(self) -> io::Error {
        let message = self.message();
        match self {
            Self::Io(error) => error,
            _ => io::Error::new(io::ErrorKind::InvalidData, message),
        }
    }

    /// Go writes `errorMismatchWriter` (resp404) on mismatch and resp400
    /// (`errorWriter`/`errorTooLongWriter`) for every other failure.
    fn error_response(&self) -> ResponseSpec {
        match self {
            Self::Mismatch => error_response_spec("404", "Not Found"),
            _ => error_response_spec("400", "Bad Request"),
        }
    }
}

/// The in-progress consumption of one header block: Go's `HeaderReader.Read`
/// loop, resumable across `poll_read` wake-ups.
#[derive(Default)]
struct HeaderScan {
    buffered: Vec<u8>,
    /// Bytes already searched for `ENDING`.
    scanned: usize,
    /// Bytes already covered by the incremental line validation.
    validated: usize,
    request_line_done: bool,
    headers_terminated: bool,
}

impl HeaderScan {
    /// The incremental `readRequest` call of Go's read loop: every complete
    /// line must still parse, so malformed data fails fast instead of
    /// filling the whole 8192-byte budget. Truncated lines are fine (Go's
    /// `io.ErrUnexpectedEOF` path keeps reading).
    fn validate_partial(&mut self) -> std::result::Result<(), ScanFailure> {
        if self.headers_terminated {
            return Ok(());
        }
        loop {
            let Some(line) = next_line(&self.buffered, &mut self.validated) else {
                return Ok(());
            };
            if self.request_line_done {
                if line.is_empty() {
                    // A blank line already ends the header block for
                    // net/http (bare-LF peers), but the scan keeps hunting
                    // for Go's literal CRLFCRLF terminator.
                    self.headers_terminated = true;
                    return Ok(());
                }
                if let Err(text) = validate_header_line(line) {
                    return Err(ScanFailure::Malformed(text));
                }
            } else {
                if let Err(text) = validate_request_line(line) {
                    return Err(ScanFailure::Malformed(text));
                }
                self.request_line_done = true;
            }
        }
    }
}

/// Splits the next CRLF- or LF-terminated line, advancing `offset` past the
/// newline. Returns `None` while the tail is still an unterminated line.
fn next_line<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let from = *offset;
    let newline = bytes[from..].iter().position(|byte| *byte == b'\n')?;
    let end = from + newline;
    let mut line = &bytes[from..end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    *offset = end + 1;
    Some(line)
}

/// Parses complete lines of a request header like net/http's `readRequest`.
/// Returns the percent-decoded request path; a missing blank line (partial
/// data) is not an error, matching the incremental validation.
fn parse_request_lines(header: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut offset = 0;
    let mut path = Vec::new();
    let mut request_line_done = false;
    while offset < header.len() {
        let Some(line) = next_line(header, &mut offset) else {
            break;
        };
        if request_line_done {
            if line.is_empty() {
                break;
            }
            validate_header_line(line)?;
        } else {
            path = validate_request_line(line)?;
            request_line_done = true;
        }
    }
    Ok(path)
}

/// The request line: `METHOD SP REQUEST-URI SP HTTP/x.y` with Go's
/// `validMethod`, `parseHTTPVersion`, and `url.ParseRequestURI` checks.
/// Returns the decoded path.
fn validate_request_line(line: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let (method, rest) = split_once(line, b' ').ok_or_else(|| malformed_request(line))?;
    let (uri, version) = split_once(rest, b' ').ok_or_else(|| malformed_request(line))?;
    if method.is_empty() || !method.iter().all(|byte| is_token(*byte)) {
        return Err(format!("invalid method \"{}\"", lossy(method)));
    }
    if !is_http_version(version) {
        return Err(format!("malformed HTTP version \"{}\"", lossy(version)));
    }
    parse_request_uri(uri)
}

/// `url.ParseRequestURI`: origin-form ("/path?query"), absolute-form
/// ("scheme://authority/path?query"), and opaque form ("scheme:rest",
/// empty path). The decoded path excludes the query.
fn parse_request_uri(uri: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if uri.is_empty() {
        return Err("empty URI for request".to_owned());
    }
    if uri.iter().any(|byte| *byte < b' ' || *byte == 0x7f) {
        return Err("invalid control character in URL".to_owned());
    }
    let raw_path: &[u8] = if uri[0] == b'/' {
        split_once(uri, b'?').map_or(uri, |(path, _)| path)
    } else if let Some(scheme) = scheme_offset(uri) {
        let after = &uri[scheme + 1..];
        if !after.starts_with(b"//") {
            return Ok(Vec::new());
        }
        let rest = &after[2..];
        let Some(end) = rest.iter().position(|byte| *byte == b'/' || *byte == b'?') else {
            return Ok(Vec::new());
        };
        if rest[end] == b'?' {
            return Ok(Vec::new());
        }
        let path = &rest[end..];
        split_once(path, b'?').map_or(path, |(path, _)| path)
    } else {
        return Err("invalid URI for request".to_owned());
    };
    percent_decode(raw_path)
}

/// net/url's `getScheme`: the offset of the first colon when the prefix is a
/// valid scheme (alpha first, then alphanumeric or `+`/`-`/`.`).
fn scheme_offset(uri: &[u8]) -> Option<usize> {
    for (index, byte) in uri.iter().enumerate() {
        if *byte == b':' {
            return (index > 0).then_some(index);
        }
        let valid = if index == 0 {
            byte.is_ascii_alphabetic()
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        };
        if !valid {
            return None;
        }
    }
    None
}

fn percent_decode(bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        let escape = &bytes[index..(index + 3).min(bytes.len())];
        let hi = bytes
            .get(index + 1)
            .and_then(|byte| (*byte as char).to_digit(16));
        let lo = bytes
            .get(index + 2)
            .and_then(|byte| (*byte as char).to_digit(16));
        match (hi, lo) {
            (Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                index += 3;
            }
            _ => return Err(format!("invalid URL escape \"{}\"", lossy(escape))),
        }
    }
    Ok(out)
}

/// net/textproto's `readMIMEHeader` line rules.
fn validate_header_line(line: &[u8]) -> std::result::Result<(), String> {
    if line
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(format!("malformed MIME header line \"{}\"", lossy(line)));
    }
    let Some((name, _)) = split_once(line, b':') else {
        return Err(format!("malformed MIME header line \"{}\"", lossy(line)));
    };
    if name.is_empty() || !name.iter().all(|byte| is_token(*byte)) {
        return Err(format!("invalid header field name \"{}\"", lossy(name)));
    }
    Ok(())
}

/// The server-side check over a complete header block: parse it like
/// `readRequest`, then match the decoded path against the configured URIs
/// (`HeaderReader.Read` with `ExpectThisRequest`).
fn validate_request_header(
    header: &[u8],
    expected: &[String],
) -> std::result::Result<(), ScanFailure> {
    let path = parse_request_lines(header).map_err(ScanFailure::Malformed)?;
    if !expected.iter().any(|uri| uri.as_bytes() == path.as_slice()) {
        return Err(ScanFailure::Mismatch);
    }
    Ok(())
}

fn malformed_request(line: &[u8]) -> String {
    format!("malformed HTTP request \"{}\"", lossy(line))
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn split_once(bytes: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|current| *current == byte)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_http_version(bytes: &[u8]) -> bool {
    bytes.len() == 8
        && &bytes[..5] == b"HTTP/"
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'.'
        && bytes[7].is_ascii_digit()
}

/// Finds the first `ENDING` at or after `scanned - 3`; returns the offset
/// just past it.
fn find_ending(buffered: &[u8], scanned: usize) -> Option<usize> {
    let start = scanned.saturating_sub(ENDING.len() - 1);
    buffered[start..]
        .windows(ENDING.len())
        .position(|window| window == ENDING)
        .map(|index| start + index + ENDING.len())
}

/// Drives `HeaderScan` to the header's end. Returns the offset just past
/// `ENDING` within `scan.buffered`; the bytes before it are the header
/// block and the bytes after it are the body bytes that must not be lost.
fn poll_scan_header(
    stream: &mut BoxStream,
    cx: &mut Context<'_>,
    scan: &mut HeaderScan,
) -> Poll<std::result::Result<usize, ScanFailure>> {
    loop {
        // Go checks for the terminator before spending the length budget.
        if let Some(end) = find_ending(&scan.buffered, scan.scanned) {
            return Poll::Ready(Ok(end));
        }
        scan.scanned = scan.buffered.len();
        // Go's loop keeps the last four bytes buffered, so the budget
        // covers the terminator as well.
        if scan.buffered.len() >= MAX_HEADER_LENGTH + ENDING.len() {
            return Poll::Ready(Err(ScanFailure::TooLong));
        }
        if let Err(failure) = scan.validate_partial() {
            return Poll::Ready(Err(failure));
        }
        let mut chunk = [0_u8; 4096];
        let mut buf = ReadBuf::new(&mut chunk);
        match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(ScanFailure::Io(error))),
            Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                return Poll::Ready(Err(ScanFailure::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before the HTTP header block completed",
                ))));
            }
            Poll::Ready(Ok(())) => scan.buffered.extend_from_slice(buf.filled()),
        }
    }
}

async fn read_header(
    stream: &mut BoxStream,
    scan: &mut HeaderScan,
) -> std::result::Result<usize, ScanFailure> {
    std::future::poll_fn(|cx| poll_scan_header(stream, cx, scan)).await
}

/// Go's `http.Conn` over one stream: a one-time header write, a one-time
/// header read/skip with body replay, and the inbound's camouflage error
/// response on close. The state lives in the stream, so a cancelled first
/// read or write resumes cleanly.
struct HttpObfsStream {
    inner: BoxStream,
    /// true for the outbound side (`Authenticator.Client`).
    client: bool,
    read: ReadState,
    /// Header bytes to prepend to the first write, plus the flushed prefix.
    pending_write: Option<(Vec<u8>, usize)>,
    /// Set once the first write is attempted; Go clears `oneTimeWriter`
    /// even when the header write fails.
    write_attempted: bool,
    /// The camouflage response driven out by `poll_shutdown`.
    close_response: Option<(Vec<u8>, usize)>,
    close_attempted: bool,
    /// Sticky read-side failure of the client's skip reader.
    failure: Option<(io::ErrorKind, String)>,
}

enum ReadState {
    /// The client side is still hunting the peer's header block.
    Scanning(HeaderScan),
    /// The header is consumed; these body bytes precede the raw stream.
    Draining(Vec<u8>),
    /// Transparent relay.
    Relay,
}

impl HttpObfsStream {
    fn server(inner: BoxStream, leftover: Vec<u8>, response_header: Vec<u8>) -> Self {
        Self {
            inner,
            client: false,
            read: ReadState::Draining(leftover),
            pending_write: Some((response_header, 0)),
            write_attempted: false,
            close_response: None,
            close_attempted: false,
            failure: None,
        }
    }

    fn client(inner: BoxStream, request_header: Vec<u8>) -> Self {
        Self {
            inner,
            client: true,
            read: ReadState::Scanning(HeaderScan::default()),
            pending_write: Some((request_header, 0)),
            write_attempted: false,
            close_response: None,
            close_attempted: false,
            failure: None,
        }
    }
}

impl AsyncRead for HttpObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some((kind, message)) = &this.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        loop {
            match std::mem::replace(&mut this.read, ReadState::Relay) {
                ReadState::Draining(mut pending) => {
                    if pending.is_empty() {
                        continue;
                    }
                    if buf.remaining() == 0 {
                        this.read = ReadState::Draining(pending);
                        return Poll::Ready(Ok(()));
                    }
                    let amount = buf.remaining().min(pending.len());
                    buf.put_slice(&pending[..amount]);
                    pending.drain(..amount);
                    this.read = ReadState::Draining(pending);
                    return Poll::Ready(Ok(()));
                }
                ReadState::Relay => return Pin::new(&mut this.inner).poll_read(cx, buf),
                ReadState::Scanning(mut scan) => {
                    match poll_scan_header(&mut this.inner, cx, &mut scan) {
                        Poll::Pending => {
                            this.read = ReadState::Scanning(scan);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(failure)) => {
                            this.read = ReadState::Scanning(scan);
                            let kind = failure.io_kind();
                            let message = failure.message();
                            this.failure = Some((kind, message.clone()));
                            return Poll::Ready(Err(io::Error::new(kind, message)));
                        }
                        Poll::Ready(Ok(end)) => {
                            // The linked-reader replay: body bytes that
                            // arrived with the header precede the raw stream.
                            this.read = ReadState::Draining(scan.buffered.split_off(end));
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for HttpObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some((header, mut offset)) = this.pending_write.take() {
            this.write_attempted = true;
            while offset < header.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &header[offset..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "HTTP header write stalled",
                        )));
                    }
                    Poll::Ready(Ok(written)) => offset += written,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        this.pending_write = Some((header, offset));
                        return Poll::Pending;
                    }
                }
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Go's Conn.Close: an inbound that never attempted its response
        // header writes a camouflage error response first (resp404 on
        // mismatch, resp400 otherwise); the outbound side has noop writers.
        // Mismatch and parse failures never reach this stream (accept_side
        // already wrote their error response), so this is always resp400.
        if !this.client && !this.write_attempted && !this.close_attempted {
            this.close_attempted = true;
            this.close_response = Some((
                render_response_header(&error_response_spec("400", "Bad Request")),
                0,
            ));
        }
        if let Some((bytes, mut offset)) = this.close_response.take() {
            while offset < bytes.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &bytes[offset..]) {
                    Poll::Ready(Ok(written)) if written > 0 => offset += written,
                    // Go ignores errors from the close-time writer.
                    Poll::Ready(_) => break,
                    Poll::Pending => {
                        this.close_response = Some((bytes, offset));
                        return Poll::Pending;
                    }
                }
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// The inbound side: parse/skip the client's request header, then relay the
/// rest verbatim (Go's `Authenticator.Server`). The request header is
/// consumed here — like the relay's first read in Go — so the camouflage
/// error response (resp404 on mismatch, resp400 on malformed or oversized
/// headers) is written even if the caller then drops the stream.
pub async fn accept_side(codec: HeaderCodec, stream: BoxStream) -> Result<BoxStream> {
    if codec.kind() == HeaderKind::Noop {
        return Ok(stream);
    }
    let mut inner = stream;
    let mut scan = HeaderScan::default();
    let end = match read_header(&mut inner, &mut scan).await {
        Ok(end) => end,
        Err(failure) => {
            let response = render_response_header(&failure.error_response());
            let _ = inner.write_all(&response).await;
            let _ = inner.shutdown().await;
            return Err(anyhow!("HTTP header obfs inbound: {}", failure.message()));
        }
    };
    let leftover = scan.buffered.split_off(end);
    let header = scan.buffered;
    if let Err(failure) = validate_request_header(&header, &codec.request.uris) {
        let response = render_response_header(&failure.error_response());
        let _ = inner.write_all(&response).await;
        let _ = inner.shutdown().await;
        return Err(anyhow!("HTTP header obfs inbound: {}", failure.message()));
    }
    let response_header = render_response_header(&codec.response);
    Ok(Box::new(HttpObfsStream::server(
        inner,
        leftover,
        response_header,
    )))
}

/// The outbound side: emit the configured request header before the first
/// write, then relay verbatim; skip the peer's first header block on the
/// first read (Go's `Authenticator.Client`).
pub async fn dial_side(codec: HeaderCodec, stream: BoxStream) -> Result<BoxStream> {
    if codec.kind() == HeaderKind::Noop {
        return Ok(stream);
    }
    let request_header = render_request_header(&codec.request);
    Ok(Box::new(HttpObfsStream::client(stream, request_header)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream};

    fn compile(value: Value) -> HeaderCodec {
        HeaderCodec::compile(&HeaderSettings::from_value(&value).unwrap()).unwrap()
    }

    fn render_request(value: Value) -> String {
        String::from_utf8(render_request_header(&compile(value).request)).unwrap()
    }

    fn render_response(value: Value) -> String {
        String::from_utf8(render_response_header(&compile(value).response)).unwrap()
    }

    /// Reads until the collected bytes end with `suffix` (bounded).
    async fn read_suffix(stream: &mut DuplexStream, suffix: &[u8]) -> Vec<u8> {
        let mut collected = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            collected.extend_from_slice(&chunk[..read]);
            if collected.ends_with(suffix) {
                return collected;
            }
        }
    }

    #[test]
    fn request_header_golden_from_go_http_test() {
        // Go TestRequestHeader: "GET / HTTP/1.1\r\nTest: Value\r\n\r\n".
        assert_eq!(
            render_request(json!({
                "type": "http",
                "request": {"path": ["/"], "headers": {"Test": ["Value"]}}
            })),
            "GET / HTTP/1.1\r\nTest: Value\r\n\r\n"
        );
        assert_eq!(
            render_request(json!({
                "type": "http",
                "request": {
                    "method": "Post",
                    "version": "1.0",
                    "path": ["/testpath"],
                    "headers": {"Host": ["www.example.com"], "User-Agent": ["Test-Agent"]}
                }
            })),
            "Post /testpath HTTP/1.0\r\nHost: www.example.com\r\nUser-Agent: Test-Agent\r\n\r\n"
        );
        // Go's Build keeps an explicitly empty path entry verbatim.
        let codec = compile(json!({"type": "http", "request": {"path": [""]}}));
        assert_eq!(codec.request.uris, [""]);
    }

    #[test]
    fn request_defaults_match_go_authenticator_request_build() {
        let header = render_request(json!({"type": "http"}));
        let lines: Vec<&str> = header.split("\r\n").collect();
        assert_eq!(lines[0], "GET / HTTP/1.1");
        let names: Vec<&str> = lines[1..13]
            .iter()
            .map(|line| line.split(": ").next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Host",
                "User-Agent",
                "Sec-CH-UA",
                "Sec-CH-UA-Mobile",
                "Sec-CH-UA-Platform",
                "Sec-Fetch-Mode",
                "Sec-Fetch-Dest",
                "Sec-Fetch-Site",
                "Sec-Fetch-User",
                "Accept-Encoding",
                "Connection",
                "Pragma",
            ]
        );
        assert!(lines[1] == "Host: www.baidu.com" || lines[1] == "Host: www.bing.com");
        assert!(lines[2].starts_with(
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"
        ));
        assert!(lines[2].ends_with(" Safari/537.36"));
        assert!(lines[3].contains("\"Chromium\""));
        assert!(lines[3].contains("\"Google Chrome\""));
        assert!(lines[3].contains("Not") && lines[3].contains("Brand"));
        assert_eq!(lines[4], "Sec-CH-UA-Mobile: ?0");
        assert_eq!(lines[5], "Sec-CH-UA-Platform: Windows");
        assert!(
            [
                "Sec-Fetch-Mode: no-cors",
                "Sec-Fetch-Mode: cors",
                "Sec-Fetch-Mode: same-origin"
            ]
            .contains(&lines[6])
        );
        assert_eq!(lines[7], "Sec-Fetch-Dest: empty");
        assert_eq!(lines[8], "Sec-Fetch-Site: none");
        assert_eq!(lines[9], "Sec-Fetch-User: ?1");
        assert_eq!(lines[10], "Accept-Encoding: gzip, deflate");
        assert_eq!(lines[11], "Connection: keep-alive");
        assert_eq!(lines[12], "Pragma: no-cache");
        // The terminating CRLFCRLF splits into two trailing empty fields.
        assert_eq!(lines[13], "");
        assert_eq!(lines[14], "");
        assert_eq!(lines.len(), 15);
    }

    #[test]
    fn response_defaults_and_go_date_header() {
        let header = render_response(json!({"type": "http"}));
        let lines: Vec<&str> = header.split("\r\n").collect();
        assert_eq!(lines[0], "HTTP/1.1 200 OK");
        let names: Vec<&str> = lines[1..6]
            .iter()
            .map(|line| line.split(": ").next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Content-Type",
                "Transfer-Encoding",
                "Connection",
                "Pragma",
                "Cache-Control"
            ]
        );
        assert!(
            [
                "Content-Type: application/octet-stream",
                "Content-Type: video/mpeg"
            ]
            .contains(&lines[1])
        );
        assert_eq!(lines[2], "Transfer-Encoding: chunked");
        assert_eq!(lines[3], "Connection: keep-alive");
        assert_eq!(lines[4], "Pragma: no-cache");
        assert!(["Cache-Control: private", "Cache-Control: no-cache"].contains(&lines[5]));
        assert!(lines[6].starts_with("Date: "));
        assert!(chrono::DateTime::parse_from_rfc2822(&lines[6][6..]).is_ok());
        // The terminating CRLFCRLF splits into two trailing empty fields.
        assert_eq!(lines[7], "");
        assert_eq!(lines[8], "");
        assert_eq!(lines.len(), 9);

        // A configured Date header suppresses Go's automatic one, and a
        // non-empty headers map replaces the whole default set.
        assert_eq!(
            render_response(json!({
                "type": "http",
                "response": {"status": "404", "reason": "Not Found", "headers": {"Date": ["X"]}}
            })),
            "HTTP/1.1 404 Not Found\r\nDate: X\r\n\r\n"
        );
        // Status and reason fall back to "200" and "OK" independently.
        let codec = compile(json!({"type": "http", "response": {"status": "403"}}));
        assert_eq!(codec.response.code, "403");
        assert_eq!(codec.response.reason, "OK");
        let codec = compile(json!({"type": "http", "response": {"reason": "No Content"}}));
        assert_eq!(codec.response.code, "200");
        assert_eq!(codec.response.reason, "No Content");
    }

    #[test]
    fn error_responses_match_go_resp_go() {
        for (code, reason) in [("400", "Bad Request"), ("404", "Not Found")] {
            let header =
                String::from_utf8(render_response_header(&error_response_spec(code, reason)))
                    .unwrap();
            let lines: Vec<&str> = header.split("\r\n").collect();
            assert_eq!(lines[0], format!("HTTP/1.1 {code} {reason}"));
            assert_eq!(lines[1], "Connection: close");
            assert_eq!(lines[2], "Cache-Control: private");
            assert_eq!(lines[3], "Content-Length: 0");
            assert!(lines[4].starts_with("Date: "));
            assert_eq!(lines[5], "");
        }
    }

    #[test]
    fn chrome_ua_profile_is_stable_and_go_shaped() {
        let first = chrome_profile();
        assert_eq!(chrome_profile().user_agent, first.user_agent);
        assert!(first.version >= 144);
        assert!(
            first
                .ch_ua
                .contains(&format!("\"Chromium\";v=\"{}\"", first.version))
        );
    }

    #[test]
    fn header_type_registry_and_named_rejections() {
        assert_eq!(
            HeaderSettings::from_value(&json!({"type": "none"}))
                .unwrap()
                .kind(),
            HeaderKind::Noop
        );
        assert_eq!(
            HeaderSettings::from_value(&json!({"type": ""}))
                .unwrap()
                .kind(),
            HeaderKind::Noop
        );
        // Go's loader lowercases the type before the registry lookup.
        assert_eq!(
            HeaderSettings::from_value(&json!({"type": "Http"}))
                .unwrap()
                .kind(),
            HeaderKind::Http
        );
        // Unknown types fail with Go's loader error, wrapped by TCPConfig.
        let error = HeaderSettings::from_value(&json!({"type": "srtp"}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown config id: srtp"), "{error}");
        for value in [json!({}), json!(null)] {
            let error = HeaderSettings::from_value(&value).unwrap_err().to_string();
            assert!(error.contains("type not found in JSON context"), "{error}");
        }
        let error = HeaderSettings::from_value(&json!({"type": "http", "request": {"path": 123}}))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unknown format of a string list: 123"),
            "{error}"
        );
        let error = HeaderSettings::from_value(&json!({"type": 5}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("header type must be a string"), "{error}");
        let error = HeaderSettings::from_value(&json!({"type": "http", "request": "x"}))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("request header settings must be an object"),
            "{error}"
        );
        // Go's `none` creator ignores the rest of the object.
        assert!(
            HeaderSettings::from_value(&json!({
                "type": "none",
                "request": {"path": 123}
            }))
            .is_ok()
        );
    }

    #[test]
    fn string_list_forms_follow_go_common_go() {
        // Single strings split on commas; null and empty lists keep defaults.
        let codec = compile(json!({"type": "http", "request": {"path": "a,b"}}));
        assert_eq!(codec.request.uris, ["a", "b"]);
        let codec = compile(json!({"type": "http", "request": {"path": null}}));
        assert_eq!(codec.request.uris, ["/"]);
        let codec = compile(json!({"type": "http", "request": {"path": []}}));
        assert_eq!(codec.request.uris, ["/"]);
        let codec = compile(json!({"type": "http", "request": {"method": "", "version": ""}}));
        assert_eq!(codec.request.method, "GET");
        assert_eq!(codec.request.version, "1.1");

        // A non-empty headers map replaces the defaults, sorted by key.
        let codec = compile(json!({
            "type": "http",
            "request": {"headers": {"Zeta": ["1"], "Alpha": ["2"]}}
        }));
        let names: Vec<&str> = codec
            .request
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(names, ["Alpha", "Zeta"]);

        // The `settings` nesting of the integration contract is honored;
        // top-level keys win over it.
        let codec = compile(json!({
            "type": "http",
            "request": {"method": "HEAD"},
            "settings": {"request": {"method": "Post"}, "response": {"status": "404"}}
        }));
        assert_eq!(codec.request.method, "HEAD");
        assert_eq!(codec.response.code, "404");
    }

    #[test]
    fn null_header_values_fail_at_compile_like_go_build() {
        let settings = HeaderSettings::from_value(&json!({
            "type": "http",
            "request": {"headers": {"Host": null}}
        }))
        .unwrap();
        let error = HeaderCodec::compile(&settings).err().unwrap().to_string();
        assert!(error.contains("empty HTTP header value: Host"), "{error}");
        let settings = HeaderSettings::from_value(&json!({
            "type": "http",
            "response": {"headers": {"X-Missing": null}}
        }))
        .unwrap();
        let error = HeaderCodec::compile(&settings).err().unwrap().to_string();
        assert!(
            error.contains("empty HTTP header value: X-Missing"),
            "{error}"
        );
        let error = HeaderSettings::from_value(&json!({
            "type": "http",
            "response": {"headers": {"X-Count": 5}}
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown format of a string list"), "{error}");
        let error = HeaderSettings::from_value(&json!({
            "type": "http",
            "request": {"version": 5}
        }))
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("request.version must be a string"),
            "{error}"
        );
        let error = HeaderSettings::from_value(&json!({
            "type": "http",
            "request": {"headers": 5}
        }))
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("request.headers must be an object"),
            "{error}"
        );
    }

    fn reject(header: &[u8], expected: &[&str]) -> ScanFailure {
        let expected: Vec<String> = expected.iter().map(|uri| uri.to_string()).collect();
        match validate_request_header(header, &expected) {
            Err(failure) => failure,
            Ok(()) => panic!("header unexpectedly accepted"),
        }
    }

    #[test]
    fn request_validation_matches_go_read_request() {
        let ok = |header: &[u8], expected: &[&str]| {
            let expected: Vec<String> = expected.iter().map(|uri| uri.to_string()).collect();
            validate_request_header(header, &expected).unwrap()
        };
        ok(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", &["/"]);
        // The compared path is percent-decoded and excludes the query; both
        // origin-form and absolute-form targets are accepted.
        ok(b"GET /%74estpath HTTP/1.1\r\n\r\n", &["/testpath"]);
        ok(b"GET /testpath?x=1 HTTP/1.1\r\n\r\n", &["/testpath"]);
        ok(
            b"GET http://www.example.com/testpath HTTP/1.1\r\n\r\n",
            &["/testpath"],
        );
        ok(b"POST /testpath HTTP/1.0\r\nX: y\r\n\r\n", &["/testpath"]);

        // Go TestReaderWriter: "abcd" is not a request line.
        assert_eq!(
            reject(b"abcd\r\n\r\n", &["/"]).message(),
            "malformed HTTP request \"abcd\""
        );
        // Go TestConnectionInvPath: the wrong path is a mismatch.
        assert_eq!(
            reject(b"POST /testpath HTTP/1.1\r\n\r\n", &["/other"]).message(),
            "Header Mismatch."
        );
        assert_eq!(
            reject(b"GET /testpath HTTP/1.1\r\n\r\n", &["/testpathErr", "/x"]).message(),
            "Header Mismatch."
        );
        assert_eq!(
            // A request line with only two fields (no HTTP version).
            reject(b"GET /\r\n\r\n", &["/"]).message(),
            "malformed HTTP request \"GET /\""
        );
        assert_eq!(
            reject(b"G@T / HTTP/1.1\r\n\r\n", &["/"]).message(),
            "invalid method \"G@T\""
        );
        assert_eq!(
            reject(b"GET / HTTP/9x\r\n\r\n", &["/"]).message(),
            "malformed HTTP version \"HTTP/9x\""
        );
        assert_eq!(
            reject(b"GET noscheme HTTP/1.1\r\n\r\n", &["/"]).message(),
            "invalid URI for request"
        );
        assert_eq!(
            reject(b"GET /%zz HTTP/1.1\r\n\r\n", &["/"]).message(),
            "invalid URL escape \"%zz\""
        );
        assert_eq!(
            reject(b"GET /testpath HTTP/1.1\r\nBadLine\r\n\r\n", &["/testpath"]).message(),
            "malformed MIME header line \"BadLine\""
        );
        assert_eq!(
            reject(
                b"GET /testpath HTTP/1.1\r\nBad Name: x\r\n\r\n",
                &["/testpath"]
            )
            .message(),
            "invalid header field name \"Bad Name\""
        );
        assert_eq!(
            reject(
                b"GET /testpath HTTP/1.1\r\n Bad-Fold: x\r\n\r\n",
                &["/testpath"]
            )
            .message(),
            "invalid header field name \" Bad-Fold\""
        );
        // Mismatch (not malformed) selects the 404 camouflage response.
        assert_eq!(
            reject(b"GET /nope HTTP/1.1\r\n\r\n", &["/"])
                .error_response()
                .code,
            "404"
        );
        assert_eq!(reject(b"abcd\r\n\r\n", &["/"]).error_response().code, "400");
    }

    #[tokio::test]
    async fn scan_fails_fast_on_malformed_partial_headers() {
        let (mut peer, server) = tokio::io::duplex(4096);
        let mut server: BoxStream = Box::new(server);
        let mut scan = HeaderScan::default();
        // A complete but malformed request line rejects before the
        // terminator ever arrives, like Go's incremental readRequest check.
        peer.write_all(b"GET \x00garbage\r\n").await.unwrap();
        let failure = read_header(&mut server, &mut scan).await.unwrap_err();
        let message = failure.message();
        assert!(message.starts_with("malformed"), "{message}");
    }

    #[tokio::test]
    async fn scan_rejects_oversized_headers_with_go_budget() {
        let (mut peer, server) = tokio::io::duplex(64 * 1024);
        let mut server: BoxStream = Box::new(server);
        let mut scan = HeaderScan::default();
        let filler = vec![b'a'; MAX_HEADER_LENGTH + ENDING.len()];
        peer.write_all(&filler).await.unwrap();
        let failure = read_header(&mut server, &mut scan).await.unwrap_err();
        assert_eq!(failure.message(), "Header too long.");
        assert_eq!(failure.error_response().code, "400");

        // A header that fits Go's budget (terminator included) is accepted
        // and the trailing body bytes are preserved.
        let (mut peer, server) = tokio::io::duplex(64 * 1024);
        let mut server: BoxStream = Box::new(server);
        let mut scan = HeaderScan::default();
        peer.write_all(b"GET / HTTP/1.1\r\nX-Fill: ").await.unwrap();
        peer.write_all(&vec![b'a'; MAX_HEADER_LENGTH - 24])
            .await
            .unwrap();
        peer.write_all(ENDING).await.unwrap();
        peer.write_all(b"body").await.unwrap();
        let end = read_header(&mut server, &mut scan).await.unwrap();
        assert_eq!(&scan.buffered[end..], b"body");
    }

    #[tokio::test]
    async fn long_garbage_payload_fails_like_go_test_long_request_header() {
        let (mut peer, server) = tokio::io::duplex(64 * 1024);
        let mut server: BoxStream = Box::new(server);
        let mut scan = HeaderScan::default();
        // A deterministic pseudo-random blob with control bytes; Go's test
        // accepts "invalid"/"malformed" error prefixes.
        let mut payload: Vec<u8> = (0..2050).map(|index| (index * 7 + 3) as u8).collect();
        payload.extend_from_slice(ENDING);
        payload.extend_from_slice(b"abcd");
        peer.write_all(&payload).await.unwrap();
        let end = read_header(&mut server, &mut scan).await.unwrap();
        let failure =
            validate_request_header(&scan.buffered[..end], &["/".to_owned()]).unwrap_err();
        let message = failure.message();
        assert!(
            message.starts_with("malformed") || message.starts_with("invalid"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn server_accept_replays_body_and_writes_response_header() {
        let (mut peer, server) = tokio::io::duplex(64 * 1024);
        let codec = compile(json!({
            "type": "http",
            "request": {"path": ["/testpath"]},
            "response": {"status": "404", "reason": "Not Found"}
        }));
        peer.write_all(b"POST /testpath HTTP/1.1\r\nHost: x\r\n\r\nPAYLOAD")
            .await
            .unwrap();
        let mut stream = accept_side(codec, Box::new(server)).await.unwrap();
        let mut body = [0_u8; 7];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"PAYLOAD");
        // The response header precedes the server's first write.
        stream.write_all(b"reply").await.unwrap();
        let wire = read_suffix(&mut peer, b"\r\n\r\nreply").await;
        let text = String::from_utf8_lossy(&wire).to_string();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
        assert!(text.contains("Date: "), "{text}");
    }

    #[tokio::test]
    async fn server_rejects_mismatch_with_404_and_malformed_with_400() {
        let (mut peer, server) = tokio::io::duplex(4096);
        let codec = compile(json!({"type": "http", "request": {"path": ["/testpath"]}}));
        peer.write_all(b"POST /testpathErr HTTP/1.1\r\n\r\nrest")
            .await
            .unwrap();
        let error = accept_side(codec, Box::new(server))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("Header Mismatch."), "{error}");
        let wire = read_suffix(&mut peer, b"\r\n\r\n").await;
        let text = String::from_utf8_lossy(&wire).to_string();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(!text.contains("rest"), "{text}");

        let (mut peer, server) = tokio::io::duplex(4096);
        let codec = compile(json!({"type": "http", "request": {"path": ["/"]}}));
        peer.write_all(b"ABCDEFGHIJKMLN\r\n\r\n").await.unwrap();
        let error = accept_side(codec, Box::new(server))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("malformed HTTP request \"ABCDEFGHIJKMLN\""),
            "{error}"
        );
        let wire = read_suffix(&mut peer, b"\r\n\r\n").await;
        let text = String::from_utf8_lossy(&wire).to_string();
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
    }

    #[tokio::test]
    async fn client_skips_peer_header_block_and_replays_body() {
        let (mut peer, client) = tokio::io::duplex(4096);
        let codec = compile(json!({
            "type": "http",
            "request": {"path": ["/"], "headers": {"Test": ["Value"]}}
        }));
        let mut client = dial_side(codec, Box::new(client)).await.unwrap();
        // A terminated but malformed header block is skipped without
        // validation on the client side (Go parses only incrementally).
        peer.write_all(b"total garbage\r\n\r\nBODY-BYTES")
            .await
            .unwrap();
        let mut body = vec![0_u8; 10];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"BODY-BYTES");
        peer.write_all(b"+more").await.unwrap();
        let mut tail = [0_u8; 5];
        client.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"+more");

        // The request header precedes the client's first write.
        client.write_all(b"PAY").await.unwrap();
        let mut wire = [0_u8; 34];
        peer.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, b"GET / HTTP/1.1\r\nTest: Value\r\n\r\nPAY");
    }

    #[tokio::test]
    async fn noop_codec_passes_bytes_through_untouched() {
        let (peer, server) = tokio::io::duplex(4096);
        let mut server = accept_side(compile(json!({"type": "none"})), Box::new(server))
            .await
            .unwrap();
        let mut client = dial_side(compile(json!({"type": ""})), Box::new(peer))
            .await
            .unwrap();
        let payload: Vec<u8> = (0..=255).collect();
        client.write_all(&payload).await.unwrap();
        let mut received = vec![0_u8; payload.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        server.write_all(b"echo").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"echo");
    }

    #[tokio::test]
    async fn server_shutdown_before_write_emits_camouflage_400() {
        // Go's Conn.Close: an inbound that never wrote still answers with
        // the default error response before closing.
        let (mut peer, server) = tokio::io::duplex(4096);
        let codec = compile(json!({"type": "http", "request": {"path": ["/"]}}));
        peer.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut stream = accept_side(codec, Box::new(server)).await.unwrap();
        stream.shutdown().await.unwrap();
        let wire = read_suffix(&mut peer, b"\r\n\r\n").await;
        let text = String::from_utf8_lossy(&wire).to_string();
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(text.contains("Content-Length: 0\r\n"), "{text}");

        // Dropping the stream without shutdown writes nothing; the runtime
        // must call shutdown to reach Go's close-time response.
        let (mut peer, server) = tokio::io::duplex(4096);
        let codec = compile(json!({"type": "http", "request": {"path": ["/"]}}));
        peer.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let stream = accept_side(codec, Box::new(server)).await.unwrap();
        drop(stream);
        let mut chunk = [0_u8; 16];
        let read = peer.read(&mut chunk).await.unwrap();
        assert_eq!(read, 0);
    }
}
