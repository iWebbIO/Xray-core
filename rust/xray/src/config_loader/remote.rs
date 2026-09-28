//! Remote configuration sources, from `main/confloader/external/external.go`.
//!
//! `http(s)://` URLs fetch over the network with a 30-second budget and the
//! system root store; Unix-socket endpoints (`/path/to/socket.sock:/api`,
//! `@abstract:/api`, `@@padded:/api`, and the deprecated `http+unix://`
//! form) issue the same HTTP GET through the socket. Both require a 200
//! response; anything else is an error, exactly like Go's
//! `FetchHTTPContent`.

use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::Format;

/// Whether `arg` names a remote (HTTP or Unix-socket) source rather than a
/// local file. Mirrors Go's `isRemoteSource`, including socket detection
/// for absolute paths without `:/`.
pub fn is_remote_source(arg: &str) -> bool {
    if arg.is_empty() {
        return false;
    }
    if arg.starts_with("http://") || arg.starts_with("https://") {
        return true;
    }
    if arg.starts_with("http+unix://") {
        return true;
    }
    if arg.starts_with('@') {
        return true;
    }
    if !arg.starts_with('/') {
        return false;
    }
    if arg.contains(":/") {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        return std::fs::metadata(arg).is_ok_and(|metadata| metadata.file_type().is_socket());
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Fetch one configuration source's bytes (Go's `ConfigLoader` remote half).
pub fn fetch(source: &str) -> Result<Vec<u8>> {
    if let Some(canonical) = canonical_http_unix(source) {
        return fetch_http_content(&canonical);
    }
    fetch_http_content(source)
}

/// The deprecated `http+unix:///path.sock/api` form becomes the canonical
/// `/path.sock:/api` (Go inserts `:` after the `.sock` extension).
fn canonical_http_unix(target: &str) -> Option<String> {
    let raw = target.strip_prefix("http+unix://")?;
    if let Some(index) = raw.find(".sock/") {
        return Some(format!("{}:{}", &raw[..index + 5], &raw[index + 5..]));
    }
    Some(raw.to_owned())
}

/// Split `socket[:/path]` into the HTTP request path and the socket target;
/// `http(s)://` targets have no socket part.
fn split_socket(target: &str) -> (String, Option<String>) {
    if target.starts_with("http://") || target.starts_with("https://") {
        return (target.to_owned(), None);
    }
    match target.split_once(":/") {
        Some((socket, path)) => (format!("http://localhost/{path}"), Some(socket.to_owned())),
        None => ("http://localhost/".to_owned(), Some(target.to_owned())),
    }
}

/// Go's `FetchHTTPContent`: one GET with a 30-second budget, 200 required.
pub fn fetch_http_content(target: &str) -> Result<Vec<u8>> {
    let (url, socket_path) = split_socket(target);
    if let Some(socket) = socket_path {
        return fetch_http_unix(&socket, &url);
    }
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build the HTTP configuration client")?
        .get(&url)
        .send()
        .with_context(|| format!("failed to dial to {target}"))?;
    let status = response.status();
    if status.as_u16() != 200 {
        bail!("unexpected HTTP status code: {}", status.as_u16());
    }
    let content = response
        .bytes()
        .with_context(|| format!("failed to read the HTTP response from {target}"))?;
    Ok(content.to_vec())
}

/// A minimal HTTP/1.1 GET over a Unix socket (`/path/to/socket.sock`,
/// `@abstract`, `@@padded`; abstract sockets are Unix-only).
fn fetch_http_unix(socket: &str, url: &str) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let path = match url.trim_start_matches("http://localhost") {
        "" => "/".to_owned(),
        path => path.to_owned(),
    };
    #[cfg(unix)]
    {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixStream,
        };
        let stream = if let Some(abstract_name) = socket.strip_prefix("@@") {
            connect_abstract(&format!("\0\0{abstract_name}"))
                .with_context(|| format!("failed to dial to {socket}"))?
        } else if let Some(abstract_name) = socket.strip_prefix('@') {
            connect_abstract(&format!("\0{abstract_name}"))
                .with_context(|| format!("failed to dial to {socket}"))?
        } else {
            UnixStream::connect(socket).with_context(|| format!("failed to dial to {socket}"))?
        };
        let mut stream = stream;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .context("send the HTTP request")?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("read the HTTP response")?;
        parse_http_response(&response)
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, url);
        bail!("Unix-socket configuration sources require a Unix platform");
    }
}

#[cfg(unix)]
fn connect_abstract(name: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::unix::net::{SocketAddr, UnixStream};
    let address = SocketAddr::from_abstract_name(name.as_bytes())?;
    UnixStream::connect_addr(&address)
}

/// Parse a full `HTTP/1.1 ...` response: require 200 and return the body.
#[cfg_attr(not(unix), allow(dead_code))] // exercised by the tests everywhere
fn parse_http_response(response: &[u8]) -> Result<Vec<u8>> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("malformed HTTP response from the configuration socket")?;
    let head = String::from_utf8_lossy(&response[..header_end]);
    let status = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .unwrap_or_default();
    if status != "200" {
        bail!("unexpected HTTP status code: {status}");
    }
    Ok(response[header_end + 4..].to_vec())
}

/// The inferred format of a remote source: the URL's final path segment's
/// extension when it names a known format (Go's `core.GetFormat`), JSON
/// otherwise (a remote stream has no filename to inspect).
pub fn infer_format(source: &str) -> Result<Format> {
    let name = source
        .rsplit(['/', ':'])
        .next()
        .unwrap_or_default()
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase());
    if let Some(format) = name.as_deref().and_then(Format::by_name) {
        return Ok(format);
    }
    Ok(Format::Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_sources_are_classified_like_go() {
        assert!(is_remote_source("http://example.com/config.json"));
        assert!(is_remote_source("https://example.com/config.json"));
        assert!(is_remote_source("http+unix:///run/x.sock/api"));
        assert!(is_remote_source("@abstract:/api"));
        assert!(is_remote_source("/run/x.sock:/api"));
        assert!(!is_remote_source("config.json"));
        assert!(!is_remote_source("stdin:"));
        assert!(!is_remote_source(""));
    }

    #[test]
    fn the_deprecated_http_unix_form_is_canonicalized_like_go() {
        assert_eq!(
            canonical_http_unix("http+unix:///run/x.sock/api"),
            Some("/run/x.sock:/api".to_owned())
        );
        assert_eq!(
            canonical_http_unix("http+unix:///run/x.sock"),
            Some("/run/x.sock".to_owned())
        );
        assert_eq!(canonical_http_unix("https://example.com"), None);
    }

    #[test]
    fn socket_targets_split_into_url_and_socket() {
        assert_eq!(
            split_socket("/run/x.sock:/api"),
            (
                "http://localhost/api".to_owned(),
                Some("/run/x.sock".to_owned())
            )
        );
        assert_eq!(
            split_socket("/run/x.sock"),
            (
                "http://localhost/".to_owned(),
                Some("/run/x.sock".to_owned())
            )
        );
        assert_eq!(
            split_socket("https://example.com/c.json"),
            ("https://example.com/c.json".to_owned(), None)
        );
    }

    #[test]
    fn http_responses_parse_with_status_and_body() {
        let response = b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\nbody";
        assert_eq!(parse_http_response(response).unwrap(), b"body".to_vec());
        let error = parse_http_response(b"HTTP/1.1 503\r\n\r\n").unwrap_err();
        assert!(error.to_string().contains("503"));
        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn formats_infer_from_the_url_extension() {
        assert!(matches!(infer_format("https://x/c.yaml"), Ok(Format::Yaml)));
        assert!(matches!(infer_format("https://x/c.json"), Ok(Format::Json)));
        assert!(matches!(infer_format("https://x/api"), Ok(Format::Json)));
    }
}
