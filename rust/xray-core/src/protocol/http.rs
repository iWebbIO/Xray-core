use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Reply, Request};
use crate::{address::Destination, config::HttpSettings};

const MAX_HEADER: usize = 32 * 1024;

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &HttpSettings,
) -> Result<Request> {
    let mut bytes = Vec::new();
    let head_len = loop {
        if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= MAX_HEADER {
            stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
            bail!("HTTP proxy headers exceed 32 KiB");
        }
        let mut chunk = [0; 2048];
        let room = (MAX_HEADER - bytes.len()).min(chunk.len());
        let count = stream.read(&mut chunk[..room]).await?;
        ensure!(count != 0, "truncated HTTP proxy request");
        bytes.extend_from_slice(&chunk[..count]);
    };
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    ensure!(
        request.parse(&bytes[..head_len])?.is_complete(),
        "incomplete HTTP proxy request"
    );
    let method = request.method.context("missing HTTP method")?;
    let target = request.path.context("missing HTTP target")?;
    let mut user = String::new();
    if !settings.accounts.is_empty() {
        let auth = request
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Proxy-Authorization"));
        let decoded = auth
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"))
            .and_then(|(_, token)| STANDARD.decode(token.trim()).ok());
        let credentials = decoded.as_deref().and_then(|v| {
            v.iter()
                .position(|b| *b == b':')
                .map(|i| (&v[..i], &v[i + 1..]))
        });
        let account = credentials.and_then(|(name, password)| {
            settings
                .accounts
                .iter()
                .rev()
                .find(|account| account.user.as_bytes() == name)
                .filter(|account| bool::from(account.pass.as_bytes().ct_eq(password)))
        });
        match account {
            Some(account) => user = account.user.clone(),
            None => {
                stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Xray\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
                bail!("HTTP proxy authentication failed");
            }
        }
    }
    if method == "CONNECT" {
        return Ok(Request {
            level: 0,
            destination: Destination::parse_authority(target, Some(443))?,
            user,
            initial_payload: bytes[head_len..].to_vec(),
            reply: Reply::HttpConnect,
        });
    }
    // Forward-proxy requests are rewritten to origin form. A single upstream is
    // used per connection; Connection: close prevents cross-host keep-alive reuse.
    let absolute = target
        .strip_prefix("http://")
        .context("HTTP forward requests require an http:// absolute URL")?;
    let authority_end = absolute.find(['/', '?', '#']).unwrap_or(absolute.len());
    let destination = Destination::parse_authority(&absolute[..authority_end], Some(80))?;
    let path = &absolute[authority_end..];
    ensure!(
        !path.contains('#'),
        "HTTP request targets cannot contain fragments"
    );
    let path = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    let mut output =
        format!("{method} {path} HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n")
            .into_bytes();
    let mut has_length = false;
    let mut has_transfer_encoding = false;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length") {
            ensure!(!has_length, "duplicate Content-Length");
            has_length = true;
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        }
        if [
            "proxy-authorization",
            "proxy-connection",
            "connection",
            "host",
        ]
        .iter()
        .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        output.extend_from_slice(header.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(header.value);
        output.extend_from_slice(b"\r\n");
    }
    ensure!(
        !(has_length && has_transfer_encoding),
        "ambiguous HTTP message framing"
    );
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&bytes[head_len..]);
    Ok(Request {
        level: 0,
        destination,
        user,
        initial_payload: output,
        reply: Reply::HttpForward,
    })
}
