//! Handshakes over an already connected outbound TCP stream.
//!
//! The caller owns connection establishment and the handshake deadline. Both
//! handshakes leave the first tunneled byte in the stream on success.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    address::{Address, Destination},
    config::Account,
};

const MAX_HTTP_HEADER: usize = 32 * 1024;
const MAX_HTTP_FIELDS: usize = 128;

/// Establish a SOCKS5 TCP CONNECT tunnel, optionally using RFC 1929 credentials.
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &Destination,
    account: Option<&Account>,
) -> Result<()> {
    validate_target(target)?;
    if let Some(account) = account {
        ensure!(
            (1..=255).contains(&account.user.len()),
            "SOCKS5 username must contain 1..255 bytes"
        );
        ensure!(
            (1..=255).contains(&account.pass.len()),
            "SOCKS5 password must contain 1..255 bytes"
        );
    }

    // Offer only the configured method, matching the Go client. In particular,
    // a password-authenticated connection must not silently fall back to noauth.
    let method = if account.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    stream.flush().await?;
    let mut selection = [0; 2];
    stream
        .read_exact(&mut selection)
        .await
        .context("reading SOCKS5 authentication selection")?;
    ensure!(
        selection[0] == 5,
        "invalid SOCKS5 negotiation version {}",
        selection[0]
    );
    ensure!(
        selection[1] != 255,
        "SOCKS5 proxy rejected authentication methods"
    );
    ensure!(
        selection[1] == method,
        "SOCKS5 proxy selected an unoffered authentication method {}",
        selection[1]
    );

    if let Some(account) = account {
        let mut credentials = Vec::with_capacity(account.user.len() + account.pass.len() + 3);
        credentials.extend_from_slice(&[1, account.user.len() as u8]);
        credentials.extend_from_slice(account.user.as_bytes());
        credentials.push(account.pass.len() as u8);
        credentials.extend_from_slice(account.pass.as_bytes());
        stream.write_all(&credentials).await?;
        stream.flush().await?;
        let mut response = [0; 2];
        stream
            .read_exact(&mut response)
            .await
            .context("reading SOCKS5 authentication response")?;
        ensure!(
            response[0] == 1,
            "invalid SOCKS5 password authentication version {}",
            response[0]
        );
        ensure!(
            response[1] == 0,
            "SOCKS5 proxy rejected credentials (status {})",
            response[1]
        );
    }

    stream.write_all(&[5, 1, 0]).await?;
    target.write_socks(stream).await?;
    stream.flush().await?;

    let mut response = [0; 3];
    stream
        .read_exact(&mut response)
        .await
        .context("reading SOCKS5 CONNECT response")?;
    ensure!(
        response[0] == 5,
        "invalid SOCKS5 response version {}",
        response[0]
    );
    ensure!(
        response[2] == 0,
        "invalid SOCKS5 response reserved byte {}",
        response[2]
    );
    ensure!(
        response[1] == 0,
        "SOCKS5 CONNECT rejected: {} (status {})",
        socks_reply(response[1]),
        response[1]
    );
    // BND.PORT can be zero and unspecified IPs are valid here, unlike a target.
    Destination::read_socks(stream)
        .await
        .context("reading SOCKS5 bound address")?;
    Ok(())
}

fn socks_reply(code: u8) -> &'static str {
    match code {
        1 => "general server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown server status",
    }
}

fn validate_target(target: &Destination) -> Result<()> {
    ensure!(target.port != 0, "destination port must be nonzero");
    if let Address::Domain(host) = &target.address {
        Address::parse(host).context("invalid destination domain")?;
    }
    Ok(())
}

/// Establish an HTTP/1.x CONNECT tunnel with optional HTTP Basic credentials.
pub async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &Destination,
    account: Option<&Account>,
) -> Result<()> {
    http_connect_with_headers(stream, target, account, &[]).await
}

/// As [`http_connect`], with additional request headers whose values have
/// already been expanded by the configuration/runtime layer.
pub async fn http_connect_with_headers<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &Destination,
    account: Option<&Account>,
    headers: &[(String, String)],
) -> Result<()> {
    validate_target(target)?;
    let authority = target.to_string();
    Destination::parse_authority(&authority, None).context("invalid HTTP CONNECT authority")?;
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );

    for (name, value) in headers {
        ensure!(
            !name.is_empty() && name.bytes().all(is_header_name_byte),
            "invalid HTTP proxy header name"
        );
        ensure!(
            value
                .bytes()
                .all(|byte| byte == b'\t' || (byte >= 32 && byte != 127)),
            "invalid HTTP proxy header value"
        );
        // Go Request.Write derives Host from the target; Proxy-Connection is
        // set to Keep-Alive after applying custom headers.
        if name.eq_ignore_ascii_case("Host") || name.eq_ignore_ascii_case("Proxy-Connection") {
            continue;
        }
        ensure!(
            !name.eq_ignore_ascii_case("Content-Length")
                && !name.eq_ignore_ascii_case("Transfer-Encoding"),
            "HTTP CONNECT request body headers are not supported"
        );
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    let authorization_is_overridden = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Proxy-Authorization"));
    if let Some(account) = account.filter(|_| !authorization_is_overridden) {
        ensure!(
            !account.user.contains(':'),
            "HTTP Basic username must not contain a colon"
        );
        let encoded = STANDARD.encode(format!("{}:{}", account.user, account.pass));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encoded);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    ensure!(
        request.len() <= MAX_HTTP_HEADER,
        "HTTP CONNECT request headers exceed 32 KiB"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Reading exactly through the delimiter is intentional: a buffering reader
    // dropped after parsing can swallow payload sent with the response headers.
    let mut response = Vec::with_capacity(1024);
    loop {
        ensure!(
            response.len() < MAX_HTTP_HEADER,
            "HTTP CONNECT response headers exceed 32 KiB"
        );
        response.push(
            stream
                .read_u8()
                .await
                .context("reading HTTP CONNECT response headers")?,
        );
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let mut fields = [httparse::EMPTY_HEADER; MAX_HTTP_FIELDS];
    let mut parsed = httparse::Response::new(&mut fields);
    ensure!(
        parsed
            .parse(&response)
            .context("invalid HTTP CONNECT response")?
            .is_complete(),
        "incomplete HTTP CONNECT response"
    );
    // Match the Go client, which specifically requires status 200.
    let status = parsed
        .code
        .context("missing HTTP CONNECT response status")?;
    if status != 200 {
        bail!("HTTP CONNECT proxy rejected request (status {status})");
    }
    Ok(())
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use std::{future::Future, time::Duration};

    use super::*;
    use tokio::{
        io::{DuplexStream, duplex},
        time::timeout,
    };

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        timeout(Duration::from_secs(3), future)
            .await
            .expect("handshake test timed out")
    }

    async fn expect_bytes(stream: &mut DuplexStream, expected: &[u8]) {
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
    }

    async fn read_http_header(stream: &mut DuplexStream) -> Vec<u8> {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < MAX_HTTP_HEADER);
            header.push(stream.read_u8().await.unwrap());
        }
        header
    }

    #[tokio::test]
    async fn socks_noauth_requests_all_address_types_and_keeps_payload() {
        for host in ["example.org", "192.0.2.1", "2001:db8::1"] {
            bounded(async {
                let (mut client, mut proxy) = duplex(128);
                let target = Destination::new(host, 443).unwrap();
                let mut expected = vec![5, 1, 0];
                target.write_socks(&mut expected).await.unwrap();
                let server = async {
                    expect_bytes(&mut proxy, &[5, 1, 0]).await;
                    proxy.write_all(&[5, 0]).await.unwrap();
                    expect_bytes(&mut proxy, &expected).await;
                    proxy
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 42, 43])
                        .await
                        .unwrap();
                };
                let user = async {
                    socks5_connect(&mut client, &target, None).await.unwrap();
                    expect_bytes(&mut client, &[42, 43]).await;
                };
                tokio::join!(server, user);
            })
            .await;
        }
    }

    #[tokio::test]
    async fn socks_password_authentication_uses_byte_lengths() {
        bounded(async {
            let (mut client, mut proxy) = duplex(128);
            let account = Account {
                user: "ü".into(),
                pass: "secret".into(),
            };
            let target = Destination::new("127.0.0.1", 80).unwrap();
            let server = async {
                expect_bytes(&mut proxy, &[5, 1, 2]).await;
                proxy.write_all(&[5, 2]).await.unwrap();
                expect_bytes(
                    &mut proxy,
                    &[1, 2, 0xc3, 0xbc, 6, b's', b'e', b'c', b'r', b'e', b't'],
                )
                .await;
                proxy.write_all(&[1, 0]).await.unwrap();
                expect_bytes(&mut proxy, &[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await;
                proxy.write_all(&[5, 0, 0, 3, 1, b'x', 0, 0]).await.unwrap();
            };
            let user = async {
                socks5_connect(&mut client, &target, Some(&account))
                    .await
                    .unwrap();
            };
            tokio::join!(server, user);
        })
        .await;
    }

    #[tokio::test]
    async fn socks_rejects_empty_and_oversized_credentials_before_writing() {
        for (user, pass) in [
            (String::new(), "p".into()),
            ("u".into(), String::new()),
            ("u".repeat(256), "p".into()),
            ("u".into(), "é".repeat(128)),
        ] {
            bounded(async {
                let (mut client, mut proxy) = duplex(1024);
                let account = Account { user, pass };
                let target = Destination::new("example.org", 80).unwrap();
                assert!(
                    socks5_connect(&mut client, &target, Some(&account))
                        .await
                        .is_err()
                );
                drop(client);
                assert_eq!(
                    proxy.read_u8().await.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            })
            .await;
        }
    }

    #[tokio::test]
    async fn socks_accepts_maximum_credentials_and_rejects_auth_downgrade() {
        bounded(async {
            let (mut client, mut proxy) = duplex(64);
            let account = Account {
                user: "u".repeat(255),
                pass: "p".repeat(255),
            };
            let target = Destination::new("127.0.0.1", 80).unwrap();
            let server = async {
                expect_bytes(&mut proxy, &[5, 1, 2]).await;
                proxy.write_all(&[5, 2]).await.unwrap();
                expect_bytes(&mut proxy, &[1, 255]).await;
                expect_bytes(&mut proxy, account.user.as_bytes()).await;
                expect_bytes(&mut proxy, &[255]).await;
                expect_bytes(&mut proxy, account.pass.as_bytes()).await;
                proxy.write_all(&[1, 0]).await.unwrap();
                expect_bytes(&mut proxy, &[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await;
                proxy
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            };
            let user = async {
                socks5_connect(&mut client, &target, Some(&account))
                    .await
                    .unwrap();
            };
            tokio::join!(server, user);
        })
        .await;
        bounded(async {
            let (mut client, mut proxy) = duplex(64);
            let account = Account {
                user: "u".into(),
                pass: "p".into(),
            };
            let target = Destination::new("example.org", 80).unwrap();
            let server = async {
                expect_bytes(&mut proxy, &[5, 1, 2]).await;
                proxy.write_all(&[5, 0]).await.unwrap();
            };
            let user = async {
                assert!(
                    socks5_connect(&mut client, &target, Some(&account))
                        .await
                        .is_err()
                );
            };
            tokio::join!(server, user);
        })
        .await;
    }

    #[tokio::test]
    async fn socks_rejects_bad_negotiation_and_authentication_responses() {
        for reply in [[4, 0], [5, 2], [5, 255]] {
            bounded(async {
                let (mut client, mut proxy) = duplex(64);
                let target = Destination::new("example.org", 80).unwrap();
                let server = async {
                    expect_bytes(&mut proxy, &[5, 1, 0]).await;
                    proxy.write_all(&reply).await.unwrap();
                };
                let user = async {
                    assert!(socks5_connect(&mut client, &target, None).await.is_err());
                };
                tokio::join!(server, user);
            })
            .await;
        }
        for reply in [[2, 0], [1, 1]] {
            bounded(async {
                let (mut client, mut proxy) = duplex(64);
                let target = Destination::new("example.org", 80).unwrap();
                let account = Account {
                    user: "u".into(),
                    pass: "p".into(),
                };
                let server = async {
                    expect_bytes(&mut proxy, &[5, 1, 2]).await;
                    proxy.write_all(&[5, 2]).await.unwrap();
                    expect_bytes(&mut proxy, &[1, 1, b'u', 1, b'p']).await;
                    proxy.write_all(&reply).await.unwrap();
                };
                let user = async {
                    assert!(
                        socks5_connect(&mut client, &target, Some(&account))
                            .await
                            .is_err()
                    );
                };
                tokio::join!(server, user);
            })
            .await;
        }
    }

    #[tokio::test]
    async fn socks_rejects_malformed_replies_and_every_failure_status() {
        let mut replies = vec![
            vec![4, 0, 0],
            vec![5, 0, 1],
            vec![5, 0, 0, 2],
            vec![5, 0, 0, 3, 0, 0, 0],
            vec![5, 0, 0, 1, 127],
        ];
        replies.extend((1..=9).map(|status| vec![5, status, 0]));
        for reply in replies {
            bounded(async {
                let (mut client, mut proxy) = duplex(128);
                let target = Destination::new("127.0.0.1", 80).unwrap();
                let server = async {
                    expect_bytes(&mut proxy, &[5, 1, 0]).await;
                    proxy.write_all(&[5, 0]).await.unwrap();
                    expect_bytes(&mut proxy, &[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await;
                    proxy.write_all(&reply).await.unwrap();
                    proxy.shutdown().await.unwrap();
                };
                let user = async {
                    assert!(socks5_connect(&mut client, &target, None).await.is_err());
                };
                tokio::join!(server, user);
            })
            .await;
        }
    }

    #[tokio::test]
    async fn http_ipv6_basic_auth_and_payload_are_preserved() {
        bounded(async {
            let (mut client, mut proxy) = duplex(256);
            let target = Destination::new("2001:db8::1", 443).unwrap();
            let account = Account { user: "u".into(), pass: "p".into() };
            let server = async {
                assert_eq!(read_http_header(&mut proxy).await, b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic dTpw\r\n\r\n");
                proxy.write_all(b"HTTP/1.1 200 Connection established\r\nContent-Length: 7\r\n\r\npayload").await.unwrap();
            };
            let user = async {
                http_connect(&mut client, &target, Some(&account)).await.unwrap();
                expect_bytes(&mut client, b"payload").await;
            };
            tokio::join!(server, user);
        }).await;
    }

    #[tokio::test]
    async fn http_accepts_fragmented_http10_response_and_custom_headers() {
        bounded(async {
            let (mut client, mut proxy) = duplex(1);
            let target = Destination::new("example.org", 80).unwrap();
            let headers = vec![("X-Test".into(), "value".into()), ("proxy-authorization".into(), "Bearer token".into()), ("Host".into(), "ignored".into()), ("proxy-connection".into(), "close".into())];
            let account = Account { user: "u".into(), pass: "p".into() };
            let server = async {
                assert_eq!(read_http_header(&mut proxy).await, b"CONNECT example.org:80 HTTP/1.1\r\nHost: example.org:80\r\nProxy-Connection: Keep-Alive\r\nX-Test: value\r\nproxy-authorization: Bearer token\r\n\r\n");
                proxy.write_all(b"HTTP/1.0 200 OK\r\n\r\nx").await.unwrap();
            };
            let user = async {
                http_connect_with_headers(&mut client, &target, Some(&account), &headers).await.unwrap();
                expect_bytes(&mut client, b"x").await;
            };
            tokio::join!(server, user);
        }).await;
    }

    #[tokio::test]
    async fn http_rejects_upstream_failures_and_malformed_responses() {
        let oversized = [
            b"HTTP/1.1 200 OK\r\nX: ".as_slice(),
            &vec![b'a'; MAX_HTTP_HEADER],
        ]
        .concat();
        let too_many_fields = format!(
            "HTTP/1.1 200 OK\r\n{}\r\n",
            "X: v\r\n".repeat(MAX_HTTP_FIELDS + 1)
        )
        .into_bytes();
        for response in [
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
            b"HTTP/1.1 502 Bad Gateway\r\n\r\n".to_vec(),
            b"HTTP/1.1 201 Created\r\n\r\n".to_vec(),
            b"HTTP/9.9 200 OK\r\n\r\n".to_vec(),
            b"HTTP/1.1 two OK\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nInvalid header\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\n".to_vec(),
            oversized,
            too_many_fields,
        ] {
            bounded(async {
                let (mut client, mut proxy) = duplex(MAX_HTTP_HEADER * 2);
                let target = Destination::new("example.org", 80).unwrap();
                let server = async {
                    read_http_header(&mut proxy).await;
                    proxy.write_all(&response).await.unwrap();
                    proxy.shutdown().await.unwrap();
                };
                let user = async {
                    assert!(http_connect(&mut client, &target, None).await.is_err());
                };
                tokio::join!(server, user);
            })
            .await;
        }
    }

    #[tokio::test]
    async fn http_accepts_response_exactly_at_header_limit() {
        bounded(async {
            let (mut client, mut proxy) = duplex(256);
            let target = Destination::new("example.org", 80).unwrap();
            let prefix = b"HTTP/1.1 200 OK\r\nX-Padding: ";
            let mut response = prefix.to_vec();
            response.resize(MAX_HTTP_HEADER - 4, b'x');
            response.extend_from_slice(b"\r\n\r\ntunnel");
            let server = async {
                assert_eq!(read_http_header(&mut proxy).await, b"CONNECT example.org:80 HTTP/1.1\r\nHost: example.org:80\r\nProxy-Connection: Keep-Alive\r\n\r\n");
                proxy.write_all(&response).await.unwrap();
            };
            let user = async {
                http_connect(&mut client, &target, None).await.unwrap();
                expect_bytes(&mut client, b"tunnel").await;
            };
            tokio::join!(server, user);
        }).await;
    }

    #[tokio::test]
    async fn http_rejects_request_header_injection_before_writing() {
        for headers in [
            vec![("X-Bad\r\nInjected".into(), "value".into())],
            vec![("X-Test".into(), "value\r\nInjected: true".into())],
            vec![("Content-Length".into(), "5".into())],
            vec![("Transfer-Encoding".into(), "chunked".into())],
            vec![("X-Large".into(), "a".repeat(MAX_HTTP_HEADER))],
        ] {
            bounded(async {
                let (mut client, mut proxy) = duplex(128);
                let target = Destination::new("example.org", 80).unwrap();
                assert!(
                    http_connect_with_headers(&mut client, &target, None, &headers)
                        .await
                        .is_err()
                );
                drop(client);
                assert_eq!(
                    proxy.read_u8().await.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            })
            .await;
        }
    }
}
