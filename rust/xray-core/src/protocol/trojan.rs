//! Trojan TCP authentication and request framing, from `proxy/trojan`.
//!
//! Requests contain the lowercase hex SHA-224 password hash, CRLF, command,
//! SOCKS address and CRLF. Trojan has no response header; subsequent bytes in
//! either direction are the application stream. TLS is the transport's job.

use std::{fmt, net::IpAddr};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha224};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Reply, Request};
use crate::address::{Address, Destination};

const TCP_COMMAND: u8 = 1;
/// `commandUDP` in Go's `proxy/trojan/protocol.go`: UDP over the very Trojan
/// connection that carried the request header.
const UDP_COMMAND: u8 = 3;
const CRLF: [u8; 2] = *b"\r\n";

#[derive(Clone)]
pub struct Account {
    key: [u8; 56],
    pub email: String,
}

impl Account {
    /// Compile a password once, matching Go's `hexSha224` byte for byte.
    pub fn new(password: &str, email: impl Into<String>) -> Self {
        let digest = Sha224::digest(password.as_bytes());
        let mut key = [0; 56];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in digest.iter().enumerate() {
            key[index * 2] = HEX[usize::from(byte >> 4)];
            key[index * 2 + 1] = HEX[usize::from(byte & 15)];
        }
        Self {
            key,
            email: email.into(),
        }
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Account")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// One authenticated Trojan request plus its command; `udp` is true for the
/// UDP-over-Trojan command 3, whose association is served by `trojan_udp`.
pub struct Accepted {
    pub request: Request,
    pub udp: bool,
}

pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    accounts: &[Account],
) -> Result<Accepted> {
    let mut key = [0; 56];
    reader
        .read_exact(&mut key)
        .await
        .context("read Trojan password hash")?;
    let mut authenticated = None;
    for account in accounts {
        if bool::from(account.key.ct_eq(&key)) {
            authenticated = Some(account);
        }
    }
    let account = authenticated.context("invalid Trojan user")?;
    read_crlf(reader)
        .await
        .context("Trojan authentication CRLF")?;
    let command = reader.read_u8().await.context("read Trojan command")?;
    // Go's `ParseHeader` maps command 3 to the UDP network and parses the
    // request address identically for both commands; every other command is
    // rejected (Go never validates more about UDP requests than TCP ones).
    ensure!(
        command == TCP_COMMAND || command == UDP_COMMAND,
        "unsupported Trojan command {command}; only TCP (1) and UDP (3) are implemented"
    );
    let udp = command == UDP_COMMAND;
    let mut destination = Destination::read_socks(reader)
        .await
        .context("read Trojan destination")?;
    if let Address::Domain(host) = &destination.address {
        let ip_host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = ip_host.parse::<IpAddr>() {
            destination.address = Address::Ip(ip);
        } else {
            ensure!(
                host.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
                "invalid Trojan domain name"
            );
        }
    }
    read_crlf(reader).await.context("Trojan destination CRLF")?;
    Ok(Accepted {
        request: Request {
            destination,
            user: account.email.clone(),
            initial_payload: Vec::new(),
            reply: Reply::None,
        },
        udp,
    })
}

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    account: &Account,
    destination: &Destination,
) -> Result<()> {
    // Fully validate the destination before sending any part of the header.
    let mut header = Vec::with_capacity(321);
    header.extend_from_slice(&account.key);
    header.extend_from_slice(&CRLF);
    header.push(TCP_COMMAND);
    destination.write_socks(&mut header).await?;
    header.extend_from_slice(&CRLF);
    writer
        .write_all(&header)
        .await
        .context("write Trojan request")
}

async fn read_crlf<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes).await?;
    ensure!(bytes == CRLF, "invalid Trojan CRLF delimiter");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PASSWORD_HASH: &[u8; 56] = b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";

    fn account() -> Account {
        Account::new("password", "love@example.com")
    }

    // Go TestTCPRequest uses password "password", 127.0.0.1:1234 and payload
    // "test string". The independently fixed SHA224 digest and framing below
    // also verify our writer without round-tripping through our own reader.
    fn request_fixture(address: &[u8]) -> Vec<u8> {
        command_fixture(address, b"\x01")
    }

    /// The same Go wire shape with an arbitrary command byte (3 = UDP).
    fn command_fixture(address: &[u8], command: &[u8; 1]) -> Vec<u8> {
        [
            PASSWORD_HASH.as_slice(),
            b"\r\n",
            command.as_slice(),
            address,
            b"\x04\xd2\r\n",
        ]
        .concat()
    }

    #[test]
    fn sha224_vectors_and_redacted_debug() {
        assert_eq!(&account().key, PASSWORD_HASH);
        assert_eq!(
            &Account::new("", "").key,
            b"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            &Account::new("abc", "").key,
            b"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        let debug = format!("{:?}", account());
        assert!(!debug.contains("password"));
        assert!(!debug.contains(std::str::from_utf8(PASSWORD_HASH).unwrap()));
    }

    #[tokio::test]
    async fn go_tcp_wire_fixtures_and_all_truncations() {
        for (host, address) in [
            ("127.0.0.1", vec![1, 127, 0, 0, 1]),
            (
                "www.example.com",
                [vec![3, 15], b"www.example.com".to_vec()].concat(),
            ),
            ("::1", [vec![4], vec![0; 15], vec![1]].concat()),
        ] {
            let fixture = request_fixture(&address);
            let destination = Destination::new(host, 1234).unwrap();
            let mut encoded = Vec::new();
            write_request(&mut encoded, &account(), &destination)
                .await
                .unwrap();
            assert_eq!(encoded, fixture);
            let accepted = read_request(&mut fixture.as_slice(), &[account()])
                .await
                .unwrap();
            assert_eq!(accepted.request.destination, destination);
            assert_eq!(accepted.request.user, "love@example.com");
            assert!(matches!(accepted.request.reply, Reply::None));
            assert!(!accepted.udp);
            for length in 0..fixture.len() {
                assert!(
                    read_request(&mut &fixture[..length], &[account()])
                        .await
                        .is_err(),
                    "accepted truncated {host} request of length {length}"
                );
            }
        }
    }

    #[tokio::test]
    async fn go_udp_wire_fixture_accepts_command_three() {
        for (host, address) in [
            ("127.0.0.1", vec![1, 127, 0, 0, 1]),
            (
                "example.com",
                [vec![3, 11], b"example.com".to_vec()].concat(),
            ),
            ("::1", [vec![4], vec![0; 15], vec![1]].concat()),
        ] {
            // hash | CRLF | command 3 | SOCKS address | CRLF, the exact Go
            // `ParseHeader` wire for a UDP-over-Trojan request.
            let fixture = command_fixture(&address, b"\x03");
            let accepted = read_request(&mut fixture.as_slice(), &[account()])
                .await
                .unwrap();
            assert!(
                accepted.udp,
                "command 3 must mark the request as a UDP association"
            );
            assert_eq!(
                accepted.request.destination,
                Destination::new(host, 1234).unwrap()
            );
            assert_eq!(accepted.request.user, "love@example.com");
            for length in 0..fixture.len() {
                assert!(
                    read_request(&mut &fixture[..length], &[account()])
                        .await
                        .is_err(),
                    "accepted truncated {host} UDP request of length {length}"
                );
            }
        }
        // Command 1 keeps meaning TCP.
        let fixture = command_fixture(&[1, 127, 0, 0, 1], b"\x01");
        assert!(
            !read_request(&mut fixture.as_slice(), &[account()])
                .await
                .unwrap()
                .udp
        );
    }

    #[tokio::test]
    async fn rejects_bad_credentials_delimiters_commands_and_addresses() {
        let fixture = request_fixture(&[1, 127, 0, 0, 1]);
        assert!(read_request(&mut fixture.as_slice(), &[]).await.is_err());
        assert!(
            read_request(
                &mut fixture.as_slice(),
                &[Account::new("different password", "")]
            )
            .await
            .is_err()
        );
        for (offset, value, expected) in [
            (0, b'D', "invalid Trojan user"),
            (56, b'!', "CRLF"),
            (57, b'!', "CRLF"),
            (58, 0, "command 0"),
            (58, 2, "command 2"),
            (58, 4, "command 4"),
            (58, 255, "command 255"),
            (59, 2, "address family"),
            (66, b'!', "CRLF"),
            (67, b'!', "CRLF"),
        ] {
            let mut wire = fixture.clone();
            wire[offset] = value;
            let error = read_request(&mut wire.as_slice(), &[account()])
                .await
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        for address in [&[3, 0][..], &[3, 1, b'/'][..], &[3, 1, 0xff][..]] {
            assert!(
                read_request(&mut request_fixture(address).as_slice(), &[account()])
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn retains_payload_sent_with_header() {
        let mut wire = request_fixture(&[1, 127, 0, 0, 1]);
        wire.extend_from_slice(b"test string");
        let mut reader = wire.as_slice();
        let accepted = read_request(&mut reader, &[account()]).await.unwrap();
        assert!(accepted.request.initial_payload.is_empty());
        assert_eq!(reader, b"test string");
    }

    #[tokio::test]
    async fn duplex_handles_fragmentation_and_has_no_response_header() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut client, mut server) = tokio::io::duplex(1);
            let client_task = async {
                let destination = Destination::new("example.com", 1234).unwrap();
                write_request(&mut client, &account(), &destination)
                    .await
                    .unwrap();
                client.write_all(b"test string").await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"raw reply");
            };
            let server_task = async {
                let accepted = read_request(&mut server, &[account()]).await.unwrap();
                assert_eq!(accepted.request.destination.to_string(), "example.com:1234");
                let mut payload = Vec::new();
                server.read_to_end(&mut payload).await.unwrap();
                assert_eq!(payload, b"test string");
                server.write_all(b"raw reply").await.unwrap();
                server.shutdown().await.unwrap();
            };
            tokio::join!(client_task, server_task);
        })
        .await
        .expect("Trojan fragmented duplex exchange timed out");
    }
}
