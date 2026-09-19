//! VLESS version 0 TCP headers, without flow addons or VLESS encryption.
//!
//! The wire layout follows `proxy/vless/encoding/encoding.go`: version, UUID,
//! addon length, command, port, and address. Reads consume exactly the header so
//! a client may send application bytes in the same packet as its request.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context, Result, bail, ensure};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{Reply, Request};
use crate::address::{Address, Destination};

const VERSION: u8 = 0;
const TCP_COMMAND: u8 = 1;

#[derive(Clone, Debug)]
pub struct Account {
    pub id: [u8; 16],
    pub email: String,
}

/// Authenticate and read one base VLESS TCP request. The success response must
/// be sent through `Request::reply` after the destination connection succeeds.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    accounts: &[Account],
) -> Result<Request> {
    let version = reader.read_u8().await.context("read VLESS version")?;
    ensure!(version == VERSION, "unsupported VLESS version {version}");

    let mut id = [0; 16];
    reader
        .read_exact(&mut id)
        .await
        .context("read VLESS UUID")?;
    let mut authenticated = None;
    for account in accounts {
        if bool::from(account.id.ct_eq(&id)) {
            authenticated = Some(account);
        }
    }
    let account = authenticated.context("invalid VLESS user")?;

    read_empty_addons(reader).await?;
    let command = reader.read_u8().await.context("read VLESS command")?;
    ensure!(
        command == TCP_COMMAND,
        "unsupported VLESS command {command}; only TCP is implemented"
    );
    let destination = read_destination(reader)
        .await
        .context("read VLESS destination")?;
    Ok(Request {
        destination,
        user: account.email.clone(),
        initial_payload: Vec::new(),
        reply: Reply::Vless,
    })
}

/// Write the base TCP request. Application data can be written immediately;
/// waiting for the response header before sending it can deadlock a peer.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    account: &Account,
    destination: &Destination,
) -> Result<()> {
    // Encode before touching the socket so invalid addresses send no partial
    // authentication header. The largest valid base header is only 278 bytes.
    let mut header = Vec::with_capacity(278);
    header.push(VERSION);
    header.extend_from_slice(&account.id);
    header.extend_from_slice(&[0, TCP_COMMAND]);
    header.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.address {
        Address::Ip(IpAddr::V4(ip)) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        Address::Domain(host) => {
            ensure!(
                !host.is_empty() && host.len() <= 255,
                "invalid VLESS domain length"
            );
            header.extend_from_slice(&[2, host.len() as u8]);
            header.extend_from_slice(host.as_bytes());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            header.push(3);
            header.extend_from_slice(&ip.octets());
        }
    }
    writer
        .write_all(&header)
        .await
        .context("write VLESS request")
}

pub async fn write_response<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    writer
        .write_all(&[VERSION, 0])
        .await
        .context("write VLESS response")
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let version = reader
        .read_u8()
        .await
        .context("read VLESS response version")?;
    ensure!(
        version == VERSION,
        "unexpected VLESS response version {version}"
    );
    read_empty_addons(reader).await
}

async fn read_empty_addons<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let length = reader.read_u8().await.context("read VLESS addon length")?;
    ensure!(
        length == 0,
        "VLESS addons and flow are not implemented (received {length} bytes)"
    );
    Ok(())
}

async fn read_destination<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Destination> {
    let port = reader.read_u16().await?;
    let address = match reader.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            Address::Ip(Ipv4Addr::from(bytes).into())
        }
        2 => {
            let length = reader.read_u8().await? as usize;
            ensure!(length != 0, "empty VLESS domain");
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).await?;
            let host = std::str::from_utf8(&bytes).context("invalid VLESS domain encoding")?;
            // Go's address parser accepts IP literals encoded as domains,
            // including bracketed IPv6, then checks the ASCII domain alphabet.
            let ip_host = host
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(host);
            if let Ok(ip) = ip_host.parse::<IpAddr>() {
                Address::Ip(ip)
            } else {
                ensure!(
                    host.bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
                    "invalid VLESS domain name"
                );
                Address::Domain(host.to_owned())
            }
        }
        3 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            Address::Ip(Ipv6Addr::from(bytes).into())
        }
        family => bail!("unsupported VLESS address family {family}"),
    };
    Ok(Destination { address, port })
}

/// A VLESS outbound stream that removes the response header on its first read.
/// Writes pass through immediately, including before a response is available.
pub struct VlessStream<S> {
    inner: S,
    header: [u8; 2],
    header_read: usize,
    failure: Option<(io::ErrorKind, &'static str)>,
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 2],
            header_read: 0,
            failure: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some((kind, message)) = this.failure {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        while this.header_read < this.header.len() {
            let mut header_buf = ReadBuf::new(&mut this.header[this.header_read..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut header_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let count = header_buf.filled().len();
                    if count == 0 {
                        let message = "truncated VLESS response header";
                        this.failure = Some((io::ErrorKind::UnexpectedEof, message));
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            message,
                        )));
                    }
                    this.header_read += count;
                    let invalid = if this.header[0] != VERSION {
                        Some("unexpected VLESS response version")
                    } else if this.header_read == 2 && this.header[1] != 0 {
                        Some("VLESS response addons and flow are not implemented")
                    } else {
                        None
                    };
                    if let Some(message) = invalid {
                        this.failure = Some((io::ErrorKind::InvalidData, message));
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            message,
                        )));
                    }
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn account() -> Account {
        Account {
            id: ID,
            email: "test@example.com".to_owned(),
        }
    }

    // Fixed version, UUID, no addons, TCP command and port 443, as emitted by
    // Go EncodeRequestHeader; address suffixes use VLESS's family bytes 1/2/3.
    fn request_fixture(address: &[u8]) -> Vec<u8> {
        let mut wire = vec![
            0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0, 1, 0x01, 0xbb,
        ];
        wire.extend_from_slice(address);
        wire
    }

    #[tokio::test]
    async fn go_wire_fixtures_and_all_truncations() {
        let cases = [
            ("127.0.0.1", vec![1, 127, 0, 0, 1]),
            (
                "www.example.com",
                [vec![2, 15], b"www.example.com".to_vec()].concat(),
            ),
            ("::1", [vec![3], vec![0; 15], vec![1]].concat()),
        ];
        for (host, address) in cases {
            let fixture = request_fixture(&address);
            let destination = Destination::new(host, 443).unwrap();
            let mut encoded = Vec::new();
            write_request(&mut encoded, &account(), &destination)
                .await
                .unwrap();
            assert_eq!(encoded, fixture);

            let request = read_request(&mut fixture.as_slice(), &[account()])
                .await
                .unwrap();
            assert_eq!(request.destination, destination);
            assert_eq!(request.user, "test@example.com");
            assert!(matches!(request.reply, Reply::Vless));
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
    async fn rejects_bad_credentials_versions_addons_commands_and_addresses() {
        let fixture = request_fixture(&[1, 127, 0, 0, 1]);
        assert!(read_request(&mut fixture.as_slice(), &[]).await.is_err());
        for (offset, value, expected) in [
            (0, 1, "version"),
            (1, 1, "invalid VLESS user"),
            (17, 1, "addons"),
            (18, 2, "command 2"),
            (18, 3, "command 3"),
            (18, 4, "command 4"),
            (18, 255, "command 255"),
            (21, 4, "address family"),
        ] {
            let mut wire = fixture.clone();
            wire[offset] = value;
            let error = read_request(&mut wire.as_slice(), &[account()])
                .await
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        for address in [&[2, 0][..], &[2, 1, b'/'][..], &[2, 1, 0xff][..]] {
            assert!(
                read_request(&mut request_fixture(address).as_slice(), &[account()])
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn request_and_response_preserve_early_payload() {
        let mut wire = request_fixture(&[1, 127, 0, 0, 1]);
        wire.extend_from_slice(b"early application bytes");
        let mut reader = wire.as_slice();
        let request = read_request(&mut reader, &[account()]).await.unwrap();
        assert!(request.initial_payload.is_empty());
        assert_eq!(reader, b"early application bytes");

        let mut response = Vec::new();
        write_response(&mut response).await.unwrap();
        assert_eq!(response, [0, 0]);
        response.extend_from_slice(b"early reply bytes");
        let mut reader = response.as_slice();
        read_response(&mut reader).await.unwrap();
        assert_eq!(reader, b"early reply bytes");
        for mut wire in [&[][..], &[0][..], &[1, 0][..], &[0, 1][..]] {
            assert!(read_response(&mut wire).await.is_err());
        }
    }

    #[tokio::test]
    async fn lazy_stream_sends_payload_before_waiting_for_response() {
        tokio::time::timeout(Duration::from_secs(3), async {
            // One-byte capacity splits every header and exercises Pending in
            // the response parser. The server deliberately waits for payload.
            let (mut client, mut server) = tokio::io::duplex(1);
            let client_task = async {
                let destination = Destination::new("example.com", 443).unwrap();
                write_request(&mut client, &account(), &destination)
                    .await
                    .unwrap();
                let mut stream = VlessStream::new(client);
                stream.write_all(b"hello").await.unwrap();
                stream.flush().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"world");
            };
            let server_task = async {
                let request = read_request(&mut server, &[account()]).await.unwrap();
                assert_eq!(request.destination.to_string(), "example.com:443");
                let mut payload = [0; 5];
                server.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"hello");
                write_response(&mut server).await.unwrap();
                server.write_all(b"world").await.unwrap();
                server.shutdown().await.unwrap();
            };
            tokio::join!(client_task, server_task);
        })
        .await
        .expect("VLESS handshake blocked before sending client payload");
    }

    #[tokio::test]
    async fn lazy_stream_rejects_invalid_or_truncated_headers_permanently() {
        for (wire, kind) in [
            (&[][..], io::ErrorKind::UnexpectedEof),
            (&[0][..], io::ErrorKind::UnexpectedEof),
            (&[1, 0, 42][..], io::ErrorKind::InvalidData),
            (&[0, 1, 42][..], io::ErrorKind::InvalidData),
        ] {
            let mut stream = VlessStream::new(wire);
            let mut payload = [0; 1];
            for _ in 0..2 {
                assert_eq!(stream.read(&mut payload).await.unwrap_err().kind(), kind);
            }
        }
        let mut stream = VlessStream::new(&[0, 0, 42][..]);
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, [42]);
        assert!(stream.into_inner().is_empty());
    }
}
