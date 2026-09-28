// P28 proxy_protocol_runtime: the runtime accept for sockopt
// acceptProxyProtocol (Go: transport/internet/system_listener.go wrapping the
// listener with github.com/pires/go-proxyproto at policy REQUIRE).
#![allow(dead_code)]
//! Accept-side PROXY protocol processing for inbounds whose sockopt sets
//! `acceptProxyProtocol: true`.
//!
//! Go wraps the TCP listener with `proxyproto.Listener{Policy: REQUIRE}` in
//! `transport/internet/system_listener.go` (and every hub — tcp, websocket,
//! gRPC, httpupgrade — merges its own transport-level `acceptProxyProtocol`
//! flag with `sockopt.acceptProxyProtocol` before that). The wrapper is the
//! FIRST thing after `accept()`: it runs before TLS, WebSocket, HTTP
//! Upgrade, or any proxy-protocol-agnostic framing, and a malformed or
//! missing header drops the connection.
//!
//! This module is a thin runtime adapter over the complete
//! [`crate::transport::proxy_protocol`] codec: it fixes the configuration to
//! Xray's semantics (REQUIRED mode, the pinned go-proxyproto v0.15 defaults —
//! a ten-second header deadline and a 4096-byte v2 payload limit) and exposes
//! the ORIGINAL source/destination endpoints for the runtime's connection
//! context, keeping the replayed post-header bytes on the returned stream
//! (the same pattern as `runtime/sniffing.rs`'s `SniffedStream`).
//!
//! Trust note: Go's policy function returns REQUIRE for every upstream peer,
//! so any peer that completes the handshake may present a header; the
//! operator is expected to restrict who can reach the port. The header is
//! metadata about the real transport peer, never authentication.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    BoxStream, Stream,
    proxy_protocol::{self as codec, Config, Header, PeerTrust},
};

/// An accepted stream after a REQUIRED PROXY v1/v2 header has been read,
/// validated, and stripped. All bytes read past the header are replayed by
/// the stream (the codec buffers the prefix, mirroring `SniffedStream`), so
/// the wrapper is a drop-in `BoxStream` for the rest of the accept chain.
///
/// For a PROXY command header, [`Self::source_addr`] and
/// [`Self::destination_addr`] expose the ORIGINAL endpoints the trusted
/// proxy reported. LOCAL and UNKNOWN headers return `None` from both, and
/// the caller must keep the real socket endpoints (go-proxyproto semantics).
pub struct AcceptedProxyProtocol {
    inner: BoxStream,
    header: Option<Header>,
}

impl AcceptedProxyProtocol {
    /// The complete decoded header, when one was presented.
    pub fn header(&self) -> Option<&Header> {
        self.header.as_ref()
    }

    /// The ORIGINAL source endpoint reported by the trusted proxy.
    pub fn source_addr(&self) -> Option<SocketAddr> {
        self.header.as_ref().and_then(Header::source_addr)
    }

    /// The ORIGINAL destination endpoint reported by the trusted proxy.
    pub fn destination_addr(&self) -> Option<SocketAddr> {
        self.header.as_ref().and_then(Header::destination_addr)
    }

    /// Unwrap into the plain replaying stream plus the decoded header.
    pub fn into_parts(self) -> (BoxStream, Option<Header>) {
        (self.inner, self.header)
    }

    /// Borrow the replaying stream for raw I/O.
    pub fn stream(&mut self) -> &mut BoxStream {
        &mut self.inner
    }
}

impl std::fmt::Debug for AcceptedProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wrapped stream is a trait object without Debug; the header
        // carries everything meaningful for logs.
        f.debug_struct("AcceptedProxyProtocol")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for AcceptedProxyProtocol {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AcceptedProxyProtocol {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, data)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Read and validate the PROXY v1/v2 header from an inbound connection whose
/// sockopt set `acceptProxyProtocol: true`.
///
/// On success the returned [`AcceptedProxyProtocol`] replays every byte read
/// past the header. On error (missing header under REQUIRE, malformed
/// header, or the ten-second deadline) the owned stream is dropped, which
/// closes the connection — Go's proxyproto.Listener fails the accept and the
/// hub closes the socket; there is no plaintext fallback.
///
/// Call this immediately after the TCP accept and BEFORE the transport
/// accept chain (TLS / REALITY / WebSocket / HTTP Upgrade / sniffing): the
/// header precedes every other framing on the wire.
pub async fn accept_proxy_protocol<S>(stream: S) -> io::Result<AcceptedProxyProtocol>
where
    S: Stream + 'static,
{
    // Xray's policy function returns REQUIRE for every peer, so the trust
    // decision is "the operator let this peer connect"; structure is what we
    // validate here. Config::default() is Mode::Required with the pinned
    // go-proxyproto v0.15 defaults (10s deadline, 4096-byte v2 payload).
    let config = Config::default();
    let accepted = codec::accept(Box::new(stream), &config, PeerTrust::Trusted).await?;
    Ok(AcceptedProxyProtocol {
        inner: accepted.stream,
        header: accepted.header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// go-proxyproto's own v1 example line, shared with the codec's tests.
    const V1: &[u8] = b"PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n";

    /// The codec's golden v2 IPv4 header (28 bytes).
    const V2: &[u8] =
        b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c\xc0\0\x02\x01\xc6\x33\x64\x02\x30\x39\x01\xbb";

    async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("proxy protocol test timed out")
    }

    #[tokio::test]
    async fn v1_header_yields_original_endpoints_and_replays_the_rest() {
        bounded(async {
            let (mut writer, reader) = tokio::io::duplex(1024);
            let mut wire = V1.to_vec();
            wire.extend_from_slice(b"\x16\x03\x01\x05hello");
            writer.write_all(&wire).await.unwrap();
            writer.shutdown().await.unwrap();
            let mut accepted = accept_proxy_protocol(reader).await.unwrap();
            assert_eq!(
                accepted.source_addr(),
                Some("192.0.2.1:12345".parse().unwrap())
            );
            assert_eq!(
                accepted.destination_addr(),
                Some("198.51.100.2:443".parse().unwrap())
            );
            assert_eq!(accepted.header().unwrap().version, 1);
            // The wrapper stays a duplex: writes pass through to the peer
            // (the peer's read direction survives its write shutdown).
            accepted.stream().write_all(b"pong").await.unwrap();
            let mut echoed = [0u8; 4];
            writer.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"pong");
            // Coalesced application bytes after the header are replayed.
            let mut replayed = Vec::new();
            accepted.stream().read_to_end(&mut replayed).await.unwrap();
            assert_eq!(replayed, b"\x16\x03\x01\x05hello");
        })
        .await;
    }

    #[tokio::test]
    async fn v2_header_yields_original_endpoints_and_replays_the_rest() {
        bounded(async {
            let (mut writer, reader) = tokio::io::duplex(1024);
            let mut wire = V2.to_vec();
            wire.extend_from_slice(b"GET / HTTP/1.1\r\n");
            writer.write_all(&wire).await.unwrap();
            writer.shutdown().await.unwrap();
            let mut accepted = accept_proxy_protocol(reader).await.unwrap();
            assert_eq!(
                accepted.source_addr(),
                Some("192.0.2.1:12345".parse().unwrap())
            );
            assert_eq!(
                accepted.destination_addr(),
                Some("198.51.100.2:443".parse().unwrap())
            );
            let header = accepted.header().unwrap();
            assert_eq!(header.version, 2);
            assert_eq!(header.transport, codec::Transport::Stream);
            let mut replayed = Vec::new();
            accepted.stream().read_to_end(&mut replayed).await.unwrap();
            assert_eq!(replayed, b"GET / HTTP/1.1\r\n");
        })
        .await;
    }

    #[tokio::test]
    async fn local_header_keeps_real_endpoints() {
        bounded(async {
            // A v2 LOCAL command header: valid, but it claims no addresses,
            // so the caller must retain the actual socket endpoints.
            let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            wire.extend_from_slice(&[0x20, 0x11, 0, 0]);
            wire.extend_from_slice(b"data");
            let (mut writer, reader) = tokio::io::duplex(1024);
            writer.write_all(&wire).await.unwrap();
            writer.shutdown().await.unwrap();
            let mut accepted = accept_proxy_protocol(reader).await.unwrap();
            assert!(accepted.source_addr().is_none());
            assert!(accepted.destination_addr().is_none());
            assert_eq!(accepted.header().unwrap().command, codec::Command::Local);
            let mut replayed = Vec::new();
            accepted.stream().read_to_end(&mut replayed).await.unwrap();
            assert_eq!(replayed, b"data");
        })
        .await;
    }

    #[tokio::test]
    async fn malformed_headers_drop_the_connection_like_go() {
        bounded(async {
            for wire in [
                // Absent header under REQUIRE (go-proxyproto REJECT).
                b"GET / HTTP/1.1\r\n\r\n".as_slice(),
                // Malformed v1 (leading-zero port).
                b"PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n".as_slice(),
                // Malformed v2 command byte.
                b"\r\n\r\n\0\r\nQUIT\n\x2f\x11\0\x0c\0\0\0\0\0\0\0\0\0\0\0\0".as_slice(),
                // Truncated v1: EOF mid-header.
                b"PROXY TCP4 1.2.3.4".as_slice(),
            ] {
                let (mut writer, reader) = tokio::io::duplex(1024);
                writer.write_all(wire).await.unwrap();
                writer.shutdown().await.unwrap();
                let error = match accept_proxy_protocol(reader).await {
                    Ok(_) => panic!("malformed header must be rejected: {wire:?}"),
                    Err(error) => error,
                };
                // The owned stream is dropped with the error, so the peer
                // observes the closed connection (Go: hub closes the conn).
                assert_eq!(writer.read(&mut [0u8; 1]).await.unwrap(), 0, "{error}");
            }
        })
        .await;
    }

    #[tokio::test]
    async fn wrapper_is_a_box_stream_for_the_accept_chain() {
        bounded(async {
            // The returned wrapper must itself satisfy the transport Stream
            // trait so the runtime can hand it to the next accept stage.
            let (mut writer, reader) = tokio::io::duplex(1024);
            writer.write_all(V1).await.unwrap();
            writer.write_all(b"payload").await.unwrap();
            writer.shutdown().await.unwrap();
            let accepted = accept_proxy_protocol(reader).await.unwrap();
            let (stream, header) = accepted.into_parts();
            assert!(header.is_some());
            let mut stream: BoxStream = stream;
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"payload");
        })
        .await;
    }
}
