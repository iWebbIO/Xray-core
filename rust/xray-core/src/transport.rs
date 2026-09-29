//! Composable asynchronous byte streams shared by proxies and transports.
pub mod browser_dialer;
pub mod finalmask;
pub mod grpc;
pub mod headers;
pub mod httpupgrade;
pub mod hysteria;
pub mod hysteria_endpoint;
pub mod kcp;
pub mod masque;
pub mod masque_connectip;
pub mod proxy_protocol;
pub mod proxy_protocol_runtime;
pub mod reality;
pub mod reality_inbound;
pub mod sockopt;
pub mod tls;
pub mod unix_listener;
pub mod websocket;
pub mod xdrive;
pub mod xhttp;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

pub(crate) enum AcceptedTransport {
    Single(Option<BoxStream>),
    Grpc(grpc::Server),
}

/// Owns the socket and, for KCP, every accepted UDP conversation. The runtime
/// closes this listener before draining its per-connection tasks.
pub(crate) enum InboundListener {
    Tcp(tokio::net::TcpListener),
    Kcp(kcp::KcpListener),
    Unix(unix_listener::UnixListener),
    Xdrive(xdrive::stream::XdriveListener),
}

impl InboundListener {
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            Self::Kcp(listener) => Ok(listener.local_addr()),
            // Go's UnixConnWrapper masks both peers as 0.0.0.0 addresses;
            // the socket path itself is not a SocketAddr.
            Self::Unix(_) => Ok(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            )),
            Self::Xdrive(listener) => Ok(listener.local_addr()),
        }
    }

    pub async fn accept(
        &mut self,
    ) -> io::Result<(BoxStream, std::net::SocketAddr, std::net::SocketAddr)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, source) = listener.accept().await?;
                stream.set_nodelay(true)?;
                let bound = stream.local_addr()?;
                Ok((Box::new(stream), source, bound))
            }
            Self::Kcp(listener) => {
                let (stream, source) = listener.accept().await?;
                let bound = stream.local_addr();
                Ok((Box::new(stream), source, bound))
            }
            Self::Unix(listener) => {
                // Go's UnixConnWrapper masks the unix peer as 0.0.0.0:0; the
                // dokodemo handler forwards it as an ordinary TCP stream.
                let (stream, _peer, _bound) = listener.accept().await?;
                let masked = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                );
                Ok((stream, masked, masked))
            }
            Self::Xdrive(listener) => {
                // The object store is the channel; the endpoint address is
                // the engine's placeholder (Go's placeholderAddr).
                let (stream, source) = listener.accept().await?;
                Ok((stream, source, xdrive::stream::PLACEHOLDER_ADDR))
            }
        }
    }

    pub async fn close(self) -> io::Result<()> {
        match self {
            Self::Tcp(_) => Ok(()),
            Self::Kcp(listener) => listener.close().await,
            Self::Unix(listener) => listener.close(),
            Self::Xdrive(listener) => listener.close().await,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct InboundTransport {
    pub tls: Option<tls::TlsServer>,
    /// The `tcpSettings.header` obfuscation (Go's tcp.Config header
    /// authenticator): applied inside the accept, after TLS.
    pub tcp_header: Option<headers::HeaderCodec>,
    /// The `xdriveSettings` object: compiled into the object-store
    /// listener at bind time (the storage constructors are async).
    pub xdrive: Option<xdrive::stream::XdriveSettings>,
    /// REALITY replaces the TLS accept: the handshake authenticates the
    /// client against `realitySettings` and decrypts the application stream.
    pub reality: Option<reality_inbound::InboundConfig>,
    pub xhttp: Option<xhttp::Server>,
    pub websocket: Option<websocket::Config>,
    pub httpupgrade: Option<httpupgrade::HttpUpgradeConfig>,
    pub grpc: Option<grpc::Config>,
    pub kcp: Option<kcp::Config>,
}

impl InboundTransport {
    pub async fn bind(&self, address: std::net::SocketAddr) -> io::Result<InboundListener> {
        if let Some(settings) = &self.xdrive {
            // The object store is the channel; the address is advisory
            // (Go's Serve ignores it the same way).
            let end = xdrive::stream::XdriveStream::compile(settings)
                .await
                .map_err(io::Error::other)?;
            let listener = xdrive::stream::serve(&end, address)
                .await
                .map_err(io::Error::other)?;
            return Ok(InboundListener::Xdrive(listener));
        }
        match &self.kcp {
            Some(config) => Ok(InboundListener::Kcp(
                kcp::KcpListener::bind(address, config.clone(), kcp::StreamOptions::default())
                    .await?,
            )),
            None => Ok(InboundListener::Tcp(
                tokio::net::TcpListener::bind(address).await?,
            )),
        }
    }

    pub async fn accept(&self, stream: BoxStream) -> anyhow::Result<AcceptedTransport> {
        if let Some(config) = &self.reality {
            // REALITY sits exactly where the TLS accept would; a failed
            // exchange closes the connection with no plaintext fallback.
            let (stream, info) = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                reality_inbound::accept_stream(config, stream),
            )
            .await??;
            if let Some(info) = info {
                tracing::debug!(
                    server_name = %info.server_name,
                    "REALITY inbound accepted a client"
                );
            }
            return self.accept_inner(stream).await;
        }
        self.accept_inner(stream).await
    }

    async fn accept_inner(&self, mut stream: BoxStream) -> anyhow::Result<AcceptedTransport> {
        if let Some(tls) = &self.tls {
            stream = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                if self.grpc.is_some() {
                    tls.accept_with_alpn(stream, b"h2").await
                } else {
                    tls.accept(stream).await
                }
            })
            .await??;
        }
        if let Some(codec) = &self.tcp_header {
            // Go's tcp hub wraps the (TLS-wrapped) connection in the header
            // authenticator before the proxy handshake: a mismatch is a
            // camouflage answer followed by a drop.
            stream = headers::accept_side(codec.clone(), stream).await?;
        }
        if let Some(config) = &self.grpc {
            return Ok(AcceptedTransport::Grpc(
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    grpc::Server::handshake(stream, config.clone()),
                )
                .await??,
            ));
        }
        if let Some(xhttp) = &self.xhttp {
            return Ok(AcceptedTransport::Single(xhttp.accept(stream).await?));
        }
        if let Some(config) = &self.websocket {
            stream = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                websocket::server(stream, config.clone()),
            )
            .await??;
        }
        if let Some(config) = &self.httpupgrade {
            stream = httpupgrade::server_upgrade(stream, config).await?;
        }
        Ok(AcceptedTransport::Single(Some(stream)))
    }
}

/// The outbound side of a streamSettings stack, assembled by config.rs and
/// dialed by the runtime's `establish`. Public so the transport-level
/// integration tests (tests/masque_transport.rs) can build one directly;
/// nothing outside the crate is expected to construct it by hand.
#[derive(Clone, Default)]
pub struct OutboundTransport {
    pub tls: Option<tls::TlsClient>,
    pub reality: Option<reality::handshake::ClientConfig>,
    /// The `tcpSettings.header` obfuscation: applied on the dial side after
    /// the transport connect (Go's tcp dialer wraps before the first write).
    pub tcp_header: Option<headers::HeaderCodec>,
    /// The `xdriveSettings` object: compiled and dialed per connect.
    pub xdrive: Option<xdrive::stream::XdriveSettings>,
    pub server_name: String,
    /// MASQUE transport settings; the transport opens one HTTP/2
    /// extended-CONNECT tunnel per dialed stream.
    pub masque: Option<masque::Settings>,
    pub masque_tls: Option<tls::TlsSettings>,
    pub xhttp: Option<xhttp::Config>,
    pub websocket: Option<websocket::Config>,
    pub httpupgrade: Option<httpupgrade::HttpUpgradeConfig>,
    pub grpc: Option<grpc::Config>,
    pub kcp: Option<kcp::Config>,
}

impl OutboundTransport {
    pub async fn connect(
        &self,
        destination: &crate::address::Destination,
    ) -> anyhow::Result<(BoxStream, std::net::SocketAddr)> {
        self.connect_resolved(destination, None).await
    }

    pub async fn connect_resolved(
        &self,
        destination: &crate::address::Destination,
        resolved: Option<&[std::net::SocketAddr]>,
    ) -> anyhow::Result<(BoxStream, std::net::SocketAddr)> {
        if let Some(settings) = &self.xdrive {
            let end = xdrive::stream::XdriveStream::compile(settings).await?;
            return xdrive::stream::dial(&end, destination).await;
        }
        if let Some(settings) = &self.masque {
            return self.connect_masque(settings, destination, resolved).await;
        }
        if let Some(config) = &self.kcp {
            anyhow::ensure!(
                self.reality.is_none(),
                "KCP does not support REALITY security"
            );
            let (mut stream, bound) =
                kcp::connect_destination(destination, resolved, config.clone()).await?;
            if let Some(tls) = &self.tls {
                stream = tls
                    .connect(stream, &destination.address.to_string())
                    .await?;
            }
            return Ok((stream, bound));
        }
        if let Some(config) = &self.xhttp {
            let authority = if self.server_name.is_empty() {
                destination.to_string()
            } else {
                self.server_name.clone()
            };
            let config = config
                .clone()
                .with_authority(authority, self.tls.is_some() || self.reality.is_some())?;
            let remote = destination.clone();
            let tls = self.tls.clone();
            let reality = self.reality.clone();
            let resolved = resolved.map(|addresses| {
                std::sync::Arc::<[std::net::SocketAddr]>::from(addresses.to_vec())
            });
            let connector: xhttp::Connector = std::sync::Arc::new(move || {
                let remote = remote.clone();
                let tls = tls.clone();
                let reality = reality.clone();
                let resolved = resolved.clone();
                Box::pin(async move {
                    let operation = async {
                        open_tcp_tls(
                            &remote,
                            tls.as_ref(),
                            reality.as_ref(),
                            resolved.as_deref(),
                            false,
                        )
                        .await
                        .map(|(stream, _)| stream)
                        .map_err(io::Error::other)
                    };
                    tokio::time::timeout(std::time::Duration::from_secs(16), operation)
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "XHTTP connector timed out")
                        })?
                })
            });
            return Ok((
                xhttp::connect(config, connector).await?,
                std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            ));
        }
        let (mut stream, bound) = open_tcp_tls(
            destination,
            self.tls.as_ref(),
            self.reality.as_ref(),
            resolved,
            self.grpc.is_some(),
        )
        .await?;
        if let Some(config) = &self.grpc {
            let authority = config.authority_for(
                destination,
                self.tls.as_ref().map(|_| self.server_name.as_str()),
                self.reality.is_some(),
            );
            // Each outbound dial owns a fresh H2 connection for now. Tunnel
            // retains its driver after this short-lived Client handle drops.
            let client = grpc::Client::handshake(stream, config.clone(), &authority).await?;
            stream = client.open().await?.boxed();
        }
        if let Some(config) = &self.websocket {
            // Go's websocket dialer routes through the browser dialer when
            // armed (XRAY_BROWSER_DIALER): the browser performs the TCP+WS
            // dial and relays the established data channel. Early data (the
            // `ed` subprotocol) is not carried through the browser path —
            // documented in PARITY_AUDIT.
            if crate::transport::browser_dialer::has_browser() {
                let protocol = if self.tls.is_some() { "wss" } else { "ws" };
                let host = if !config.host.is_empty() {
                    config.host.clone()
                } else if !self.server_name.is_empty() {
                    self.server_name.clone()
                } else {
                    destination.address.to_string()
                };
                let host = match destination.port {
                    80 if protocol == "ws" => host,
                    443 if protocol == "wss" => host,
                    _ => format!("{host}:{}", destination.port),
                };
                let uri = format!("{protocol}://{host}{}", config.normalized_path());
                return Ok((
                    crate::transport::browser_dialer::dial(&uri).await?,
                    std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                ));
            }
            stream = websocket::client(
                stream,
                &destination.address.to_string(),
                Some(&self.server_name),
                config.clone(),
            )
            .await?;
        }
        if let Some(config) = &self.httpupgrade {
            let fallback = if self.server_name.is_empty() {
                destination.address.to_string()
            } else {
                self.server_name.clone()
            };
            stream = httpupgrade::client_upgrade(stream, config, &fallback).await?;
        }
        Ok((stream, bound))
    }

    /// The MASQUE arm of [Self::connect_resolved].
    ///
    /// Go reference (transport/internet/masque/dialer.go): the masque dialer
    /// is registered via `internet.RegisterTransportDialer(protocolName,
    /// Dial)` and receives the *outbound's* destination — the proxy-server
    /// address the runtime is dialing, never the inner protocol's final
    /// target. `dialHTTP2` forces `dest.Network = TCP`, dials TCP+TLS+h2 to
    /// that destination, and establishes the CONNECT-IP tunnel with the
    /// server reached there using `authority(config, serverName, dest.Port)`.
    /// The proxied protocol then runs inside the tunnel and addresses its
    /// real target at the protocol level (proxy/masque/client.go wraps the
    /// returned tunnel in a wireguard TUN netstack and dials the final target
    /// through it: `t.tnet.Dial("tcp", ob.Target.NetAddr())`). The
    /// composition for a generic proxy over the masque transport is therefore
    /// that the tunneled target IS the destination — the proxy server itself
    /// — and the masque server connects to exactly that address; the inner
    /// protocol carries its real destination inside. This port's per-target
    /// stream model (transport/masque.rs) encodes that destination in the
    /// extended-CONNECT path, so the runtime needs no TUN netstack here.
    async fn connect_masque(
        &self,
        settings: &masque::Settings,
        destination: &crate::address::Destination,
        resolved: Option<&[std::net::SocketAddr]>,
    ) -> anyhow::Result<(BoxStream, std::net::SocketAddr)> {
        // config.rs pairs network "masque" with security "tls" (h2-only
        // ALPN); a hand-built transport without the TLS settings fails here
        // instead of dialing plaintext.
        let tls = self.masque_tls.as_ref().ok_or_else(|| {
            anyhow::anyhow!("the masque transport requires \"security\": \"tls\"")
        })?;
        // The HTTP authority / TLS SNI fallback, derived like the xhttp
        // arm's authority and Go's authority(): the configured TLS server
        // name wins, else the destination host. masque::Settings::authority
        // appends the dialed port itself, so only the host is passed on.
        let host = if self.server_name.is_empty() {
            destination.address.to_string()
        } else {
            self.server_name.clone()
        };
        let addresses = masque_dial_addresses(destination, resolved).await?;
        let client = dial_masque_client(&addresses, &host, settings, tls).await?;
        // The tunnel target is the destination itself: the proxy server
        // being dialed through the tunnel (see the method doc above).
        let stream = client
            .connect_stream(&masque::Target::tcp(
                destination.address.to_string(),
                destination.port,
            ))
            .await?;
        // The stream must keep the tunnel alive after this frame returns:
        // only the MasqueClient owns the h2 connection driver, so it rides
        // along inside MasqueTunnel. The placeholder matches the xhttp arm:
        // the real socket lives inside the client, not on this stream.
        Ok((
            Box::new(MasqueTunnel {
                stream,
                _client: client,
            }),
            std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        ))
    }
}

async fn open_tcp_tls(
    destination: &crate::address::Destination,
    tls: Option<&tls::TlsClient>,
    reality: Option<&reality::handshake::ClientConfig>,
    resolved: Option<&[std::net::SocketAddr]>,
    require_h2: bool,
) -> anyhow::Result<(BoxStream, std::net::SocketAddr)> {
    use crate::address::Address;
    let stream = if let Some(addresses) = resolved {
        tokio::net::TcpStream::connect(addresses).await?
    } else {
        match &destination.address {
            Address::Ip(ip) => tokio::net::TcpStream::connect((*ip, destination.port)).await?,
            Address::Domain(host) => {
                tokio::net::TcpStream::connect((host.as_str(), destination.port)).await?
            }
        }
    };
    stream.set_nodelay(true)?;
    let bound = stream.local_addr()?;
    let mut stream: BoxStream = Box::new(stream);
    if let Some(tls) = tls {
        stream = if require_h2 {
            tls.connect_with_alpn(stream, &destination.address.to_string(), b"h2")
                .await?
        } else {
            tls.connect(stream, &destination.address.to_string())
                .await?
        };
    }
    if let Some(reality) = reality {
        let mut config = reality.clone();
        if config.server_name.is_empty() {
            config.server_name = destination.address.to_string();
        }
        stream = if require_h2 {
            let (stream, info) = reality::handshake::client(stream, config).await?;
            anyhow::ensure!(
                info.alpn.as_deref() == Some(b"h2".as_slice()),
                "REALITY peer did not negotiate required h2 ALPN"
            );
            Box::new(stream)
        } else {
            reality::handshake::client_boxed(stream, config).await?
        };
    }
    Ok((stream, bound))
}

/// The MASQUE dial candidates, mirroring how [open_tcp_tls] resolves the
/// destination: the `resolved` override wins, an IP destination dials its
/// literal, and a domain destination resolves through `lookup_host` — the
/// same resolver `TcpStream::connect((host, port))` uses in the TCP arm.
async fn masque_dial_addresses(
    destination: &crate::address::Destination,
    resolved: Option<&[std::net::SocketAddr]>,
) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    use crate::address::Address;
    let addresses = if let Some(addresses) = resolved {
        addresses.to_vec()
    } else {
        match &destination.address {
            Address::Ip(ip) => vec![std::net::SocketAddr::new(*ip, destination.port)],
            Address::Domain(host) => tokio::net::lookup_host((host.as_str(), destination.port))
                .await?
                .collect(),
        }
    };
    anyhow::ensure!(
        !addresses.is_empty(),
        "no address resolved for the MASQUE transport dial"
    );
    Ok(addresses)
}

/// Dials the MASQUE server across the candidates in order, like
/// `TcpStream::connect(&addresses)` in the TCP arm: the first TLS+h2
/// handshake that succeeds wins, and the last failure surfaces when none do.
async fn dial_masque_client(
    addresses: &[std::net::SocketAddr],
    host: &str,
    settings: &masque::Settings,
    tls: &tls::TlsSettings,
) -> anyhow::Result<masque::MasqueClient> {
    let mut last = None;
    for address in addresses {
        match masque::MasqueClient::dial(*address, host, settings, tls).await {
            Ok(client) => return Ok(client),
            Err(error) => last = Some(error),
        }
    }
    let error = last.unwrap_or_else(|| io::Error::other("no MASQUE dial address"));
    Err(anyhow::Error::new(error).context("MASQUE transport dial failed"))
}

/// One MASQUE extended-CONNECT tunnel bound to the client that owns its
/// HTTP/2 connection.
///
/// Unlike the gRPC transport — where the `Tunnel` returned by
/// `grpc::Client::open` retains the connection driver itself, letting the
/// short-lived `Client` handle drop after `connect_resolved` —
/// `masque::H2Stream` does not hold the driver: only
/// [masque::MasqueClient] keeps it, and its `Driver` aborts the h2
/// connection task when the last client drops (the component's own tests
/// hold the client beside the stream for exactly this reason). The stream
/// this arm returns must outlive `connect_resolved`'s stack frame, so the
/// wrapper carries the client alongside the stream. Dropping it resets the
/// CONNECT stream first (field declaration order: `stream` before
/// `_client`), then drops the client and aborts the driver task, tearing
/// the tunnel down without a panic or leak.
struct MasqueTunnel {
    stream: BoxStream,
    /// Dropped after `stream` so the h2 stream is reset before the
    /// connection driver aborts.
    _client: masque::MasqueClient,
}

impl AsyncRead for MasqueTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MasqueTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub struct Joined<R, W> {
    pub reader: R,
    pub writer: W,
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Joined<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Joined<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
