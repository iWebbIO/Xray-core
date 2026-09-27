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
}

impl InboundListener {
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),
            Self::Kcp(listener) => Ok(listener.local_addr()),
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
        }
    }

    pub async fn close(self) -> io::Result<()> {
        match self {
            Self::Tcp(_) => Ok(()),
            Self::Kcp(listener) => listener.close().await,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct InboundTransport {
    pub tls: Option<tls::TlsServer>,
    pub xhttp: Option<xhttp::Server>,
    pub websocket: Option<websocket::Config>,
    pub httpupgrade: Option<httpupgrade::HttpUpgradeConfig>,
    pub grpc: Option<grpc::Config>,
    pub kcp: Option<kcp::Config>,
}

impl InboundTransport {
    pub async fn bind(&self, address: std::net::SocketAddr) -> io::Result<InboundListener> {
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

    pub async fn accept(&self, mut stream: BoxStream) -> anyhow::Result<AcceptedTransport> {
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

#[derive(Clone, Default)]
pub(crate) struct OutboundTransport {
    pub tls: Option<tls::TlsClient>,
    pub reality: Option<reality::handshake::ClientConfig>,
    pub server_name: String,
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
