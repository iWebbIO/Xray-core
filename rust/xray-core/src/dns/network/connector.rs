//! Runtime routing and numeric-target admission for DNS exchanges.

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::{dns::encrypted::DialMode, protocol::freedom::FinalRules, transport::BoxStream};

pub type IoFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Logical identity is available only at routing time. The immutable candidates
/// are the complete numeric target set; routing must not resolve the host again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRequest {
    pub(super) server_index: usize,
    pub(super) host: String,
    pub(super) tag: String,
    pub(super) mode: DialMode,
    pub(super) network: Network,
    pub(super) candidates: Arc<[SocketAddr]>,
}

impl RouteRequest {
    pub fn server_index(&self) -> usize {
        self.server_index
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn tag(&self) -> &str {
        &self.tag
    }
    pub fn mode(&self) -> DialMode {
        self.mode
    }
    pub fn network(&self) -> Network {
        self.network
    }
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    Local,
    Freedom,
    Proxy,
}

/// A checked outbound plan bound to its original numeric DNS targets.
///
/// Transport methods receive no hostname: TLS identity and HTTP authority stay
/// in EncryptedClient. `route_id` identifies the runtime's selected outbound plan.
#[derive(Clone, Debug)]
pub struct CheckedRoute {
    request: RouteRequest,
    route_id: String,
    admission: Admission,
}

impl CheckedRoute {
    /// Apply the selected Freedom outbound's rules to every pinned DNS target,
    /// with the correct TCP/UDP network and source inbound protocol. A denied
    /// candidate rejects the entire plan; no unchecked alternative survives.
    pub async fn admit_freedom(
        request: RouteRequest,
        route_id: String,
        rules: &FinalRules,
        inbound_protocol: &str,
        cancel: &CancellationToken,
    ) -> io::Result<Self> {
        require_routed(&request)?;
        if let Some(delay) = request.candidates.iter().find_map(|target| {
            rules.block_delay(
                inbound_protocol,
                request.network.as_str(),
                target.ip(),
                target.port(),
            )
        }) {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(cancelled()),
                _ = tokio::time::sleep(delay) => {}
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS target denied by Freedom final rules",
            ));
        }
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        Ok(Self {
            request,
            route_id,
            admission: Admission::Freedom,
        })
    }

    /// Bind a non-Freedom proxy outbound to the pinned DNS targets. The runtime
    /// must separately admit and pin its proxy-hop endpoint before returning a
    /// stream/datagram. Freedom target rules do not apply to DNS targets carried
    /// through another outbound. Unsupported proxy transports must return errors.
    pub fn for_proxy(request: RouteRequest, route_id: String) -> io::Result<Self> {
        require_routed(&request)?;
        Ok(Self {
            request,
            route_id,
            admission: Admission::Proxy,
        })
    }

    pub fn route_id(&self) -> &str {
        &self.route_id
    }
    pub fn network(&self) -> Network {
        self.request.network
    }
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.request.candidates
    }
    pub fn is_local(&self) -> bool {
        self.admission == Admission::Local
    }
    pub fn is_freedom(&self) -> bool {
        self.admission == Admission::Freedom
    }

    pub(super) fn matches(&self, request: &RouteRequest) -> bool {
        &self.request == request
    }
}

fn require_routed(request: &RouteRequest) -> io::Result<()> {
    if request.mode != DialMode::Routed || request.candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a routed DNS request with numeric targets",
        ));
    }
    Ok(())
}

pub(super) fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "DNS query cancelled")
}

/// A connected, peer-restricted datagram transport. Implementations must not
/// accept packets from any peer other than the numeric target they connected.
pub trait Datagram: Send + Sync {
    fn send<'a>(&'a self, bytes: &'a [u8]) -> IoFuture<'a, usize>;
    fn recv<'a>(&'a self, bytes: &'a mut [u8]) -> IoFuture<'a, usize>;
}

impl Datagram for UdpSocket {
    fn send<'a>(&'a self, bytes: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(UdpSocket::send(self, bytes))
    }
    fn recv<'a>(&'a self, bytes: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(UdpSocket::recv(self, bytes))
    }
}

/// Injected runtime bridge. Implementations select an outbound during `route`,
/// and dial only `CheckedRoute::candidates` during transport connection.
/// Connections and route operations must release resources when dropped.
pub trait Connector: Send + Sync {
    fn route<'a>(
        &'a self,
        request: RouteRequest,
        cancel: &'a CancellationToken,
    ) -> IoFuture<'a, CheckedRoute>;
    fn connect_tcp<'a>(&'a self, route: &'a CheckedRoute) -> IoFuture<'a, BoxStream>;
    fn connect_udp<'a>(&'a self, route: &'a CheckedRoute) -> IoFuture<'a, Box<dyn Datagram>>;
}

/// Explicit source `+local` transport. It never accepts routed endpoints and
/// never inherits unrelated Freedom outbound rules.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalConnector;

impl Connector for LocalConnector {
    fn route<'a>(
        &'a self,
        request: RouteRequest,
        cancel: &'a CancellationToken,
    ) -> IoFuture<'a, CheckedRoute> {
        Box::pin(async move {
            if cancel.is_cancelled() {
                return Err(cancelled());
            }
            if request.mode != DialMode::Local || request.candidates.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "routed DNS requires a runtime connector",
                ));
            }
            Ok(CheckedRoute {
                request,
                route_id: String::new(),
                admission: Admission::Local,
            })
        })
    }

    fn connect_tcp<'a>(&'a self, route: &'a CheckedRoute) -> IoFuture<'a, BoxStream> {
        Box::pin(async move {
            require_local(route, Network::Tcp)?;
            let mut last_error = None;
            for target in route.candidates() {
                match TcpStream::connect(*target).await {
                    Ok(stream) => return Ok(Box::new(stream) as BoxStream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no DNS targets")))
        })
    }

    fn connect_udp<'a>(&'a self, route: &'a CheckedRoute) -> IoFuture<'a, Box<dyn Datagram>> {
        Box::pin(async move {
            require_local(route, Network::Udp)?;
            let mut last_error = None;
            for target in route.candidates() {
                let bind = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let result = async {
                    let socket = UdpSocket::bind(bind).await?;
                    socket.connect(*target).await?;
                    Ok::<_, io::Error>(socket)
                }
                .await;
                match result {
                    Ok(socket) => return Ok(Box::new(socket) as Box<dyn Datagram>),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no DNS targets")))
        })
    }
}

fn require_local(route: &CheckedRoute, network: Network) -> io::Result<()> {
    if !route.is_local() || route.network() != network {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid local DNS transport plan",
        ));
    }
    Ok(())
}
