// P30 wireguard_inbound: agent-owned runtime file; stub created for the parallel batch.
#![allow(dead_code)]
//! The WireGuard inbound runtime (Go's proxy/wireguard/server.go): Xray runs
//! the WireGuard engine in server role on the inbound's UDP endpoint, peers
//! connect to it, and every decrypted peer session is terminated through the
//! userspace netstack and dispatched through the runtime dispatcher.
//!
//! Composition (batch components, never edited here):
//! * `protocol::wireguard` — the Noise engine (`WireGuardDevice`) in server
//!   role: the inbound's `peers` entries are Go's `users` (infra/conf/
//!   wireguard.go's server branch), their allowed-IPs are both the cryptokey
//!   routes and the `GetUserByAddr` accounting table.
//! * `protocol::wireguard_netstack` — `Netstack` (userspace TCP/IP
//!   termination) and `WgUdpSocket` (the endpoint's UDP transport).
//!
//! Go's `createForwarder` puts the gVisor stack in promiscuous+spoofing mode
//! and installs a TCP forwarder accepting a connection to ANY destination
//! address and port; the accepted endpoint's local address is the peer's
//! original requested destination (`tcp.ForwarderRequest.ID()`). The
//! netstack exposes per-port listeners whose unspecified bind matches every
//! destination address and family (smoltcp's listen endpoint with no address
//! accepts any destination IP), so this engine peeks the TCP SYNs of
//! decrypted packets and bootstraps a catch-all listener for each new
//! destination port before the packet enters the stack — the listen is
//! confirmed before the SYN is written, so no connection is lost to a race.
//! The accepted stream's local endpoint is then the original destination.
//!
//! UDP parity is `tun.go`'s `udpManager`: one session per peer source
//! (a 1024-deep queue that drops on overflow like the wire), each datagram
//! dispatched through the runtime's UDP dispatcher, replies written back
//! through the stack with the session's first destination as the source
//! address (Go's `writeRawUDPPacket(payload, dst, c.src)` fallback).
//!
//! INTEGRATION CONTRACT (fixed): `compile_inbound` compiles the settings
//! JSON (infra/conf/wireguard.go exact keys, Role::Server) into a
//! serve-ready entry; `serve` runs the endpoint until the cancellation
//! token fires. The dispatcher handoff is the hysteria seam pattern: TCP
//! sessions through `super::dispatch_request`, UDP datagrams through
//! `dispatcher.udp`.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use tokio_util::sync::CancellationToken;

use super::{Dispatcher, sniffing::SniffingRequest};
use crate::{
    config::Inbound,
    protocol::wireguard::{DeviceConfig, PeerConfig, Role, WireGuardConfig},
};

#[cfg(feature = "native-tun")]
use super::{accounting::CountedStream, udp, udp::DispatchAction};
#[cfg(feature = "native-tun")]
use crate::{
    address::Destination,
    protocol::{
        self,
        wireguard::{PacketAction, WireGuardDevice},
        wireguard_netstack::{NetTcpListener, NetTcpStream, Netstack, WgUdpSocket, WgUdpTransport},
    },
};
#[cfg(not(feature = "native-tun"))]
use anyhow::bail;
#[cfg(feature = "native-tun")]
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::Mutex as StdMutex,
    time::Instant,
};
#[cfg(feature = "native-tun")]
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};

/// Go's `udpManager` queue depth (`make(chan *packet, 1024)`): a full queue
/// drops the datagram like a congested network device.
const UDP_SOURCE_QUEUE: usize = 1024;
/// Reply funnel depth back into the engine (hysteria's session queue shape).
const UDP_REPLY_QUEUE: usize = 64;
/// The engine's timer cadence (`device.Device` polls roughly every 250ms).
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Compile the proxy/wireguard inbound settings JSON (infra/conf/wireguard.go
/// exact keys and validation; Role::Server) into the serve-ready entry.
pub fn compile_inbound(settings: &serde_json::Value) -> Result<WireguardInbound> {
    let raw: WireGuardConfig =
        serde_json::from_value(settings.clone()).context("WireGuard inbound settings")?;
    let config = raw
        .build(Role::Server)
        .context("WireGuard inbound settings")?;
    #[cfg(feature = "native-tun")]
    {
        // Engine-level constraints (Go's device.IpcSet in Start): a peer using
        // the server's own public key, duplicates, and low-order keys fail at
        // config time so a rejected configuration never reaches `serve`.
        WireGuardDevice::new(config.clone()).context("WireGuard inbound settings")?;
    }
    Ok(WireguardInbound {
        settings: raw,
        config,
        bind: None,
    })
}

/// One serve-ready WireGuard inbound: the raw settings (mirroring
/// `Outbound::Wireguard`'s retained settings), the compiled server-role
/// device configuration, and the endpoint's UDP listen address set with
/// [`Self::listen_on`]. Clone serves an inbound's port range: each port
/// gets its own listen address and `serve` task over the same settings.
#[derive(Clone)]
pub struct WireguardInbound {
    settings: WireGuardConfig,
    config: DeviceConfig,
    /// Go's `Server.Start` binds `&net.UDPAddr{IP: src.Address.IP(), Port:
    /// src.Port}`; the runtime sets this from the inbound's listen address.
    bind: Option<SocketAddr>,
}

/// Redacted like the settings value: strings may carry private key material.
impl std::fmt::Debug for WireguardInbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireguardInbound")
            .field("config", &self.config)
            .field("bind", &self.bind)
            .finish_non_exhaustive()
    }
}

impl WireguardInbound {
    /// Set the UDP endpoint address (Go's `internet.ListenSystemPacket`
    /// bind in `Server.Start`). The integrator calls this with
    /// `SocketAddr::new(raw.listen, port)` per bound port before `serve`.
    pub fn listen_on(mut self, address: SocketAddr) -> Self {
        self.bind = Some(address);
        self
    }

    /// INTEGRATION POINT: the `config::Inbound` value every dispatched
    /// session rides. Go's `session.Inbound` is `{Name: "wireguard", Tag,
    /// Source, User}`; `dispatch_common` maps the variant to the freedom
    /// `origin` name, and proxy/freedom/freedom.go:167 treats "wireguard"
    /// exactly like the other proxy inbounds. The frozen `Inbound` enum has
    /// no Wireguard arm yet — the integrator must add
    /// `Inbound::Wireguard { settings: crate::protocol::wireguard::
    /// WireGuardConfig }` (plus `Inbound::Wireguard { .. } => "wireguard"`
    /// in dispatch_common's freedom name match) and swap this body. Until
    /// then the hysteria arm is the interim carrier: "hysteria" and
    /// "wireguard" share every freedom admit path (both `needs_check` and
    /// `private_default` select them in protocol/freedom.rs, mirroring
    /// freedom.go:167).
    fn dispatch_inbound(&self) -> Inbound {
        Inbound::Wireguard {
            entry: self.clone(),
        }
    }

    /// Go's `GetUserByAddr`: the first user whose allowed IPs contain the
    /// peer's tunnel address (the engine's inner-source check already
    /// guarantees the address belongs to the authenticated peer).
    fn user_by_addr(&self, address: IpAddr) -> Option<PeerUser> {
        user_by_addr(&self.config.peers, address)
    }
}

/// One inbound user (Go's `MemoryUser` view of a `PeerConfig`).
#[derive(Debug, Clone)]
struct PeerUser {
    #[allow(dead_code)]
    pub_key: [u8; 32],
    #[allow(dead_code)]
    allowed_ips: Vec<IpNet>,
    level: u32,
    email: String,
}

fn user_by_addr(peers: &[PeerConfig], address: IpAddr) -> Option<PeerUser> {
    peers
        .iter()
        .find(|peer| peer.allowed_ips.iter().any(|net| net.contains(&address)))
        .map(|peer| PeerUser {
            pub_key: peer.public_key,
            allowed_ips: peer.allowed_ips.clone(),
            level: peer.level,
            email: peer.email.clone(),
        })
}

/// Serve the inbound: run the WireGuard engine in server role on its
/// endpoint, terminate peer sessions through the netstack, and dispatch
/// every TCP session / UDP flow through the runtime dispatcher until the
/// cancellation token fires. Must return promptly on cancel.
#[allow(private_interfaces)] // the Dispatcher type stays runtime-private
pub async fn serve(
    entry: WireguardInbound,
    dispatcher: Arc<Dispatcher>,
    tag: Arc<str>,
    sniff: Option<Arc<SniffingRequest>>,
    cancel: CancellationToken,
) -> Result<()> {
    #[cfg(not(feature = "native-tun"))]
    {
        let _ = (entry, dispatcher, tag, sniff, cancel);
        bail!(
            "the WireGuard inbound requires the native-tun build feature; \
             rebuild with the default feature set"
        );
    }
    #[cfg(feature = "native-tun")]
    {
        // Go's dispatcher session policy governs the UDP source lifetime
        // (the dispatcher closes the udpConn when its session idles out).
        let idle = dispatcher.policy.for_level(0).timeouts.connection_idle;
        let engine = bind_engine(entry).await?;
        let bound = engine.bound;
        let inbound = engine.dispatch_inbound.clone();
        let seam: Arc<dyn WgSessionDispatch> = Arc::new(RuntimeSeam {
            dispatcher,
            inbound,
            tag,
            bound,
            cancel: cancel.clone(),
            sniff,
        });
        serve_engine(engine, seam, idle, cancel).await
    }
}

// ---------------------------------------------------------------------------
// The engine (native-tun): Go's Server.Start plus the pump halves of
// WgNet::run. The shared WgNet adapter feeds decrypted Tunnel packets
// straight into the netstack; the server must bootstrap catch-all listeners
// on first sight of a destination port first, so the pumps are driven here
// over the same public primitives.
// ---------------------------------------------------------------------------

/// The per-session handoff into the dispatcher (hysteria's
/// `HysteriaDispatch` shape): one TCP stream session, one UDP source
/// session with its packet queue and reply funnel.
#[cfg(feature = "native-tun")]
trait WgSessionDispatch: Send + Sync + 'static {
    fn dispatch_stream(&self, session: StreamSession) -> WgDispatchFuture;
    fn dispatch_udp(&self, session: UdpSession) -> WgDispatchFuture;
}

#[cfg(feature = "native-tun")]
type WgDispatchFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

/// One terminated TCP session (Go's `HandleConnection(conn, dest)`).
#[cfg(feature = "native-tun")]
struct StreamSession {
    stream: NetTcpStream,
    /// The peer's tunnel address (Go's `conn.RemoteAddr()`).
    source: SocketAddr,
    /// The peer's original requested destination (the accepted stream's
    /// local endpoint inside the netstack, Go's forwarder `id.Local*`).
    #[allow(dead_code)]
    destination: Destination,
    level: u32,
    email: String,
}

/// One UDP source session (Go's `udpConn` fed by `udpManager.feed`).
#[cfg(feature = "native-tun")]
struct UdpSession {
    /// The peer's tunnel address (the manager's map key).
    #[allow(dead_code)]
    source: SocketAddr,
    /// The session's first destination (Go's `uc.dst`; the engine uses it as
    /// the reply source address, like `writeRawUDPPacket`'s fallback).
    #[allow(dead_code)]
    destination: Destination,
    /// The session user's email (Go's `session.Inbound.User`).
    #[allow(dead_code)]
    email: String,
    /// Inbound datagrams; closing ends the session (Go's queue channel).
    packets: mpsc::Receiver<(Destination, Vec<u8>)>,
    /// Reply payloads funneled home; the engine writes them through the
    /// netstack back to the peer.
    replies: mpsc::Sender<Vec<u8>>,
}

/// The bound engine: the endpoint's UDP transport, the packet engine, the
/// netstack, the users table and the endpoint address.
#[cfg(feature = "native-tun")]
struct Engine {
    transport: WgUdpSocket,
    device: StdMutex<WireGuardDevice>,
    netstack: Netstack,
    peers: Arc<Vec<PeerConfig>>,
    dispatch_inbound: Inbound,
    bound: SocketAddr,
}

/// Bind the endpoint and build the engine (Go's NewServer + Start minus the
/// forwarder, which the serve loop installs on demand).
#[cfg(feature = "native-tun")]
async fn bind_engine(entry: WireguardInbound) -> Result<Engine> {
    let bind = entry.bind.context(
        "the WireGuard inbound requires the listen address; \
         set it with listen_on before serve",
    )?;
    let transport = WgUdpSocket::bind(bind)
        .with_context(|| format!("bind the WireGuard inbound UDP socket on {bind}"))?;
    let bound = transport.local_addr()?;
    let mtu = entry.config.mtu;
    let dispatch_inbound = entry.dispatch_inbound();
    let peers = Arc::new(entry.config.peers.clone());
    let device = WireGuardDevice::new(entry.config).context("build the WireGuard engine")?;
    Ok(Engine {
        transport,
        device: StdMutex::new(device),
        netstack: Netstack::new(mtu)?,
        peers,
        dispatch_inbound,
        bound,
    })
}

/// Run the engine until the cancellation fires or a pump fails: the
/// endpoint's datagram pump, the netstack's outbound IP pump, the UDP
/// datagram pump, and the engine timers (WgNet::run's three arms plus the
/// UDP session manager and listener maintenance).
#[cfg(feature = "native-tun")]
async fn serve_engine(
    engine: Engine,
    seam: Arc<dyn WgSessionDispatch>,
    idle: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let Engine {
        transport,
        device,
        netstack,
        peers,
        ..
    } = engine;
    let mut buffer = vec![0u8; netstack.mtu()];
    // Go's forwarder listeners, bootstrapped per destination port.
    let mut listeners: HashSet<u16> = HashSet::new();
    // Go's udpManager map, keyed by the peer's tunnel source address.
    let mut sources: HashMap<SocketAddr, UdpSource> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut timers = interval(TIMER_TICK);
    timers.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut maintenance = maintenance_interval(idle);

    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            datagram = transport.recv_datagram() => {
                let (source, datagram) = match datagram {
                    Ok(received) => received,
                    Err(error) => break Err(anyhow::Error::new(error)
                        .context("WireGuard inbound endpoint receive failed")),
                };
                let actions = {
                    let mut guard = lock_device(&device);
                    guard.decapsulate(source, &datagram)
                };
                match actions {
                    Ok(actions) => {
                        if let Err(error) = deliver_actions(
                            &transport, &netstack, &peers, &seam, &cancel,
                            &mut listeners, &mut tasks, actions,
                        ).await {
                            break Err(error);
                        }
                    }
                    Err(error) => {
                        // Rejected datagrams never reach the stack; the
                        // endpoint stays up for the other peers.
                        tracing::debug!(%error, "WireGuard inbound datagram rejected");
                    }
                }
            }
            read = netstack.read_ip(&mut buffer) => {
                let count = match read {
                    Ok(count) => count,
                    Err(error) => break Err(anyhow::Error::new(error)
                        .context("WireGuard netstack egress failed")),
                };
                let actions = {
                    let mut guard = lock_device(&device);
                    guard.encapsulate(&buffer[..count])
                };
                match actions {
                    Ok(actions) => {
                        if let Err(error) = deliver_actions(
                            &transport, &netstack, &peers, &seam, &cancel,
                            &mut listeners, &mut tasks, actions,
                        ).await {
                            break Err(error);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "WireGuard outbound packet rejected");
                    }
                }
            }
            datagram = netstack.udp_recv() => {
                let received = match datagram {
                    Ok(received) => received,
                    Err(error) => break Err(anyhow::Error::new(error)
                        .context("WireGuard netstack UDP receive failed")),
                };
                feed_udp_source(
                    &peers, &netstack, &mut sources, &mut tasks, &seam, &cancel,
                    received.source, received.destination, received.payload,
                );
            }
            _ = timers.tick() => {
                let events = {
                    let mut guard = lock_device(&device);
                    guard.update_timers()
                };
                for (peer, error) in events.errors {
                    tracing::warn!(peer, %error, "WireGuard timer error");
                }
                if let Err(error) = deliver_actions(
                    &transport, &netstack, &peers, &seam, &cancel,
                    &mut listeners, &mut tasks, events.actions,
                ).await {
                    break Err(error);
                }
            }
            _ = maintenance.tick() => {
                prune_sources(&mut sources, idle);
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "WireGuard inbound session task ended");
                }
            }
        }
    };
    // Dropping the JoinSet aborts every listener, session and connection
    // task; the dropped transport closes the endpoint socket.
    result
}

/// Maintenance cadence for the UDP source table: a quarter of the idle
/// timeout, clamped into a 1s..30s window.
#[cfg(feature = "native-tun")]
fn maintenance_interval(idle: Duration) -> tokio::time::Interval {
    let step = (idle / 4).clamp(Duration::from_secs(1), Duration::from_secs(30));
    let mut timer = interval(step);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer
}

#[cfg(feature = "native-tun")]
fn lock_device(device: &StdMutex<WireGuardDevice>) -> std::sync::MutexGuard<'_, WireGuardDevice> {
    device
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Deliver engine actions: encrypted datagrams go to their endpoint;
/// decrypted packets enter the netstack — after a fresh SYN bootstrapped the
/// catch-all listener for its destination port (Go's forwarder accepts any
/// destination; see the module docs).
#[cfg(feature = "native-tun")]
#[allow(clippy::too_many_arguments)]
async fn deliver_actions(
    transport: &WgUdpSocket,
    netstack: &Netstack,
    peers: &Arc<Vec<PeerConfig>>,
    seam: &Arc<dyn WgSessionDispatch>,
    cancel: &CancellationToken,
    listeners: &mut HashSet<u16>,
    tasks: &mut JoinSet<()>,
    actions: Vec<PacketAction>,
) -> Result<()> {
    for action in actions {
        match action {
            PacketAction::Network {
                endpoint, packet, ..
            } => {
                transport
                    .send_datagram(endpoint, &packet)
                    .await
                    .context("WireGuard inbound endpoint send failed")?;
            }
            PacketAction::Tunnel { packet, .. } => {
                if let Some(port) = syn_destination_port(&packet)
                    && listeners.insert(port)
                {
                    bootstrap_listener(netstack, peers, seam, cancel, tasks, port).await?;
                }
                match netstack.write_ip(&packet) {
                    Ok(()) => (),
                    // A congested stack drops like a network device (Go's
                    // bounded channel queues behave the same).
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tracing::debug!("WireGuard netstack dropped a packet: ingress full");
                    }
                    Err(error) => {
                        return Err(
                            anyhow::Error::new(error).context("WireGuard netstack ingress failed")
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Bootstrapped catch-all bind: the unspecified address makes the smoltcp
/// listener match every destination address and family on this port — Go's
/// promiscuous forwarder behavior.
#[cfg(feature = "native-tun")]
fn catch_all_bind(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
}

/// Install the per-port catch-all listener and its accept loop (one
/// confirmed `listen_tcp` before the SYN enters the stack: the runner
/// applies commands before polling ingress, so the connection is never
/// lost to a race).
#[cfg(feature = "native-tun")]
async fn bootstrap_listener(
    netstack: &Netstack,
    peers: &Arc<Vec<PeerConfig>>,
    seam: &Arc<dyn WgSessionDispatch>,
    cancel: &CancellationToken,
    tasks: &mut JoinSet<()>,
    port: u16,
) -> Result<()> {
    let listener = netstack
        .listen_tcp(catch_all_bind(port))
        .await
        .with_context(|| format!("listen for WireGuard sessions on port {port}"))?;
    let peers = Arc::clone(peers);
    let seam = Arc::clone(seam);
    let cancel = cancel.clone();
    tasks.spawn(async move {
        accept_loop(listener, peers, seam, cancel).await;
    });
    Ok(())
}

/// Go's forwarder request handler loop: every accepted connection is
/// `HandleConnection` (user lookup by the peer's tunnel address, then the
/// dispatcher handoff). The listener itself lives for the engine's lifetime
/// and respawns per accepted connection inside the netstack, like Go's
/// single forwarder.
#[cfg(feature = "native-tun")]
async fn accept_loop(
    mut listener: NetTcpListener,
    peers: Arc<Vec<PeerConfig>>,
    seam: Arc<dyn WgSessionDispatch>,
    cancel: CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, remote) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::debug!(%error, "WireGuard session listener ended");
                        break;
                    }
                };
                let seam = Arc::clone(&seam);
                let peers = Arc::clone(&peers);
                connections.spawn(handle_connection(stream, remote, peers, seam));
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                let _ = completed;
            }
        }
    }
    // Aborts every in-flight session task with the loop's exit.
}

/// Go's `Server.HandleConnection`: a nil user (no allowed-IP match for the
/// peer's tunnel address) closes the session with an error log; otherwise
/// the stream is dispatched with the user's email and level and the stream's
/// original destination.
#[cfg(feature = "native-tun")]
async fn handle_connection(
    stream: NetTcpStream,
    remote: SocketAddr,
    peers: Arc<Vec<PeerConfig>>,
    seam: Arc<dyn WgSessionDispatch>,
) {
    let Some(user) = user_by_addr(&peers, remote.ip()) else {
        tracing::warn!(from = %remote, "WireGuard session from an address no user owns");
        return;
    };
    let session = StreamSession {
        destination: Destination::from(stream.local_addr()),
        stream,
        source: remote,
        level: user.level,
        email: user.email,
    };
    if let Err(error) = seam.dispatch_stream(session).await {
        tracing::debug!(%error, "WireGuard session dispatch ended");
    }
}

/// One UDP source's engine bookkeeping: the session queue and its activity.
#[cfg(feature = "native-tun")]
struct UdpSource {
    packets: mpsc::Sender<(Destination, Vec<u8>)>,
    last_seen: Instant,
}

/// Go's `udpManager.feed`: route one decrypted datagram to its source's
/// session, opening a session (Go's `go handler(uc, dst)`) on first sight
/// and dropping on a full queue.
#[cfg(feature = "native-tun")]
#[allow(clippy::too_many_arguments)]
fn feed_udp_source(
    peers: &Arc<Vec<PeerConfig>>,
    netstack: &Netstack,
    sources: &mut HashMap<SocketAddr, UdpSource>,
    tasks: &mut JoinSet<()>,
    seam: &Arc<dyn WgSessionDispatch>,
    cancel: &CancellationToken,
    source: SocketAddr,
    destination: SocketAddr,
    payload: Vec<u8>,
) {
    let Some(user) = user_by_addr(peers, source.ip()) else {
        tracing::warn!(from = %source, to = %destination, "WireGuard UDP from an address no user owns");
        return;
    };
    // Go's `uc.dst`: the reply is written with the session's first
    // destination as its source address.
    let reply_from = destination;
    let destination = Destination::from(destination);
    let entry = if let Some(entry) = sources.get_mut(&source) {
        entry.last_seen = Instant::now();
        entry
    } else {
        let (packets_tx, packets_rx) = mpsc::channel(UDP_SOURCE_QUEUE);
        let (replies_tx, replies_rx) = mpsc::channel(UDP_REPLY_QUEUE);
        let session = UdpSession {
            source,
            destination: destination.clone(),
            email: user.email.clone(),
            packets: packets_rx,
            replies: replies_tx,
        };
        let netstack = netstack.clone();
        let cancel = cancel.clone();
        tasks.spawn(udp_source_pump(
            seam.dispatch_udp(session),
            replies_rx,
            netstack,
            source,
            reply_from,
            cancel,
        ));
        sources.insert(
            source,
            UdpSource {
                packets: packets_tx,
                last_seen: Instant::now(),
            },
        );
        sources.get_mut(&source).expect("inserted above")
    };
    if entry.packets.try_send((destination, payload)).is_err() {
        // Go: "drop udp ... queue full".
        tracing::debug!(from = %source, "WireGuard UDP dropped: session queue full");
    }
}

/// The engine half of one UDP source session: pump the dispatcher session
/// and write every reply through the netstack back to the peer, with the
/// session's first destination as the reply source (Go's
/// `writeRawUDPPacket(payload, dst, c.src)` fallback).
#[cfg(feature = "native-tun")]
async fn udp_source_pump(
    session: WgDispatchFuture,
    mut replies: mpsc::Receiver<Vec<u8>>,
    netstack: Netstack,
    source: SocketAddr,
    reply_from: SocketAddr,
    cancel: CancellationToken,
) {
    tokio::pin!(session);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = session.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!(%error, "WireGuard UDP session dispatch ended");
                }
                return;
            }
            reply = replies.recv() => {
                let Some(reply) = reply else { continue };
                if let Err(error) = netstack.udp_send(reply_from, source, &reply).await {
                    tracing::debug!(%error, "WireGuard UDP reply write failed");
                }
            }
        }
    }
}

/// Go's dispatcher closes the udpConn when the session idles out; the engine
/// drops the queue so the dispatch session ends the same way.
#[cfg(feature = "native-tun")]
fn prune_sources(sources: &mut HashMap<SocketAddr, UdpSource>, idle: Duration) {
    let now = Instant::now();
    sources.retain(|_, source| now.saturating_duration_since(source.last_seen) < idle);
}

/// The destination port of a fresh TCP SYN (SYN set, ACK clear — the only
/// segment a listening socket accepts), or None for anything else. Go's
/// forwarder intercepts exactly these connection initiations.
#[cfg(feature = "native-tun")]
fn syn_destination_port(packet: &[u8]) -> Option<u16> {
    let (&version, _) = packet.split_first()?;
    let header_length = match version >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            if packet[9] != 6 {
                return None;
            }
            usize::from(packet[0] & 0x0f) * 4
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            if packet[6] != 6 {
                return None;
            }
            40
        }
        _ => return None,
    };
    if packet.len() < header_length + 14 {
        return None;
    }
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    let flags = packet[header_length + 13];
    if flags & SYN == 0 || flags & ACK != 0 {
        return None;
    }
    let port = u16::from_be_bytes([packet[header_length + 2], packet[header_length + 3]]);
    (port != 0).then_some(port)
}

// ---------------------------------------------------------------------------
// The runtime seam: the dispatcher handoff (hysteria_seam's RuntimeSeam over
// the WireGuard session shapes).
// ---------------------------------------------------------------------------

/// One connected relay socket toward an admitted UDP endpoint, with a pump
/// that returns remote replies to the session loop (hysteria_seam's
/// RelayPeer; the reply payload rides the session's funnel home).
#[cfg(feature = "native-tun")]
struct RelayPeer {
    socket: Arc<tokio::net::UdpSocket>,
    stop: CancellationToken,
}

#[cfg(feature = "native-tun")]
impl RelayPeer {
    fn new(replies: mpsc::Sender<Vec<u8>>, target: SocketAddr) -> Self {
        let family = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = std::net::UdpSocket::bind(family).expect("bind a WireGuard relay socket");
        socket
            .set_nonblocking(true)
            .expect("non-blocking WireGuard relay socket");
        let socket =
            Arc::new(tokio::net::UdpSocket::from_std(socket).expect("register relay socket"));
        let stop = CancellationToken::new();
        let pump_socket = Arc::clone(&socket);
        let pump_replies = replies;
        let pump_stop = stop.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = pump_stop.cancelled() => return,
                    received = tokio::time::timeout(
                        Duration::from_secs(300),
                        pump_socket.recv_from(&mut buffer),
                    ) => received,
                };
                match received {
                    Ok(Ok((size, _))) => {
                        if pump_replies.send(buffer[..size].to_vec()).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
            }
        });
        Self { socket, stop }
    }
}

#[cfg(feature = "native-tun")]
impl Drop for RelayPeer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// The runtime's dispatch seam over one WireGuard inbound: TCP sessions run
/// the standard post-handshake dispatch (`dispatch_request`), UDP source
/// sessions dispatch each datagram through the UDP routing dispatcher
/// exactly like the hysteria seam.
#[cfg(feature = "native-tun")]
struct RuntimeSeam {
    dispatcher: Arc<Dispatcher>,
    inbound: Inbound,
    tag: Arc<str>,
    bound: SocketAddr,
    cancel: CancellationToken,
    sniff: Option<Arc<SniffingRequest>>,
}

#[cfg(feature = "native-tun")]
impl WgSessionDispatch for RuntimeSeam {
    fn dispatch_stream(&self, session: StreamSession) -> WgDispatchFuture {
        let StreamSession {
            stream,
            source,
            destination,
            level,
            email,
        } = session;
        let dispatcher = Arc::clone(&self.dispatcher);
        let inbound = self.inbound.clone();
        let tag = Arc::clone(&self.tag);
        let bound = self.bound;
        let cancel = self.cancel.clone();
        let sniff = self.sniff.clone();
        Box::pin(async move {
            let request = protocol::Request {
                level,
                destination,
                user: email,
                initial_payload: Vec::new(),
                reply: protocol::Reply::None,
            };
            let stream = match &dispatcher.stats {
                Some(stats) => CountedStream::wrap(
                    Box::new(stream),
                    stats.inbound_counters(&tag, dispatcher.policy.for_system().stats),
                    true,
                ),
                None => Box::new(stream),
            };
            super::dispatch_request(
                stream,
                source,
                bound,
                &inbound,
                &tag,
                &dispatcher,
                &cancel,
                request,
                None,
                sniff,
            )
            .await
        })
    }

    fn dispatch_udp(&self, session: UdpSession) -> WgDispatchFuture {
        let UdpSession {
            source,
            email,
            packets,
            replies,
            ..
        } = session;
        let dispatcher = Arc::clone(&self.dispatcher);
        let tag = Arc::clone(&self.tag);
        Box::pin(async move {
            let udp = dispatcher
                .udp
                .as_ref()
                .context("WireGuard inbound UDP dispatcher unavailable")?
                .clone();
            let user_tag: Arc<str> = Arc::from(email);
            // The bounded reply queue and per-target relay peers mirror
            // hysteria_seam's session loop; the engine's idle pruning governs
            // the source session's lifetime inside the endpoint.
            let (relay_tx, mut relay_rx) = mpsc::channel::<Vec<u8>>(UDP_REPLY_QUEUE);
            let mut peers: HashMap<SocketAddr, RelayPeer> = HashMap::new();
            let mut xudp_pumps = JoinSet::new();
            let stop = CancellationToken::new();
            let mut packets = packets;
            let result = loop {
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => break Ok(()),
                    reply = relay_rx.recv() => {
                        let Some(reply) = reply else { continue };
                        tokio::select! {
                            _ = stop.cancelled() => break Ok(()),
                            sent = replies.send(reply) => {
                                if sent.is_err() {
                                    break Ok(());
                                }
                            }
                        }
                    }
                    completed = xudp_pumps.join_next(), if !xudp_pumps.is_empty() => {
                        if completed.is_some() {
                            // The lease closed; its replies already flowed.
                        }
                    }
                    packet = packets.recv() => {
                        let Some((destination, payload)) = packet else { break Ok(()) };
                        let action = udp
                            .dispatch(udp::DispatchContext {
                                destination: destination.clone(),
                                source,
                                inbound_tag: Arc::clone(&tag),
                                user: Arc::clone(&user_tag),
                                network: "udp",
                            })
                            .await;
                        let action = match action {
                            Ok(action) => action,
                            Err(error) => {
                                tracing::debug!(%error, "WireGuard UDP dispatch failed");
                                continue;
                            }
                        };
                        match action {
                            DispatchAction::Drop => continue,
                            DispatchAction::Direct(target)
                            | DispatchAction::TrackedDirect { target, .. } => {
                                if !udp::valid_endpoint(target) {
                                    continue;
                                }
                                let peer = peers
                                    .entry(target)
                                    .or_insert_with(|| RelayPeer::new(relay_tx.clone(), target));
                                let _ = peer.socket.send_to(&payload, target).await;
                            }
                            DispatchAction::Xudp { lease } => {
                                // One pump per lease feeds the session's
                                // replies; the packet rides the carrier.
                                let sender = replies.clone();
                                let pump_stop = stop.clone();
                                let pump_lease = std::sync::Arc::clone(&lease);
                                xudp_pumps.spawn(async move {
                                    loop {
                                        let reply = tokio::select! {
                                            biased;
                                            _ = pump_stop.cancelled() => return,
                                            reply = pump_lease.recv() => reply,
                                        };
                                        let Some((_target, payload)) = reply else { return };
                                        if sender.send(payload).await.is_err() {
                                            return;
                                        }
                                    }
                                });
                                let target = crate::mux::Target::from_destination(
                                    crate::mux::Network::Udp,
                                    &destination,
                                );
                                let _ = lease.send(target, &payload).await;
                            }
                        }
                    }
                }
            };
            stop.cancel();
            peers.clear();
            xudp_pumps.abort_all();
            result
        })
    }
}

// ---------------------------------------------------------------------------
// Tests: the Go fixtures from testing/scenarios/wireguard_test.go (pairing
// corrected like the netstack and outbound tests), an echo seam standing in
// for the dispatcher, and loopback engines on ephemeral ports.
// ---------------------------------------------------------------------------
#[cfg(all(test, feature = "native-tun"))]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::Mutex as AsyncMutex,
        task::JoinHandle,
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    use crate::protocol::wireguard::{Role, WireGuardConfig, WireGuardPeerConfig};
    use crate::protocol::wireguard_netstack::{WgNet, WgUdpSocket};

    use super::{WgSessionDispatch, bind_engine, compile_inbound, serve_engine};

    const SERVER_PRIVATE: &str = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=";
    const SERVER_PUBLIC: &str = "MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=";
    const CLIENT_PRIVATE: &str = "CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=";
    const CLIENT_PUBLIC: &str = "osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=";

    const WAIT: Duration = Duration::from_secs(5);

    fn tunnel_v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    /// The inbound settings JSON with infra/conf/wireguard.go's exact keys.
    fn settings_json(peers: Value) -> Value {
        json!({
            "secretKey": SERVER_PRIVATE,
            "address": ["10.0.0.1"],
            "mtu": 1420,
            "peers": peers,
        })
    }

    fn peer_json(public_key: &str) -> Value {
        json!({
            "publicKey": public_key,
            "preSharedKey": "",
            "keepAlive": 25,
            "allowedIPs": ["10.0.0.2/32"],
            "email": "wg-peer@example.test",
            "level": 2,
        })
    }

    /// The echo seam: every dispatched TCP session is echoed, every UDP
    /// datagram is echoed home, and the observed session metadata is
    /// recorded for the assertions (owned `Arc` state because the dispatch
    /// futures are boxed and `'static`, like the runtime seam's).
    #[derive(Default)]
    struct EchoSeam {
        #[allow(clippy::type_complexity)] // test wiring pair
        streams: std::sync::Arc<
            AsyncMutex<
                Vec<(
                    std::net::SocketAddr,
                    crate::address::Destination,
                    String,
                    u32,
                )>,
            >,
        >,
        datagrams: std::sync::Arc<
            AsyncMutex<Vec<(std::net::SocketAddr, crate::address::Destination, String)>>,
        >,
    }

    impl WgSessionDispatch for EchoSeam {
        fn dispatch_stream(&self, session: super::StreamSession) -> super::WgDispatchFuture {
            let seen = std::sync::Arc::clone(&self.streams);
            Box::pin(async move {
                seen.lock().await.push((
                    session.source,
                    session.destination.clone(),
                    session.email.clone(),
                    session.level,
                ));
                let (mut reader, mut writer) = tokio::io::split(session.stream);
                tokio::io::copy(&mut reader, &mut writer).await?;
                Ok(())
            })
        }

        fn dispatch_udp(&self, session: super::UdpSession) -> super::WgDispatchFuture {
            let seen = std::sync::Arc::clone(&self.datagrams);
            let mut packets = session.packets;
            let replies = session.replies;
            let source = session.source;
            let email = session.email;
            Box::pin(async move {
                while let Some((destination, payload)) = packets.recv().await {
                    seen.lock().await.push((source, destination, email.clone()));
                    replies.send(payload).await?;
                }
                Ok(())
            })
        }
    }

    /// Aborts a task on unwind or scope exit so no engine survives a test.
    struct AbortOnDrop<T>(JoinHandle<T>);

    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// A client-role engine (the existing engine in client role, exactly like
    /// the outbound tests use) over its own loopback UDP socket, pointed at
    /// the served endpoint. Returns the client netstack and its pump guard.
    async fn client_engine(
        endpoint: std::net::SocketAddr,
    ) -> anyhow::Result<(
        std::sync::Arc<WgNet<WgUdpSocket>>,
        AbortOnDrop<anyhow::Result<()>>,
    )> {
        let transport = WgUdpSocket::bind(std::net::SocketAddr::new(tunnel_v4(127, 0, 0, 1), 0))?;
        let client = std::sync::Arc::new(WgNet::new(
            WireGuardConfig {
                secret_key: CLIENT_PRIVATE.to_owned(),
                // Go's client scenario: the client's tunnel address is the
                // source the server's user allowed-IPs must authorize.
                address: Some(vec!["10.0.0.2".to_owned()]),
                peers: vec![WireGuardPeerConfig {
                    public_key: SERVER_PUBLIC.to_owned(),
                    endpoint: endpoint.to_string(),
                    allowed_ips: Some(vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()]),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .build(Role::Client)?,
            transport,
        )?);
        let runner = {
            let client = client.clone();
            AbortOnDrop(tokio::spawn(async move { client.run().await }))
        };
        Ok((client, runner))
    }

    async fn serve_echo(
        settings: Value,
    ) -> anyhow::Result<(
        std::net::SocketAddr,
        std::sync::Arc<EchoSeam>,
        AbortOnDrop<anyhow::Result<()>>,
        CancellationToken,
    )> {
        let entry = compile_inbound(&settings)?
            .listen_on(std::net::SocketAddr::new(tunnel_v4(127, 0, 0, 1), 0));
        let engine = bind_engine(entry).await?;
        let bound = engine.bound;
        let seam = std::sync::Arc::new(EchoSeam::default());
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let served = std::sync::Arc::clone(&seam);
        let task = AbortOnDrop(tokio::spawn(async move {
            serve_engine(engine, served, Duration::from_secs(300), stop).await
        }));
        Ok((bound, seam, task, cancel))
    }

    #[test]
    fn compile_inbound_ports_go_keys_and_defaults() {
        let entry = compile_inbound(&settings_json(json!([peer_json(CLIENT_PUBLIC)])))
            .expect("compile the fixture settings");
        let config = &entry.config;
        assert_eq!(config.role, Role::Server);
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.addresses, vec![tunnel_v4(10, 0, 0, 1)]);
        let peer = &config.peers[0];
        assert_eq!(peer.email, "wg-peer@example.test");
        assert_eq!(peer.level, 2);
        assert_eq!(peer.persistent_keepalive, Some(25));
        assert!(peer.preshared_key.is_none());
        assert_eq!(
            peer.allowed_ips,
            vec!["10.0.0.2/32".parse::<ipnet::IpNet>().unwrap()]
        );
        assert_eq!(peer.endpoint, None);
        // The user-by-address lookup follows the allowed IPs.
        let user = entry.user_by_addr(tunnel_v4(10, 0, 0, 2)).unwrap();
        assert_eq!(user.email, "wg-peer@example.test");
        assert_eq!(user.level, 2);
        assert!(entry.user_by_addr(tunnel_v4(10, 0, 0, 3)).is_none());
        // listen_on carries the endpoint bind.
        let entry = entry.listen_on("127.0.0.1:51820".parse().unwrap());
        assert_eq!(entry.bind, Some("127.0.0.1:51820".parse().unwrap()));

        // Defaults with an empty settings object: Go's bogon addresses, the
        // 1420 MTU, and the 0.0.0.0/0 + ::0/0 allowed-IP defaults. A server
        // with no users compiles (Go's NewServer has no peer requirement).
        let empty = compile_inbound(&json!({"secretKey": SERVER_PRIVATE})).unwrap();
        assert_eq!(
            empty.config.addresses,
            vec![
                tunnel_v4(10, 0, 0, 1),
                "fd59:7153:2388:b5fd::1".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(empty.config.mtu, 1420);
        assert!(empty.config.peers.is_empty());

        // A peer without allowedIPs gets Go's defaults; the server zeroes
        // the reserved marker regardless of the settings (Go's server bind
        // has no reserved marker).
        let entry = compile_inbound(&json!({
            "secretKey": SERVER_PRIVATE,
            "reserved": [1, 2, 3],
            "peers": [{"publicKey": CLIENT_PUBLIC}],
        }))
        .unwrap();
        // A peer without allowedIPs gets both of Go's default routes.
        assert_eq!(
            entry.config.peers[0].allowed_ips,
            vec![
                "0.0.0.0/0".parse::<ipnet::IpNet>().unwrap(),
                "::/0".parse::<ipnet::IpNet>().unwrap(),
            ]
        );
        assert_eq!(entry.config.reserved, [0; 3]);
    }

    #[test]
    fn compile_inbound_rejects_go_error_cases_with_named_errors() {
        // Secret key: empty and undecodable (Go: "key must not be empty",
        // "failed to deserialize key", wrapped as "invalid WireGuard secret key").
        for secret in ["", "not-a-key"] {
            let error = compile_inbound(&json!({ "secretKey": secret })).unwrap_err();
            assert!(
                format!("{error:#}").contains("key"),
                "unexpected error: {error:#}"
            );
        }
        // Reserved length (Go: `"reserved" should be empty or 3 bytes`).
        let error = compile_inbound(&json!({
            "secretKey": SERVER_PRIVATE,
            "reserved": [1, 2],
        }))
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("reserved"),
            "unexpected error: {error:#}"
        );
        // Allowed IP without a prefix (Go: netip.ParsePrefix).
        let error = compile_inbound(&settings_json(json!([{
            "publicKey": CLIENT_PUBLIC,
            "allowedIPs": ["10.0.0.1"],
        }])))
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("allowed IP"),
            "unexpected error: {error:#}"
        );
        // Peer key errors (Go: ParseKey on the account).
        let error = compile_inbound(&settings_json(json!([{"publicKey": ""}]))).unwrap_err();
        assert!(
            format!("{error:#}").contains("key must not be empty"),
            "unexpected error: {error:#}"
        );
        // Go's AddUser "invalid public key": a peer using the server's own
        // public key is rejected by the engine at compile time.
        let own_public = crate::protocol::wireguard::SecretKey::parse(SERVER_PRIVATE)
            .unwrap()
            .public_key();
        let mut peer = peer_json(CLIENT_PUBLIC);
        peer["publicKey"] = Value::String(STANDARD.encode(own_public));
        let error = compile_inbound(&settings_json(json!([peer]))).unwrap_err();
        assert!(
            format!("{error:#}").contains("local public key"),
            "unexpected error: {error:#}"
        );
        // Duplicate peer public keys (wireguard-go's IpcSet).
        let error = compile_inbound(&settings_json(json!([
            peer_json(CLIENT_PUBLIC),
            peer_json(CLIENT_PUBLIC),
        ])))
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("duplicate"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn serve_dispatches_tcp_sessions_end_to_end() {
        let (bound, seam, mut server, cancel) =
            serve_echo(settings_json(json!([peer_json(CLIENT_PUBLIC)])))
                .await
                .unwrap();
        let (client, mut runner) = client_engine(bound).await.unwrap();
        let work = async {
            // The destination is arbitrary (Go's forwarder accepts any
            // address): a TEST-NET-1 target proves the transparency.
            let remote = std::net::SocketAddr::new(tunnel_v4(192, 0, 2, 10), 4747);
            let local = std::net::SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_001);
            let mut stream = client.netstack().dial_tcp(local, remote).await?;
            let payload: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
            stream.write_all(&payload).await?;
            let mut echoed = vec![0u8; payload.len()];
            stream.read_exact(&mut echoed).await?;
            assert_eq!(echoed, payload);
            drop(stream);
            // The dispatch handoff saw the peer's tunnel source, the original
            // destination, and the user (Go's HandleConnection semantics).
            let streams = seam.streams.lock().await;
            assert_eq!(streams.len(), 1);
            let (source, destination, email, level) = &streams[0];
            assert_eq!(source.ip(), tunnel_v4(10, 0, 0, 2));
            assert_eq!(source.port(), 40_001);
            assert_eq!(destination, &crate::address::Destination::from(remote));
            assert_eq!(email, "wg-peer@example.test");
            assert_eq!(*level, 2);
            anyhow::Ok(())
        };
        timeout(WAIT, async {
            tokio::select! {
                result = &mut runner.0 => Err(anyhow::anyhow!("client pumps ended: {result:?}")),
                result = &mut server.0 => Err(anyhow::anyhow!("server pumps ended: {result:?}")),
                result = work => result,
            }
        })
        .await
        .expect("TCP echo test finished within the deadline")
        .unwrap();
        cancel.cancel();
    }

    #[tokio::test]
    async fn serve_dispatches_udp_sessions_end_to_end() {
        let (bound, seam, mut server, cancel) =
            serve_echo(settings_json(json!([peer_json(CLIENT_PUBLIC)])))
                .await
                .unwrap();
        let (client, mut runner) = client_engine(bound).await.unwrap();
        let work = async {
            let source = std::net::SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_002);
            let target = std::net::SocketAddr::new(tunnel_v4(192, 0, 2, 53), 53);
            client.netstack().udp_send(source, target, b"query").await?;
            let reply = client.netstack().udp_recv().await?;
            assert_eq!(reply.payload, b"query");
            // The reply appears to come from the queried destination
            // (Go's writeRawUDPPacket source).
            assert_eq!(reply.source, target);
            assert_eq!(reply.destination, source);
            let datagrams = seam.datagrams.lock().await;
            assert_eq!(datagrams.len(), 1);
            let (origin, destination, email) = &datagrams[0];
            assert_eq!(origin.ip(), tunnel_v4(10, 0, 0, 2));
            assert_eq!(destination, &crate::address::Destination::from(target));
            assert_eq!(email, "wg-peer@example.test");
            anyhow::Ok(())
        };
        timeout(WAIT, async {
            tokio::select! {
                result = &mut runner.0 => Err(anyhow::anyhow!("client pumps ended: {result:?}")),
                result = &mut server.0 => Err(anyhow::anyhow!("server pumps ended: {result:?}")),
                result = work => result,
            }
        })
        .await
        .expect("UDP echo test finished within the deadline")
        .unwrap();
        cancel.cancel();
    }

    #[tokio::test]
    async fn serve_returns_promptly_on_cancel() {
        let (bound, _seam, mut server, cancel) =
            serve_echo(settings_json(json!([peer_json(CLIENT_PUBLIC)])))
                .await
                .unwrap();
        let _ = bound;
        cancel.cancel();
        timeout(Duration::from_secs(1), &mut server.0)
            .await
            .expect("serve returns promptly on cancel")
            .expect("server task alive")
            .unwrap();
    }
}
