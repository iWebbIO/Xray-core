// P29 runtime/tun_inbound: the proxyman TUN inbound runtime (proxy/tun).
//
// Compiles the Go `infra/conf/tun.go` JSON surface into a serve-ready entry,
// then serves it: create the TUN device, run the ported userspace netstack
// (`protocol::tun::native`), and dispatch every TCP session and full-cone UDP
// flow through the runtime dispatcher exactly like Go's proxy/tun handler
// (handler.go HandleConnection over stack_gvisor.go with udp_fullcone.go's
// source-keyed NAT). ICMP echo requests are answered by the netstack layer
// for any destination (stack_gvisor_icmp_handler.go).
//
// Platform honesty: device creation goes through `tun-rs`, which needs the
// Wintun driver plus elevation on Windows and CAP_NET_ADMIN on Linux. The
// session plumbing (run_sessions/udp_flow over `run_packets`' packet
// channels) is device-independent and unit-tested without privileges.
#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context as _, Result, bail, ensure};
use rand::Rng;
use serde::Deserialize;

use super::{Dispatcher, sniffing::SniffingRequest};
use crate::{
    address::Destination,
    config::Inbound,
    protocol::tun::{TunConfig, route::IpPrefix},
};
use tokio_util::sync::CancellationToken;

/// `utun`, the prefix and index range of infra/conf/tun.go's generated names.
const TUN_NAME_PREFIX: &str = "utun";
const MIN_TUN_INDEX: u16 = 10;
const MAX_TUN_INDEX: u16 = 1024;
/// infra/conf/tun.go Build: a zero `mtu` becomes 1500.
const DEFAULT_MTU: u16 = 1500;
/// Go's per-udpConn egress queue capacity (udp_fullcone.go).
const FLOW_QUEUE: usize = 1024;

#[cfg(feature = "native-tun")]
use std::{collections::HashMap, io, sync::Mutex};

#[cfg(feature = "native-tun")]
use tokio::{net::UdpSocket, sync::mpsc};

#[cfg(feature = "native-tun")]
use super::{
    accounting::CountedStream,
    udp::{self, DispatchAction, DispatchContext, UdpDispatcher},
};

#[cfg(feature = "native-tun")]
use crate::{
    features::stats::TrafficCounters,
    protocol::{
        self,
        tun::{
            native,
            native::{TunEvent, UdpReplies},
            session::SessionKey,
        },
    },
    transport::BoxStream,
};

/// The `settings` object of a tun inbound — `infra/conf/tun.go`'s exact JSON
/// keys (camelCase is identity for every one of them) with Go's zero-value
/// defaults. Go's json decoder ignores unknown keys; the workspace convention
/// rejects them, so every rejection below names the offending key.
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct TunSettings {
    name: String,
    desc: String,
    /// Go's `uint32`; the native device takes a `u16` and the netstack a
    /// 1280 dual-stack floor, both enforced with named rejections.
    mtu: u64,
    gateway: Vec<String>,
    dns: Vec<String>,
    /// Go's `uint32`.
    user_level: u64,
    auto_system_routing_table: Vec<String>,
    /// Pointer semantics in Go: `null`/absent is "auto" when a routing table
    /// exists, `""` is disabled, any other value names the fixed interface.
    auto_outbounds_interface: Option<String>,
}

/// The compiled inbound: everything serve() needs (see the module contract).
#[derive(Clone)]
pub struct TunInbound {
    /// The validated device/netstack configuration.
    pub config: TunConfig,
    /// `userLevel`: the policy level of every session (Go's MemoryUser level
    /// and the stack's idle-timeout level).
    pub user_level: u32,
    /// The dispatch-seam inbound value. A stand-in until the integrator adds
    /// the `Inbound::Tun { entry }` variant — see `dispatch_inbound`'s note.
    pub inbound: Inbound,
}

/// Compile the proxy/tun inbound settings JSON (infra/conf/tun.go's exact
/// keys and validation) into the serve-ready runtime entry.
pub fn compile_inbound(settings: &serde_json::Value) -> anyhow::Result<TunInbound> {
    let raw: TunSettings =
        serde_json::from_value(settings.clone()).context("tun inbound settings")?;
    let user_level = u32::try_from(raw.user_level)
        .context("tun `userLevel` exceeds the uint32 range of Go's config")?;
    // infra/conf/tun.go Build: the empty name becomes a generated one and a
    // zero MTU becomes 1500.
    let name = if raw.name.is_empty() {
        available_tun_name()?
    } else {
        raw.name
    };
    let mtu = if raw.mtu == 0 {
        DEFAULT_MTU
    } else {
        u16::try_from(raw.mtu).context("tun `mtu` exceeds the 65535 device maximum")?
    };
    // The shared netstack is dual-stack; Go accepts any MTU its platforms
    // allow, so this floor is a named deviation rather than a silent pass.
    ensure!(
        mtu >= 1280,
        "tun `mtu` {mtu} is below the netstack's 1280 dual-stack minimum"
    );
    // Go validates none of these at Build time (its device Start panics on
    // malformed CIDRs via MustParsePrefix); the runtime rejects them up front
    // with the option named, never silently.
    ensure!(
        raw.desc.is_empty(),
        "tun `desc` (the interface description) is not implemented by the native adapter"
    );
    let mut gateway = Vec::with_capacity(raw.gateway.len());
    for cidr in &raw.gateway {
        let prefix: IpPrefix = cidr
            .parse()
            .with_context(|| format!("tun `gateway` entry {cidr:?} is not a CIDR address"))?;
        gateway.push(prefix);
    }
    ensure!(
        gateway
            .iter()
            .filter(|prefix| prefix.address().is_ipv4())
            .count()
            <= 1,
        "tun `gateway` lists more than one IPv4 interface address; the native adapter supports one"
    );
    ensure!(
        raw.dns.is_empty(),
        "tun `dns` (installing the interface resolver) is not implemented"
    );
    ensure!(
        raw.auto_system_routing_table.is_empty(),
        "tun `autoSystemRoutingTable` (installing OS routes) is not implemented"
    );
    ensure!(
        raw.auto_outbounds_interface
            .as_deref()
            .unwrap_or("")
            .is_empty(),
        "tun `autoOutboundsInterface` (binding outbounds to a physical interface) is not implemented"
    );
    let config = TunConfig {
        name,
        mtu,
        gateway,
        ..TunConfig::default()
    };
    config
        .validate()
        .map_err(anyhow::Error::from)
        .context("tun inbound settings")?;
    let inbound = dispatch_inbound(&config);
    Ok(TunInbound {
        config,
        user_level,
        inbound,
    })
}

/// Go's GetAvailableTunName: `utun` plus a random index in 10..=1024. Go
/// scans the live interface list and skips used names; no interface
/// enumeration is available to this crate, so the random candidate is
/// returned directly and a collision surfaces as the device-creation error.
fn available_tun_name() -> Result<String> {
    let index = rand::thread_rng().gen_range(MIN_TUN_INDEX..=MAX_TUN_INDEX);
    Ok(format!("{TUN_NAME_PREFIX}{index}"))
}

/// The `Inbound` value the dispatch seam presents for every session.
///
/// INTEGRATION NOTE: `config.rs` has no `tun` arm yet, so this stand-in picks
/// the closest transparent relay, dokodemo-door. `dispatch_common` reads only
/// the variant name (freedom's admission origin), and "dokodemo-door" and
/// "tun" have identical freedom final-rule behavior (neither is in the
/// private-IP default-block list). When the integrator adds
/// `Inbound::Tun { entry: TunInbound }` plus the `"tun"` arm in runtime.rs's
/// freedom-origin match, replace this body with the real variant — one line.
fn dispatch_inbound(config: &TunConfig) -> Inbound {
    let address = config
        .gateway
        .first()
        .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |prefix| prefix.address());
    Inbound::Dokodemo {
        destination: Destination::from(SocketAddr::new(address, 1)),
        udp: true,
    }
}

/// Serve the TUN inbound on its own task: create the device, run the
/// netstack, dispatch every TCP session and UDP flow through the runtime
/// dispatcher until the cancellation token fires. Must return promptly on
/// cancel and clean up the device.
// The signature is the frozen integration contract; the Dispatcher type it
// names stays runtime-private like every other seam's.
#[allow(private_interfaces)]
pub async fn serve(
    entry: TunInbound,
    dispatcher: std::sync::Arc<crate::runtime::Dispatcher>,
    tag: std::sync::Arc<str>,
    sniff: Option<std::sync::Arc<crate::runtime::sniffing::SniffingRequest>>,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    #[cfg(not(feature = "native-tun"))]
    {
        let _ = (entry, dispatcher, tag, sniff, cancel);
        bail!(
            "the TUN inbound requires the native-tun build feature; \
             rebuild with the default feature set"
        );
    }
    #[cfg(feature = "native-tun")]
    {
        serve_native(entry, dispatcher, tag, sniff, cancel).await
    }
}

/// The seam between the netstack's session events and the Xray runtime: one
/// method per lifecycle event, mirroring the calls Go's stack makes on the
/// Handler. Split from the concrete seam so the session plumbing is testable
/// against a recording seam (the real one needs the runtime Dispatcher).
#[cfg(feature = "native-tun")]
trait TunSessions: Send + Sync {
    /// One accepted netstack TCP connection (Go HandleConnection). Takes
    /// ownership of the stream; the session ends when its relay does.
    fn dispatch_tcp(&self, stream: BoxStream, source: SocketAddr, destination: SocketAddr);
    /// A new full-cone UDP flow appeared for a client source.
    fn open_udp(&self, session: SessionKey);
    /// One datagram of a flow; the destination may differ packet to packet
    /// (Go's full-cone NAT keys the connection by the source alone).
    fn udp_datagram(&self, session: SessionKey, destination: SocketAddr, payload: Vec<u8>);
    /// The flow ended: idle expiry or explicit close (Go connectionFinished).
    fn close_udp(&self, session: SessionKey);
}

/// Serve the TUN inbound with the native stack: the tun-rs device pumps raw
/// IP packets into `run_packets` (the ported netstack), whose session events
/// dispatch through the runtime seam until cancellation or device failure.
#[cfg(feature = "native-tun")]
async fn serve_native(
    entry: TunInbound,
    dispatcher: Arc<Dispatcher>,
    tag: Arc<str>,
    sniff: Option<Arc<SniffingRequest>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut config = entry.config;
    // Go: the stack's idle timeout is the user level's ConnectionIdle policy
    // (handler.go Start passes policyManager.ForLevel(userLevel)).
    let session_policy = dispatcher.policy.for_level(entry.user_level);
    if !session_policy.timeouts.connection_idle.is_zero() {
        config.udp_idle_timeout = session_policy.timeouts.connection_idle;
    }
    // The native runtime's own contract, re-checked at serve time so a
    // hand-built TunInbound cannot bypass the compile-time rejections.
    config
        .validate_native()
        .map_err(anyhow::Error::from)
        .context("tun inbound settings")?;
    for key in ["xray.tun.fd", "XRAY_TUN_FD"] {
        if std::env::var_os(key).is_some_and(|value| !value.is_empty()) {
            bail!(
                "tun inherited device descriptors ({key}) are not implemented; \
                 let the runtime create its own interface"
            );
        }
    }
    let udp = dispatcher
        .udp
        .as_ref()
        .context("the TUN inbound requires the runtime UDP dispatcher")?
        .clone();
    let (endpoint, native_dispatcher) =
        native::channels(config.event_capacity).context("tun inbound channels")?;

    let device = open_device(&config)
        .with_context(|| format!("create the TUN interface {:?}", config.name))?;
    device.enabled(true).context("bring the TUN interface up")?;
    tracing::info!(interface = %config.name, "TUN interface created");

    let (packet_input, ingress) = mpsc::channel(config.event_capacity);
    let (egress, packet_output) = mpsc::channel::<Vec<u8>>(config.event_capacity);
    // An owned, non-persistent interface disappears when its descriptor
    // closes, including stack/setup failures and cancellation.
    let reader = read_pump(&device, packet_input);
    let writer = write_pump(&device, packet_output);

    let stack = CancellationToken::new();
    let flows_stop = CancellationToken::new();
    let stack_runner = native::run_packets(config, ingress, egress, endpoint, stack.clone());
    let seam: Arc<dyn TunSessions> = Arc::new(DispatcherSeam::new(
        dispatcher,
        entry.inbound,
        entry.user_level,
        tag,
        sniff,
        cancel.clone(),
        udp,
        native_dispatcher.udp.clone(),
    ));
    let sessions = run_sessions(native_dispatcher.events, seam, flows_stop.clone());
    // Bias order matters: a netstack failure must win over the sessions
    // loop's plain completion when both wake together.
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        result = stack_runner => result.map_err(anyhow::Error::from).context("the TUN netstack stopped"),
        result = reader => result.context("read the TUN device"),
        result = writer => result.context("write the TUN device"),
        _ = sessions => Ok(()),
    };
    stack.cancel();
    flows_stop.cancel();
    let _ = device.enabled(false);
    result
}

/// Create the TUN device from the compiled settings. tun-rs applies the
/// interface addresses (Go's gateway handling), the MTU and the name; L3 is
/// wintun on Windows, /dev/net/tun elsewhere. Requires the driver and
/// privileges the OS demands for interface creation.
#[cfg(feature = "native-tun")]
fn open_device(config: &TunConfig) -> io::Result<tun_rs::AsyncDevice> {
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(config.name.clone())
        .mtu(config.mtu)
        .layer(tun_rs::Layer::L3)
        .enable(false);
    // Offload and multi-queue are Linux-only knobs of the tun-rs builder.
    #[cfg(target_os = "linux")]
    {
        builder = builder.offload(false).multi_queue(false);
    }
    for address in &config.gateway {
        builder = match address.address() {
            IpAddr::V4(ip) => builder.ipv4(ip, address.prefix_len(), None),
            IpAddr::V6(ip) => builder.ipv6(ip, address.prefix_len()),
        };
    }
    builder.build_async()
}

#[cfg(feature = "native-tun")]
fn channel_closed(name: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, name)
}

/// Pump raw packets from the device into the netstack's ingress channel.
#[cfg(feature = "native-tun")]
async fn read_pump(device: &tun_rs::AsyncDevice, output: mpsc::Sender<Vec<u8>>) -> io::Result<()> {
    let mut buffer = vec![0; crate::protocol::tun::packet::MAX_IP_PACKET];
    loop {
        let count = device.recv(&mut buffer).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN device returned EOF",
            ));
        }
        output
            .send(buffer[..count].to_vec())
            .await
            .map_err(|_| channel_closed("TUN ingress pump"))?;
    }
}

/// Pump the netstack's egress packets into the device.
#[cfg(feature = "native-tun")]
async fn write_pump(
    device: &tun_rs::AsyncDevice,
    mut input: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(packet) = input.recv().await {
        let count = device.send(&packet).await?;
        if count != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "TUN device wrote a partial packet",
            ));
        }
    }
    Err(channel_closed("TUN egress pump"))
}

/// Pump the netstack's session events into the seam until the events channel
/// closes (the netstack ended) or `cancel` fires; every flow spawned under
/// `cancel` is torn down on exit.
#[cfg(feature = "native-tun")]
async fn run_sessions(
    mut events: mpsc::Receiver<TunEvent>,
    seam: Arc<dyn TunSessions>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            event = events.recv() => {
                let Some(event) = event else {
                    tracing::debug!("TUN netstack event stream closed");
                    break;
                };
                match event {
                    TunEvent::Tcp {
                        stream,
                        source,
                        destination,
                    } => seam.dispatch_tcp(Box::new(stream), source, destination),
                    TunEvent::Udp {
                        session,
                        is_new,
                        destination,
                        payload,
                    } => {
                        if is_new {
                            seam.open_udp(session);
                        }
                        seam.udp_datagram(session, destination, payload);
                    }
                    TunEvent::UdpClosed(session) => seam.close_udp(session),
                }
            }
        }
    }
    cancel.cancel();
}

/// One live full-cone UDP flow in the seam's table.
#[cfg(feature = "native-tun")]
struct FlowHandle {
    packets: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    stop: CancellationToken,
}

/// The runtime dispatch seam: TCP sessions run the shared post-handshake
/// dispatch (routing, sniffing, stats, relay) and UDP datagrams each flow
/// through the runtime UDP dispatcher like the hysteria and SOCKS seams.
#[cfg(feature = "native-tun")]
struct DispatcherSeam {
    dispatcher: Arc<Dispatcher>,
    inbound: Arc<Inbound>,
    tag: Arc<str>,
    cancel: CancellationToken,
    sniff: Option<Arc<SniffingRequest>>,
    user_level: u32,
    udp: Arc<dyn UdpDispatcher>,
    replies: UdpReplies,
    counters: TrafficCounters,
    flows: Mutex<HashMap<SessionKey, FlowHandle>>,
}

#[cfg(feature = "native-tun")]
impl DispatcherSeam {
    #[allow(clippy::too_many_arguments)]
    fn new(
        dispatcher: Arc<Dispatcher>,
        inbound: Inbound,
        user_level: u32,
        tag: Arc<str>,
        sniff: Option<Arc<SniffingRequest>>,
        cancel: CancellationToken,
        udp: Arc<dyn UdpDispatcher>,
        replies: UdpReplies,
    ) -> Self {
        let counters = dispatcher
            .stats
            .as_ref()
            .map(|stats| stats.inbound_counters(&tag, dispatcher.policy.for_system().stats))
            .unwrap_or_default();
        Self {
            dispatcher,
            inbound: Arc::new(inbound),
            tag,
            cancel,
            sniff,
            user_level,
            udp,
            replies,
            counters,
            flows: Mutex::new(HashMap::new()),
        }
    }

    fn spawn_flow_locked(&self, flows: &mut HashMap<SessionKey, FlowHandle>, session: SessionKey) {
        let (packets, inbox) = mpsc::channel(FLOW_QUEUE);
        let stop = CancellationToken::new();
        let counters = self.counters.clone();
        let udp = Arc::clone(&self.udp);
        let replies = self.replies.clone();
        let tag = Arc::clone(&self.tag);
        tokio::spawn(udp_flow(
            session,
            udp,
            replies,
            tag,
            counters,
            stop.clone(),
            inbox,
        ));
        flows.insert(session, FlowHandle { packets, stop });
    }
}

#[cfg(feature = "native-tun")]
impl TunSessions for DispatcherSeam {
    fn dispatch_tcp(&self, stream: BoxStream, source: SocketAddr, destination: SocketAddr) {
        // Go wraps the connection in stat.CounterConnection (uplink on read,
        // downlink on write) before dispatching.
        let stream = CountedStream::wrap(stream, self.counters.clone(), true);
        let request = protocol::Request {
            level: self.user_level,
            destination: Destination::from(destination),
            user: String::new(),
            initial_payload: Vec::new(),
            reply: protocol::Reply::None,
        };
        let dispatcher = Arc::clone(&self.dispatcher);
        let inbound = Arc::clone(&self.inbound);
        let tag = Arc::clone(&self.tag);
        let cancel = self.cancel.clone();
        let sniff = self.sniff.clone();
        tokio::spawn(async move {
            // The netstack accepted on the destination address, so it is the
            // bound side of the relay (unused by Reply::None requests).
            if let Err(error) = super::dispatch_request(
                stream,
                source,
                destination,
                &inbound,
                &tag,
                &dispatcher,
                &cancel,
                request,
                None,
                sniff,
            )
            .await
            {
                // Go's HandleConnection logs the dispatcher error, never
                // failing the inbound.
                tracing::debug!(%error, from = %source, to = %destination, "TUN TCP session closed");
            }
        });
    }

    fn open_udp(&self, session: SessionKey) {
        let mut flows = self.flows.lock().expect("TUN flow table lock");
        if !flows.contains_key(&session) {
            self.spawn_flow_locked(&mut flows, session);
        }
    }

    fn udp_datagram(&self, session: SessionKey, destination: SocketAddr, payload: Vec<u8>) {
        let mut flows = self.flows.lock().expect("TUN flow table lock");
        let mut datagram = (destination, payload);
        loop {
            let Some(flow) = flows.get(&session) else {
                self.spawn_flow_locked(&mut flows, session);
                continue;
            };
            match flow.packets.try_send(datagram) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Go drops to a debug log when the flow's 1024-slot
                    // egress queue is full.
                    tracing::debug!(source = %session.source, "drop TUN UDP datagram: flow queue full");
                    return;
                }
                // The flow task exited (a reply-path failure closes it, like
                // Go's udpConn write error); the datagram re-delivers to a
                // fresh flow, exactly like Go's next packet opening a new
                // udpConn for the same source.
                Err(mpsc::error::TrySendError::Closed(recovered)) => {
                    datagram = recovered;
                    flows.remove(&session);
                }
            }
        }
    }

    fn close_udp(&self, session: SessionKey) {
        let mut flows = self.flows.lock().expect("TUN flow table lock");
        if let Some(flow) = flows.remove(&session) {
            flow.stop.cancel();
        }
    }
}

/// One connected relay socket toward an admitted UDP endpoint; replies return
/// to the flow loop with their remote address (plain_udp's Peer shape).
#[cfg(feature = "native-tun")]
struct Peer {
    socket: Arc<UdpSocket>,
    reader: CancellationToken,
}

#[cfg(feature = "native-tun")]
impl Peer {
    fn new(
        target: SocketAddr,
        replies: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        parent: CancellationToken,
    ) -> io::Result<Self> {
        let socket = Arc::new(connected_socket(target)?);
        let reader = parent.child_token();
        let pump_socket = Arc::clone(&socket);
        let pump_stop = reader.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = pump_stop.cancelled() => return,
                    received = pump_socket.recv(&mut buffer) => received,
                };
                match received {
                    Ok(size) => {
                        if replies
                            .send((target, buffer[..size].to_vec()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Self { socket, reader })
    }
}

#[cfg(feature = "native-tun")]
impl Drop for Peer {
    fn drop(&mut self) {
        self.reader.cancel();
    }
}

/// Dual-family unconnected-bind, then connect: replies can only come from the
/// admitted endpoint, exactly like the SOCKS UDP association's peers.
#[cfg(feature = "native-tun")]
fn connected_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    let local = match target.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    // These numeric-address OS calls perform no DNS or admission of their own.
    let socket = std::net::UdpSocket::bind(SocketAddr::new(local, 0))?;
    socket.set_nonblocking(true)?;
    socket.connect(target)?;
    UdpSocket::from_std(socket)
}

/// The full-cone UDP flow of one client source (Go's udpConn goroutine): every
/// datagram dispatches through the runtime UDP dispatcher — direct peers get
/// one connected socket per target, XUDP packets ride the carrier lease — and
/// every reply is written back to the TUN with its remote as the packet
/// source, so the client sees which endpoint answered.
#[cfg(feature = "native-tun")]
#[allow(clippy::too_many_arguments)]
async fn udp_flow(
    session: SessionKey,
    udp: Arc<dyn UdpDispatcher>,
    replies: UdpReplies,
    tag: Arc<str>,
    counters: TrafficCounters,
    stop: CancellationToken,
    mut inbox: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
) {
    let (relay_tx, mut relay_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(FLOW_QUEUE);
    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
    let mut xudp_pumps = tokio::task::JoinSet::new();
    let mut xudp_leases: Vec<std::sync::Arc<super::mux_runtime::XudpLease>> = Vec::new();
    let user: Arc<str> = Arc::from("");
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            // A reply of any remote (full-cone): downlink-counted, then sent
            // back through the netstack's raw packet path.
            relay = relay_rx.recv() => {
                let Some((remote, payload)) = relay else { continue };
                counters.add_downlink(payload.len());
                if replies.send(session, remote, payload).await.is_err() {
                    // Go closes the udpConn when a write fails.
                    break;
                }
            }
            completed = xudp_pumps.join_next(), if !xudp_pumps.is_empty() => {
                let _ = completed;
            }
            datagram = inbox.recv() => {
                let Some((destination, payload)) = datagram else { break };
                counters.add_uplink(payload.len());
                let action = udp
                    .dispatch(DispatchContext {
                        destination: Destination::from(destination),
                        source: session.source,
                        inbound_tag: Arc::clone(&tag),
                        user: Arc::clone(&user),
                        network: "udp",
                    })
                    .await;
                let action = match action {
                    Ok(action) => action,
                    Err(error) => {
                        tracing::debug!(%error, "TUN UDP dispatch failed");
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
                        let peer = match peers.get(&target) {
                            Some(peer) => peer,
                            None => match Peer::new(target, relay_tx.clone(), stop.clone()) {
                                Ok(peer) => peers.entry(target).or_insert(peer),
                                Err(error) => {
                                    // A relay socket that cannot be created
                                    // drops this datagram, like the SOCKS
                                    // UDP association does.
                                    tracing::debug!(%error, %target, "cannot open a TUN UDP relay socket");
                                    continue;
                                }
                            },
                        };
                        if peer.socket.send(&payload).await.is_err() {
                            // Go's writePacket failure closes the udpConn.
                            break;
                        }
                    }
                    DispatchAction::Xudp { lease } => {
                        // One pump per lease feeds the flow's replies; the
                        // packet rides the carrier.
                        if !xudp_leases
                            .iter()
                            .any(|kept| std::sync::Arc::ptr_eq(kept, &lease))
                        {
                            xudp_leases.push(lease.clone());
                            let pump_lease = lease.clone();
                            let sender = relay_tx.clone();
                            let pump_stop = stop.clone();
                            xudp_pumps.spawn(async move {
                                loop {
                                    let reply = tokio::select! {
                                        biased;
                                        _ = pump_stop.cancelled() => return,
                                        reply = pump_lease.recv() => reply,
                                    };
                                    let Some((target, payload)) = reply else { return };
                                    let Some(endpoint) = udp::endpoint_of(&target) else {
                                        continue;
                                    };
                                    if sender.send((endpoint, payload)).await.is_err() {
                                        return;
                                    }
                                }
                            });
                        }
                        let target = crate::mux::Target::from_destination(
                            crate::mux::Network::Udp,
                            &Destination::from(destination),
                        );
                        if let Err(error) = lease.send(target, &payload).await {
                            tracing::debug!(%error, "TUN XUDP uplink send failed");
                        }
                    }
                }
            }
        }
    }
    stop.cancel();
    peers.clear();
    xudp_pumps.abort_all();
}

#[cfg(all(test, feature = "native-tun"))]
mod tests {
    use super::*;
    use crate::protocol::tun::packet;
    use serde_json::json;
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
        time::timeout,
    };

    // ---------------------------------------------------------------------
    // compile_inbound: infra/conf/tun.go's JSON surface
    // ---------------------------------------------------------------------

    #[test]
    fn go_json_defaults_and_exact_keys() {
        let entry = compile_inbound(&json!({})).unwrap();
        assert_eq!(entry.config.mtu, 1500);
        let suffix: u16 = entry
            .config
            .name
            .strip_prefix(TUN_NAME_PREFIX)
            .unwrap()
            .parse()
            .unwrap();
        assert!((MIN_TUN_INDEX..=MAX_TUN_INDEX).contains(&suffix));
        assert_eq!(entry.user_level, 0);
        assert!(entry.config.gateway.is_empty());

        let entry = compile_inbound(&json!({
            "name": "tun0",
            "mtu": 1400,
            "gateway": ["172.20.0.1/24", "fd00::1/64"],
            "userLevel": 3,
        }))
        .unwrap();
        assert_eq!(entry.config.name, "tun0");
        assert_eq!(entry.config.mtu, 1400);
        assert_eq!(entry.config.gateway.len(), 2);
        assert_eq!(entry.user_level, 3);

        // An explicit empty autoOutboundsInterface is "disabled" in Go, not
        // an error; the empty desc behaves like the absent one.
        compile_inbound(&json!({
            "name": "tun0",
            "desc": "",
            "autoOutboundsInterface": ""
        }))
        .unwrap();
    }

    #[test]
    fn unsupported_go_options_fail_with_the_option_named() {
        for (settings, needle) in [
            (json!({"desc": "Wintun"}), "desc"),
            (json!({"dns": ["1.1.1.1"]}), "dns"),
            (
                json!({"autoSystemRoutingTable": ["0.0.0.0/0"]}),
                "autoSystemRoutingTable",
            ),
            (
                json!({"autoOutboundsInterface": "auto"}),
                "autoOutboundsInterface",
            ),
            (
                json!({"autoOutboundsInterface": "eth0"}),
                "autoOutboundsInterface",
            ),
            (json!({"gateway": ["172.20.0.1"]}), "gateway"),
            (
                json!({"gateway": ["172.20.0.1/24", "172.21.0.1/24"]}),
                "IPv4",
            ),
            (json!({"mtu": 68}), "mtu"),
            (json!({"mtu": 70000}), "mtu"),
            (json!({"userLevel": 5000000000u64}), "userLevel"),
            (json!({"name": "tun%d"}), "name"),
            (json!({"unknownKey": 1}), "unknownKey"),
        ] {
            // The full anyhow chain: the named option rides the source, not
            // the generic "tun inbound settings" wrapper.
            let error = compile_inbound(&settings).err().unwrap();
            let error = format!("{error:#}");
            assert!(
                error.contains(needle),
                "expected the error for {settings} to name {needle:?}: {error}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // run_sessions over the real netstack with a recording seam
    // ---------------------------------------------------------------------

    struct RecordingSeam {
        replies: UdpReplies,
        tcp: Mutex<Vec<(SocketAddr, SocketAddr)>>,
        streams: Mutex<Vec<BoxStream>>,
        opened: Mutex<Vec<SessionKey>>,
        datagrams: Mutex<Vec<(SessionKey, SocketAddr, Vec<u8>)>>,
        closed: Mutex<Vec<SessionKey>>,
    }

    impl TunSessions for RecordingSeam {
        fn dispatch_tcp(&self, stream: BoxStream, source: SocketAddr, destination: SocketAddr) {
            self.tcp.lock().unwrap().push((source, destination));
            self.streams.lock().unwrap().push(stream);
        }
        fn open_udp(&self, session: SessionKey) {
            self.opened.lock().unwrap().push(session);
        }
        fn udp_datagram(&self, session: SessionKey, destination: SocketAddr, payload: Vec<u8>) {
            self.datagrams
                .lock()
                .unwrap()
                .push((session, destination, payload.clone()));
            // Answer from the destination like a dispatched remote would.
            let replies = self.replies.clone();
            tokio::spawn(async move {
                let _ = replies.send(session, destination, payload).await;
            });
        }
        fn close_udp(&self, session: SessionKey) {
            self.closed.lock().unwrap().push(session);
        }
    }

    async fn until<T>(probe: impl Fn() -> Option<T>) -> T {
        timeout(Duration::from_secs(3), async {
            loop {
                if let Some(value) = probe() {
                    return value;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    fn client_tcp(sequence: u32, acknowledgement: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0x30, 0x39, 0x01, 0xbb]; // ports 12345 -> 443
        tcp.extend_from_slice(&sequence.to_be_bytes());
        tcp.extend_from_slice(&acknowledgement.to_be_bytes());
        tcp.extend_from_slice(&[0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0]);
        tcp.extend_from_slice(data);
        let mut pseudo = vec![192, 0, 2, 1, 198, 51, 100, 2, 0, 6];
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&tcp);
        tcp[16..18].copy_from_slice(&packet::checksum(&pseudo).to_be_bytes());
        packet::build_ip(
            "192.0.2.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
            packet::TCP,
            &tcp,
        )
        .unwrap()
    }

    async fn next_packet(output: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        timeout(Duration::from_secs(3), output.recv())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn sessions_pump_dispatches_udp_and_tcp_through_the_seam() {
        let config = TunConfig::default();
        let (endpoint, native_dispatcher) = native::channels(16).unwrap();
        let (ingress_tx, ingress) = mpsc::channel(16);
        let (egress, mut egress_rx) = mpsc::channel(16);
        let stack = CancellationToken::new();
        let stack_task = tokio::spawn(native::run_packets(
            config,
            ingress,
            egress,
            endpoint,
            stack.clone(),
        ));
        let seam = Arc::new(RecordingSeam {
            replies: native_dispatcher.udp.clone(),
            tcp: Mutex::new(Vec::new()),
            streams: Mutex::new(Vec::new()),
            opened: Mutex::new(Vec::new()),
            datagrams: Mutex::new(Vec::new()),
            closed: Mutex::new(Vec::new()),
        });
        let flows_stop = CancellationToken::new();
        let sessions_task = tokio::spawn(run_sessions(
            native_dispatcher.events,
            seam.clone(),
            flows_stop.clone(),
        ));

        // One UDP flow, two full-cone destinations, one reply path.
        let client: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let first: SocketAddr = "198.51.100.2:53".parse().unwrap();
        let second: SocketAddr = "203.0.113.4:9876".parse().unwrap();
        ingress_tx
            .send(packet::build_udp(client, first, b"q1").unwrap())
            .await
            .unwrap();
        let session = until(|| {
            seam.datagrams
                .lock()
                .unwrap()
                .first()
                .map(|(session, destination, payload)| {
                    assert_eq!(*destination, first);
                    assert_eq!(payload, b"q1");
                    *session
                })
        })
        .await;
        assert_eq!(*seam.opened.lock().unwrap(), vec![session]);
        ingress_tx
            .send(packet::build_udp(client, second, b"q2").unwrap())
            .await
            .unwrap();
        until(|| {
            let datagrams = seam.datagrams.lock().unwrap();
            (datagrams.len() == 2).then_some(())
        })
        .await;
        assert_eq!(*seam.opened.lock().unwrap(), vec![session]);
        let reply = next_packet(&mut egress_rx).await;
        let ip = packet::parse_ip(&reply).unwrap();
        let udp = packet::parse_udp(&ip).unwrap();
        assert_eq!(udp.source, first);
        assert_eq!(udp.destination, client);
        assert_eq!(udp.payload, b"q1");

        // The UDP flow closes on expiry: UdpClosed reaches the seam.
        native_dispatcher.udp.close(session).await.unwrap();
        until(|| (!seam.closed.lock().unwrap().is_empty()).then_some(())).await;
        assert_eq!(*seam.closed.lock().unwrap(), vec![session]);

        // A full TCP handshake reaches the seam with the session's addresses,
        // and the stream relays both directions through the netstack.
        ingress_tx
            .send(hex_bytes(
                "450000280000000040068e99c0000201c6336402303901bb10203040000000005002faf056660000",
            ))
            .await
            .unwrap();
        let mut server_sequence = 0;
        timeout(Duration::from_secs(3), async {
            loop {
                let bytes = egress_rx.recv().await.unwrap();
                let ip = match packet::parse_ip(&bytes) {
                    Ok(ip) if ip.protocol == packet::TCP => ip,
                    // Skip the queued UDP replies until the handshake answer.
                    _ => continue,
                };
                packet::validate_tcp(&ip).unwrap();
                if ip.payload[13] & 0x12 == 0x12 {
                    server_sequence = u32::from_be_bytes(ip.payload[4..8].try_into().unwrap());
                    return;
                }
            }
        })
        .await
        .unwrap();
        ingress_tx
            .send(client_tcp(
                0x10203041,
                server_sequence.wrapping_add(1),
                0x10,
                &[],
            ))
            .await
            .unwrap();
        let mut stream = until(|| {
            let mut streams = seam.streams.lock().unwrap();
            if streams.len() == 1 {
                Some(streams.remove(0))
            } else {
                None
            }
        })
        .await;
        let (source, destination) = seam.tcp.lock().unwrap().remove(0);
        assert_eq!(source, "192.0.2.1:12345".parse().unwrap());
        assert_eq!(destination, "198.51.100.2:443".parse().unwrap());
        ingress_tx
            .send(client_tcp(
                0x10203041,
                server_sequence.wrapping_add(1),
                0x18,
                b"hello",
            ))
            .await
            .unwrap();
        let mut data = [0; 5];
        timeout(Duration::from_secs(3), stream.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data, b"hello");
        timeout(Duration::from_secs(3), stream.write_all(b"reply"))
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                let bytes = next_packet(&mut egress_rx).await;
                let ip = match packet::parse_ip(&bytes) {
                    Ok(ip) if ip.protocol == packet::TCP => ip,
                    _ => continue,
                };
                packet::validate_tcp(&ip).unwrap();
                let tcp_header = usize::from(ip.payload[12] >> 4) * 4;
                if ip.payload.len() > tcp_header {
                    assert_eq!(&ip.payload[tcp_header..], b"reply");
                    return;
                }
            }
        })
        .await
        .unwrap();

        // Cancellation releases everything.
        flows_stop.cancel();
        timeout(Duration::from_secs(3), sessions_task)
            .await
            .unwrap()
            .unwrap();
        stack.cancel();
        timeout(Duration::from_secs(3), stack_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // ---------------------------------------------------------------------
    // The full-cone flow worker against a direct UDP dispatcher
    // ---------------------------------------------------------------------

    /// A dispatcher that admits the datagram's own destination directly.
    fn direct_dispatcher() -> Arc<dyn UdpDispatcher> {
        Arc::new(|context: DispatchContext| async move {
            match context.destination.address {
                crate::address::Address::Ip(ip) => Ok(DispatchAction::Direct(SocketAddr::new(
                    ip,
                    context.destination.port,
                ))),
                _ => Ok(DispatchAction::Drop),
            }
        })
    }

    async fn echo_socket() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(socket);
        let pump = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let Ok((size, peer)) = pump.recv_from(&mut buffer).await else {
                    return;
                };
                if pump.send_to(&buffer[..size], peer).await.is_err() {
                    return;
                }
            }
        });
        socket.local_addr().unwrap()
    }

    #[tokio::test]
    async fn full_cone_flow_relays_two_targets_and_their_replies() {
        let config = TunConfig::default();
        let (endpoint, mut native_dispatcher) = native::channels(16).unwrap();
        let (ingress_tx, ingress) = mpsc::channel(16);
        let (egress, mut egress_rx) = mpsc::channel(16);
        let stack = CancellationToken::new();
        let stack_task = tokio::spawn(native::run_packets(
            config,
            ingress,
            egress,
            endpoint,
            stack.clone(),
        ));

        let client: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let echo_a = echo_socket().await;
        let echo_b = echo_socket().await;
        ingress_tx
            .send(packet::build_udp(client, echo_a, b"one").unwrap())
            .await
            .unwrap();
        // The netstack registers the flow on its first packet; the flow worker
        // takes over that session's datagrams (what the real seam does).
        let session = timeout(Duration::from_secs(3), native_dispatcher.events.recv())
            .await
            .unwrap()
            .unwrap();
        let session = match session {
            TunEvent::Udp {
                session,
                is_new,
                destination,
                payload,
            } => {
                assert!(is_new);
                assert_eq!(destination, echo_a);
                assert_eq!(payload, b"one");
                session
            }
            _ => panic!("expected the first UDP event"),
        };
        let (inbox_tx, inbox) = mpsc::channel(8);
        let stop = CancellationToken::new();
        let flow = tokio::spawn(udp_flow(
            session,
            direct_dispatcher(),
            native_dispatcher.udp.clone(),
            "tun".into(),
            TrafficCounters::default(),
            stop.clone(),
            inbox,
        ));
        inbox_tx.send((echo_a, b"one".to_vec())).await.unwrap();
        inbox_tx.send((echo_b, b"two".to_vec())).await.unwrap();

        // Full-cone: both targets answer and each reply carries its own
        // remote as the packet source back to the client.
        let mut replies = Vec::new();
        timeout(Duration::from_secs(3), async {
            while replies.len() < 2 {
                let bytes = next_packet(&mut egress_rx).await;
                let ip = packet::parse_ip(&bytes).unwrap();
                let udp = packet::parse_udp(&ip).unwrap();
                assert_eq!(udp.destination, client);
                replies.push((udp.source, udp.payload.to_vec()));
            }
        })
        .await
        .unwrap();
        assert!(replies.contains(&(echo_a, b"one".to_vec())));
        assert!(replies.contains(&(echo_b, b"two".to_vec())));

        stop.cancel();
        timeout(Duration::from_secs(3), flow)
            .await
            .unwrap()
            .unwrap();
        stack.cancel();
        timeout(Duration::from_secs(3), stack_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
