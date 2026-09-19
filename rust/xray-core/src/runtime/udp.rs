//! Bounded SOCKS5 UDP associations. The caller owns routing and final admission.
//!
//! Every forwarded client packet goes through UdpDispatcher; only its checked numeric
//! Direct endpoint may be contacted. There is no resolver, freedom fallback, or
//! routing-policy shortcut here. Parent wiring must evaluate network="udp" and
//! final rules against that exact resolved endpoint before returning Direct.
//!
//! Source restrictions deliberately tighten Go's TempUDPConn behavior: a concrete
//! requested IP must equal the TCP peer, a nonzero requested port is honored even
//! with an unspecified/domain address, and malformed/fragmented packets cannot
//! pin a learned port or refresh activity. SOCKS UDP has no authentication tag or
//! sequence number: duplicate valid packets remain valid, and this is not
//! cryptographic spoof/replay protection. Connected upstream sockets filter
//! response IP/port; generation checks discard responses from retired sockets.
//! This relay is unicast-only: unspecified, multicast, limited-broadcast and
//! zero-port destinations are rejected. Empty request payloads are dropped as in
//! proxy/socks/server.go. Network probing, encrypted UDP, full-cone behavior,
//! transparent/bound-interface socket options, and cross-proxy UDP are out of scope.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
    task::JoinSet,
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    address::{Address, Destination},
    features::stats::{TrafficCounters, UserSessionStats},
    protocol::{
        Reply,
        socks::AssociateRequest,
        udp::{
            SOCKS5_MAX_PACKET_SIZE, Socks5UdpSession, decode_socks5_packet, encode_socks5_packet,
        },
    },
};

#[derive(Clone, Debug)]
pub struct DispatchContext {
    pub destination: Destination,
    /// Actual pinned UDP source, including its UDP port, for RouteContext.
    pub source: SocketAddr,
    pub inbound_tag: Arc<str>,
    pub user: Arc<str>,
    pub network: &'static str,
}

#[derive(Clone, Debug)]
pub enum DispatchAction {
    /// A blackhole, rejected final rule, or another deliberate silent UDP drop.
    Drop,
    /// Only the exact numeric endpoint admitted by the parent may be returned.
    Direct(SocketAddr),
    /// Route identity keeps sockets and outbound accounting separate even when
    /// different selected routes resolve to the same endpoint.
    TrackedDirect {
        target: SocketAddr,
        route: usize,
        counters: TrafficCounters,
    },
}

pub type DispatchFuture = Pin<Box<dyn Future<Output = io::Result<DispatchAction>> + Send>>;

pub trait UdpDispatcher: Send + Sync {
    fn dispatch(&self, context: DispatchContext) -> DispatchFuture;
}

impl<F, Fut> UdpDispatcher for F
where
    F: Fn(DispatchContext) -> Fut + Send + Sync,
    Fut: Future<Output = io::Result<DispatchAction>> + Send + 'static,
{
    fn dispatch(&self, context: DispatchContext) -> DispatchFuture {
        Box::pin(self(context))
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub idle_timeout: Duration,
    pub peer_idle_timeout: Duration,
    /// Bound dispatcher/DNS/admission waits, sends, and initial TCP response.
    pub operation_timeout: Duration,
    pub max_peers: usize,
    pub max_pending: usize,
    pub response_queue: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(300),
            peer_idle_timeout: Duration::from_secs(60),
            operation_timeout: Duration::from_secs(5),
            max_peers: 64,
            max_pending: 16,
            response_queue: 64,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> io::Result<()> {
        if self.peer_idle_timeout.is_zero()
            || self.operation_timeout.is_zero()
            || !(1..=256).contains(&self.max_peers)
            || !(1..=1024).contains(&self.max_pending)
            || !(1..=1024).contains(&self.response_queue)
        {
            return Err(invalid("UDP association limits exceed supported bounds"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndReason {
    ControlClosed,
    IdleTimeout,
    Cancelled,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub accepted_packets: u64,
    pub rejected_source: u64,
    pub malformed_packets: u64,
    pub policy_drops: u64,
    pub dispatch_errors: u64,
    pub capacity_drops: u64,
    pub send_errors: u64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub reason: EndReason,
    pub counters: Counters,
}

pub struct Association {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    requested_source: Destination,
    user: Arc<str>,
    limits: Limits,
    user_stats: UserSessionStats,
}

impl Association {
    /// Use settings.ip or the TCP socket's actual local IP for bind_ip, as Go
    /// does. Callers send a SOCKS failure if bind fails. This method sends no TCP
    /// response and cannot become a usable association without serve().
    pub async fn bind(
        peer: SocketAddr,
        request: AssociateRequest,
        bind_ip: IpAddr,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let peer_ip = canonical_ip(peer.ip());
        if peer_ip.is_unspecified() || peer.port() == 0 {
            return Err(invalid("UDP association requires a concrete TCP peer"));
        }
        if let Address::Ip(ip) = &request.requested_source.address {
            let ip = canonical_ip(*ip);
            if !ip.is_unspecified() && ip != peer_ip {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UDP source IP differs from TCP peer",
                ));
            }
        }
        // Normalize before using the existing session helper so it cannot trust
        // a third-party IP or discard the explicitly requested source port.
        let requested_source = Destination {
            address: Address::Ip(peer_ip),
            port: request.requested_source.port,
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
        Ok(Self {
            socket: Arc::new(socket),
            peer,
            requested_source,
            user: request.user.into(),
            limits,
            user_stats: UserSessionStats::default(),
        })
    }

    /// Hold one online-user guard for the association lifetime. User counters
    /// measure accepted request payload and response payload offered to the
    /// association queue, following dispatcher SizeStatWriter's pre-write count.
    /// Like Go's TempUDPConn, this dynamic relay does not add system inbound UDP wire
    /// counters; the caller's TCP control stream keeps its normal accounting.
    pub fn with_stats(mut self, user_stats: UserSessionStats) -> Self {
        self.user_stats = user_stats;
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Own the TCP control stream until association termination. Success is sent
    /// only after bind succeeded. Dropping this future aborts its owned JoinSets
    /// and releases the TCP/local UDP/upstream sockets; no detached workers live.
    pub async fn serve<S>(
        self,
        mut control: S,
        inbound_tag: Arc<str>,
        dispatcher: Arc<dyn UdpDispatcher>,
        cancel: CancellationToken,
    ) -> io::Result<Outcome>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let bound = self.local_addr()?;
        let Self {
            socket,
            peer,
            requested_source,
            user,
            limits,
            user_stats,
        } = self;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(Outcome { reason: EndReason::Cancelled, counters: Counters::default() }),
            result = timeout(limits.operation_timeout, async {
                Reply::Socks5.success(&mut control, bound).await.map_err(io::Error::other)?;
                control.flush().await
            }) => result.map_err(|_| timed_out("UDP associate response timed out"))??,
        }

        let mut session =
            Socks5UdpSession::new(peer, &requested_source, limits.idle_timeout, Instant::now());
        let stop = CancellationToken::new();
        let mut peers: HashMap<PeerKey, Peer> = HashMap::new();
        let mut readers = JoinSet::new();
        let mut pending: JoinSet<(io::Result<DispatchAction>, Vec<u8>)> = JoinSet::new();
        let mut sends: JoinSet<io::Result<SendReport>> = JoinSet::new();
        let (responses_tx, mut responses) = mpsc::channel::<Response>(limits.response_queue);
        let mut next_id = 0u64;
        let mut counters = Counters::default();
        // Large enough to detect and discard an oversized datagram without
        // truncating it into a syntactically valid 8192-byte packet.
        let mut packet = vec![0; 65_536];
        let mut control_data = [0; 512];
        let mut maintenance = interval(limits.peer_idle_timeout.min(Duration::from_secs(1)));
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let result = loop {
            let Some(remaining) = session.idle_remaining(Instant::now()) else {
                break Ok(EndReason::IdleTimeout);
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break Ok(EndReason::Cancelled),
                _ = sleep(remaining) => {
                    if !session.is_open(Instant::now()) { break Ok(EndReason::IdleTimeout); }
                }
                data = control.read(&mut control_data) => match data {
                    Ok(0) => { session.close_tcp(); break Ok(EndReason::ControlClosed); }
                    Ok(_) => (), // TCP junk never refreshes UDP activity.
                    Err(error) => { session.close_tcp(); break Err(error); }
                },
                _ = maintenance.tick() => prune_peers(&mut peers, limits.peer_idle_timeout),
                completed = readers.join_next(), if !readers.is_empty() => {
                    if let Some(Ok((target, id))) = completed
                        && peers.get(&target).is_some_and(|peer| peer.id == id) {
                        peers.remove(&target);
                    }
                }
                completed = sends.join_next(), if !sends.is_empty() => {
                    if let Some(completed) = completed { apply_send_report(&mut counters, completed); }
                },
                completed = pending.join_next(), if !pending.is_empty() => {
                    let Some(Ok((action, payload))) = completed else { counters.dispatch_errors += 1; continue; };
                    let action = match action { Ok(action) => action, Err(_) => { counters.dispatch_errors += 1; continue; } };
                    let (mut target, route, outbound_counters) = match action {
                        DispatchAction::Drop => { counters.policy_drops += 1; continue; }
                        DispatchAction::Direct(target) => (target, None, TrafficCounters::default()),
                        DispatchAction::TrackedDirect { target, route, counters } => (target, Some(route), counters),
                    };
                    target.set_ip(canonical_ip(target.ip()));
                    if !valid_endpoint(target) { counters.dispatch_errors += 1; continue; }
                    let key = PeerKey { target, route };
                    if sends.len() >= limits.max_pending { counters.capacity_drops += 1; continue; }
                    prune_peers(&mut peers, limits.peer_idle_timeout);
                    if !peers.contains_key(&key) {
                        if peers.len() >= limits.max_peers || readers.len() >= limits.max_peers * 2 {
                            counters.capacity_drops += 1; continue;
                        }
                        let upstream = match connected_socket(target) { Ok(socket) => Arc::new(socket), Err(_) => { counters.send_errors += 1; continue; } };
                        next_id = next_id.wrapping_add(1);
                        let id = next_id;
                        let peer_stop = stop.child_token();
                        let reader_socket = Arc::clone(&upstream);
                        let reader_stop = peer_stop.clone();
                        let sender = responses_tx.clone();
                        let reader_counters = outbound_counters.clone();
                        let user_counters = user_stats.traffic.clone();
                        readers.spawn(async move {
                            receive_responses(reader_socket, key, id, sender, reader_stop, reader_counters, user_counters).await;
                            (key, id)
                        });
                        peers.insert(key, Peer { socket: upstream, id, last_activity: Instant::now(), stop: peer_stop });
                    }
                    let entry = peers.get_mut(&key).expect("entry installed above");
                    entry.last_activity = Instant::now();
                    let upstream = Arc::clone(&entry.socket);
                    let peer_stop = entry.stop.clone();
                    let duration = limits.operation_timeout;
                    sends.spawn(async move {
                        tokio::select! {
                            biased;
                            _ = peer_stop.cancelled() => Ok(SendReport::Cancelled),
                            result = timeout(duration,upstream.send(&payload)) => {
                                let sent = result.map_err(|_|timed_out("UDP uplink send timed out"))??;
                                outbound_counters.add_uplink(sent);
                                if sent != payload.len() { return Err(io::Error::new(io::ErrorKind::WriteZero,"partial UDP datagram send")); }
                                Ok(SendReport::Uplink(sent))
                            }
                        }
                    });
                }
                response = responses.recv() => {
                    let Some(response) = response else { continue; };
                    let Some(entry) = peers.get_mut(&response.key).filter(|peer|peer.id==response.id) else { continue; };
                    if sends.len() >= limits.max_pending { counters.capacity_drops += 1; continue; }
                    let encoded = match encode_socks5_packet(&Destination::from(response.key.target),&response.payload) {
                        Ok(packet) => packet, Err(_) => { counters.malformed_packets += 1; continue; }
                    };
                    let Some(remote) = session.response_target(Instant::now()) else { continue; };
                    entry.last_activity = Instant::now();
                    let socket = Arc::clone(&socket);
                    let stop = stop.clone();
                    let duration = limits.operation_timeout;
                    let payload_size = response.payload.len();
                    sends.spawn(async move {
                        tokio::select! {
                            biased;
                            _ = stop.cancelled() => Ok(SendReport::Cancelled),
                            result = timeout(duration,socket.send_to(&encoded,remote)) => {
                                let sent=result.map_err(|_|timed_out("UDP downlink send timed out"))??;
                                if sent!=encoded.len(){return Err(io::Error::new(io::ErrorKind::WriteZero,"partial SOCKS UDP response"));}
                                Ok(SendReport::Downlink(payload_size))
                            }
                        }
                    });
                }
                received = socket.recv_from(&mut packet) => {
                    let (size, source) = match received { Ok(value)=>value,Err(error)=>break Err(error) };
                    if canonical_ip(source.ip()) != canonical_ip(peer.ip())
                        || source.port()==0
                        || (requested_source.port!=0 && source.port()!=requested_source.port)
                        || session.remote_addr().is_some_and(|remote|canonical_ip(remote.ip())!=canonical_ip(source.ip()) || remote.port()!=source.port()) {
                        counters.rejected_source += 1; continue;
                    }
                    if size>SOCKS5_MAX_PACKET_SIZE {counters.malformed_packets+=1;continue;}
                    let datagram=match decode_socks5_packet(&packet[..size]) {
                        Ok(datagram) if valid_destination(&datagram.destination) && !datagram.payload.is_empty()=>datagram,
                        _=>{counters.malformed_packets+=1;continue;}
                    };
                    if !session.accept_source(source,Instant::now()) {counters.rejected_source+=1;continue;}
                    user_stats.traffic.add_uplink(datagram.payload.len());
                    counters.accepted_packets+=1;
                    if pending.len()>=limits.max_pending {counters.capacity_drops+=1;continue;}
                    let context=DispatchContext {destination:datagram.destination,source,inbound_tag:Arc::clone(&inbound_tag),user:Arc::clone(&user),network:"udp"};
                    let dispatcher=Arc::clone(&dispatcher);
                    let duration=limits.operation_timeout;
                    let stop=stop.clone();
                    pending.spawn(async move {
                        let action=tokio::select! {
                            biased;
                            _=stop.cancelled()=>Err(io::Error::new(io::ErrorKind::Interrupted,"UDP association closed")),
                            result=timeout(duration,dispatcher.dispatch(context))=>result.unwrap_or_else(|_|Err(timed_out("UDP dispatch timed out"))),
                        };
                        (action,datagram.payload)
                    });
                }
            }
        };
        stop.cancel();
        session.close();
        peers.clear();
        pending.abort_all();
        readers.abort_all();
        sends.abort_all();
        while pending.join_next().await.is_some() {}
        while readers.join_next().await.is_some() {}
        while let Some(completed) = sends.join_next().await {
            apply_send_report(&mut counters, completed);
        }
        // Shutdown is bounded; dropping control also closes a raw TCP socket.
        let _ = timeout(limits.operation_timeout, control.shutdown()).await;
        result.map(|reason| Outcome { reason, counters })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PeerKey {
    target: SocketAddr,
    route: Option<usize>,
}

struct Peer {
    socket: Arc<UdpSocket>,
    id: u64,
    last_activity: Instant,
    stop: CancellationToken,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
struct Response {
    key: PeerKey,
    id: u64,
    payload: Vec<u8>,
}
enum SendReport {
    Uplink(usize),
    Downlink(usize),
    Cancelled,
}

fn apply_send_report(
    counters: &mut Counters,
    completed: Result<io::Result<SendReport>, tokio::task::JoinError>,
) {
    match completed {
        Ok(Ok(SendReport::Uplink(count))) => {
            counters.uplink_bytes = counters.uplink_bytes.saturating_add(count as u64);
        }
        Ok(Ok(SendReport::Downlink(count))) => {
            counters.downlink_bytes = counters.downlink_bytes.saturating_add(count as u64);
        }
        Ok(Ok(SendReport::Cancelled)) => (),
        Err(error) if error.is_cancelled() => (),
        _ => counters.send_errors = counters.send_errors.saturating_add(1),
    }
}

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub(super) fn valid_endpoint(endpoint: SocketAddr) -> bool {
    endpoint.port() != 0
        && !endpoint.ip().is_unspecified()
        && !endpoint.ip().is_multicast()
        && endpoint.ip() != IpAddr::V4(Ipv4Addr::BROADCAST)
}

pub(super) fn valid_destination(destination: &Destination) -> bool {
    if destination.port == 0 {
        return false;
    }
    match &destination.address {
        Address::Ip(ip) => valid_endpoint(SocketAddr::new(canonical_ip(*ip), destination.port)),
        // Wire codec has already enforced its source-derived ASCII name grammar.
        Address::Domain(host) => !host.is_empty() && host.len() <= 255,
    }
}

fn connected_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    let local = match target.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    // These numeric-address OS calls perform no DNS or admission of their own.
    let socket = std::net::UdpSocket::bind(SocketAddr::new(local, 0))?;
    socket.set_nonblocking(true)?;
    socket.connect(target)?;
    UdpSocket::from_std(socket)
}

fn prune_peers(peers: &mut HashMap<PeerKey, Peer>, idle: Duration) {
    let now = Instant::now();
    peers.retain(|_, peer| now.saturating_duration_since(peer.last_activity) < idle);
}

async fn receive_responses(
    socket: Arc<UdpSocket>,
    key: PeerKey,
    id: u64,
    sender: mpsc::Sender<Response>,
    stop: CancellationToken,
    counters: TrafficCounters,
    user_counters: TrafficCounters,
) {
    let mut buffer = vec![0; 65_536];
    loop {
        let size = tokio::select! {biased; _=stop.cancelled()=>return,result=socket.recv(&mut buffer)=>match result{Ok(size)=>size,Err(_)=>return}};
        counters.add_downlink(size);
        if size > SOCKS5_MAX_PACKET_SIZE {
            continue;
        }
        user_counters.add_downlink(size);
        let response = Response {
            key,
            id,
            payload: buffer[..size].to_vec(),
        };
        tokio::select! {biased; _=stop.cancelled()=>return,result=sender.send(response)=>if result.is_err(){return}}
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::Notify,
        task::JoinHandle,
    };

    const WAIT: Duration = Duration::from_secs(2);
    const QUIET: Duration = Duration::from_millis(60);

    struct Harness {
        control: Option<TcpStream>,
        relay: SocketAddr,
        cancel: CancellationToken,
        task: Option<JoinHandle<io::Result<Outcome>>>,
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.cancel.cancel();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }
    impl Harness {
        async fn finish(mut self) -> Outcome {
            self.cancel.cancel();
            timeout(WAIT, self.task.take().unwrap())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        }
        async fn joined(&mut self) -> Outcome {
            timeout(WAIT, self.task.take().unwrap())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        }
    }

    async fn socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }
    fn requested(port: u16) -> Destination {
        Destination {
            address: Address::Ip(Ipv4Addr::UNSPECIFIED.into()),
            port,
        }
    }

    async fn start(
        source: Destination,
        limits: Limits,
        dispatcher: Arc<dyn UdpDispatcher>,
    ) -> Harness {
        start_with_mapping(source, limits, dispatcher, false).await
    }

    async fn start_with_mapping(
        source: Destination,
        limits: Limits,
        dispatcher: Arc<dyn UdpDispatcher>,
        mapped_peer: bool,
    ) -> Harness {
        start_with_stats(
            source,
            limits,
            dispatcher,
            mapped_peer,
            UserSessionStats::default(),
        )
        .await
    }

    async fn start_with_stats(
        source: Destination,
        limits: Limits,
        dispatcher: Arc<dyn UdpDispatcher>,
        mapped_peer: bool,
        user_stats: UserSessionStats,
    ) -> Harness {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut control = timeout(WAIT, TcpStream::connect(listener.local_addr().unwrap()))
            .await
            .unwrap()
            .unwrap();
        let (server, mut peer) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        if mapped_peer {
            peer.set_ip(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()));
        }
        let association = Association::bind(
            peer,
            AssociateRequest {
                requested_source: source,
                user: "alice".into(),
            },
            Ipv4Addr::LOCALHOST.into(),
            limits,
        )
        .await
        .unwrap()
        .with_stats(user_stats);
        let relay = association.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(association.serve(server, Arc::from("udp-in"), dispatcher, stop));
        let mut prefix = [0; 3];
        timeout(WAIT, control.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prefix, [5, 0, 0]);
        let advertised = timeout(WAIT, Destination::read_socks(&mut control))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(advertised, Destination::from(relay));
        Harness {
            control: Some(control),
            relay,
            cancel,
            task: Some(task),
        }
    }

    async fn send(client: &UdpSocket, relay: SocketAddr, target: &Destination, payload: &[u8]) {
        let packet = encode_socks5_packet(target, payload).unwrap();
        timeout(WAIT, client.send_to(&packet, relay))
            .await
            .unwrap()
            .unwrap();
    }

    async fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = vec![0; 16384];
        let (size, source) = timeout(WAIT, socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        buffer.truncate(size);
        (buffer, source)
    }

    async fn assert_quiet(socket: &UdpSocket) {
        let mut packet = [0; 16384];
        assert!(
            timeout(QUIET, socket.recv_from(&mut packet)).await.is_err(),
            "unexpected UDP delivery"
        );
    }

    #[tokio::test]
    async fn relay_uses_checked_numeric_endpoint_and_dispatches_every_packet() {
        let upstream = socket().await;
        let endpoint = upstream.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&seen);
        let dispatcher: Arc<dyn UdpDispatcher> = Arc::new(move |context: DispatchContext| {
            captured.lock().unwrap().push(context);
            async move { Ok(DispatchAction::Direct(endpoint)) }
        });
        let harness = start(requested(0), Limits::default(), dispatcher).await;
        let client = socket().await;
        let requested = Destination::new("policy.example", 53).unwrap();
        for data in [&b"first"[..], &b"second"[..]] {
            send(&client, harness.relay, &requested, data).await;
            let (body, remote) = receive(&upstream).await;
            assert_eq!(body, data);
            upstream.send_to(b"real-response", remote).await.unwrap();
            let (reply, source) = receive(&client).await;
            assert_eq!(source, harness.relay);
            let reply = decode_socks5_packet(&reply).unwrap();
            assert_eq!(reply.destination, Destination::from(endpoint));
            assert_eq!(reply.payload, b"real-response");
        }
        let contexts = seen.lock().unwrap().clone();
        assert_eq!(contexts.len(), 2);
        for context in contexts {
            assert_eq!(context.destination, requested);
            assert_eq!(context.source, client.local_addr().unwrap());
            assert_eq!(&*context.inbound_tag, "udp-in");
            assert_eq!(&*context.user, "alice");
            assert_eq!(context.network, "udp");
        }
        assert_eq!(harness.finish().await.reason, EndReason::Cancelled);
    }

    #[tokio::test]
    async fn malformed_fragmented_and_oversized_packets_cannot_pin_source() {
        let upstream = socket().await;
        let endpoint = upstream.local_addr().unwrap();
        let dispatcher: Arc<dyn UdpDispatcher> =
            Arc::new(move |_| async move { Ok(DispatchAction::Direct(endpoint)) });
        let harness = start(requested(0), Limits::default(), dispatcher).await;
        let attacker = socket().await;
        let client = socket().await;
        let target = Destination::from(endpoint);
        let mut fragmented = encode_socks5_packet(&target, b"bad").unwrap();
        fragmented[2] = 1;
        let mut zero_port = encode_socks5_packet(&target, b"bad").unwrap();
        zero_port[8] = 0;
        zero_port[9] = 0;
        for packet in [
            fragmented,
            zero_port,
            vec![0, 0],
            vec![0; SOCKS5_MAX_PACKET_SIZE + 1],
            encode_socks5_packet(&target, b"").unwrap(),
        ] {
            attacker.send_to(&packet, harness.relay).await.unwrap();
        }
        assert_quiet(&upstream).await;
        send(&client, harness.relay, &target, b"valid").await;
        assert_eq!(receive(&upstream).await.0, b"valid");
        send(&attacker, harness.relay, &target, b"wrong-pinned-port").await;
        assert_quiet(&upstream).await;
        let outcome = harness.finish().await;
        assert_eq!(outcome.counters.accepted_packets, 1);
        assert_eq!(outcome.counters.malformed_packets, 5);
        assert_eq!(outcome.counters.rejected_source, 1);
    }

    #[tokio::test]
    async fn wildcard_requested_port_is_enforced_and_third_party_ip_is_rejected() {
        let upstream = socket().await;
        let endpoint = upstream.local_addr().unwrap();
        let client = socket().await;
        let attacker = socket().await;
        let dispatcher: Arc<dyn UdpDispatcher> =
            Arc::new(move |_| async move { Ok(DispatchAction::Direct(endpoint)) });
        let harness = start(
            requested(client.local_addr().unwrap().port()),
            Limits::default(),
            dispatcher,
        )
        .await;
        send(
            &attacker,
            harness.relay,
            &Destination::from(endpoint),
            b"wrong-port",
        )
        .await;
        assert_quiet(&upstream).await;
        send(
            &client,
            harness.relay,
            &Destination::from(endpoint),
            b"right-port",
        )
        .await;
        assert_eq!(receive(&upstream).await.0, b"right-port");
        harness.finish().await;
        let request = AssociateRequest {
            requested_source: Destination::from("127.0.0.2:1234".parse::<SocketAddr>().unwrap()),
            user: String::new(),
        };
        let result = Association::bind(
            "127.0.0.1:5678".parse().unwrap(),
            request,
            Ipv4Addr::LOCALHOST.into(),
            Limits::default(),
        )
        .await;
        assert!(matches!(result,Err(error) if error.kind()==io::ErrorKind::PermissionDenied));
    }

    #[tokio::test]
    async fn connected_upstream_discards_unrelated_response_source() {
        let upstream = socket().await;
        let endpoint = upstream.local_addr().unwrap();
        let forged = socket().await;
        let dispatcher: Arc<dyn UdpDispatcher> =
            Arc::new(move |_| async move { Ok(DispatchAction::Direct(endpoint)) });
        let harness = start(requested(0), Limits::default(), dispatcher).await;
        let client = socket().await;
        send(
            &client,
            harness.relay,
            &Destination::from(endpoint),
            b"question",
        )
        .await;
        let (_, remote) = receive(&upstream).await;
        forged.send_to(b"forged-response", remote).await.unwrap();
        assert_quiet(&client).await;
        upstream.send_to(b"trusted-response", remote).await.unwrap();
        assert_eq!(
            decode_socks5_packet(&receive(&client).await.0)
                .unwrap()
                .payload,
            b"trusted-response"
        );
        harness.finish().await;
    }

    #[tokio::test]
    async fn mapped_tcp_and_requested_source_match_ipv4_udp_through_session_helper() {
        let upstream = socket().await;
        let endpoint = upstream.local_addr().unwrap();
        let client = socket().await;
        let dispatcher: Arc<dyn UdpDispatcher> =
            Arc::new(move |_| async move { Ok(DispatchAction::Direct(endpoint)) });
        let source = Destination {
            address: Address::Ip(Ipv4Addr::LOCALHOST.to_ipv6_mapped().into()),
            port: client.local_addr().unwrap().port(),
        };
        let harness = start_with_mapping(source, Limits::default(), dispatcher, true).await;
        send(
            &client,
            harness.relay,
            &Destination::from(endpoint),
            b"mapped",
        )
        .await;
        let (payload, remote) = receive(&upstream).await;
        assert_eq!(payload, b"mapped");
        upstream.send_to(b"v4-response", remote).await.unwrap();
        assert_eq!(
            decode_socks5_packet(&receive(&client).await.0)
                .unwrap()
                .payload,
            b"v4-response"
        );
        assert_eq!(harness.finish().await.counters.accepted_packets, 1);
    }

    #[tokio::test]
    async fn dispatch_timeout_releases_capacity_and_association_remains_usable() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let dispatcher: Arc<dyn UdpDispatcher> = Arc::new(move |_| {
            let first = count.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                if first {
                    std::future::pending::<()>().await;
                }
                Ok(DispatchAction::Drop)
            }
        });
        let harness = start(
            requested(0),
            Limits {
                max_pending: 1,
                operation_timeout: Duration::from_millis(30),
                ..Default::default()
            },
            dispatcher,
        )
        .await;
        let client = socket().await;
        let target = Destination::new("127.0.0.1", 53).unwrap();
        send(&client, harness.relay, &target, b"timeout").await;
        sleep(Duration::from_millis(90)).await;
        send(&client, harness.relay, &target, b"next").await;
        sleep(Duration::from_millis(30)).await;
        let outcome = harness.finish().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(outcome.counters.dispatch_errors, 1);
        assert_eq!(outcome.counters.policy_drops, 1);
    }

    #[tokio::test]
    async fn blackhole_and_peer_capacity_do_not_fall_back_to_direct() {
        let first = socket().await;
        let second = socket().await;
        let a = first.local_addr().unwrap();
        let b = second.local_addr().unwrap();
        let dispatcher: Arc<dyn UdpDispatcher> =
            Arc::new(move |context: DispatchContext| async move {
                if context.destination.port == 9 {
                    Ok(DispatchAction::Drop)
                } else if context.destination.port == a.port() {
                    Ok(DispatchAction::Direct(a))
                } else {
                    Ok(DispatchAction::Direct(b))
                }
            });
        let harness = start(
            requested(0),
            Limits {
                max_peers: 1,
                ..Default::default()
            },
            dispatcher,
        )
        .await;
        let client = socket().await;
        send(&client, harness.relay, &Destination::from(a), b"first").await;
        let (_, remote) = receive(&first).await;
        send(&client, harness.relay, &Destination::from(b), b"capacity").await;
        assert_quiet(&second).await;
        send(
            &client,
            harness.relay,
            &Destination::new("127.0.0.1", 9).unwrap(),
            b"blackhole",
        )
        .await;
        assert_quiet(&first).await;
        assert_quiet(&second).await;
        first.send_to(b"still-live", remote).await.unwrap();
        assert_eq!(
            decode_socks5_packet(&receive(&client).await.0)
                .unwrap()
                .payload,
            b"still-live"
        );
        let outcome = harness.finish().await;
        assert_eq!(outcome.counters.capacity_drops, 1);
        assert_eq!(outcome.counters.policy_drops, 1);
    }

    #[tokio::test]
    async fn control_eof_and_cancellation_abort_blocked_dispatch_and_release_udp() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for eof in [false, true] {
            let started = Arc::new(Notify::new());
            let dropped = Arc::new(AtomicBool::new(false));
            let notice = Arc::clone(&started);
            let was_dropped = Arc::clone(&dropped);
            let dispatcher: Arc<dyn UdpDispatcher> = Arc::new(move |_| {
                let notice = Arc::clone(&notice);
                let dropped = Arc::clone(&was_dropped);
                async move {
                    let _guard = Dropped(dropped);
                    notice.notify_one();
                    std::future::pending::<io::Result<DispatchAction>>().await
                }
            });
            let mut harness = start(
                requested(0),
                Limits {
                    max_pending: 1,
                    ..Default::default()
                },
                dispatcher,
            )
            .await;
            let client = socket().await;
            send(
                &client,
                harness.relay,
                &Destination::new("127.0.0.1", 53).unwrap(),
                b"wait",
            )
            .await;
            timeout(WAIT, started.notified()).await.unwrap();
            send(
                &client,
                harness.relay,
                &Destination::new("127.0.0.1", 53).unwrap(),
                b"over-capacity",
            )
            .await;
            sleep(Duration::from_millis(20)).await;
            if eof {
                drop(harness.control.take());
            } else {
                harness.cancel.cancel();
            }
            let outcome = harness.joined().await;
            assert_eq!(
                outcome.reason,
                if eof {
                    EndReason::ControlClosed
                } else {
                    EndReason::Cancelled
                }
            );
            assert!(dropped.load(Ordering::SeqCst));
            assert_eq!(outcome.counters.capacity_drops, 1);
            let rebound = UdpSocket::bind(harness.relay).await.unwrap();
            drop(rebound);
        }
    }

    #[tokio::test]
    async fn tcp_control_data_and_invalid_udp_do_not_extend_idle_deadline() {
        let dispatcher: Arc<dyn UdpDispatcher> = Arc::new(|_| async { Ok(DispatchAction::Drop) });
        let mut harness = start(
            requested(0),
            Limits {
                idle_timeout: Duration::from_millis(100),
                operation_timeout: Duration::from_millis(100),
                ..Default::default()
            },
            dispatcher,
        )
        .await;
        let client = socket().await;
        for _ in 0..4 {
            harness
                .control
                .as_mut()
                .unwrap()
                .write_all(&[1; 32])
                .await
                .unwrap();
            client.send_to(&[0, 0, 1], harness.relay).await.unwrap();
            sleep(Duration::from_millis(15)).await;
        }
        let outcome = harness.joined().await;
        assert_eq!(outcome.reason, EndReason::IdleTimeout);
        assert_eq!(outcome.counters.accepted_packets, 0);
        assert_eq!(
            timeout(WAIT, harness.control.as_mut().unwrap().read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn bounds_and_unicast_destination_validation_are_explicit() {
        for limits in [
            Limits {
                max_peers: 0,
                ..Default::default()
            },
            Limits {
                max_pending: 1025,
                ..Default::default()
            },
            Limits {
                response_queue: 0,
                ..Default::default()
            },
            Limits {
                operation_timeout: Duration::ZERO,
                ..Default::default()
            },
        ] {
            assert!(limits.validate().is_err());
        }
        for endpoint in [
            "0.0.0.0:53",
            "127.0.0.1:0",
            "224.0.0.1:53",
            "255.255.255.255:53",
            "[::]:53",
            "[ff02::1]:53",
        ] {
            assert!(
                !valid_destination(&Destination::from(endpoint.parse::<SocketAddr>().unwrap())),
                "{endpoint}"
            );
        }
        assert_eq!(
            canonical_ip("::ffff:127.0.0.1".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert!(valid_destination(
            &Destination::new("dns.example", 53).unwrap()
        ));
    }

    #[tokio::test]
    async fn same_endpoint_routes_have_separate_sockets_and_real_io_counters() {
        use crate::features::{
            StatsManager,
            policy::{SystemStatsPolicy, UserStatsPolicy},
        };
        let stats = StatsManager::new();
        let policy = SystemStatsPolicy {
            outbound_uplink: true,
            outbound_downlink: true,
            ..Default::default()
        };
        let first = stats.outbound_counters("first", policy);
        let second = stats.outbound_counters("second", policy);
        let user = stats.user_session(
            "alice",
            "192.0.2.1",
            UserStatsPolicy {
                user_uplink: true,
                user_downlink: true,
                user_online: true,
            },
        );
        let user_traffic = user.traffic.clone();
        let online = stats.get_online_map("user>>>alice>>>online").unwrap();
        let upstream = socket().await;
        let target = upstream.local_addr().unwrap();
        let first_counters = first.clone();
        let second_counters = second.clone();
        let dispatch: Arc<dyn UdpDispatcher> = Arc::new(move |context: DispatchContext| {
            let route = usize::from(context.destination.port == 54);
            let counters = if route == 0 {
                first_counters.clone()
            } else {
                second_counters.clone()
            };
            async move {
                Ok(DispatchAction::TrackedDirect {
                    target,
                    route,
                    counters,
                })
            }
        });
        let harness =
            start_with_stats(requested(0), Limits::default(), dispatch, false, user).await;
        let client = socket().await;
        send(
            &client,
            harness.relay,
            &Destination::new("route.test", 53).unwrap(),
            b"one",
        )
        .await;
        let (body, first_peer) = receive(&upstream).await;
        assert_eq!(body, b"one");
        send(
            &client,
            harness.relay,
            &Destination::new("route.test", 54).unwrap(),
            b"second",
        )
        .await;
        let (body, second_peer) = receive(&upstream).await;
        assert_eq!(body, b"second");
        assert_ne!(
            first_peer, second_peer,
            "different routes must not share a socket"
        );
        upstream.send_to(b"first-answer", first_peer).await.unwrap();
        assert_eq!(
            decode_socks5_packet(&receive(&client).await.0)
                .unwrap()
                .payload,
            b"first-answer"
        );
        upstream
            .send_to(b"second-answer", second_peer)
            .await
            .unwrap();
        assert_eq!(
            decode_socks5_packet(&receive(&client).await.0)
                .unwrap()
                .payload,
            b"second-answer"
        );
        assert_eq!(first.uplink.unwrap().value(), 3);
        assert_eq!(second.uplink.unwrap().value(), 6);
        assert_eq!(first.downlink.unwrap().value(), 12);
        assert_eq!(second.downlink.unwrap().value(), 13);
        assert_eq!(user_traffic.uplink.unwrap().value(), 9);
        assert_eq!(user_traffic.downlink.unwrap().value(), 25);
        assert_eq!(online.count(), 1);
        harness.finish().await;
        assert_eq!(online.count(), 0);
        assert!(
            stats
                .get_counter("inbound>>>udp-in>>>traffic>>>uplink")
                .is_none()
        );
    }

    #[tokio::test]
    async fn policy_drop_counts_user_link_payload_but_no_outbound_io() {
        use crate::features::{
            StatsManager,
            policy::{SystemStatsPolicy, UserStatsPolicy},
        };
        let stats = StatsManager::new();
        let outbound = stats.outbound_counters(
            "blocked",
            SystemStatsPolicy {
                outbound_uplink: true,
                outbound_downlink: true,
                ..Default::default()
            },
        );
        let user = stats.user_session(
            "alice",
            "192.0.2.1",
            UserStatsPolicy {
                user_uplink: true,
                user_downlink: true,
                user_online: true,
            },
        );
        let user_traffic = user.traffic.clone();
        let online = stats.get_online_map("user>>>alice>>>online").unwrap();
        let seen = Arc::new(Notify::new());
        let called = Arc::clone(&seen);
        let dispatch: Arc<dyn UdpDispatcher> = Arc::new(move |_| {
            called.notify_one();
            async { Ok(DispatchAction::Drop) }
        });
        let mut harness =
            start_with_stats(requested(0), Limits::default(), dispatch, false, user).await;
        let client = socket().await;
        client.send_to(&[0, 0, 1], harness.relay).await.unwrap();
        send(
            &client,
            harness.relay,
            &Destination::new("blocked.test", 53).unwrap(),
            b"dropped",
        )
        .await;
        timeout(WAIT, seen.notified()).await.unwrap();
        assert_eq!(user_traffic.uplink.unwrap().value(), 7);
        assert_eq!(user_traffic.downlink.unwrap().value(), 0);
        assert_eq!(outbound.uplink.unwrap().value(), 0);
        assert_eq!(outbound.downlink.unwrap().value(), 0);
        harness.control.take();
        assert_eq!(harness.joined().await.reason, EndReason::ControlClosed);
        assert_eq!(online.count(), 0);
    }

    #[tokio::test]
    async fn cancellation_drains_ready_send_reports_without_counting_aborts_as_errors() {
        let receiver = socket().await;
        let target = receiver.local_addr().unwrap();
        let sender = Arc::new(socket().await);
        let uplink_sender = Arc::clone(&sender);
        let mut sends = JoinSet::new();
        let uplink = sends.spawn(async move {
            Ok(SendReport::Uplink(
                uplink_sender.send_to(b"uplink", target).await?,
            ))
        });
        let downlink = sends.spawn(async move {
            Ok(SendReport::Downlink(
                sender.send_to(b"downlink", target).await?,
            ))
        });
        let failed = sends.spawn(async {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "real send failure",
            ))
        });
        let cancelled = sends.spawn(async { Ok(SendReport::Cancelled) });
        sends.spawn(std::future::pending::<io::Result<SendReport>>());
        // Completed jobs remain uncollected, making the cancellation/report
        // race deterministic without depending on a particular UDP scheduler.
        timeout(WAIT, async {
            while !uplink.is_finished()
                || !downlink.is_finished()
                || !failed.is_finished()
                || !cancelled.is_finished()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => (),
            _ = sends.join_next() => panic!("biased cancellation should win"),
        }
        sends.abort_all();
        let mut counters = Counters::default();
        while let Some(completed) = sends.join_next().await {
            apply_send_report(&mut counters, completed);
        }
        assert_eq!(counters.uplink_bytes, 6);
        assert_eq!(counters.downlink_bytes, 8);
        assert_eq!(counters.send_errors, 1);
    }
}
