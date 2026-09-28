//! CONTRACT (fixed by the integrator): the Shadowsocks-2022 UDP listener,
//! one per `network: "tcp,udp"` 2022 inbound, bound on the same address:port
//! as the TCP listener.
//!
//! OWNER: wiring batch agent A-UDP. This runtime drives
//! [`crate::protocol::shadowsocks2022::udp::Server`], the socket-free port of
//! the pinned sing single-key 2022 UDP service that Go's single-account
//! `proxy/shadowsocks_2022/inbound.go` uses (`NewServiceWithPassword` with the
//! 500-second UDP timeout). The Phase-0 stub named
//! `protocol::ss2022_udp::UdpServer`; that component is the multi-user EIH
//! service of Go's `shadowsocks-2022-multi` inbound — it rejects the
//! single-key request wire this single-account inbound receives and cannot be
//! built from the configured `shadowsocks2022::Account` (which exposes no raw
//! PSK), so using it would break every real single-user client. The
//! substituted component's module doc prescribes the same rules the stub
//! cites: callers serialize access to one server per listener, supply clocks
//! and randomness explicitly, and route only admitted datagrams. Both
//! components are pinned to the same sing-shadowsocks v0.2.7 packet format,
//! so a single-key `ss2022_udp::UdpClient` interoperates with this listener.
//!
//! Inbound datagrams are authenticated per packet, dispatched through
//! `dispatcher.udp` (the `udp::UdpDispatcher`, exactly like the SOCKS packet
//! session in `runtime/udp.rs`), sent through a connected upstream socket per
//! (session, target, route) so distinct client sessions never share replies,
//! and responses return through `Server::encode_reply` to the session's
//! latest authenticated peer. An invalid packet ends nothing: Go's per-source
//! read loop returns on the error and the next packet restarts it, so the
//! net behavior is drop-and-continue. A periodic sweep expires idle sessions
//! and peers; every buffer and in-flight set is bounded by `udp::Limits`.
//!
//! Contract gap (reported): the runtime does not hand the listener the
//! inbound tag, so `DispatchContext::inbound_tag` is empty and
//! inboundTag-based routing rules cannot match until `run` takes one.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use rand::rngs::OsRng;
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::JoinSet,
    time::{MissedTickBehavior, interval, timeout},
};
use tokio_util::sync::CancellationToken;

use super::{Dispatcher, udp};
use crate::{
    address::Destination,
    features::stats::TrafficCounters,
    protocol::shadowsocks2022::{self, Account, udp::SessionToken},
};

pub(super) struct Ss2022UdpListener {
    socket: Arc<UdpSocket>,
    server: shadowsocks2022::udp::Server,
    user: Arc<str>,
}

impl Ss2022UdpListener {
    /// Bind the UDP socket and build the single-user 2022 UDP service. Fails
    /// explicitly so a `tcp,udp` inbound never starts without its UDP half.
    pub(super) fn bind(address: SocketAddr, account: &Account) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(address)
            .with_context(|| format!("bind Shadowsocks 2022 UDP listener on {address}"))?;
        socket
            .set_nonblocking(true)
            .context("set Shadowsocks 2022 UDP listener non-blocking")?;
        let server = shadowsocks2022::udp::Server::new(account)
            .context("build the Shadowsocks 2022 single-user UDP service")?;
        Ok(Self {
            socket: Arc::new(UdpSocket::from_std(socket)?),
            server,
            user: Arc::from(account.email()),
        })
    }

    pub(super) async fn run(
        self,
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let Ss2022UdpListener {
            socket,
            mut server,
            user,
        } = self;
        let udp_dispatcher = dispatcher
            .udp
            .as_ref()
            .context("Shadowsocks 2022 UDP dispatcher unavailable")?
            .clone();
        let limits = udp::Limits::default();
        limits.validate()?;
        let inbound_tag: Arc<str> = Arc::from("");

        let (reply_tx, mut reply_rx) = mpsc::channel::<Response>(limits.response_queue);
        let stop = CancellationToken::new();
        let mut peers: HashMap<PeerKey, Peer> = HashMap::new();
        let mut readers = JoinSet::new();
        let mut pending = JoinSet::new();
        let mut sends = JoinSet::new();
        let mut next_id = 0u64;
        let mut counters = Counters::default();
        // Large enough to detect and discard an oversized datagram without
        // truncating it into a valid packet.
        let mut packet = vec![0; 65_536];
        let mut maintenance = interval(limits.peer_idle_timeout.min(Duration::from_secs(1)));
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let result: Result<()> = loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break Ok(()),
                _ = maintenance.tick() => {
                    server.expire(Instant::now());
                    prune_peers(&mut peers, limits.peer_idle_timeout);
                }
                received = socket.recv_from(&mut packet) => {
                    let (size, peer) = match received {
                        Ok(received) => received,
                        Err(error) => break Err(anyhow::Error::new(error).context("Shadowsocks 2022 UDP listener receive failed")),
                    };
                    let now = Instant::now();
                    let unix = match unix_now() {
                        Ok(unix) => unix,
                        Err(error) => break Err(error),
                    };
                    let accepted = server.accept_from(peer, &packet[..size], unix, now, &mut OsRng);
                    let accepted = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            // Go: NewPacket errors end the per-source loop and
                            // the next packet restarts it; drop and continue.
                            counters.rejected_packets += 1;
                            tracing::debug!(%peer, %error, "dropping invalid Shadowsocks 2022 UDP packet");
                            continue;
                        }
                    };
                    counters.accepted_packets += 1;
                    if !udp::valid_destination(&accepted.datagram.destination) {
                        counters.malformed_datagrams += 1;
                        continue;
                    }
                    if pending.len() >= limits.max_pending {
                        counters.capacity_drops += 1;
                        continue;
                    }
                    let context = udp::DispatchContext {
                        destination: accepted.datagram.destination,
                        source: peer,
                        inbound_tag: Arc::clone(&inbound_tag),
                        user: Arc::clone(&user),
                        network: "udp",
                    };
                    let payload = accepted.datagram.payload;
                    let token = accepted.session.clone();
                    let dispatcher = Arc::clone(&udp_dispatcher);
                    let duration = limits.operation_timeout;
                    let stop_token = stop.clone();
                    pending.spawn(async move {
                        let action = tokio::select! {
                            biased;
                            _ = stop_token.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "Shadowsocks 2022 UDP listener closed")),
                            result = timeout(duration, dispatcher.dispatch(context)) => {
                                result.unwrap_or_else(|_| Err(timed_out("Shadowsocks 2022 UDP dispatch timed out")))
                            }
                        };
                        (action, payload, token)
                    });
                }
                completed = pending.join_next(), if !pending.is_empty() => {
                    let Some(Ok((action, payload, token))) = completed else { counters.dispatch_errors += 1; continue; };
                    let action = match action { Ok(action) => action, Err(_) => { counters.dispatch_errors += 1; continue; } };
                    let (mut target, route, outbound_counters) = match action {
                        udp::DispatchAction::Drop => { counters.policy_drops += 1; continue; }
                        udp::DispatchAction::Direct(target) => (target, None, TrafficCounters::default()),
                        udp::DispatchAction::TrackedDirect { target, route, counters } => (target, Some(route), counters),
                    };
                    target.set_ip(udp::canonical_ip(target.ip()));
                    if !udp::valid_endpoint(target) { counters.dispatch_errors += 1; continue; }
                    let key = PeerKey { session: token.session_id(), target, route };
                    if sends.len() >= limits.max_pending { counters.capacity_drops += 1; continue; }
                    prune_peers(&mut peers, limits.peer_idle_timeout);
                    if !peers.contains_key(&key) {
                        if peers.len() >= limits.max_peers || readers.len() >= limits.max_peers * 2 {
                            counters.capacity_drops += 1; continue;
                        }
                        let upstream = match connected_socket(target) {
                            Ok(socket) => Arc::new(socket),
                            Err(_) => { counters.send_errors += 1; continue; }
                        };
                        next_id = next_id.wrapping_add(1);
                        let id = next_id;
                        let peer_stop = stop.child_token();
                        let reader_socket = Arc::clone(&upstream);
                        let reader_stop = peer_stop.clone();
                        let sender = reply_tx.clone();
                        let reader_counters = outbound_counters.clone();
                        readers.spawn(async move {
                            receive_responses(reader_socket, key, id, sender, reader_stop, reader_counters).await;
                            (key, id)
                        });
                        // The peer keeps the token of the dispatch that created
                        // it: if the client session expires and the same id is
                        // admitted again, replies fail closed instead of
                        // crossing to the new session.
                        peers.insert(key, Peer { socket: upstream, id, last_activity: Instant::now(), stop: peer_stop, token });
                    } else {
                        peers.get_mut(&key).expect("entry checked above").last_activity = Instant::now();
                    }
                    let entry = peers.get_mut(&key).expect("entry present");
                    let upstream = Arc::clone(&entry.socket);
                    let peer_stop = entry.stop.clone();
                    let duration = limits.operation_timeout;
                    sends.spawn(async move {
                        tokio::select! {
                            biased;
                            _ = peer_stop.cancelled() => Ok(SendReport::Cancelled),
                            result = timeout(duration, upstream.send(&payload)) => {
                                let sent = result.map_err(|_| timed_out("Shadowsocks 2022 UDP uplink send timed out"))??;
                                outbound_counters.add_uplink(sent);
                                if sent != payload.len() {
                                    return Err(io::Error::new(io::ErrorKind::WriteZero, "partial Shadowsocks 2022 UDP datagram send"));
                                }
                                Ok(SendReport::Uplink(sent))
                            }
                        }
                    });
                }
                completed = readers.join_next(), if !readers.is_empty() => {
                    if let Some(Ok((target, id))) = completed
                        && peers.get(&target).is_some_and(|peer| peer.id == id) {
                        peers.remove(&target);
                    }
                }
                response = reply_rx.recv() => {
                    let Some(response) = response else { continue; };
                    let Some(entry) = peers.get_mut(&response.key).filter(|peer| peer.id == response.id) else { continue; };
                    entry.last_activity = Instant::now();
                    let unix = match unix_now() {
                        Ok(unix) => unix,
                        Err(error) => break Err(error),
                    };
                    let origin = Destination::from(response.key.target);
                    let reply = server.encode_reply(&entry.token, &origin, &response.payload, unix, Instant::now(), &mut OsRng);
                    let reply = match reply {
                        Ok(reply) => reply,
                        Err(error) => {
                            // The client session expired while its datagram was
                            // in flight; Go's link is interrupted the same way.
                            counters.expired_sessions += 1;
                            tracing::debug!(%error, "dropping Shadowsocks 2022 UDP reply for an expired session");
                            continue;
                        }
                    };
                    if sends.len() >= limits.max_pending { counters.capacity_drops += 1; continue; }
                    let socket = Arc::clone(&socket);
                    let stop_token = stop.clone();
                    let duration = limits.operation_timeout;
                    let target = reply.peer;
                    let wire = reply.wire;
                    sends.spawn(async move {
                        tokio::select! {
                            biased;
                            _ = stop_token.cancelled() => Ok(SendReport::Cancelled),
                            result = timeout(duration, socket.send_to(&wire, target)) => {
                                let sent = result.map_err(|_| timed_out("Shadowsocks 2022 UDP reply send timed out"))??;
                                if sent != wire.len() {
                                    return Err(io::Error::new(io::ErrorKind::WriteZero, "partial Shadowsocks 2022 UDP reply"));
                                }
                                Ok(SendReport::Downlink(sent))
                            }
                        }
                    });
                }
                completed = sends.join_next(), if !sends.is_empty() => {
                    if let Some(completed) = completed { apply_send_report(&mut counters, completed); }
                }
            }
        };
        stop.cancel();
        peers.clear();
        pending.abort_all();
        readers.abort_all();
        sends.abort_all();
        while pending.join_next().await.is_some() {}
        while readers.join_next().await.is_some() {}
        while let Some(completed) = sends.join_next().await {
            apply_send_report(&mut counters, completed);
        }
        tracing::debug!(counters = ?counters, "Shadowsocks 2022 UDP listener closed");
        result
    }
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before 1970")?
        .as_secs())
}

#[derive(Debug, Default)]
struct Counters {
    accepted_packets: u64,
    rejected_packets: u64,
    malformed_datagrams: u64,
    policy_drops: u64,
    dispatch_errors: u64,
    capacity_drops: u64,
    send_errors: u64,
    expired_sessions: u64,
    uplink_bytes: u64,
    downlink_bytes: u64,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct PeerKey {
    session: u64,
    target: SocketAddr,
    route: Option<usize>,
}

struct Peer {
    socket: Arc<UdpSocket>,
    id: u64,
    last_activity: Instant,
    stop: CancellationToken,
    token: SessionToken,
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
) {
    let mut buffer = vec![0; 65_536];
    loop {
        let size = tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            result = socket.recv(&mut buffer) => match result { Ok(size) => size, Err(_) => return },
        };
        counters.add_downlink(size);
        // The 2022 packet format caps packets at MaxPacketSize; anything
        // larger cannot be re-sealed and is dropped whole.
        if size > shadowsocks2022::udp::MAX_PACKET_SIZE {
            continue;
        }
        let response = Response {
            key,
            id,
            payload: buffer[..size].to_vec(),
        };
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            result = sender.send(response) => if result.is_err() { return },
        }
    }
}

fn connected_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    let local = match target.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    // These numeric-address OS calls perform no DNS or admission of their own.
    let socket = std::net::UdpSocket::bind(local)?;
    socket.set_nonblocking(true)?;
    socket.connect(target)?;
    UdpSocket::from_std(socket)
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ss2022_udp;
    use crate::{Config, Server};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    use tokio::{net::TcpListener, task::JoinHandle, time::timeout};

    const WAIT: Duration = Duration::from_secs(5);
    const QUIET: Duration = Duration::from_millis(150);

    /// A loopback UDP socket that echoes every datagram back to its source.
    struct Echo {
        address: SocketAddr,
        task: JoinHandle<()>,
    }
    impl Drop for Echo {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn udp_echo() -> Echo {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_536];
            loop {
                let (size, source) = socket.recv_from(&mut buffer).await.unwrap();
                socket.send_to(&buffer[..size], source).await.unwrap();
            }
        });
        Echo { address, task }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// The SS2022 UDP listener shares the configured TCP port, which a zero
    /// port would re-randomize; discover a free loopback port and retry the
    /// whole startup when another socket races us to it.
    async fn start_on_free_port(settings: serde_json::Value) -> Server {
        for attempt in 0..3 {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let config = Config::from_json(
                &json!({
                    "inbounds": [{
                        "listen": "127.0.0.1", "port": port, "tag": "ss-in",
                        "protocol": "shadowsocks", "settings": settings
                    }],
                    "outbounds": [{"tag": "direct", "protocol": "freedom"}]
                })
                .to_string(),
            )
            .unwrap();
            match Server::start(config).await {
                Ok(server) => return server,
                Err(error) if attempt < 2 => {
                    let _ = error;
                }
                Err(error) => panic!("SS2022 inbound failed to start: {error:#}"),
            }
        }
        unreachable!("the loop returns or panics on the last attempt")
    }

    #[tokio::test]
    async fn ss2022_udp_inbound_relays_datagrams_and_drops_invalid_packets() {
        timeout(Duration::from_secs(10), async {
            let echo = udp_echo().await;
            let psk: Vec<u8> = (0..16u8).collect();
            let password = STANDARD.encode(&psk);
            let server = start_on_free_port(json!({
                "method": "2022-blake3-aes-128-gcm",
                "password": password,
                "network": "tcp,udp",
            }))
            .await;
            let listener = SocketAddr::from(([127, 0, 0, 1], server.local_addresses()[0].port()));

            // A single-key ss2022_udp::UdpClient speaks exactly the pinned
            // single-key 2022 UDP wire this inbound serves.
            let mut session = ss2022_udp::UdpClient::with_session_id(
                ss2022_udp::Method::Aes128Gcm,
                &password,
                0x0123_4567_89ab_cdef,
            )
            .unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut buffer = vec![0u8; 65_536];

            async fn roundtrip(
                session: &mut ss2022_udp::UdpClient,
                client: &tokio::net::UdpSocket,
                buffer: &mut [u8],
                destination: &Destination,
                listener: std::net::SocketAddr,
                payload: &'static [u8],
            ) {
                let wire = session
                    .encode(destination, payload, unix_now(), &mut OsRng)
                    .unwrap();
                client.send_to(&wire, listener).await.unwrap();
                let (size, _) = timeout(WAIT, client.recv_from(buffer))
                    .await
                    .unwrap()
                    .unwrap();
                let datagram = session.decode_reply(&buffer[..size], unix_now()).unwrap();
                assert_eq!(datagram.destination, *destination);
                assert_eq!(datagram.payload, payload);
            }
            roundtrip(
                &mut session,
                &client,
                &mut buffer,
                &Destination::from(echo.address),
                listener,
                b"ss2022-udp-ping",
            )
            .await;

            // An unauthenticated datagram is dropped and the listener keeps
            // serving the same session afterwards.
            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            attacker
                .send_to(b"not a shadowsocks 2022 packet", listener)
                .await
                .unwrap();
            let mut junk = [0u8; 64];
            assert!(
                timeout(QUIET, attacker.recv_from(&mut junk)).await.is_err(),
                "unexpected reply to an unauthenticated packet"
            );
            roundtrip(
                &mut session,
                &client,
                &mut buffer,
                &Destination::from(echo.address),
                listener,
                b"still-alive",
            )
            .await;

            server.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }
}
