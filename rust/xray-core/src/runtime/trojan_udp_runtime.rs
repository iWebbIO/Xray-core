//! Trojan UDP-over-TCP association, ported from `proxy/trojan/server.go`
//! `handleUDPPayload` over the `trojan_udp` frame codec.
//!
//! Go multiplexes every frame through one dispatched outbound link and writes
//! responses back through the association's own TCP stream. The Rust UDP
//! dispatch model is per-datagram (exactly like the SOCKS association in
//! `runtime/udp.rs`): each frame's destination goes through `dispatcher.udp`,
//! an admitted endpoint gets a connected upstream socket per (target, route),
//! and responses return as frames whose destination is the remote UDP source.
//! Go's cone `dest` pinning only chooses the destination used to re-establish
//! its single reusable link; per-packet delivery always follows the frame's
//! own in-band destination, which the per-frame dispatch preserves.
//!
//! Association lifecycle, matching Go: the zero-length close frame (this
//! port's explicit close signal) and a clean TCP EOF both end the whole
//! association after any already-parsed frames are dispatched — Go's
//! `requestDone` returns on `io.EOF` and the handler closes the connection.
//! A malformed frame ends the association with an error (Go: "unexpected
//! EOF"). Bytes the client keeps sending after the close are discarded with
//! the connection, like Go. The inactivity deadline is refreshed by frames
//! and by response writes (Go's `timer.Update()`), and cancellation ends the
//! association immediately.
//!
//! Contract gap (reported): `serve` is not handed the TCP peer address, so
//! `DispatchContext::source` carries the unspecified endpoint and
//! source-based routing rules cannot match; Go would route with the real
//! TCP peer.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{MissedTickBehavior, interval, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

use super::{Dispatcher, udp};
use crate::{
    address::Destination,
    features::stats::TrafficCounters,
    protocol::{Request, trojan_udp, trojan_udp::UdpFrame},
    transport::BoxStream,
};

pub(super) async fn serve(
    stream: BoxStream,
    request: Request,
    dispatcher: &Dispatcher,
    tag: &str,
    cancel: &CancellationToken,
) -> Result<()> {
    let policy = dispatcher.policy.for_level(0);
    ensure!(
        !policy.timeouts.connection_idle.is_zero(),
        "proxy session inactivity timeout"
    );
    let udp_dispatcher = dispatcher
        .udp
        .as_ref()
        .context("Trojan UDP dispatcher unavailable")?
        .clone();
    let limits = udp::Limits {
        idle_timeout: policy.timeouts.connection_idle,
        operation_timeout: policy
            .timeouts
            .connection_idle
            .min(udp::Limits::default().operation_timeout),
        ..udp::Limits::default()
    };
    limits.validate()?;

    let (reader, writer) = tokio::io::split(stream);
    let (frame_tx, mut frame_rx) = mpsc::channel::<UdpFrame>(limits.response_queue);
    let (reply_tx, mut reply_rx) = mpsc::channel::<Response>(limits.response_queue);
    let (out_tx, out_rx) = mpsc::channel::<UdpFrame>(limits.response_queue);
    let stop = CancellationToken::new();

    // Client direction: decode frames off the TCP stream. Returning means the
    // zero-length close frame, a clean EOF, or a malformed frame (error).
    let mut read_pump: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut reader = reader;
        trojan_udp::pump_frames_to_queue(&mut reader, frame_tx).await
    });
    // Server direction: response frames, then the zero-length close frame
    // addressed to the request's own destination (Go `PacketWriter.Target`),
    // then the TCP write side is shut down with the association.
    let close_target = request.destination.clone();
    let mut write_pump: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut writer = writer;
        trojan_udp::pump_queue_to_frames(&mut writer, &close_target, out_rx).await?;
        writer
            .shutdown()
            .await
            .map_err(io::Error::other)
            .context("shutdown Trojan UDP reply stream")?;
        Ok(())
    });

    let inbound_tag: Arc<str> = tag.into();
    let user: Arc<str> = request.user.into();
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    let mut peers: HashMap<PeerKey, Peer> = HashMap::new();
    let mut readers = JoinSet::new();
    let mut pending = JoinSet::new();
    let mut sends = JoinSet::new();
    let mut next_id = 0u64;
    let mut counters = Counters::default();
    let mut idle_since = tokio::time::Instant::now();
    let mut maintenance = interval(limits.peer_idle_timeout.min(Duration::from_secs(1)));
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let result: Result<EndReason> = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(EndReason::Cancelled),
            _ = sleep_until(idle_since + limits.idle_timeout) => break Ok(EndReason::IdleTimeout),
            // The client direction ended. Frames decoded before the terminator
            // were dispatched in order by Go's requestDone, so drain them
            // before ending the whole association (Go returns on io.EOF).
            result = &mut read_pump => {
                while let Ok(frame) = frame_rx.try_recv() {
                    enqueue_dispatch(
                        frame, &mut pending, &mut counters, &limits, source,
                        &inbound_tag, &user, &udp_dispatcher, &stop,
                    );
                }
                break match result {
                    Ok(Ok(())) => Ok(EndReason::ClientClosed),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(error).context("Trojan UDP frame pump task panicked"),
                };
            }
            // Only reachable while out_tx is alive, i.e. a write error on the
            // client stream; Go cancels the association on write failure.
            result = &mut write_pump => {
                break match result {
                    Ok(Ok(())) => Ok(EndReason::WriterClosed),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(error).context("Trojan UDP reply writer task panicked"),
                };
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else { continue };
                idle_since = tokio::time::Instant::now();
                enqueue_dispatch(
                    frame, &mut pending, &mut counters, &limits, source,
                    &inbound_tag, &user, &udp_dispatcher, &stop,
                );
            }
            completed = pending.join_next(), if !pending.is_empty() => {
                let Some(Ok((action, payload))) = completed else { counters.dispatch_errors += 1; continue; };
                let action = match action { Ok(action) => action, Err(_) => { counters.dispatch_errors += 1; continue; } };
                let (mut target, route, outbound_counters) = match action {
                    udp::DispatchAction::Drop => { counters.policy_drops += 1; continue; }
                    udp::DispatchAction::Direct(target) => (target, None, TrafficCounters::default()),
                    udp::DispatchAction::TrackedDirect { target, route, counters } => (target, Some(route), counters),
                };
                target.set_ip(udp::canonical_ip(target.ip()));
                if !udp::valid_endpoint(target) { counters.dispatch_errors += 1; continue; }
                let key = PeerKey { target, route };
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
                        result = timeout(duration, upstream.send(&payload)) => {
                            let sent = result.map_err(|_| timed_out("Trojan UDP uplink send timed out"))??;
                            outbound_counters.add_uplink(sent);
                            if sent != payload.len() {
                                return Err(io::Error::new(io::ErrorKind::WriteZero, "partial Trojan UDP datagram send"));
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
                idle_since = tokio::time::Instant::now();
                if sends.len() >= limits.max_pending { counters.capacity_drops += 1; continue; }
                let frame = UdpFrame::new(Destination::from(response.key.target), response.payload);
                let payload_len = frame.payload.len();
                let out_tx = out_tx.clone();
                let stop_token = stop.clone();
                let duration = limits.operation_timeout;
                sends.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = stop_token.cancelled() => Ok(SendReport::Cancelled),
                        result = timeout(duration, out_tx.send(frame)) => {
                            if result.is_err() {
                                return Err(timed_out("Trojan UDP response queue closed"));
                            }
                            Ok(SendReport::Downlink(payload_len))
                        }
                    }
                });
            }
            completed = sends.join_next(), if !sends.is_empty() => {
                if let Some(completed) = completed { apply_send_report(&mut counters, completed); }
            }
            _ = maintenance.tick() => prune_peers(&mut peers, limits.peer_idle_timeout),
        }
    };
    // Tear down: stop peers and in-flight work, then let the reply writer
    // flush the close frame and shut the TCP stream down, bounded.
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
    read_pump.abort();
    let _ = read_pump.await;
    drop(out_tx);
    match timeout(limits.operation_timeout, &mut write_pump).await {
        Ok(Ok(Ok(()))) => (),
        Ok(Ok(Err(error))) => {
            tracing::warn!(inbound = tag, %error, "Trojan UDP reply writer failed")
        }
        Ok(Err(error)) => {
            tracing::warn!(inbound = tag, %error, "Trojan UDP reply writer task panicked")
        }
        Err(_) => {
            write_pump.abort();
            tracing::warn!(inbound = tag, "Trojan UDP close frame flush timed out");
        }
    }
    tracing::debug!(
        inbound = tag,
        reason = ?result,
        counters = ?counters,
        "Trojan UDP association closed"
    );
    result?;
    Ok(())
}

/// Hand one decoded client frame to the dispatcher as a bounded per-dispatch
/// future, exactly like the SOCKS packet session does.
#[allow(clippy::too_many_arguments)] // the association state is iterated per frame
fn enqueue_dispatch(
    frame: UdpFrame,
    pending: &mut JoinSet<(io::Result<udp::DispatchAction>, Vec<u8>)>,
    counters: &mut Counters,
    limits: &udp::Limits,
    source: SocketAddr,
    inbound_tag: &Arc<str>,
    user: &Arc<str>,
    dispatcher: &Arc<dyn udp::UdpDispatcher>,
    stop: &CancellationToken,
) {
    if !udp::valid_destination(&frame.destination) {
        counters.malformed_frames += 1;
        return;
    }
    counters.accepted_packets += 1;
    if pending.len() >= limits.max_pending {
        counters.capacity_drops += 1;
        return;
    }
    let context = udp::DispatchContext {
        destination: frame.destination,
        source,
        inbound_tag: Arc::clone(inbound_tag),
        user: Arc::clone(user),
        network: "udp",
    };
    let payload = frame.payload;
    let dispatcher = Arc::clone(dispatcher);
    let duration = limits.operation_timeout;
    let stop = stop.clone();
    pending.spawn(async move {
        let action = tokio::select! {
            biased;
            _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "Trojan UDP association closed")),
            result = timeout(duration, dispatcher.dispatch(context)) => {
                result.unwrap_or_else(|_| Err(timed_out("Trojan UDP dispatch timed out")))
            }
        };
        (action, payload)
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndReason {
    ClientClosed,
    IdleTimeout,
    Cancelled,
    WriterClosed,
}

#[derive(Debug, Default)]
struct Counters {
    accepted_packets: u64,
    malformed_frames: u64,
    policy_drops: u64,
    dispatch_errors: u64,
    capacity_drops: u64,
    send_errors: u64,
    uplink_bytes: u64,
    downlink_bytes: u64,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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
        // Trojan frames cannot carry datagrams above the protocol maximum;
        // larger responses are dropped instead of being truncated on the wire.
        if size > trojan_udp::MAX_PAYLOAD {
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
    use crate::{Config, Server};
    use serde_json::json;
    use sha2::{Digest, Sha224};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        task::JoinHandle,
        time::timeout,
    };

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

    /// The lowercase hex SHA-224 password hash of a Trojan request header.
    fn trojan_key_hex(password: &str) -> Vec<u8> {
        let digest = Sha224::digest(password.as_bytes());
        let mut key = Vec::with_capacity(56);
        for byte in digest {
            key.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        key
    }

    #[tokio::test]
    async fn trojan_udp_inbound_relays_frames_and_closes_the_association() {
        timeout(Duration::from_secs(10), async {
            let echo = udp_echo().await;
            let config = Config::from_json(
                &json!({
                    "inbounds": [{
                        "listen": "127.0.0.1", "port": 0, "tag": "trojan-in",
                        "protocol": "trojan",
                        "settings": {"clients": [{"password": "password", "email": "love@example.com"}]}
                    }],
                    "outbounds": [{"tag": "direct", "protocol": "freedom"}]
                })
                .to_string(),
            )
            .unwrap();
            let server = Server::start(config).await.unwrap();
            let mut client = TcpStream::connect(server.local_addresses()[0])
                .await
                .unwrap();

            // Trojan UDP request header: hash, CRLF, command 3, SOCKS
            // address, CRLF. The request's own destination is only the
            // close-frame target (Go `PacketWriter.Target`).
            let request_destination = Destination::new("trojan-udp.example", 443).unwrap();
            let mut header = trojan_key_hex("password");
            header.extend_from_slice(b"\r\n\x03");
            request_destination.write_socks(&mut header).await.unwrap();
            header.extend_from_slice(b"\r\n");
            client.write_all(&header).await.unwrap();

            // One datagram frame to the echo socket relays through the UDP
            // dispatcher and returns as a frame whose destination is the
            // remote UDP source.
            trojan_udp::write_frame(
                &mut client,
                &UdpFrame::new(Destination::from(echo.address), b"trojan-udp-ping".to_vec()),
            )
            .await
            .unwrap();
            let reply = timeout(WAIT, trojan_udp::read_frame(&mut client))
                .await
                .unwrap()
                .unwrap()
                .expect("echo reply frame");
            assert_eq!(reply.destination, Destination::from(echo.address));
            assert_eq!(reply.payload, b"trojan-udp-ping");

            // A frame to a port with no listener is dropped without ending
            // the association (UDP dials never error; the reply simply never
            // arrives), matching Go's drop of unroutable datagrams.
            trojan_udp::write_frame(
                &mut client,
                &UdpFrame::new(
                    Destination::new("127.0.0.1", 1).unwrap(),
                    b"nowhere".to_vec(),
                ),
            )
            .await
            .unwrap();
            let mut probe = [0u8; 16];
            assert!(
                timeout(QUIET, client.read(&mut probe)).await.is_err(),
                "unexpected data after an invalid destination frame"
            );

            // The zero-length close frame ends the association: the server
            // answers with its own close frame addressed to the request's
            // destination and then closes the stream, exactly like Go's
            // requestDone EOF path.
            trojan_udp::write_frame(
                &mut client,
                &UdpFrame::new(Destination::from(echo.address), Vec::new()),
            )
            .await
            .unwrap();
            let close_target = timeout(WAIT, Destination::read_socks(&mut client))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(close_target, request_destination);
            let mut tail = [0u8; 4];
            timeout(WAIT, client.read_exact(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&tail, b"\x00\x00\r\n");
            assert_eq!(
                timeout(WAIT, client.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );

            server.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }
}
