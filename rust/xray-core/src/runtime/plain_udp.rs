//! The legacy Shadowsocks AEAD UDP relay and the dokodemo UDP forwarder.
//!
//! The legacy Shadowsocks inbound with `network: "tcp,udp"` answers on a UDP
//! socket beside its TCP listener: each datagram is opened with the
//! account-scoped [`LegacyUdp`] codec (salt-framed AEAD with a bounded replay
//! cache), dispatched through the UDP routing dispatcher and answered with
//! sealed replies addressed to the remote source (Go's
//! `shadowsocks.NewPacketWriter`).
//!
//! The dokodemo UDP forwarder relays every datagram from a client peer to the
//! one configured destination, tracking peers so replies return to their
//! originating socket address (`proxy/dokodemo` without redirection: the
//! destination is static).

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};
use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::{
    address::Destination,
    protocol::{
        shadowsocks_session,
        shadowsocks_udp::{LegacyCipher, LegacyUdp},
    },
};

/// One client peer's relay socket toward the admitted endpoints, with a
/// bounded pump that returns remote replies to the listener loop.
struct Peer {
    relay: Arc<UdpSocket>,
    stop: CancellationToken,
}

/// A remote reply: which peer's relay received it and the payload.
struct PeerReply {
    client: SocketAddr,
    from: SocketAddr,
    payload: Vec<u8>,
}

fn relay_bind(peer: SocketAddr) -> Arc<UdpSocket> {
    let bind = if peer.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let socket = std::net::UdpSocket::bind(bind).expect("bind a peer relay socket");
    socket
        .set_nonblocking(true)
        .expect("non-blocking relay socket");
    Arc::new(UdpSocket::from_std(socket).expect("register relay socket"))
}

/// The shared dispatch half: route one datagram, returning the admitted
/// endpoint or `None` for a drop or dispatch error.
async fn route(
    dispatcher: &Dispatcher,
    inbound_tag: &Arc<str>,
    user: &Arc<str>,
    destination: &Destination,
    source: SocketAddr,
) -> Option<SocketAddr> {
    let udp = dispatcher.udp.as_ref()?;
    let action = udp
        .dispatch(super::udp::DispatchContext {
            destination: destination.clone(),
            source,
            inbound_tag: Arc::clone(inbound_tag),
            user: Arc::clone(user),
            network: "udp",
        })
        .await
        .ok()?;
    match action {
        super::udp::DispatchAction::Direct(target) => Some(target),
        super::udp::DispatchAction::TrackedDirect { target, .. } => Some(target),
        super::udp::DispatchAction::Drop | super::udp::DispatchAction::Xudp { .. } => None,
    }
}

impl Peer {
    fn new(client: SocketAddr, replies: mpsc::Sender<PeerReply>) -> Self {
        let relay = relay_bind(client);
        let stop = CancellationToken::new();
        let pump_socket = Arc::clone(&relay);
        let pump_replies = replies.clone();
        let pump_stop = stop.clone();
        let pump_client = client;
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = pump_stop.cancelled() => return,
                    received = timeout(Duration::from_secs(300), pump_socket.recv_from(&mut buffer)) => received,
                };
                match received {
                    Ok(Ok((size, from))) => {
                        let reply = PeerReply {
                            client: pump_client,
                            from,
                            payload: buffer[..size].to_vec(),
                        };
                        if pump_replies.send(reply).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
            }
        });
        Self { relay, stop }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// One legacy Shadowsocks UDP listener bound beside its TCP listener.
pub(super) struct LegacyShadowsocksUdp {
    socket: Arc<UdpSocket>,
    codec: LegacyUdp,
    user: Arc<str>,
}

impl LegacyShadowsocksUdp {
    /// Bind the UDP socket and build the account codec (the derived AEAD key
    /// with its bounded salt replay cache).
    pub(super) fn bind(
        address: SocketAddr,
        account: &shadowsocks_session::Account,
    ) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(address)
            .with_context(|| format!("bind legacy Shadowsocks UDP listener on {address}"))?;
        socket
            .set_nonblocking(true)
            .context("set legacy Shadowsocks UDP listener non-blocking")?;
        let (kind, key) = account.aead_material();
        let cipher = LegacyCipher::from_key(kind, &key)
            .map_err(|error| anyhow::anyhow!("legacy Shadowsocks UDP cipher: {error}"))?;
        Ok(Self {
            socket: Arc::new(UdpSocket::from_std(socket)?),
            codec: LegacyUdp::new(cipher),
            user: Arc::from(account.email.as_str()),
        })
    }

    pub(super) async fn run(
        self,
        dispatcher: Arc<Dispatcher>,
        inbound_tag: Arc<str>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let Self {
            socket,
            mut codec,
            user,
        } = self;
        let mut buffer = vec![0u8; 65_535];
        let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
        let (replies_tx, mut replies_rx) = mpsc::channel::<PeerReply>(64);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    peers.clear();
                    return Ok(());
                }
                reply = replies_rx.recv() => {
                    // Seal the remote reply and return it to its client.
                    let Some(reply) = reply else { continue };
                    match codec.encode(
                        &Destination::from(reply.from),
                        &reply.payload,
                        Instant::now(),
                        &mut rand::rngs::OsRng,
                    ) {
                        Ok(sealed) => {
                            let _ = socket.send_to(&sealed, reply.client).await;
                        }
                        Err(error) => {
                            tracing::debug!(%error, "legacy Shadowsocks UDP reply dropped");
                        }
                    }
                }
                received = socket.recv_from(&mut buffer) => {
                    let (size, source) = received.context("legacy Shadowsocks UDP receive failed")?;
                    let wire = buffer[..size].to_vec();
                    let datagram = match codec.decode(&wire, Instant::now()) {
                        Ok(datagram) => datagram,
                        Err(error) => {
                            // Unauthenticated or malformed packets are dropped
                            // without touching any session state.
                            tracing::debug!(%source, %error, "legacy Shadowsocks UDP packet dropped");
                            continue;
                        }
                    };
                    if datagram.payload.is_empty() {
                        // The explicit association close.
                        peers.remove(&source);
                        continue;
                    }
                    let Some(target) = route(
                        &dispatcher,
                        &inbound_tag,
                        &user,
                        &datagram.destination,
                        source,
                    )
                    .await
                    else {
                        continue;
                    };
                    let peer = peers
                        .entry(source)
                        .or_insert_with(|| Peer::new(source, replies_tx.clone()));
                    let _ = peer.relay.send_to(&datagram.payload, target).await;
                }
            }
        }
    }
}

/// Serve one dokodemo UDP inbound: every client datagram relays to the one
/// configured destination, replies flow back to the sending peer.
pub(super) async fn serve_dokodemo_udp(
    address: SocketAddr,
    destination: Destination,
    dispatcher: Arc<Dispatcher>,
    inbound_tag: Arc<str>,
    cancel: CancellationToken,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(address)
            .await
            .with_context(|| format!("bind dokodemo UDP listener on {address}"))?,
    );
    let user: Arc<str> = Arc::from("");
    let mut buffer = vec![0u8; 65_535];
    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
    let (replies_tx, mut replies_rx) = mpsc::channel::<PeerReply>(64);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                peers.clear();
                return Ok(());
            }
            reply = replies_rx.recv() => {
                // A reply from an admitted endpoint returns to its peer.
                let Some(reply) = reply else { continue };
                let _ = socket.send_to(&reply.payload, reply.client).await;
            }
            received = socket.recv_from(&mut buffer) => {
                let (size, source) = received.context("dokodemo UDP receive failed")?;
                let payload = buffer[..size].to_vec();
                let Some(target) = route(
                    &dispatcher,
                    &inbound_tag,
                    &user,
                    &destination,
                    source,
                )
                .await
                else {
                    continue;
                };
                let peer = peers
                    .entry(source)
                    .or_insert_with(|| Peer::new(source, replies_tx.clone()));
                let _ = peer.relay.send_to(&payload, target).await;
            }
        }
    }
}
