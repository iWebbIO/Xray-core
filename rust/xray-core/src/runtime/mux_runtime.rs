//! Mux.Cool outbound multiplexing and the inbound carrier server.
//!
//! Client side (Go `app/proxyman/outbound` Handler + `common/mux` client):
//! every outbound with `"mux": {"enabled": true}` owns two carrier pools —
//! one for TCP streams and one for XUDP packet sessions — each lazily
//! dialing carrier connections to `v1.mux.cool:9527` through the outbound's
//! own establish path (the carrier IS a proxy connection, exactly like Go's
//! `DialingWorkerFactory` dialing through `proxy.Process`). Pick follows
//! Go's `IncrementalWorkerPicker`: reuse a non-full worker or spawn a new
//! one, up to sixteen attempts per stream.
//!
//! Server side (Go `app/proxyman/inbound` wrapping every dispatcher with
//! `mux.NewServer`): a proxy request whose destination address is
//! `v1.mux.cool` turns the connection body into a Mux.Cool carrier; every
//! accepted session dispatches through the runtime's normal path (TCP
//! sessions as ordinary requests, XUDP sessions as packet relays through the
//! UDP dispatcher, with the component's association registry retaining
//! global-id leases across session generations).

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::Context;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::{
    address::{Address, Destination},
    config::{Inbound, PoolLimits, Udp443Policy},
    mux::{
        self, Connection, Network, OpenOptions, Options, Packet, Session, SessionSender, Target,
        xudp::AssociationRegistry,
    },
    protocol::Request,
    router::RouteContext,
    transport::BoxStream,
};

/// One carrier worker: a Mux.Cool client connection over a proxy connection.
struct Worker {
    connection: Connection,
}

/// Go's per-worker `ClientStrategy` limits plus the worker list. The pool
/// dials through the dispatcher (a `Weak` link set once it exists), so pools
/// stay constructible before the runtime is assembled.
pub struct MuxPool {
    limits: PoolLimits,
    kind: Network,
    dispatcher: std::sync::OnceLock<Weak<Dispatcher>>,
    workers: tokio::sync::Mutex<Vec<Arc<Worker>>>,
}

impl std::fmt::Debug for MuxPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MuxPool")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl MuxPool {
    pub(super) fn new(limits: PoolLimits, kind: Network) -> Arc<Self> {
        Arc::new(Self {
            limits,
            kind,
            dispatcher: std::sync::OnceLock::new(),
            workers: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    /// Link the pool to its dispatcher for carrier dials (a weak link so the
    /// pool never keeps the runtime alive).
    pub(super) fn attach(&self, dispatcher: &Arc<Dispatcher>) {
        let _ = self.dispatcher.set(Arc::downgrade(dispatcher));
    }

    /// Pick or spawn a worker, then open one session on it, mirroring Go's
    /// `ClientManager.Dispatch` (sixteen attempts across workers; a worker
    /// whose open fails is dropped and replaced).
    async fn open(&self, target: Target, initial_data: Option<Vec<u8>>) -> anyhow::Result<Session> {
        let mut last = None;
        for _ in 0..16 {
            let candidate = {
                let mut workers = self.workers.lock().await;
                workers.retain(|worker| !worker.connection.is_closed());
                workers
                    .iter()
                    .find(|worker| !worker.connection.is_full())
                    .cloned()
            };
            let worker = match candidate {
                Some(worker) => worker,
                None => match self.spawn().await {
                    Ok(worker) => worker,
                    Err(error) => {
                        last = Some(error);
                        continue;
                    }
                },
            };
            let options = OpenOptions {
                initial_data: initial_data.clone(),
                ..OpenOptions::default()
            };
            match worker.connection.open(target.clone(), options).await {
                Ok(session) => {
                    return Ok(session);
                }
                Err(error) => {
                    // The worker is unusable (likely a dead carrier); drop it
                    // and pick again, exactly like Go's pick loop.
                    let mut workers = self.workers.lock().await;
                    workers.retain(|live| !Arc::ptr_eq(live, &worker));
                    last = Some(anyhow::Error::new(error));
                }
            }
        }
        Err(anyhow::anyhow!(
            "unable to find an available mux client: {}",
            last.map(|error| error.to_string()).unwrap_or_default()
        ))
    }

    /// Dial one carrier connection through the outbound's establish path.
    async fn spawn(&self) -> anyhow::Result<Arc<Worker>> {
        let dispatcher = self
            .dispatcher
            .get()
            .and_then(Weak::upgrade)
            .context("mux pool is not attached to a runtime")?;
        // The carrier targets the mux address, exactly like Go's factory
        // dialing `muxCoolAddress:muxCoolPort` through the proxy handler.
        let destination = Destination {
            address: Address::Domain(mux::MUX_DOMAIN.to_owned()),
            port: mux::MUX_PORT,
        };
        let (selected, _routed) = dispatcher.router.select_with_route(&RouteContext {
            destination: &destination,
            source: SocketAddr::from(([0, 0, 0, 0], 0)),
            inbound_tag: "mux",
            user: "",
            network: "tcp",
        });
        let outbound = dispatcher
            .outbounds
            .get(selected)
            .context("mux carrier selected a missing outbound")?;
        let transport = dispatcher
            .transports
            .get(selected)
            .context("mux carrier transport is missing")?;
        let counters = dispatcher
            .stats
            .as_ref()
            .map(|stats| {
                stats.outbound_counters(
                    &dispatcher.outbound_tags[selected],
                    dispatcher.policy.for_system().stats,
                )
            })
            .unwrap_or_default();
        let (stream, _) = super::establish(
            &dispatcher,
            outbound,
            transport,
            &destination,
            None,
            counters,
        )
        .await?;
        let connection = Connection::client(
            stream,
            Options {
                max_concurrency: self.limits.max_concurrency,
                max_connections: self.limits.max_connections,
                // Go's TCP manager carries both stream and packet sessions
                // on the same carriers; the XUDP manager is packet-only.
                allowed_network: if self.kind == Network::Udp {
                    Some(Network::Udp)
                } else {
                    None
                },
                ..Options::default()
            },
        )?;
        let worker = Arc::new(Worker { connection });
        let mut workers = self.workers.lock().await;
        workers.push(worker.clone());
        Ok(worker)
    }
}

/// The UDP routing view of one outbound's mux plan: the pool that serves
/// UDP (XUDP pool when configured, else the plain TCP pool, like Go's
/// ClientManager choice) and its UDP/443 policy.
pub struct MuxUdpRoute {
    pub(super) pool: std::sync::Arc<MuxPool>,
    pub(super) udp443: Udp443Policy,
}

impl MuxUdpRoute {
    pub(crate) fn pool(&self) -> &std::sync::Arc<MuxPool> {
        &self.pool
    }

    pub(crate) fn udp443(&self) -> Udp443Policy {
        self.udp443
    }
}

/// The compiled mux state of one outbound: its two carrier pools.
pub(super) struct MuxOutbound {
    pub(super) tcp: Option<Arc<MuxPool>>,
    pub(super) xudp: Option<Arc<MuxPool>>,
    pub(super) udp443: Udp443Policy,
}

impl Dispatcher {
    /// Open one TCP stream through the outbound's mux carrier pool (the
    /// runtime-facing half of Go's `ClientManager.Dispatch`).
    pub(super) async fn mux_open_stream(
        &self,
        index: usize,
        target: &Destination,
    ) -> anyhow::Result<BoxStream> {
        let pool = self
            .mux
            .get(index)
            .and_then(|mux| mux.as_ref())
            .and_then(|mux| mux.tcp.as_ref())
            .context("mux dispatch selected a non-mux outbound")?;
        let session = pool
            .open(Target::from_destination(Network::Tcp, target), None)
            .await?;
        Ok(session.into_stream()?)
    }
}

/// One open XUDP session handed to a UDP association: packets flow through
/// the sender with per-packet targets; replies arrive on the receiver as
/// (reply source endpoint, payload). Dropping the lease closes the session.
pub struct XudpLease {
    pub(super) route: usize,
    sender: SessionSender,
    replies: tokio::sync::Mutex<mpsc::Receiver<(Target, Vec<u8>)>>,
}

impl std::fmt::Debug for XudpLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XudpLease")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl XudpLease {
    pub(super) async fn send(&self, target: Target, payload: &[u8]) -> io::Result<()> {
        self.sender.send(payload, Some(target)).await
    }

    /// The session's terminal state: closed by either side or failed.
    pub(super) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(super) async fn recv(&self) -> Option<(Target, Vec<u8>)> {
        self.replies.lock().await.recv().await
    }
}

impl MuxPool {
    /// Open one XUDP packet session toward `target`. The first packet rides
    /// the session-open metadata (Go's first-payload framing); later packets
    /// carry per-packet targets.
    pub(super) async fn open_xudp(
        self: &Arc<Self>,
        route: usize,
        target: &Destination,
    ) -> anyhow::Result<Arc<XudpLease>> {
        let session = self
            .open(Target::from_destination(Network::Udp, target), None)
            .await?;
        let (sender, mut receiver) = session.split();
        let (reply_tx, reply_rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Ok(Some(Packet { target, payload })) = receiver.recv().await {
                // Replies without an endpoint cannot be routed back.
                if let Some(target) = target
                    && reply_tx.send((target, payload)).await.is_err()
                {
                    break;
                }
            }
        });
        Ok(Arc::new(XudpLease {
            route,
            sender,
            replies: tokio::sync::Mutex::new(reply_rx),
        }))
    }
}

// ---------------------------------------------------------------------------
// Inbound carrier server (Go app/proxyman/inbound + common/mux server)
// ---------------------------------------------------------------------------

/// Per-global-id state shared across XUDP session generations: the NAT
/// sockets keyed by the admitted target endpoint.
struct XudpAssociation {
    sockets: std::sync::Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>,
}

/// Serve one accepted proxy connection whose request targeted `v1.mux.cool`.
/// The proxy reply header must already be on the wire; every accepted session
/// dispatches through the runtime's normal path under the original inbound.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_carrier(
    dispatcher: &Arc<Dispatcher>,
    inbound: Arc<Inbound>,
    tag: Arc<str>,
    user: String,
    source: SocketAddr,
    stream: BoxStream,
    cancel: &CancellationToken,
    sniff: Option<Arc<super::sniffing::SniffingRequest>>,
) -> anyhow::Result<()> {
    let (connection, mut incoming) = Connection::server(
        stream,
        Options {
            // The server consumes XUDP global ids through the association
            // registry below (Go's XUDPManager leases).
            global_ids: mux::GlobalIdPolicy::Dispatch,
            ..Options::default()
        },
    )?;
    let registry = Arc::new(tokio::sync::Mutex::new(AssociationRegistry::default()));
    let mut sessions = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            completed = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(inbound = %tag, %source, error = %format!("{error:#}"), "mux session task ended");
                }
            }
            session = incoming.recv() => {
                let Some(session) = session else { break Ok(()) };
                let dispatcher = dispatcher.clone();
                let inbound = inbound.clone();
                let tag = tag.clone();
                let user = user.clone();
                let registry = registry.clone();
                let session_cancel = cancel.child_token();
                let session_sniff = sniff.clone();
                sessions.spawn(async move {
                    // The explicit box erases the session's future type: mux
                    // sessions dispatch back through `dispatch_request`, whose
                    // own carrier interception awaits this carrier again.
                    let session: std::pin::Pin<
                        Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>,
                    > = Box::pin(serve_session(
                        source,
                        dispatcher,
                        inbound,
                        tag,
                        user,
                        registry,
                        session,
                        &session_cancel,
                        session_sniff,
                    ));
                    if let Err(error) = session.await {
                        tracing::debug!(error = %format!("{error:#}"), "mux session closed");
                    }
                });
            }
        }
    };
    connection.close();
    while sessions.join_next().await.is_some() {}
    result
}

#[allow(clippy::too_many_arguments)]
async fn serve_session(
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    inbound: Arc<Inbound>,
    tag: Arc<str>,
    user: String,
    registry: Arc<tokio::sync::Mutex<AssociationRegistry<XudpAssociation>>>,
    session: Session,
    cancel: &CancellationToken,
    sniff: Option<Arc<super::sniffing::SniffingRequest>>,
) -> anyhow::Result<()> {
    if session.target.network == Network::Tcp {
        // An ordinary request riding the carrier; dispatch exactly like a
        // fresh inbound connection (Go's mux server dispatches each session
        // through the dispatcher with the original inbound context).
        let request = Request {
            destination: session.target.destination(),
            user,
            level: 0,
            initial_payload: Vec::new(),
            reply: crate::protocol::Reply::None,
        };
        // A session targeting the Mux.Cool address again would nest carriers;
        // Go tolerates nesting, this runtime fails the inner request instead
        // of recursing.
        if matches!(&request.destination.address, Address::Domain(domain) if domain == mux::MUX_DOMAIN)
        {
            anyhow::bail!("nested Mux.Cool carriers are not supported");
        }
        let stream = session.into_stream()?;
        return super::dispatch_common(
            stream,
            // The inner request inherits the carrier's client address as its
            // source, like Go's session context carrying the inbound. The
            // session's reply needs no bound address (the carrier already
            // answered the enclosing proxy handshake).
            source,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            &inbound,
            &tag,
            &dispatcher,
            cancel,
            request,
            None,
            sniff,
        )
        .await;
    }
    serve_xudp_session(dispatcher, tag, registry, session, cancel).await
}

/// Serve one XUDP packet session: every inbound packet dispatches through the
/// UDP dispatcher (like the SOCKS association), and replies flow back through
/// the session with their source endpoints as per-packet targets.
#[allow(clippy::too_many_arguments)]
async fn serve_xudp_session(
    dispatcher: Arc<Dispatcher>,
    tag: Arc<str>,
    registry: Arc<tokio::sync::Mutex<AssociationRegistry<XudpAssociation>>>,
    mut session: Session,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    // A nonzero global id attaches this session to the retained association
    // (the component registry's lease; generation checks keep an old session
    // from expiring its replacement). Zero-id sessions own their state alone.
    let association = match session.global_id {
        Some(id) if id != [0; 8] => {
            let mut registry = registry.lock().await;
            let lease = registry
                .acquire(id, std::time::Instant::now(), || {
                    Ok(XudpAssociation {
                        sockets: std::sync::Mutex::new(HashMap::new()),
                    })
                })
                .map_err(io::Error::other)?;
            lease.resource.clone()
        }
        _ => Arc::new(XudpAssociation {
            sockets: std::sync::Mutex::new(HashMap::new()),
        }),
    };
    let session_sender = session.sender();
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Target, Vec<u8>)>(64);
    let mut nat = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            reply = reply_rx.recv() => {
                let Some((target, payload)) = reply else { break Ok(()) };
                if session_sender.send(&payload, Some(target)).await.is_err() {
                    break Ok(());
                }
            }
            packet = session.recv() => {
                let packet = match packet {
                    Ok(Some(packet)) => packet,
                    Ok(None) | Err(_) => break Ok(()),
                };
                // The session-open metadata already delivered the first
                // packet; every received packet forwards the same way.
                let target = packet
                    .target
                    .clone()
                    .unwrap_or_else(|| session.target.clone());
                if let Err(error) = xudp_forward(
                    &dispatcher,
                    &tag,
                    &association,
                    &reply_tx,
                    &mut nat,
                    target.destination(),
                    packet.payload,
                    cancel,
                )
                .await
                {
                    tracing::debug!(inbound = %tag, %error, "mux XUDP packet dropped");
                }
            }
        }
    };
    while nat.join_next().await.is_some() {}
    let _ = session_sender.close(false).await;
    result
}

/// Forward one inbound packet through the UDP dispatcher, opening (or
/// reusing) the association's NAT socket toward the admitted endpoint, and
/// spawning its bounded reply pump.
#[allow(clippy::too_many_arguments)]
async fn xudp_forward(
    dispatcher: &Arc<Dispatcher>,
    tag: &Arc<str>,
    association: &Arc<XudpAssociation>,
    replies: &mpsc::Sender<(Target, Vec<u8>)>,
    nat: &mut JoinSet<()>,
    destination: Destination,
    payload: Vec<u8>,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let Some(udp) = dispatcher.udp.as_ref() else {
        anyhow::bail!("mux XUDP session arrived without a UDP dispatcher");
    };
    let action = udp
        .dispatch(super::udp::DispatchContext {
            destination,
            source: SocketAddr::from(([0, 0, 0, 0], 0)),
            inbound_tag: tag.clone(),
            user: Arc::from(""),
            network: "udp",
        })
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let endpoint = match action {
        super::udp::DispatchAction::Drop => return Ok(()),
        super::udp::DispatchAction::Direct(endpoint) => endpoint,
        super::udp::DispatchAction::TrackedDirect { target, .. } => target,
        super::udp::DispatchAction::Xudp { .. } => {
            anyhow::bail!("mux XUDP dispatch looped back into XUDP")
        }
    };
    let socket = {
        let sockets = association
            .sockets
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        sockets.get(&endpoint).cloned()
    };
    let socket = match socket {
        Some(socket) => socket,
        None => {
            let bind = if endpoint.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            socket.connect(endpoint).await?;
            association
                .sockets
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(endpoint, socket.clone());
            // The reply pump owns one NAT socket; every datagram from the
            // endpoint flows back through the session.
            let pump_socket = socket.clone();
            let pump_replies = replies.clone();
            let pump_stop = cancel.child_token();
            nat.spawn(async move {
                let mut buffer = vec![0u8; 65_535];
                loop {
                    let received = tokio::select! {
                        biased;
                        _ = pump_stop.cancelled() => break,
                        received = timeout(Duration::from_secs(300), pump_socket.recv_from(&mut buffer)) => received,
                    };
                    let (size, from) = match received {
                        Ok(Ok(received)) => received,
                        _ => break,
                    };
                    let target = Target::from_destination(Network::Udp, &Destination::from(from));
                    if pump_replies
                        .send((target, buffer[..size].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            socket
        }
    };
    socket.send(&payload).await?;
    Ok(())
}
