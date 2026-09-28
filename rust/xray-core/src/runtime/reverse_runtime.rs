//! Runtime glue for the root `reverse` object (Go app/reverse): the portal
//! half attaches bridge-domain carriers that arrive at any inbound and opens
//! logical sessions for outbound tags routed to a portal; the bridge half
//! dials `domain:0`/TCP carriers through the outbound the router selects for
//! the bridge inbound tag and pumps inner sessions through the runtime's own
//! route → admission → establish → relay path.
//!
//! Go semantics (app/reverse/portal.go, app/reverse/bridge.go): a portal
//! registers itself as an *outbound handler* under its tag, so both carriers
//! and relays reach it only through routing rules that select the portal tag —
//! there is no built-in interception of the bridge domain. The portal's
//! `HandleConnection` then splits by target domain: the configured bridge
//! domain marks a carrier (the portal becomes the Mux.Cool client, opens the
//! `reverse:0` UDP control session and heartbeats every 2s), anything else is
//! relayed over a session on the least-loaded carrier. The bridge dials each
//! carrier by dispatching `domain:0`/TCP with the bridge tag as the inbound
//! tag; its monitor keeps at least one Active carrier and adds another when
//! the integer average of active sessions per Active carrier exceeds 16.
//!
//! The runtime wiring models the carrier split with `is_portal_destination`/
//! `attach_carrier` (checked before routing) and the relay split with
//! `portal_tags`/`open_session`, both consumed by runtime.rs. Carriers are
//! expected to arrive on a proxy inbound that preserves the dialed destination
//! (Go's examples use VLESS); the inbound handshake reply must be written
//! before `attach_carrier`, because the portal starts emitting Mux.Cool
//! frames immediately and the dialing side strips its proxy reply first.

#![allow(dead_code)] // portal-side entry points are consumed by runtime.rs

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    io::AsyncWriteExt,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::{
    address::{Address, Destination},
    config::Outbound,
    features::session::relay_with_idle_since,
    logging::{AccessRecord, DetourKind, format_detour},
    mux::{Network, OpenOptions, Session, Target as MuxTarget},
    protocol::{Reply, Request, freedom::Admission},
    reverse::{
        BridgeOptions, Dispatcher as SessionDispatcher, PortalOptions,
        bridge::{Portal, PortalDialer, Reverse, ReverseConfig},
    },
    router::RouteContext,
    transport::BoxStream,
};

/// Go dispatches reverse carriers and bridge inner sessions with no source
/// address in the session context; an unspecified source keeps the router's
/// source rules from matching them, like Go's absent context source.
const UNATTACHED_SOURCE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Origin reported to freedom's final-rule admission for sessions dispatched
/// by a reverse bridge. Go's context carries the bridge tag with no inbound
/// protocol name, so no name-specific default final rule applies.
const BRIDGE_ORIGIN: &str = "reverse-bridge";

pub(super) struct ReverseRuntime {
    /// The Go `Reverse` container; a watcher task starts its bridge monitors
    /// and closes it (carriers, portals) when the server cancels.
    reverse: Arc<tokio::sync::Mutex<Reverse>>,
    /// Clone-able handles into the container's portals; the portal workers
    /// are shared through their inner `Arc`.
    portals: Vec<Portal>,
    cancel: CancellationToken,
    started: AtomicBool,
}

/// Build the reverse app over the runtime's dispatcher. Bridges dial their
/// carriers and dispatch inner sessions through this very dispatcher, so the
/// closure captures stay alive until the runtime closes.
pub(super) fn new(
    config: &ReverseConfig,
    dispatcher: Arc<Dispatcher>,
    cancel: CancellationToken,
) -> anyhow::Result<Arc<ReverseRuntime>> {
    let reverse = Reverse::new(
        config,
        carrier_dialer(Arc::clone(&dispatcher)),
        session_dispatcher(Arc::clone(&dispatcher), cancel.clone()),
        BridgeOptions::default(),
        PortalOptions::default(),
    )?;
    let portals = reverse.portals().to_vec();
    Ok(Arc::new(ReverseRuntime {
        reverse: Arc::new(tokio::sync::Mutex::new(reverse)),
        portals,
        cancel,
        started: AtomicBool::new(false),
    }))
}

impl ReverseRuntime {
    /// Start the bridges' carrier monitors, linked to the server cancellation
    /// token: the watcher closes the container (Go `Reverse.Close`) once the
    /// token fires. Portals are passive handles registered through
    /// `portal_tags`, exactly like Go's `Portal.Start` only registers the
    /// outbound handler.
    pub(super) fn start(&self) -> std::io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reverse app runtime is already started",
            ));
        }
        let reverse = Arc::clone(&self.reverse);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let mut runtime = reverse.lock().await;
            if let Err(error) = runtime.start() {
                tracing::warn!(%error, "reverse bridge monitor failed to start");
                return;
            }
            drop(runtime);
            cancel.cancelled().await;
            let mut runtime = reverse.lock().await;
            if let Err(error) = runtime.close().await {
                tracing::warn!(%error, "reverse app close failed");
            }
        });
        Ok(())
    }

    /// Outbound tags that route through a portal (Go registers each portal
    /// as an outbound handler under this tag).
    pub(super) fn portal_tags(&self) -> Vec<String> {
        self.portals
            .iter()
            .map(|portal| portal.tag().to_owned())
            .collect()
    }

    /// Whether this destination is a carrier arriving at a portal. Go's
    /// `isDomain` compares the domain only; the port is not part of the match.
    pub(super) fn is_portal_destination(&self, destination: &Destination) -> bool {
        self.portals.iter().any(|portal| {
            matches!(&destination.address, Address::Domain(domain) if domain == portal.domain())
        })
    }

    /// Hand a bridge-domain carrier connection to the portal. Go selects the
    /// portal through the outbound the carrier was routed to; the pre-routing
    /// interception carries no target, so the first portal takes the carrier
    /// (carrier workers are interchangeable; documented setups expose one
    /// tunnel inbound per portal).
    pub(super) async fn attach_carrier(&self, stream: BoxStream) -> anyhow::Result<()> {
        let Some(portal) = self.portals.first() else {
            anyhow::bail!("reverse carrier arrived without a configured portal");
        };
        portal.attach(stream).await?;
        Ok(())
    }

    /// Open one logical session through a portal for the tagged outbound (Go
    /// `client.Dispatch` over the least-loaded non-draining carrier).
    pub(super) async fn open_session(
        &self,
        tag: &str,
        target: &Destination,
    ) -> std::io::Result<BoxStream> {
        let Some(portal) = self.portal_for_tag(tag) else {
            return Err(io::Error::other(format!(
                "unknown reverse portal tag {tag:?}"
            )));
        };
        let session = portal
            .open_session(
                MuxTarget::from_destination(Network::Tcp, target),
                OpenOptions::default(),
            )
            .await?;
        session.into_stream()
    }

    fn portal_for_tag(&self, tag: &str) -> Option<&Portal> {
        self.portals.iter().find(|portal| portal.tag() == tag)
    }
}

/// The bridge→portal carrier dial of Go `NewBridgeWorker`: dispatch
/// `domain:0`/TCP with the bridge tag as the inbound tag, so the router
/// selects the outbound configured for the bridge (the tunnel to the portal).
fn carrier_dialer(dispatcher: Arc<Dispatcher>) -> Arc<dyn PortalDialer> {
    Arc::new(
        move |domain: &str, tag: &str| -> crate::reverse::ConnectFuture {
            let dispatcher = Arc::clone(&dispatcher);
            let domain = domain.to_owned();
            let tag = tag.to_owned();
            Box::pin(async move {
                let target = Destination {
                    address: Address::parse(&domain).map_err(io::Error::other)?,
                    port: 0,
                };
                let (selected, routed) = dispatcher.router.select_with_route(&RouteContext {
                    destination: &target,
                    source: UNATTACHED_SOURCE,
                    inbound_tag: &tag,
                    user: "",
                    network: "tcp",
                });
                let outbound = dispatcher.outbounds.get(selected).ok_or_else(|| {
                    io::Error::other("reverse carrier selected a missing outbound")
                })?;
                if matches!(outbound, Outbound::Api | Outbound::Blackhole { .. }) {
                    return Err(io::Error::other(
                        "reverse carrier cannot be routed to an internal outbound",
                    ));
                }
                let transport = dispatcher
                    .transports
                    .get(selected)
                    .ok_or_else(|| io::Error::other("reverse carrier transport is missing"))?;
                let mut resolved = None;
                if matches!(outbound, Outbound::Freedom { .. }) {
                    match timeout(
                        super::DIAL_TIMEOUT,
                        super::admission::admit(
                            outbound,
                            BRIDGE_ORIGIN,
                            &target,
                            dispatcher.dns.as_ref(),
                        ),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "reverse carrier admission timed out",
                        )
                    })?
                    .map_err(io::Error::other)?
                    {
                        Admission::Allowed(addresses) => resolved = addresses,
                        Admission::Blocked(_) => {
                            return Err(io::Error::other(
                                "freedom final rule blocked the reverse carrier target",
                            ));
                        }
                    }
                }
                let outbound_tag = dispatcher
                    .outbound_tags
                    .get(selected)
                    .cloned()
                    .unwrap_or_default();
                let counters = dispatcher
                    .stats
                    .as_ref()
                    .map(|stats| {
                        stats.outbound_counters(&outbound_tag, dispatcher.policy.for_system().stats)
                    })
                    .unwrap_or_default();
                let (stream, _) = timeout(
                    super::DIAL_TIMEOUT,
                    super::establish(
                        &dispatcher,
                        outbound,
                        transport,
                        &target,
                        resolved.as_deref(),
                        counters,
                    ),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "reverse carrier dial timed out")
                })?
                .map_err(io::Error::other)?;
                tracing::debug!(
                    inbound = %tag,
                    target = %target,
                    outbound = %outbound_tag,
                    routed,
                    "reverse carrier dialed"
                );
                Ok(stream)
            })
        },
    )
}

/// The bridge's inner-session pump (Go `BridgeWorker.Dispatch`): sessions the
/// portal opened on a carrier are dispatched through the runtime's own
/// route → admission → establish → relay path under the bridge inbound tag.
fn session_dispatcher(dispatcher: Arc<Dispatcher>, cancel: CancellationToken) -> SessionDispatcher {
    Arc::new(move |session: Session, tag: String| {
        let dispatcher = Arc::clone(&dispatcher);
        let cancel = cancel.clone();
        Box::pin(async move { dispatch_bridge_session(session, tag, &dispatcher, &cancel).await })
    })
}

async fn dispatch_bridge_session(
    session: Session,
    tag: String,
    dispatcher: &Dispatcher,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let target = session.target.destination();
    // into_stream rejects UDP sessions explicitly: XUDP dispatch through the
    // reverse tunnel is not wired yet.
    let mut stream = session.into_stream()?;
    let request = Request {
        destination: target,
        user: String::new(),
        initial_payload: Vec::new(),
        reply: Reply::None,
    };
    let policy = dispatcher.policy.for_level(0);
    if let Some(stats) = &dispatcher.stats {
        stream = super::accounting::CountedStream::wrap(
            stream,
            stats.inbound_counters(&tag, dispatcher.policy.for_system().stats),
            true,
        );
    }
    let (selected, routed) = dispatcher.router.select_with_route(&RouteContext {
        destination: &request.destination,
        source: UNATTACHED_SOURCE,
        inbound_tag: &tag,
        user: "",
        network: "tcp",
    });
    let outbound_tag = dispatcher
        .outbound_tags
        .get(selected)
        .cloned()
        .unwrap_or_default();
    let record = |accepted: bool, reason: String| {
        let mut record = if accepted {
            AccessRecord::accepted(UNATTACHED_SOURCE, &request.destination)
        } else {
            AccessRecord::rejected(UNATTACHED_SOURCE, &request.destination, reason)
        };
        record.detour = format_detour(
            &tag,
            &outbound_tag,
            if routed {
                DetourKind::Routed
            } else {
                DetourKind::Default
            },
        );
        if let Err(error) = dispatcher.logger.write_access(&record) {
            tracing::warn!(%error, "cannot write access record");
        }
    };
    tracing::debug!(
        inbound = %tag,
        target = %request.destination,
        outbound = %outbound_tag,
        "routing reverse session"
    );
    let outbound = dispatcher
        .outbounds
        .get(selected)
        .ok_or_else(|| io::Error::other("reverse session selected a missing outbound"))?;
    // A bridge may route inner sessions back into a portal (Go dispatches to
    // any registered outbound handler); open the tunnel session instead of
    // establishing a stream.
    if let Some(reverse) = dispatcher.reverse.get()
        && reverse.portal_for_tag(&outbound_tag).is_some()
    {
        {
            let mut tunneled = reverse
                .open_session(&outbound_tag, &request.destination)
                .await?;
            record(true, String::new());
            relay_with_idle_since(
                &mut stream,
                &mut tunneled,
                &policy,
                None,
                &[],
                cancel,
                Instant::now(),
            )
            .await?;
            return Ok(());
        }
    }
    match outbound {
        Outbound::Blackhole { response } => {
            record(true, String::new());
            let idle = policy.timeouts.connection_idle;
            if !response.is_empty() {
                timeout(idle, stream.write_all(response)).await??;
            }
            timeout(idle, stream.shutdown()).await??;
            Ok(())
        }
        Outbound::Api => {
            record(
                false,
                "management API unavailable for reverse sessions".into(),
            );
            Err(io::Error::other(
                "reverse bridge cannot dispatch to the management API",
            ))
        }
        other => {
            let mut resolved = None;
            if matches!(other, Outbound::Freedom { .. }) {
                match timeout(
                    super::DIAL_TIMEOUT,
                    super::admission::admit(
                        other,
                        BRIDGE_ORIGIN,
                        &request.destination,
                        dispatcher.dns.as_ref(),
                    ),
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "reverse session admission timed out",
                    )
                })?
                .map_err(io::Error::other)?
                {
                    Admission::Allowed(addresses) => resolved = addresses,
                    Admission::Blocked(_) => {
                        // Go's freedom blocks the dispatch; the session ends
                        // without relaying the delay-drain the client path
                        // performs.
                        record(
                            false,
                            "freedom final rule blocked reverse session target".into(),
                        );
                        return Ok(());
                    }
                }
            }
            let transport = dispatcher
                .transports
                .get(selected)
                .ok_or_else(|| io::Error::other("reverse session transport is missing"))?;
            let counters = dispatcher
                .stats
                .as_ref()
                .map(|stats| {
                    stats.outbound_counters(&outbound_tag, dispatcher.policy.for_system().stats)
                })
                .unwrap_or_default();
            let (mut upstream, _) = match timeout(
                super::DIAL_TIMEOUT,
                super::establish(
                    dispatcher,
                    other,
                    transport,
                    &request.destination,
                    resolved.as_deref(),
                    counters,
                ),
            )
            .await
            {
                Ok(Ok(established)) => established,
                Ok(Err(error)) => {
                    record(false, error.to_string());
                    return Err(io::Error::other(error.to_string()));
                }
                Err(_) => {
                    let message = "reverse session outbound connection timed out";
                    record(false, message.into());
                    return Err(io::Error::new(io::ErrorKind::TimedOut, message));
                }
            };
            record(true, String::new());
            relay_with_idle_since(
                &mut stream,
                &mut upstream,
                &policy,
                None,
                &[],
                cancel,
                Instant::now(),
            )
            .await?;
            Ok(())
        }
    }
}
