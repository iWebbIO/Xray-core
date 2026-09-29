use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

mod accounting;
mod admission;
mod burst_observatory;
mod dialer_proxy;
mod dns_runtime;
mod handler_registry;
mod hysteria_seam;
mod mux_runtime;
mod observatory;
mod plain_udp;
mod reverse_runtime;
mod sniffing;
mod ss2022_udp_runtime;
mod trojan_udp_runtime;
pub mod tun_inbound;
pub mod udp;
mod udp_integration;
pub mod udp_routing;
mod wireguard_inbound;
mod wireguard_runtime;

use crate::{
    address::Destination,
    config::{Config, Inbound, Outbound},
    features::stats::TrafficCounters,
    protocol::{self, Reply, Request},
    router::{RouteContext, RouterHandle},
    transport::{
        AcceptedTransport, BoxStream, InboundListener, InboundTransport, OutboundTransport,
    },
};

use accounting::CountedStream;

const DIAL_TIMEOUT: Duration = Duration::from_secs(16);
const MAX_GRPC_STREAM_TASKS: usize = 64;

struct Dispatcher {
    outbounds: Vec<Outbound>,
    transports: Vec<OutboundTransport>,
    router: Arc<RouterHandle>,
    udp: Option<Arc<dyn udp::UdpDispatcher>>,
    policy: crate::features::PolicyManager,
    stats: Option<Arc<crate::features::StatsManager>>,
    /// Routing outbound tags in the Router's outbound order: the configured
    /// outbounds, then the API tag, then the reverse portal tags. Indexes
    /// beyond `outbounds`/`transports` select a portal (dispatched through
    /// `reverse`, like Go's portal outbound handlers in the manager).
    outbound_tags: Vec<String>,
    logger: crate::logging::Logger,
    api: Option<crate::api::ApiStreamSender>,
    /// The configured DNS app, used by freedom's non-AsIs strategies and the
    /// UDP dispatcher resolver.
    dns: Option<Arc<crate::dns::app::DnsApp>>,
    /// Reverse app handle; installed once after construction because the
    /// bridges dial carriers through this very dispatcher.
    reverse: std::sync::OnceLock<Arc<reverse_runtime::ReverseRuntime>>,
    /// Lazily-built WireGuard engines, one per outbound settings value.
    wireguard: wireguard_runtime::WireguardPool,
    /// Lazily-dialed MASQUE h2 clients, one per outbound index (Go shares
    /// one CONNECT-IP tunnel across every connection of the outbound); a
    /// broken tunnel is dropped so the next connection re-dials.
    masque: tokio::sync::Mutex<
        std::collections::HashMap<usize, std::sync::Arc<crate::transport::masque::MasqueClient>>,
    >,
    /// Mux.Cool carrier pools per outbound, aligned with `outbounds`
    /// (Go's two ClientManagers per mux-enabled outbound handler).
    mux: Vec<Option<mux_runtime::MuxOutbound>>,
    /// The FakeDNS engine: fake-pool destinations map back to their domain
    /// before routing (Go's dispatcher IsIPInIPPool swap).
    fake_dns: Option<std::sync::Arc<crate::dns::fakedns::FakeDnsEngine>>,
    /// The loopback dispatch seam (loopback outbounds re-enter here).
    loopback: std::sync::OnceLock<Arc<dyn protocol::loopback::LoopbackDispatch>>,
    /// One shared authenticated QUIC session per hysteria outbound (Go's
    /// clientManager cache); seeded from the compiled outbounds.
    hysteria: hysteria_seam::HysteriaPool,
}

/// Owns listening sockets and every connection task. Dropping it cancels all work.
pub struct Server {
    addresses: Vec<SocketAddr>,
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
    stats: Option<Arc<crate::features::StatsManager>>,
    api_address: Option<SocketAddr>,
}

impl Server {
    /// Validates the whole configuration and binds every socket before accepting
    /// any traffic. A bind failure releases all previously acquired listeners.
    pub async fn start(config: Config) -> Result<Self> {
        // Validate before opening log files, so a rejected configuration has no outputs.
        config.validate()?;
        let logger = crate::logging::Logger::from_optional_config(config.log.as_ref())?;
        Self::start_with_logger(config, logger).await
    }

    pub async fn start_with_logger(config: Config, logger: crate::logging::Logger) -> Result<Self> {
        let compiled = config.compile()?;
        // Created before the app runtimes: the reverse bridges and the
        // handler registry both link their child tasks to this token.
        let cancel_token = CancellationToken::new();
        let policy = config
            .policy
            .as_ref()
            .map(crate::features::PolicyManager::new)
            .unwrap_or_default();
        let stats = config
            .stats
            .as_ref()
            .map(|_| Arc::new(crate::features::StatsManager::new()));
        if let Some(stats) = &stats {
            let system = policy.for_system().stats;
            for inbound in &config.inbounds {
                stats.inbound_counters(&inbound.tag, system);
            }
            for outbound in &config.outbounds {
                stats.outbound_counters(&outbound.tag, system);
            }
        }
        let mut outbound_tags: Vec<_> =
            config.outbounds.iter().map(|raw| raw.tag.clone()).collect();
        // Reverse portal tags are routing outbounds exactly like Go's portal
        // handlers in the outbound manager (app/reverse/portal.go Start).
        // The frozen config compiler builds its router from the configured
        // outbounds only, so the router is recompiled here with the portal
        // entries appended in the same order they extend `outbound_tags`.
        let portal_tags: Vec<String> = compiled
            .reverse
            .as_ref()
            .map(|reverse| {
                reverse
                    .portals
                    .iter()
                    .map(|portal| portal.tag.clone())
                    .collect()
            })
            .unwrap_or_default();
        let router = Arc::new(RouterHandle::new(Arc::new(compiled.router)));
        // Mux.Cool carrier pools, one pair per mux-enabled outbound; each
        // pool dials its carriers through the dispatcher (weak-linked after
        // construction). The UDP routing view exposes the pool serving UDP
        // for each outbound (XUDP pool when configured, else the plain TCP
        // pool, like Go's ClientManager choice) with its UDP/443 policy.
        let mux_pools: Vec<Option<mux_runtime::MuxOutbound>> = compiled
            .mux
            .iter()
            .map(|plan| {
                plan.as_ref().map(|plan| mux_runtime::MuxOutbound {
                    tcp: plan
                        .tcp
                        .map(|limits| mux_runtime::MuxPool::new(limits, crate::mux::Network::Tcp)),
                    xudp: plan
                        .xudp
                        .map(|limits| mux_runtime::MuxPool::new(limits, crate::mux::Network::Udp)),
                    udp443: plan.udp443,
                })
            })
            .collect();
        let mux_udp_routes: Vec<Option<mux_runtime::MuxUdpRoute>> = mux_pools
            .iter()
            .map(|pools| {
                pools.as_ref().map(|pools| mux_runtime::MuxUdpRoute {
                    pool: pools
                        .xudp
                        .clone()
                        .or_else(|| pools.tcp.clone())
                        .expect("a mux plan has at least one pool"),
                    udp443: pools.udp443,
                })
            })
            .collect();
        // The UDP routing dispatcher is always installed: SOCKS/Trojan/SS2022
        // associations dispatch through it, XUDP carrier sessions arrive on
        // any inbound, and Go's dispatcher always owns the UDP NAT.
        let udp_resolver: Arc<dyn udp_routing::UdpResolver> = match &compiled.dns {
            Some(app) => dns_runtime::resolver(app.clone()),
            None => Arc::new(udp_routing::SystemResolver),
        };
        let udp = Some(udp_integration::dispatcher(
            &config,
            &compiled.outbounds,
            router.clone(),
            stats.as_deref(),
            policy.for_system().stats,
            udp_resolver,
            &mux_udp_routes,
        )?);
        let mut api_listener = None;
        let mut api_channel = None;
        let mut api_sender = None;
        let mut api_address = None;
        if let Some(api) = &config.api {
            outbound_tags.push(api.tag.clone());
            if !api.listen.is_empty() {
                let listener = TcpListener::bind(&api.listen)
                    .await
                    .context("bind management API")?;
                api_address = Some(listener.local_addr()?);
                api_listener = Some(listener);
            }
            let (sender, incoming) = crate::api::incoming_channel(32)?;
            api_sender = Some(sender);
            api_channel = Some(incoming);
        }
        // Portal tags ride behind the API tag in both the router's outbound
        // list and `outbound_tags` (the reverse portal dispatch reads them by
        // index); a tag already used by an outbound or the API is a conflict.
        for tag in &portal_tags {
            anyhow::ensure!(
                !outbound_tags.iter().any(|existing| existing == tag),
                "reverse portal tag {tag:?} conflicts with another outbound tag"
            );
            outbound_tags.push(tag.clone());
        }
        let mut listeners: Vec<ListenerEntry> = Vec::new();
        // The QUIC listeners of the hysteria inbounds: served through the
        // dispatch seam, not the per-stream accept loop.
        let mut hysteria_listeners: Vec<HysteriaListenerEntry> = Vec::new();
        // Startup inbound snapshots for the HandlerService registry, plus the
        // SS2022 UDP listeners that bind alongside their TCP listener.
        let mut seeds: Vec<(crate::config::InboundConfig, Inbound, InboundTransport)> = Vec::new();
        // One cancellation token per inbound tag: the HandlerService
        // RemoveInbound path cancels exactly this inbound's listeners.
        let mut inbound_tokens = std::collections::HashMap::<String, CancellationToken>::new();
        let mut addresses = Vec::new();
        for (raw, inbound, transport) in compiled.inbounds {
            // Go's PortList: one listener per port of the inbound's range.
            let sniff = sniffing::SniffingRequest::compile(
                raw.sniffing.as_ref(),
                &crate::geodata::GeoDataStore::from_env()?,
            )
            .with_context(|| format!("inbound {:?} sniffing", raw.tag))?;
            let sniff = sniff.map(Arc::new);
            let inbound_cancel = cancel_token.child_token();
            inbound_tokens.insert(raw.tag.clone(), inbound_cancel.clone());
            for port in raw.port.ports() {
                // Hysteria owns a QUIC listener per port: no TCP socket is
                // bound and the streams dispatch through the QUIC seam.
                if let Inbound::Hysteria { users } = &inbound {
                    let listener =
                        hysteria_seam::bind_inbound(&raw, users, *port).with_context(|| {
                            format!(
                                "cannot bind inbound {:?} on {}:{}",
                                raw.tag, raw.listen, port
                            )
                        });
                    let listener = match listener {
                        Ok(listener) => listener,
                        Err(error) => {
                            for (listener, _, _, _, _, _) in listeners {
                                if let Err(close_error) = listener.close().await {
                                    tracing::warn!(%close_error, "inbound rollback close failed");
                                }
                            }
                            hysteria_listeners.clear();
                            return Err(error);
                        }
                    };
                    addresses.push(listener.local_addr());
                    seeds.push((raw.clone(), inbound.clone(), transport.clone()));
                    hysteria_listeners.push((
                        listener,
                        inbound.clone(),
                        raw.tag.clone(),
                        sniff.clone(),
                        inbound_cancel.clone(),
                    ));
                    continue;
                }
                let listener = match transport
                    .bind(SocketAddr::new(raw.listen, *port))
                    .await
                    .with_context(|| {
                        format!(
                            "cannot bind inbound {:?} on {}:{}",
                            raw.tag, raw.listen, port
                        )
                    }) {
                    Ok(listener) => listener,
                    Err(error) => {
                        // KCP owns a UDP receive task. Join every prior
                        // listener's close before returning so failed startup
                        // releases ports.
                        for (listener, _, _, _, _, _) in listeners {
                            if let Err(close_error) = listener.close().await {
                                tracing::warn!(%close_error, "inbound rollback close failed");
                            }
                        }
                        return Err(error);
                    }
                };
                addresses.push(listener.local_addr()?);
                seeds.push((raw.clone(), inbound.clone(), transport.clone()));
                listeners.push((
                    listener,
                    inbound.clone(),
                    raw.tag.clone(),
                    transport.clone(),
                    sniff.clone(),
                    inbound_cancel.clone(),
                ));
            }
        }
        // UDP listener specs: bound sockets whose serve loops spawn in the
        // root task where the dispatcher and stopping token exist.
        let mut udp_listeners = Vec::new();
        for (raw, inbound, _) in &seeds {
            if let Inbound::Shadowsocks { account, udp: true } = inbound {
                for port in raw.port.ports() {
                    let bound = plain_udp::LegacyShadowsocksUdp::bind(
                        SocketAddr::new(raw.listen, *port),
                        account,
                    );
                    let bound = match bound {
                        Ok(bound) => bound,
                        Err(error) => {
                            for (listener, _, _, _, _, _) in listeners {
                                if let Err(close_error) = listener.close().await {
                                    tracing::warn!(%close_error, "inbound rollback close failed");
                                }
                            }
                            return Err(error)
                                .with_context(|| format!("cannot bind inbound {:?} UDP", raw.tag));
                        }
                    };
                    udp_listeners.push(UdpEntry::LegacyShadowsocks {
                        bound,
                        tag: raw.tag.clone(),
                    });
                }
            }
            if let Inbound::Dokodemo { udp: true, .. } = inbound {
                for port in raw.port.ports() {
                    let address = SocketAddr::new(raw.listen, *port);
                    let Inbound::Dokodemo { destination, .. } = inbound else {
                        unreachable!("checked above");
                    };
                    udp_listeners.push(UdpEntry::Dokodemo {
                        address,
                        destination: destination.clone(),
                        tag: raw.tag.clone(),
                    });
                }
            }
            if let Inbound::Shadowsocks2022 { account, udp: true } = inbound {
                for port in raw.port.ports() {
                    let bound = ss2022_udp_runtime::Ss2022UdpListener::bind(
                        SocketAddr::new(raw.listen, *port),
                        account,
                    );
                    let bound = match bound {
                        Ok(bound) => bound,
                        Err(error) => {
                            // Release the already-bound TCP listeners before the
                            // failed startup propagates, exactly like a TCP bind
                            // failure inside the loop above.
                            for (listener, _, _, _, _, _) in listeners {
                                if let Err(close_error) = listener.close().await {
                                    tracing::warn!(%close_error, "inbound rollback close failed");
                                }
                            }
                            return Err(error)
                                .with_context(|| format!("cannot bind inbound {:?} UDP", raw.tag));
                        }
                    };
                    udp_listeners.push(UdpEntry::Shadowsocks2022 {
                        bound,
                        tag: raw.tag.clone(),
                    });
                }
            }
        }
        // One shared authenticated QUIC session per hysteria outbound, keyed
        // by the dialer Arc identity establish hands back.
        let mut hysteria_pool = hysteria_seam::HysteriaPool::new();
        for outbound in &compiled.outbounds {
            hysteria_pool.seed(outbound);
        }
        let dispatcher = Arc::new(Dispatcher {
            outbounds: compiled.outbounds,
            transports: compiled.outbound_transports,
            router,
            udp,
            policy,
            stats: stats.clone(),
            outbound_tags,
            logger,
            api: api_sender,
            dns: compiled.dns.clone(),
            reverse: Default::default(),
            wireguard: wireguard_runtime::WireguardPool::new(),
            masque: Default::default(),
            mux: mux_pools,
            fake_dns: compiled.fake_dns.clone(),
            loopback: Default::default(),
            hysteria: hysteria_pool,
        });
        for outbound_mux in dispatcher.mux.iter().flatten() {
            for pool in [&outbound_mux.tcp, &outbound_mux.xudp]
                .into_iter()
                .flatten()
            {
                pool.attach(&dispatcher);
            }
        }
        let observatory = compiled
            .observatory
            .map(|compiled| observatory::new(compiled, dispatcher.clone()))
            .transpose()?;
        // Built after the dispatcher: the reverse bridges dial their carriers
        // through this very dispatcher, and the burst observer probes through
        // the runtime's own establish path.
        let burst = match compiled.burst {
            Some(settings) => Some(burst_observatory::new(settings, dispatcher.clone())?),
            None => None,
        };
        if let Some(config) = &compiled.reverse {
            let runtime = reverse_runtime::new(config, dispatcher.clone(), cancel_token.clone())?;
            // Single installation at startup; the OnceLock only needs to
            // outlive this constructor. The runtime keeps its own handle.
            let _ = dispatcher.reverse.set(runtime.clone());
            runtime.start()?;
        }
        // The registry serves HandlerService listings from the startup
        // snapshot and can spawn added inbounds through the accept loop.
        let registry = handler_registry::RuntimeRegistry::new(
            dispatcher.clone(),
            cancel_token.clone(),
            config.routing.clone(),
            dispatcher.outbound_tags.clone(),
        );
        registry.attach_router(Arc::clone(&dispatcher.router));
        for (raw, inbound, transport) in seeds {
            registry.seed_inbound(raw, inbound, transport);
        }
        for (tag, token) in inbound_tokens {
            registry.attach_inbound_cancel(tag, token);
        }
        registry.seed_outbounds(config.outbounds.clone());
        let reflection_service = config
            .api
            .as_ref()
            .is_some_and(|api| {
                api.services
                    .iter()
                    .any(|service| service.eq_ignore_ascii_case("ReflectionService"))
            })
            .then(|| {
                tonic_reflection::server::Builder::configure()
                    .register_encoded_file_descriptor_set(xray_proto::FILE_DESCRIPTOR_SET)
                    .build_v1()
                    .context("build the reflection service")
            })
            .transpose()?;
        let api_server = config.api.as_ref().map(|api| {
            let mut routes = tonic::service::Routes::default();
            for service in &api.services {
                if service.eq_ignore_ascii_case("StatsService") {
                    routes = crate::api::stats_routes(crate::api::StatsService::new(
                        stats.clone().unwrap_or_default(),
                    ));
                }
            }
            if api
                .services
                .iter()
                .any(|service| service.eq_ignore_ascii_case("LoggerService"))
            {
                routes = crate::api::add_logger_routes(
                    routes,
                    crate::api::LoggerService::new(dispatcher.logger.clone()),
                );
            }
            if api
                .services
                .iter()
                .any(|service| service.eq_ignore_ascii_case("ObservatoryService"))
            {
                let provider = if let Some(ordinary) = observatory.as_ref() {
                    ordinary.provider()
                } else {
                    burst
                        .as_ref()
                        .expect("configuration requires an observatory provider")
                        .provider()
                };
                routes = crate::api::observatory::add_observatory_routes(
                    routes,
                    crate::api::observatory::ObservatoryService::new(provider),
                );
            }
            if api
                .services
                .iter()
                .any(|service| service.eq_ignore_ascii_case("HandlerService"))
            {
                routes = crate::api::handler::add_handler_routes(
                    routes,
                    crate::api::handler::HandlerService::new(registry.store()),
                );
            }
            if api
                .services
                .iter()
                .any(|service| service.eq_ignore_ascii_case("RoutingService"))
            {
                routes = crate::api::routing::add_routing_routes(
                    routes,
                    crate::api::routing::RoutingServiceBackend::new(registry.routing_store()),
                );
            }
            if api
                .services
                .iter()
                .any(|service| service.eq_ignore_ascii_case("ReflectionService"))
            {
                // gRPC server reflection over the full descriptor set (Go's
                // commander reflection service).
                if let Some(reflection) = reflection_service.as_ref() {
                    routes = routes.add_service(reflection.clone());
                }
            }
            crate::api::ApiServer::from_routes(routes)
        });
        let cancel = cancel_token;
        let stopping = cancel.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            if let Some(observer) = observatory.filter(|observer| observer.is_enabled()) {
                let stop = stopping.clone();
                tasks.spawn(async move { observer.run(&stop).await });
            }
            if let Some(burst) = burst.filter(|burst| burst.is_enabled()) {
                let stop = stopping.clone();
                tasks.spawn(async move { burst.run(&stop).await });
            }
            for entry in udp_listeners {
                let dispatcher = dispatcher.clone();
                let stop = stopping.clone();
                tasks.spawn(async move {
                    let result = match entry {
                        UdpEntry::Shadowsocks2022 { bound, tag } => {
                            let _ = tag;
                            bound.run(dispatcher, stop).await
                        }
                        UdpEntry::LegacyShadowsocks { bound, tag } => {
                            let tag: Arc<str> = Arc::from(tag);
                            bound.run(dispatcher, tag, stop).await
                        }
                        UdpEntry::Dokodemo {
                            address,
                            destination,
                            tag,
                        } => {
                            let tag: Arc<str> = Arc::from(tag);
                            plain_udp::serve_dokodemo_udp(
                                address,
                                destination,
                                dispatcher,
                                tag,
                                stop,
                            )
                            .await
                        }
                    };
                    if let Err(error) = result {
                        tracing::warn!(%error, "inbound UDP listener ended");
                    }
                    Ok::<(), anyhow::Error>(())
                });
            }
            if let Some(api) = api_server {
                if let Some(listener) = api_listener {
                    let api = api.clone();
                    let stop = stopping.clone();
                    tasks.spawn(async move {
                        tokio::select! { _=stop.cancelled()=>Ok(()), result=api.serve_tcp(listener,stop.clone())=>result.map_err(Into::into) }
                    });
                }
                if let Some(incoming) = api_channel {
                    let stop = stopping.clone();
                    tasks.spawn(async move {
                        tokio::select! { _=stop.cancelled()=>Ok(()), result=api.serve_incoming(incoming,stop.clone())=>result.map_err(Into::into) }
                    });
                }
            }
            for (listener, inbound, tag, transport, sniff, inbound_stop) in listeners {
                tasks.spawn(accept_loop(
                    listener,
                    inbound,
                    tag,
                    transport,
                    sniff,
                    dispatcher.clone(),
                    inbound_stop,
                ));
            }
            for (listener, inbound, tag, sniff, inbound_stop) in hysteria_listeners {
                let dispatcher = dispatcher.clone();
                let tag: Arc<str> = Arc::from(tag);
                tasks.spawn(async move {
                    hysteria_seam::serve(listener, inbound, tag, sniff, dispatcher, inbound_stop)
                        .await
                });
            }
            if tasks.is_empty() {
                stopping.cancelled().await;
                return Ok(());
            }
            let result = tokio::select! {
                _ = stopping.cancelled() => Ok(()),
                result = tasks.join_next() => match result {
                    Some(result) => result.context("listener task panicked")?,
                    None => Ok(()),
                },
            };
            stopping.cancel();
            while tasks.join_next().await.is_some() {}
            result
        });
        Ok(Self {
            addresses,
            cancel,
            task: Some(task),
            stats,
            api_address,
        })
    }

    pub fn local_addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    pub fn stats(&self) -> Option<Arc<crate::features::StatsManager>> {
        self.stats.clone()
    }
    pub fn api_address(&self) -> Option<SocketAddr> {
        self.api_address
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.await.context("server task panicked")??;
        }
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<()> {
        if let Some(task) = self.task.as_mut() {
            task.await.context("server task panicked")??;
        }
        self.task = None;
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn accept_loop(
    mut listener: InboundListener,
    inbound: Inbound,
    tag: String,
    transport: InboundTransport,
    sniff: Option<std::sync::Arc<sniffing::SniffingRequest>>,
    dispatcher: Arc<Dispatcher>,
    cancel: CancellationToken,
) -> Result<()> {
    let inbound = Arc::new(inbound);
    let tag: Arc<str> = tag.into();
    let transport = Arc::new(transport);
    let mut sessions = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            _ = sessions.join_next(), if !sessions.is_empty() => (),
            accepted = listener.accept() => {
                let (stream, source, bound) = match accepted.context("inbound accept failed") {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error),
                };
                let context = ConnectionContext {
                    inbound: inbound.clone(),
                    tag: tag.clone(),
                    dispatcher: dispatcher.clone(),
                    cancel: cancel.clone(),
                    sniff: sniff.clone(),
                };
                let transport = transport.clone();
                sessions.spawn(async move {
                    let log_tag = context.tag.clone();
                    if let Err(error) = handle_connection(stream, source, bound, transport, context).await {
                        tracing::debug!(inbound = %log_tag, %source, error = %format!("{error:#}"), "connection closed");
                    }
                });
            }
        }
    };
    // Let every connection cancel and drain its owned logical stream tasks
    // before this listener finishes; dropping a nested JoinSet would only abort.
    cancel.cancel();
    let close_result = listener
        .close()
        .await
        .context("inbound listener close failed");
    while sessions.join_next().await.is_some() {}
    result.and(close_result)
}

/// Per-connection inbound plumbing shared by every accepted transport stream.
#[derive(Clone)]
struct ConnectionContext {
    inbound: Arc<Inbound>,
    tag: Arc<str>,
    dispatcher: Arc<Dispatcher>,
    cancel: CancellationToken,
    sniff: Option<std::sync::Arc<sniffing::SniffingRequest>>,
}

async fn handle_connection(
    stream: BoxStream,
    source: SocketAddr,
    bound: SocketAddr,
    transport: Arc<InboundTransport>,
    context: ConnectionContext,
) -> Result<()> {
    let ConnectionContext {
        inbound,
        tag,
        dispatcher,
        cancel,
        sniff,
    } = context;
    let accepted = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        accepted = transport.accept(stream) => accepted?,
    };
    match accepted {
        AcceptedTransport::Single(None) => Ok(()),
        AcceptedTransport::Single(Some(stream)) => {
            handle_stream(
                stream,
                source,
                bound,
                &inbound,
                &tag,
                &dispatcher,
                &cancel,
                sniff.as_ref().cloned(),
            )
            .await
        }
        AcceptedTransport::Grpc(mut server) => {
            // The H2 driver runs independently of accept(), so waiting for a
            // logical task slot cannot stall established streams' flow control.
            let mut streams = JoinSet::new();
            let stream_cancel = cancel.child_token();
            let result = loop {
                tokio::select! {
                    _ = cancel.cancelled() => break Ok(()),
                    completed = streams.join_next(), if !streams.is_empty() => {
                        if let Some(Err(error)) = completed {
                            tracing::debug!(inbound = %tag, %source, %error, "gRPC stream task ended");
                        }
                    }
                    accepted = server.accept(), if streams.len() < MAX_GRPC_STREAM_TASKS => {
                        let accepted = match accepted {
                            Ok(Some(accepted)) => accepted,
                            Ok(None) => break Ok(()),
                            Err(error) => break Err(error.into()),
                        };
                        let inbound = inbound.clone();
                        let tag = tag.clone();
                        let dispatcher = dispatcher.clone();
                        let cancel = stream_cancel.clone();
                        let stream_sniff = sniff.clone();
                        streams.spawn(async move {
                            if let Err(error) = handle_stream(accepted.stream.boxed(), source, bound, &inbound, &tag, &dispatcher, &cancel, stream_sniff).await {
                                tracing::debug!(inbound = %tag, %source, error = %format!("{error:#}"), "gRPC logical stream closed");
                            }
                        });
                    }
                }
            };
            stream_cancel.cancel();
            while streams.join_next().await.is_some() {}
            result
        }
    }
}

/// One bound UDP listener beside an inbound's TCP listener.
enum UdpEntry {
    Shadowsocks2022 {
        bound: ss2022_udp_runtime::Ss2022UdpListener,
        tag: String,
    },
    LegacyShadowsocks {
        bound: plain_udp::LegacyShadowsocksUdp,
        tag: String,
    },
    Dokodemo {
        address: SocketAddr,
        destination: Destination,
        tag: String,
    },
}

/// One bound inbound: its listener, compiled protocol/transport, tag and
/// compiled sniffing request.
/// One bound hysteria QUIC listener: the endpoint, the compiled inbound,
/// its tag, sniffing request and per-tag cancellation token.
type HysteriaListenerEntry = (
    crate::transport::hysteria_endpoint::HysteriaEndpointListener,
    Inbound,
    String,
    Option<std::sync::Arc<sniffing::SniffingRequest>>,
    CancellationToken,
);

type ListenerEntry = (
    InboundListener,
    Inbound,
    String,
    InboundTransport,
    Option<std::sync::Arc<sniffing::SniffingRequest>>,
    CancellationToken,
);

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    mut stream: BoxStream,
    source: SocketAddr,
    bound: SocketAddr,
    inbound: &Inbound,
    tag: &str,
    dispatcher: &Arc<Dispatcher>,
    cancel: &CancellationToken,
    sniff: Option<std::sync::Arc<sniffing::SniffingRequest>>,
) -> Result<()> {
    let policy = dispatcher.policy.for_level(0);
    if let Some(stats) = &dispatcher.stats {
        stream = CountedStream::wrap(
            stream,
            stats.inbound_counters(tag, dispatcher.policy.for_system().stats),
            true,
        );
    }
    // The DNS inbound is terminal: it speaks DNS frames, not a proxy
    // handshake, so it never produces a protocol::Request.
    if let Inbound::Dns(settings) = inbound {
        let proxy =
            protocol::dns_proxy::DnsProxy::compile(settings).context("dns inbound settings")?;
        return match dispatcher.dns.as_ref() {
            Some(app) => {
                let resolver = dns_runtime::DnsAppQuery(app.clone());
                let dial = dns_runtime::RuntimeDial(dispatcher.clone());
                proxy
                    .serve_inbound(stream, Some(&resolver), &dial, cancel)
                    .await
            }
            None => anyhow::bail!("dns proxy hijack requires a configured DNS app"),
        };
    }
    let (stream, handshake) = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        result = timeout(policy.timeouts.handshake, proxy_handshake(stream, inbound)) => result.context("proxy handshake timed out")??,
    };
    let (request, vision) = match handshake {
        InboundHandshake::Connect(request, vision) => (request, vision),
        InboundHandshake::SocksAssociate(request) => {
            let Inbound::Socks(settings) = inbound else {
                unreachable!("only SOCKS can associate UDP")
            };
            return udp_integration::serve(
                stream,
                request,
                settings,
                udp_integration::ConnectionEnds { source, bound },
                tag,
                dispatcher,
                cancel,
            )
            .await;
        }
        // Trojan carries its UDP association as frames over the very
        // connection that carried the request header.
        InboundHandshake::TrojanUdp(request) => {
            let Inbound::Trojan { .. } = inbound else {
                unreachable!("only Trojan associates UDP over its connection")
            };
            return trojan_udp_runtime::serve(stream, request, dispatcher, tag, cancel).await;
        }
    };
    dispatch_request(
        stream, source, bound, inbound, tag, dispatcher, cancel, request, vision, sniff,
    )
    .await
}

/// Route, establish and relay one authenticated inbound request (the
/// post-handshake half of `handle_stream`). A request targeting the Mux.Cool
/// address turns the connection body into a carrier (Go's proxyman inbound
/// wraps every dispatcher with `mux.NewServer`; the check is on the address
/// alone). Sessions arriving inside a carrier dispatch through
/// `dispatch_common`, which does not intercept again — nested carriers fail
/// explicitly instead of recursing.
#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    mut stream: BoxStream,
    source: SocketAddr,
    bound: SocketAddr,
    inbound: &Inbound,
    tag: &str,
    dispatcher: &Arc<Dispatcher>,
    cancel: &CancellationToken,
    request: protocol::Request,
    vision: Option<[u8; 16]>,
    sniff: Option<std::sync::Arc<sniffing::SniffingRequest>>,
) -> Result<()> {
    // A request whose destination address is v1.mux.cool turns the
    // connection body into a Mux.Cool carrier. The carrier runs on its own
    // task: its sessions dispatch back through the runtime, and a directly
    // awaited carrier would make the recursive future unprovable.
    if matches!(&request.destination.address, crate::address::Address::Domain(domain)
        if domain == crate::mux::MUX_DOMAIN)
    {
        request.reply.success(&mut stream, bound).await?;
        if let Err(error) = dispatcher
            .logger
            .write_access(&crate::logging::AccessRecord::accepted(
                source,
                &request.destination,
            ))
        {
            tracing::warn!(%error, "cannot write access record");
        }
        let carrier_dispatcher = Arc::clone(dispatcher);
        let carrier_inbound = Arc::new(inbound.clone());
        let carrier_tag: Arc<str> = tag.into();
        let carrier_user = request.user.clone();
        let carrier_cancel = cancel.clone();
        let carrier = tokio::spawn(async move {
            let carrier: std::pin::Pin<
                Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>,
            > = Box::pin(mux_runtime::serve_carrier(
                &carrier_dispatcher,
                carrier_inbound,
                carrier_tag,
                carrier_user,
                source,
                stream,
                &carrier_cancel,
                sniff.clone(),
            ));
            carrier.await
        });
        return match carrier.await {
            Ok(result) => result,
            Err(error) => Err(anyhow::Error::from(error).context("mux carrier task panicked")),
        };
    }
    dispatch_common(
        stream, source, bound, inbound, tag, dispatcher, cancel, request, vision, sniff,
    )
    .await
}

/// The non-intercepting dispatch body shared by fresh requests and Mux.Cool
/// session requests.
#[allow(clippy::too_many_arguments)]
async fn dispatch_common(
    mut stream: BoxStream,
    source: SocketAddr,
    bound: SocketAddr,
    inbound: &Inbound,
    tag: &str,
    dispatcher: &Arc<Dispatcher>,
    cancel: &CancellationToken,
    mut request: protocol::Request,
    vision: Option<[u8; 16]>,
    sniff: Option<std::sync::Arc<sniffing::SniffingRequest>>,
) -> Result<()> {
    // Go's dispatcher sniffs the connection before routing: the payload is
    // peeked within Go's budget and replayed into the relay; destOverride
    // replaces the routed (and, without routeOnly, the dialed) destination
    // with the sniffed domain. A failed sniff relays unchanged.
    // A destination inside the FakeDNS pool maps back to its leased domain
    // before routing and dialing (Go's dispatcher swaps the target when
    // IsIPInIPPool); unmapped pool addresses route unchanged.
    if let (Some(engine), crate::address::Address::Ip(ip)) =
        (&dispatcher.fake_dns, &request.destination.address)
        && let Some(domain) = engine.domain_from_ip(*ip)
    {
        request.destination.address = crate::address::Address::Domain(domain);
    }
    let mut sniffed_protocol = None;
    let mut route_destination = request.destination.clone();
    if let Some(sniff) = sniff.as_ref() {
        let (wrapped, result) = sniffing::sniff(
            stream,
            sniffing::Network::Tcp,
            sniff.metadata_only,
            sniffing::SniffLimits::default(),
        )
        .await;
        stream = Box::new(wrapped);
        if let Some(result) = result {
            sniffed_protocol = Some(result.protocol);
            if let Some(override_) = sniff.destination_override(&result, &request.destination) {
                if override_.route_only {
                    // routeOnly: the router sees the sniffed domain, the
                    // outbound dials the original target (Go's RouteTarget).
                    route_destination.address = crate::address::Address::Domain(override_.domain);
                } else {
                    // Go's Target: the sniffed domain replaces routing AND
                    // dialing.
                    request.destination.address = crate::address::Address::Domain(override_.domain);
                    route_destination = request.destination.clone();
                }
            }
        }
    }
    // The authenticated user's policy level selects the session policy
    // (Go's PolicyManager.ForLevel over the user's account level); the
    // caller's pre-auth handshake policy stays level zero.
    let session_policy = dispatcher.policy.for_level(request.level);
    let exchange = async {
        let idle_since = Instant::now();
        anyhow::ensure!(
            !session_policy.timeouts.connection_idle.is_zero(),
            "proxy session inactivity timeout"
        );
        let user_stats = dispatcher.stats.as_ref().map(|stats| {
            stats.user_session(
                &request.user,
                &source_ip_string(source),
                session_policy.stats,
            )
        });
        let (selected, routed) = dispatcher.router.select_with_route_sniffed(
            &RouteContext {
                destination: &route_destination,
                source,
                inbound_tag: tag,
                user: &request.user,
                network: "tcp",
            },
            sniffed_protocol,
        );
        // Portal indexes sit beyond the real outbounds (the routing-only
        // reverse entries); they dispatch through the reverse app.
        let portal_selected = selected >= dispatcher.outbounds.len();
        let outbound = dispatcher.outbounds.get(selected);
        let record = |accepted: bool, reason: String| {
            let mut record = if accepted {
                crate::logging::AccessRecord::accepted(source, &request.destination)
            } else {
                crate::logging::AccessRecord::rejected(source, &request.destination, reason)
            };
            record.email = request.user.clone();
            record.detour = crate::logging::format_detour(
                tag,
                &dispatcher.outbound_tags[selected],
                if routed {
                    crate::logging::DetourKind::Routed
                } else {
                    crate::logging::DetourKind::Default
                },
            );
            if let Err(error) = dispatcher.logger.write_access(&record) {
                tracing::warn!(%error,"cannot write access record");
            }
        };
        tracing::debug!(inbound = tag, %source, target = %request.destination, outbound = selected, "routing connection");
        enum Dispatch<'a> {
            Relay(BoxStream),
            Blocked(Duration),
            Blackhole(&'a [u8]),
        }
        let idle_deadline = idle_since + session_policy.timeouts.connection_idle;
        // A bridge-domain destination is a reverse carrier the bridge dialed:
        // the portal takes the whole connection before routing (Go's isDomain
        // check in app/reverse/portal.go HandleConnection).
        if let Some(reverse) = dispatcher.reverse.get()
            && reverse.is_portal_destination(&request.destination)
        {
            return tokio::select! {
                biased;
                _ = cancel.cancelled() => Ok(()),
                result = timeout_at(idle_deadline, async {
                    request.reply.success(&mut stream, bound).await?;
                    record(true, String::new());
                    reverse.attach_carrier(stream).await
                }) => result.context("reverse carrier timed out")?,
            };
        }
        // The dns and loopback outbounds own their relays (Go's
        // Handler.Process / Loopback.Process): they bypass the establish
        // path entirely, so they are served before the dispatch block.
        if let Some(Outbound::Dns { settings }) = outbound {
            let proxy = protocol::dns_proxy::DnsProxy::compile(settings)
                .context("dns outbound settings")?;
            let app_query = dispatcher
                .dns
                .as_ref()
                .map(|app| dns_runtime::DnsAppQuery(app.clone()));
            let dial = dns_runtime::RuntimeDial(dispatcher.clone());
            request.reply.success(&mut stream, bound).await?;
            record(true, String::new());
            return proxy
                .serve_outbound(
                    stream,
                    &request.destination,
                    protocol::dns_proxy::Framing::Tcp,
                    app_query
                        .as_ref()
                        .map(|query| query as &dyn protocol::dns_proxy::DnsQuery),
                    &dial,
                    cancel,
                )
                .await;
        }
        if let Some(Outbound::Loopback { settings }) = outbound {
            let dispatch = dispatcher
                .loopback
                .get()
                .context("loopback outbound requires the dispatch seam")?
                .clone();
            let loopback = protocol::loopback::Loopback::new(settings.clone(), dispatch);
            request.reply.success(&mut stream, bound).await?;
            record(true, String::new());
            return loopback
                .process(&request.destination, stream)
                .await
                .context("loopback outbound relay");
        }
        // The authenticated session owns its policy and online guard during DNS,
        // dialing, outbound authentication, proxy replies and API queue backpressure.
        let dispatch = timeout_at(idle_deadline, async {
            let mut resolved = None;
            if matches!(outbound, Some(Outbound::Freedom { .. })) {
                let name = match inbound {
                    Inbound::Socks(_) => "socks",
                    Inbound::Http(_) => "http",
                    Inbound::Dokodemo { .. } => "dokodemo-door",
                    Inbound::Vless { .. } => "vless",
                    Inbound::Vmess(_) => "vmess",
                    Inbound::Trojan { .. } => "trojan",
                    Inbound::Shadowsocks { .. } => "shadowsocks",
                    Inbound::Shadowsocks2022 { .. } => "shadowsocks-2022",
                    Inbound::Dns(_) => "dns",
                    Inbound::Hysteria { .. } => "hysteria",
                };
                let admission = timeout(
                    DIAL_TIMEOUT,
                    admission::admit(
                        // The Freedom match above proved this is a real
                        // outbound; unwrap cannot fail.
                        outbound.expect("freedom admission requires a real outbound"),
                        name,
                        &request.destination,
                        dispatcher.dns.as_ref(),
                    ),
                )
                .await
                .context("freedom admission timed out")??;
                match admission {
                    protocol::freedom::Admission::Allowed(addresses) => resolved = addresses,
                    protocol::freedom::Admission::Blocked(delay) => {
                        record(false, "freedom final rule blocked target".into());
                        request.reply.success(&mut stream, bound).await?;
                        return Ok::<_, anyhow::Error>(Dispatch::Blocked(delay));
                    }
                }
            }
            let dispatch = match outbound {
                Some(Outbound::Api) => {
                    // Keep the client and user guard in this connection task. The
                    // API receives only the other end of the bounded relay, as Go's
                    // commander receives a connection backed by dispatcher pipes.
                    let (upstream, service) =
                        tokio::io::duplex(relay_buffer_size(session_policy.buffer));
                    dispatcher
                        .api
                        .as_ref()
                        .context("management API unavailable")?
                        .accept(Box::new(service), Some(source))
                        .await?;
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Relay(Box::new(upstream))
                }
                Some(Outbound::Blackhole { response }) => {
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Blackhole(response)
                }
                Some(Outbound::Masque { .. }) => {
                    // The MASQUE proxy owns the relay: one shared h2 client
                    // per outbound (Go reuses one CONNECT-IP tunnel), one
                    // extended-CONNECT stream per target connection.
                    let upstream = timeout(
                        DIAL_TIMEOUT,
                        dispatcher.masque_stream(selected, &request.destination),
                    )
                    .await
                    .context("MASQUE outbound connection timed out")
                    .and_then(|r| r);
                    let (upstream, bound) = match upstream {
                        Ok(upstream) => upstream,
                        Err(error) => {
                            record(false, error.to_string());
                            request.reply.failure(&mut stream, 5).await?;
                            return Err(error);
                        }
                    };
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Relay(upstream)
                }
                None if portal_selected => {
                    // A portal-tag routing outbound (Go's reverse `Outbound`
                    // handler): the session opens through the portal's least
                    // loaded carrier and relays like any proxy hop.
                    let reverse = dispatcher
                        .reverse
                        .get()
                        .context("reverse portal selected without a reverse app")?;
                    let tag = dispatcher.outbound_tags[selected].clone();
                    let upstream = match timeout(
                        DIAL_TIMEOUT,
                        reverse.open_session(&tag, &request.destination),
                    )
                    .await
                    .context("reverse portal connection timed out")
                    .and_then(|result| result.map_err(anyhow::Error::from))
                    {
                        Ok(upstream) => upstream,
                        Err(error) => {
                            record(false, error.to_string());
                            request.reply.failure(&mut stream, 5).await?;
                            return Err(error);
                        }
                    };
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Relay(upstream)
                }
                _ if dispatcher
                    .mux
                    .get(selected)
                    .is_some_and(|mux| mux.as_ref().is_some_and(|mux| mux.tcp.is_some())) =>
                {
                    // Go's mux ClientManager: one stream on a shared carrier
                    // connection to v1.mux.cool:9527 (up to sixteen pick
                    // attempts across workers).
                    let upstream = timeout(
                        DIAL_TIMEOUT,
                        dispatcher.mux_open_stream(selected, &request.destination),
                    )
                    .await
                    .context("mux outbound connection timed out")
                    .and_then(|r| r);
                    let upstream = match upstream {
                        Ok(upstream) => upstream,
                        Err(error) => {
                            record(false, error.to_string());
                            request.reply.failure(&mut stream, 5).await?;
                            return Err(error);
                        }
                    };
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Relay(upstream)
                }
                _ => {
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
                    let upstream = timeout(
                        DIAL_TIMEOUT,
                        establish(
                            dispatcher,
                            outbound.context("selected outbound unavailable")?,
                            dispatcher
                                .transports
                                .get(selected)
                                .context("selected outbound transport unavailable")?,
                            &request.destination,
                            resolved.as_deref(),
                            counters,
                        ),
                    )
                    .await
                    .context("outbound connection timed out")
                    .and_then(|r| r);
                    let (upstream, bound) = match upstream {
                        Ok(upstream) => upstream,
                        Err(error) => {
                            record(false, error.to_string());
                            request.reply.failure(&mut stream, 5).await?;
                            return Err(error);
                        }
                    };
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Relay(upstream)
                }
            };
            record(true, String::new());
            Ok(dispatch)
        })
        .await
        .context("proxy session inactivity timeout during setup")??;
        // A Vision request wraps the inbound body after the reply header is
        // on the wire (Go wraps between the response header and the relay).
        if let Some(uuid) = vision {
            stream = Box::new(protocol::vless_vision::VisionStream::server(stream, uuid));
        }
        // Bytes read ahead by HTTP must pass through the same timed and accounted
        // transfer as all subsequent payload; their wire bytes were already counted.
        if !request.initial_payload.is_empty() {
            let (reader, writer) = tokio::io::split(stream);
            stream = Box::new(crate::transport::Joined {
                reader: std::io::Cursor::new(request.initial_payload).chain(reader),
                writer,
            });
        }
        match dispatch {
            Dispatch::Relay(mut upstream) => {
                crate::features::session::relay_with_idle_since(
                    &mut stream,
                    &mut upstream,
                    &session_policy,
                    user_stats,
                    &[],
                    cancel,
                    idle_since,
                )
                .await?;
            }
            Dispatch::Blocked(delay) => {
                let mut deadline = idle_deadline;
                let mut buffer = vec![0; relay_buffer_size(session_policy.buffer)];
                let drain = async {
                    loop {
                        let count = timeout_at(deadline, stream.read(&mut buffer)).await??;
                        if count == 0 {
                            break;
                        }
                        if let Some(stats) = &user_stats {
                            stats.traffic.add_uplink(count);
                        }
                        deadline = Instant::now() + session_policy.timeouts.connection_idle;
                    }
                    timeout_at(deadline, stream.shutdown()).await??;
                    Ok::<_, anyhow::Error>(())
                };
                if let Ok(result) = timeout(delay, drain).await {
                    result?;
                }
            }
            Dispatch::Blackhole(mut response) => {
                let mut deadline = idle_deadline;
                while !response.is_empty() {
                    let count = timeout_at(deadline, stream.write(response)).await??;
                    anyhow::ensure!(count != 0, "blackhole response write returned zero");
                    if let Some(stats) = &user_stats {
                        stats.traffic.add_downlink(count);
                    }
                    response = &response[count..];
                    deadline = Instant::now() + session_policy.timeouts.connection_idle;
                }
                timeout_at(deadline, stream.shutdown()).await??;
            }
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        result = exchange => result,
    }
}

/// The three inbound session shapes the connection dispatcher understand.
enum InboundHandshake {
    /// One proxied TCP request; the second field is the matched VLESS
    /// account's UUID when the request rode the Vision flow (the body wrap
    /// seed, `proxy.NewTrafficState`).
    Connect(protocol::Request, Option<[u8; 16]>),
    /// A SOCKS UDP ASSOCIATE with its control-stream protocol.
    SocksAssociate(protocol::socks::AssociateRequest),
    /// A Trojan UDP association: frames over the request's own connection.
    TrojanUdp(protocol::Request),
}

async fn proxy_handshake(
    mut stream: BoxStream,
    inbound: &Inbound,
) -> Result<(BoxStream, InboundHandshake)> {
    use protocol::socks::Handshake;
    let request = match inbound {
        // The DNS inbound never reaches a proxy handshake.
        Inbound::Dns(_) => unreachable!("the dns inbound is served before the handshake"),
        // Hysteria streams dispatch through the QUIC seam, never through the
        // TCP handshake path.
        Inbound::Hysteria { .. } => {
            unreachable!("the hysteria inbound dispatches through its QUIC seam")
        }
        Inbound::Vmess(authenticator) => {
            let (stream, request) = protocol::vmess::stream::accept(stream, authenticator).await?;
            return Ok((stream, InboundHandshake::Connect(request, None)));
        }
        Inbound::Shadowsocks { account, .. } => {
            let (stream, request) = protocol::shadowsocks_session::accept(stream, account).await?;
            return Ok((stream, InboundHandshake::Connect(request, None)));
        }
        Inbound::Shadowsocks2022 { account, .. } => {
            let (stream, request) = protocol::shadowsocks2022::accept(stream, account).await?;
            return Ok((stream, InboundHandshake::Connect(request, None)));
        }
        Inbound::Socks(settings) => {
            let handshake = protocol::socks::handshake_with_udp(&mut stream, settings).await?;
            return match handshake {
                Handshake::Connect(request) => {
                    Ok((stream, InboundHandshake::Connect(request, None)))
                }
                Handshake::Associate(request) => {
                    Ok((stream, InboundHandshake::SocksAssociate(request)))
                }
            };
        }
        Inbound::Http(settings) => protocol::http::handshake(&mut stream, settings).await?,
        Inbound::Vless {
            accounts,
            decryption,
        } => {
            // `mlkem768x25519plus` wraps the whole VLESS session: the request
            // header is exchanged inside the encrypted stream, and the shared
            // decryption instance keeps its replay history across connections.
            let mut stream: BoxStream = match decryption {
                Some(server) => Box::new(
                    protocol::vless_encryption::accept(stream, server)
                        .await
                        .context("VLESS encrypted session")?,
                ),
                None => stream,
            };
            let accepted = protocol::vless::read_request(&mut stream, accounts).await?;
            // The reader validated the flow against the account; a Vision
            // request carries the account UUID for the body wrap.
            let vision = (accepted.flow == protocol::vless::XRV_FLOW).then_some(accepted.id);
            return Ok((stream, InboundHandshake::Connect(accepted.request, vision)));
        }
        Inbound::Trojan { accounts, .. } => {
            let accepted = protocol::trojan::read_request(&mut stream, accounts).await?;
            if accepted.udp {
                return Ok((stream, InboundHandshake::TrojanUdp(accepted.request)));
            }
            return Ok((stream, InboundHandshake::Connect(accepted.request, None)));
        }
        Inbound::Dokodemo { destination, .. } => Request {
            destination: destination.clone(),
            level: 0,
            user: String::new(),
            initial_payload: Vec::new(),
            reply: Reply::None,
        },
    };
    Ok((stream, InboundHandshake::Connect(request, None)))
}

fn source_ip_string(source: SocketAddr) -> String {
    // Go's Address.String brackets IPv6; OnlineMap excludes exactly "[::1]".
    if source.is_ipv6() {
        format!("[{}]", source.ip())
    } else {
        source.ip().to_string()
    }
}

impl Dispatcher {
    /// Open one proxied TCP stream toward `target` through the outbound's
    /// cached MASQUE h2 client, re-dialing the shared tunnel once when the
    /// cached connection has broken.
    async fn masque_stream(
        &self,
        index: usize,
        target: &Destination,
    ) -> Result<(crate::transport::BoxStream, SocketAddr)> {
        let Outbound::Masque { server, .. } = &self.outbounds[index] else {
            anyhow::bail!("MASQUE dispatch selected a non-masque outbound");
        };
        let transport = &self.transports[index];
        let (settings, tls) = match (&transport.masque, &transport.masque_tls) {
            (Some(settings), Some(tls)) => (settings.clone(), tls.clone()),
            _ => anyhow::bail!("MASQUE outbound requires the masque transport with TLS"),
        };
        let host = if transport.server_name.is_empty() {
            server.address.to_string()
        } else {
            transport.server_name.clone()
        };
        let addresses: Vec<SocketAddr> = match &server.address {
            crate::address::Address::Ip(ip) => vec![SocketAddr::new(*ip, server.port)],
            crate::address::Address::Domain(name) => {
                let ips: Vec<std::net::IpAddr> = match &self.dns {
                    Some(app) => {
                        app.lookup_ip(name, crate::dns::QueryOptions::default())
                            .await?
                            .ips
                    }
                    None => tokio::net::lookup_host((name.as_str(), server.port))
                        .await?
                        .map(|address| address.ip())
                        .collect(),
                };
                ips.into_iter()
                    .map(|ip| SocketAddr::new(ip, server.port))
                    .collect()
            }
        };
        let open = |client: std::sync::Arc<crate::transport::masque::MasqueClient>| {
            let host = target.address.to_string();
            async move {
                client
                    .connect_stream(&crate::transport::masque::Target::tcp(host, target.port))
                    .await
            }
        };
        let mut cache = self.masque.lock().await;
        if let Some(client) = cache.get(&index) {
            if let Ok(stream) = open(client.clone()).await {
                return Ok((stream, SocketAddr::from(([0, 0, 0, 0], 0))));
            }
            // The shared tunnel broke; drop it and dial a fresh one below.
            cache.remove(&index);
        }
        let mut last = None;
        for address in addresses {
            let client =
                crate::transport::masque::MasqueClient::dial(address, &host, &settings, &tls).await;
            match client {
                Ok(client) => {
                    let client = std::sync::Arc::new(client);
                    match open(client.clone()).await {
                        Ok(stream) => {
                            cache.insert(index, client);
                            return Ok((stream, SocketAddr::from(([0, 0, 0, 0], 0))));
                        }
                        Err(error) => last = Some(error.into()),
                    }
                }
                Err(error) => last = Some(error.into()),
            }
        }
        Err(last.unwrap_or_else(|| {
            anyhow::anyhow!("MASQUE server {server} resolved to no dialable address")
        }))
    }
}

fn relay_buffer_size(policy: crate::features::policy::BufferPolicy) -> usize {
    match policy.per_connection {
        0 => 2048,
        limit if limit > 0 => (limit as usize).min(16 * 1024),
        _ => 16 * 1024,
    }
}

async fn establish(
    dispatcher: &Dispatcher,
    outbound: &Outbound,
    transport: &OutboundTransport,
    target: &Destination,
    resolved: Option<&[SocketAddr]>,
    counters: TrafficCounters,
) -> Result<(crate::transport::BoxStream, SocketAddr)> {
    let remote = match outbound {
        Outbound::Freedom { redirect, .. } => {
            // Non-AsIs strategies were resolved by admission (the configured
            // DNS app, falling back to the system resolver like Go); the
            // resolved addresses dial through `connect_resolved` below.
            redirect.as_ref().unwrap_or(target)
        }
        Outbound::Socks { server, .. }
        | Outbound::Http { server, .. }
        | Outbound::Vless { server, .. }
        | Outbound::Vmess { server, .. }
        | Outbound::Trojan { server, .. }
        | Outbound::Shadowsocks { server, .. }
        | Outbound::Shadowsocks2022 { server, .. }
        | Outbound::Masque { server, .. } => server,
        Outbound::Blackhole { .. } | Outbound::Api => {
            anyhow::bail!("internal outbound cannot establish a remote stream")
        }
        Outbound::Dns { .. } | Outbound::Loopback { .. } => {
            anyhow::bail!("the dns and loopback outbounds own their relays")
        }
        Outbound::Wireguard { settings } => {
            // One lazily-built engine per settings value, dialed through the
            // netstack's TCP path; the pool owns the Noise pumps.
            return dispatcher
                .wireguard
                .connect(dispatcher, settings, target)
                .await;
        }
        Outbound::Hysteria { dialer } => {
            // One shared authenticated QUIC session per outbound; the pool
            // keeps the cached connection and its UDP session table.
            return dispatcher.hysteria.connect(dialer, target).await;
        }
    };
    let (mut stream, bound) = if let Some(addresses) = resolved {
        transport.connect_resolved(remote, Some(addresses)).await?
    } else {
        transport.connect(remote).await?
    };
    stream = CountedStream::wrap(stream, counters, false);
    match outbound {
        Outbound::Vmess {
            account, security, ..
        } => {
            use protocol::vmess::encoding::{
                OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING,
            };
            return Ok((
                protocol::vmess::stream::connect_with_options(
                    stream,
                    account,
                    target,
                    *security,
                    OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
                )
                .await?,
                bound,
            ));
        }
        Outbound::Shadowsocks { account, .. } => {
            return Ok((
                protocol::shadowsocks_session::connect(stream, account, target).await?,
                bound,
            ));
        }
        Outbound::Shadowsocks2022 { account, .. } => {
            return Ok((
                protocol::shadowsocks2022::connect(stream, account, target).await?,
                bound,
            ));
        }
        Outbound::Socks { account, .. } => {
            protocol::outbound::socks5_connect(&mut stream, target, account.as_ref()).await?
        }
        Outbound::Http { account, .. } => {
            protocol::outbound::http_connect(&mut stream, target, account.as_ref()).await?
        }
        Outbound::Vless {
            account,
            encryption,
            ..
        } => {
            // The hybrid encrypted session wraps the transport before the
            // VLESS header; the plaintext path is the historical behavior.
            let mut stream: BoxStream = match encryption {
                Some(client) => Box::new(
                    protocol::vless_encryption::connect(stream, client)
                        .await
                        .context("VLESS encrypted session")?,
                ),
                None => stream,
            };
            protocol::vless::write_request(&mut stream, account, target).await?;
            let stream = Box::new(protocol::vless::VlessStream::new(stream));
            // Vision accounts wrap the body after the request header (the
            // writer already stripped the client-only `-udp443` spelling);
            // with no early payload available at this point, the empty
            // long-padding camouflage frame goes on the wire first, exactly
            // like Go's "Insert padding with empty content".
            if protocol::vless_vision::is_vision_flow(&account.flow) {
                let mut vision = protocol::vless_vision::VisionStream::client(stream, account.id);
                vision
                    .queue_header_camo()
                    .context("VLESS Vision header camouflage")?;
                return Ok((Box::new(vision), bound));
            }
            return Ok((stream, bound));
        }
        Outbound::Trojan { account, .. } => {
            protocol::trojan::write_request(&mut stream, account, target).await?
        }
        _ => (),
    }
    Ok((stream, bound))
}
