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
mod observatory;
pub mod udp;
mod udp_integration;
pub mod udp_routing;

use crate::{
    address::Destination,
    config::{Config, Inbound, Outbound},
    features::stats::TrafficCounters,
    protocol::{self, Reply, Request},
    router::{RouteContext, Router},
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
    router: Arc<Router>,
    udp: Option<Arc<dyn udp::UdpDispatcher>>,
    policy: crate::features::PolicyManager,
    stats: Option<Arc<crate::features::StatsManager>>,
    outbound_tags: Vec<String>,
    logger: crate::logging::Logger,
    api: Option<crate::api::ApiStreamSender>,
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
        let router = Arc::new(compiled.router);
        let udp = if compiled
            .inbounds
            .iter()
            .any(|(_, inbound, _)| matches!(inbound, Inbound::Socks(settings) if settings.udp))
        {
            Some(udp_integration::dispatcher(
                &config,
                &compiled.outbounds,
                router.clone(),
                stats.as_deref(),
                policy.for_system().stats,
            )?)
        } else {
            None
        };
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
        let mut listeners: Vec<(InboundListener, Inbound, String, InboundTransport)> = Vec::new();
        let mut addresses = Vec::new();
        for (raw, inbound, transport) in compiled.inbounds {
            let listener = match transport
                .bind(SocketAddr::new(raw.listen, raw.port))
                .await
                .with_context(|| {
                    format!(
                        "cannot bind inbound {:?} on {}:{}",
                        raw.tag, raw.listen, raw.port
                    )
                }) {
                Ok(listener) => listener,
                Err(error) => {
                    // KCP owns a UDP receive task. Join every prior listener's
                    // close before returning so failed startup releases ports.
                    for (listener, _, _, _) in listeners {
                        if let Err(close_error) = listener.close().await {
                            tracing::warn!(%close_error, "inbound rollback close failed");
                        }
                    }
                    return Err(error);
                }
            };
            addresses.push(listener.local_addr()?);
            listeners.push((listener, inbound, raw.tag, transport));
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
        });
        let observatory = compiled
            .observatory
            .map(|compiled| observatory::new(compiled, dispatcher.clone()))
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
                let provider = observatory
                    .as_ref()
                    .expect("configuration requires observatory provider")
                    .provider();
                routes = crate::api::observatory::add_observatory_routes(
                    routes,
                    crate::api::observatory::ObservatoryService::new(provider),
                );
            }
            crate::api::ApiServer::from_routes(routes)
        });
        let cancel = CancellationToken::new();
        let stopping = cancel.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            if let Some(observer) = observatory.filter(|observer| observer.is_enabled()) {
                let stop = stopping.clone();
                tasks.spawn(async move { observer.run(&stop).await });
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
            for (listener, inbound, tag, transport) in listeners {
                tasks.spawn(accept_loop(
                    listener,
                    inbound,
                    tag,
                    transport,
                    dispatcher.clone(),
                    stopping.clone(),
                ));
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
    } = context;
    let accepted = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        accepted = transport.accept(stream) => accepted?,
    };
    match accepted {
        AcceptedTransport::Single(None) => Ok(()),
        AcceptedTransport::Single(Some(stream)) => {
            handle_stream(stream, source, bound, &inbound, &tag, &dispatcher, &cancel).await
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
                        streams.spawn(async move {
                            if let Err(error) = handle_stream(accepted.stream.boxed(), source, bound, &inbound, &tag, &dispatcher, &cancel).await {
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

async fn handle_stream(
    mut stream: BoxStream,
    source: SocketAddr,
    bound: SocketAddr,
    inbound: &Inbound,
    tag: &str,
    dispatcher: &Dispatcher,
    cancel: &CancellationToken,
) -> Result<()> {
    let policy = dispatcher.policy.for_level(0);
    if let Some(stats) = &dispatcher.stats {
        stream = CountedStream::wrap(
            stream,
            stats.inbound_counters(tag, dispatcher.policy.for_system().stats),
            true,
        );
    }
    let (mut stream, handshake) = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        result = timeout(policy.timeouts.handshake, proxy_handshake(stream, inbound)) => result.context("proxy handshake timed out")??,
    };
    let request = match handshake {
        protocol::socks::Handshake::Connect(request) => request,
        protocol::socks::Handshake::Associate(request) => {
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
    };
    let exchange = async {
        let idle_since = Instant::now();
        anyhow::ensure!(
            !policy.timeouts.connection_idle.is_zero(),
            "proxy session inactivity timeout"
        );
        let user_stats = dispatcher.stats.as_ref().map(|stats| {
            stats.user_session(&request.user, &source_ip_string(source), policy.stats)
        });
        let (selected, routed) = dispatcher.router.select_with_route(&RouteContext {
            destination: &request.destination,
            source,
            inbound_tag: tag,
            user: &request.user,
            network: "tcp",
        });
        let outbound = &dispatcher.outbounds[selected];
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
        let idle_deadline = idle_since + policy.timeouts.connection_idle;
        // The authenticated session owns its policy and online guard during DNS,
        // dialing, outbound authentication, proxy replies and API queue backpressure.
        let dispatch = timeout_at(idle_deadline, async {
            let mut resolved = None;
            if matches!(outbound, Outbound::Freedom { .. }) {
                let name = match inbound {
                    Inbound::Socks(_) => "socks",
                    Inbound::Http(_) => "http",
                    Inbound::Dokodemo(_) => "dokodemo-door",
                    Inbound::Vless(_) => "vless",
                    Inbound::Vmess(_) => "vmess",
                    Inbound::Trojan(_) => "trojan",
                    Inbound::Shadowsocks(_) => "shadowsocks",
                    Inbound::Shadowsocks2022(_) => "shadowsocks-2022",
                };
                let admission = timeout(
                    DIAL_TIMEOUT,
                    admission::admit(outbound, name, &request.destination),
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
                Outbound::Api => {
                    // Keep the client and user guard in this connection task. The
                    // API receives only the other end of the bounded relay, as Go's
                    // commander receives a connection backed by dispatcher pipes.
                    let (upstream, service) = tokio::io::duplex(relay_buffer_size(policy.buffer));
                    dispatcher
                        .api
                        .as_ref()
                        .context("management API unavailable")?
                        .accept(Box::new(service), Some(source))
                        .await?;
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Relay(Box::new(upstream))
                }
                Outbound::Blackhole { response } => {
                    request.reply.success(&mut stream, bound).await?;
                    Dispatch::Blackhole(response)
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
                            outbound,
                            &dispatcher.transports[selected],
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
                    &policy,
                    user_stats,
                    &[],
                    cancel,
                    idle_since,
                )
                .await?;
            }
            Dispatch::Blocked(delay) => {
                let mut deadline = idle_deadline;
                let mut buffer = vec![0; relay_buffer_size(policy.buffer)];
                let drain = async {
                    loop {
                        let count = timeout_at(deadline, stream.read(&mut buffer)).await??;
                        if count == 0 {
                            break;
                        }
                        if let Some(stats) = &user_stats {
                            stats.traffic.add_uplink(count);
                        }
                        deadline = Instant::now() + policy.timeouts.connection_idle;
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
                    deadline = Instant::now() + policy.timeouts.connection_idle;
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

async fn proxy_handshake(
    mut stream: BoxStream,
    inbound: &Inbound,
) -> Result<(BoxStream, protocol::socks::Handshake)> {
    use protocol::socks::Handshake;
    let request = match inbound {
        Inbound::Vmess(authenticator) => {
            let (stream, request) = protocol::vmess::stream::accept(stream, authenticator).await?;
            return Ok((stream, Handshake::Connect(request)));
        }
        Inbound::Shadowsocks(account) => {
            let (stream, request) = protocol::shadowsocks_session::accept(stream, account).await?;
            return Ok((stream, Handshake::Connect(request)));
        }
        Inbound::Shadowsocks2022(account) => {
            let (stream, request) = protocol::shadowsocks2022::accept(stream, account).await?;
            return Ok((stream, Handshake::Connect(request)));
        }
        Inbound::Socks(settings) => {
            let request = protocol::socks::handshake_with_udp(&mut stream, settings).await?;
            return Ok((stream, request));
        }
        Inbound::Http(settings) => protocol::http::handshake(&mut stream, settings).await?,
        Inbound::Vless(accounts) => protocol::vless::read_request(&mut stream, accounts).await?,
        Inbound::Trojan(accounts) => protocol::trojan::read_request(&mut stream, accounts).await?,
        Inbound::Dokodemo(destination) => Request {
            destination: destination.clone(),
            user: String::new(),
            initial_payload: Vec::new(),
            reply: Reply::None,
        },
    };
    Ok((stream, Handshake::Connect(request)))
}

fn source_ip_string(source: SocketAddr) -> String {
    // Go's Address.String brackets IPv6; OnlineMap excludes exactly "[::1]".
    if source.is_ipv6() {
        format!("[{}]", source.ip())
    } else {
        source.ip().to_string()
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
    outbound: &Outbound,
    transport: &OutboundTransport,
    target: &Destination,
    resolved: Option<&[SocketAddr]>,
    counters: TrafficCounters,
) -> Result<(crate::transport::BoxStream, SocketAddr)> {
    let remote = match outbound {
        Outbound::Freedom { redirect, .. } => redirect.as_ref().unwrap_or(target),
        Outbound::Socks { server, .. }
        | Outbound::Http { server, .. }
        | Outbound::Vless { server, .. }
        | Outbound::Vmess { server, .. }
        | Outbound::Trojan { server, .. }
        | Outbound::Shadowsocks { server, .. }
        | Outbound::Shadowsocks2022 { server, .. } => server,
        Outbound::Blackhole { .. } | Outbound::Api => {
            anyhow::bail!("internal outbound cannot establish a remote stream")
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
        Outbound::Vless { account, .. } => {
            protocol::vless::write_request(&mut stream, account, target).await?;
            return Ok((Box::new(protocol::vless::VlessStream::new(stream)), bound));
        }
        Outbound::Trojan { account, .. } => {
            protocol::trojan::write_request(&mut stream, account, target).await?
        }
        _ => (),
    }
    Ok((stream, bound))
}
