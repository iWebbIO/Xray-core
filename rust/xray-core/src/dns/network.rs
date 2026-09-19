//! Policy-driven classic and encrypted DNS with checked numeric dial targets.
//!
//! CompiledDns owns hosts, server selection, family policy, filtering and serial
//! fallback. This adapter owns per-server caches, bounded singleflight and wire
//! exchanges. No bootstrap path invokes the system resolver. The runtime must
//! supply Connector for routed endpoints; LocalConnector supports only +local.
//!
//! Foreground exchanges have the configured per-server timeout. Stale refreshes
//! use the source's separate eight-second budget and survive caller cancellation,
//! but are cancelled by shutdown or dropping the last NetworkDns owner. Native
//! answer extraction additionally validates owner/class/CNAME chains, unlike the
//! more permissive Go answer parser. DoT remains a documented native extension.

mod connector;
pub use connector::{
    CheckedRoute, Connector, Datagram, IoFuture, LocalConnector, Network, RouteRequest,
};

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::{
    DnsAnswer, DnsError, LookupResult, QueryOptions, Question, RecordType, Result, Transport,
    cache::{Cache, CacheKey, Cached},
    encrypted::EncryptedClient,
    read_tcp_message,
    resolver::{answer_from_message, validate_response},
    wire::{self, Message},
    write_tcp_message,
};
use crate::{
    config::dns::{
        CompiledDns, CompiledServer, HostLookup, NameServerEndpoint, QueryFuture, ServerQuery,
    },
    transport::tls::TlsSettings,
};

const REFRESH_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Debug, Default)]
pub struct ServerBinding {
    /// Optional explicit numeric pins for a named encrypted endpoint. Without
    /// these, only a complete static-host result is accepted. Numeric endpoints
    /// pin themselves and reject conflicting override addresses.
    pub bootstrap: Vec<IpAddr>,
    pub tls: Option<TlsSettings>,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_servers: usize,
    pub max_candidates_per_server: usize,
    pub max_cache_entries_total: usize,
    pub max_inflight_queries: usize,
    pub max_refresh_tasks: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_servers: 128,
            max_candidates_per_server: 32,
            max_cache_entries_total: 65_536,
            max_inflight_queries: 256,
            max_refresh_tasks: 32,
        }
    }
}

#[derive(Clone)]
pub struct NetworkDns {
    owner: Arc<Owner>,
}

struct Owner {
    state: Arc<State>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        let _guard = self
            .state
            .refreshing
            .lock()
            .expect("DNS refresh mutex poisoned");
        self.state.cancel.cancel();
        self.state.tasks.close();
    }
}

struct State {
    policy: Arc<CompiledDns>,
    connector: Arc<dyn Connector>,
    servers: Vec<ServerState>,
    flights: Mutex<HashMap<FlightKey, Weak<Flight>>>,
    refreshing: Mutex<HashSet<FlightKey>>,
    queries: Semaphore,
    refresh_slots: Arc<Semaphore>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

struct ServerState {
    request: RouteRequest,
    encrypted: Option<EncryptedClient>,
    cache: Mutex<Cache>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlightKey {
    server: usize,
    name: String,
    families: u8,
}

type SharedResult = std::result::Result<LookupResult, Arc<DnsError>>;
#[derive(Default)]
struct Flight {
    result: AsyncMutex<Option<SharedResult>>,
}

impl NetworkDns {
    pub fn new(
        policy: Arc<CompiledDns>,
        connector: Arc<dyn Connector>,
        mut bindings: HashMap<usize, ServerBinding>,
        limits: Limits,
    ) -> Result<Self> {
        if limits.max_servers == 0
            || limits.max_candidates_per_server == 0
            || limits.max_inflight_queries == 0
            || policy.servers.len() > limits.max_servers
            || limits.max_inflight_queries > Semaphore::MAX_PERMITS
            || limits.max_refresh_tasks > Semaphore::MAX_PERMITS
        {
            return Err(DnsError::InvalidConfig(
                "invalid DNS network resource limits",
            ));
        }
        let mut total_cache_entries = 0usize;
        let mut servers = Vec::with_capacity(policy.servers.len());
        for (index, server) in policy.servers.iter().enumerate() {
            if server.index != index || server.timeout.is_zero() {
                return Err(DnsError::InvalidConfig(
                    "invalid compiled DNS server index or timeout",
                ));
            }
            if server.cache.enabled {
                total_cache_entries = total_cache_entries
                    .checked_add(server.cache.max_entries)
                    .ok_or(DnsError::InvalidConfig("DNS cache allocation overflow"))?;
                if total_cache_entries > limits.max_cache_entries_total {
                    return Err(DnsError::InvalidConfig(
                        "DNS cache allocation exceeds limit",
                    ));
                }
            }
            let binding = bindings.remove(&index).unwrap_or_default();
            if binding.bootstrap.len() > limits.max_candidates_per_server {
                return Err(DnsError::InvalidConfig("too many DNS bootstrap addresses"));
            }
            let (host, network, port, numeric) = match &server.endpoint {
                NameServerEndpoint::Classic { upstream, .. } => (
                    upstream.address.ip().to_string(),
                    if upstream.transport == Transport::Tcp {
                        Network::Tcp
                    } else {
                        Network::Udp
                    },
                    upstream.address.port(),
                    Some(upstream.address.ip()),
                ),
                NameServerEndpoint::Encrypted(endpoint) => (
                    endpoint.host().to_owned(),
                    Network::Tcp,
                    endpoint.port(),
                    endpoint.host().parse::<IpAddr>().ok(),
                ),
            };
            let mut pins = if let Some(ip) = numeric {
                let ip = canonical_ip(ip);
                if binding
                    .bootstrap
                    .iter()
                    .any(|candidate| canonical_ip(*candidate) != ip)
                {
                    return Err(DnsError::InvalidConfig(
                        "bootstrap conflicts with numeric DNS endpoint",
                    ));
                }
                vec![ip]
            } else if !binding.bootstrap.is_empty() {
                binding.bootstrap.into_iter().map(canonical_ip).collect()
            } else {
                match policy.lookup_hosts(&host, QueryOptions::BOTH)? {
                    HostLookup::Addresses(ips) if !ips.is_empty() => {
                        ips.into_iter().map(canonical_ip).collect()
                    }
                    _ => {
                        return Err(DnsError::InvalidConfig(
                            "named DNS endpoint requires numeric bootstrap or static hosts",
                        ));
                    }
                }
            };
            if pins.len() > limits.max_candidates_per_server {
                return Err(DnsError::InvalidConfig("too many DNS bootstrap addresses"));
            }
            let mut seen = HashSet::new();
            pins.retain(|ip| seen.insert(*ip));
            let encrypted = if let Some(mut config) = server.encrypted_client_config() {
                config.bootstrap = pins.clone();
                // The enclosing foreground timeout remains server.timeout;
                // refreshes must not inherit that shorter foreground budget.
                config.timeout = server.timeout.max(REFRESH_TIMEOUT);
                if let Some(tls) = binding.tls {
                    config.tls = tls;
                }
                Some(EncryptedClient::new(config).map_err(encrypted_error)?)
            } else {
                if binding.tls.is_some() {
                    return Err(DnsError::InvalidConfig(
                        "TLS binding supplied for classic DNS",
                    ));
                }
                None
            };
            servers.push(ServerState {
                request: RouteRequest {
                    server_index: index,
                    host,
                    tag: server.tag.clone(),
                    mode: server.endpoint.mode(),
                    network,
                    candidates: pins
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect::<Vec<_>>()
                        .into(),
                },
                encrypted,
                cache: Mutex::new(Cache::default()),
            });
        }
        if !bindings.is_empty() {
            return Err(DnsError::InvalidConfig(
                "binding references an unknown DNS server",
            ));
        }
        Ok(Self {
            owner: Arc::new(Owner {
                state: Arc::new(State {
                    policy,
                    connector,
                    servers,
                    flights: Mutex::new(HashMap::new()),
                    refreshing: Mutex::new(HashSet::new()),
                    queries: Semaphore::new(limits.max_inflight_queries),
                    refresh_slots: Arc::new(Semaphore::new(limits.max_refresh_tasks)),
                    cancel: CancellationToken::new(),
                    tasks: TaskTracker::new(),
                }),
            }),
        })
    }

    pub async fn lookup(
        &self,
        name: &str,
        options: QueryOptions,
        cancel: &CancellationToken,
    ) -> Result<LookupResult> {
        let state = &self.owner.state;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(connector::cancelled().into()),
            _ = state.cancel.cancelled() => Err(connector::cancelled().into()),
            result = state.policy.lookup_with(name, options, self) => result,
        }
    }

    pub fn clear_cache(&self) {
        for server in &self.owner.state.servers {
            server
                .cache
                .lock()
                .expect("DNS cache mutex poisoned")
                .clear();
        }
    }

    pub fn cache_len(&self) -> usize {
        self.owner
            .state
            .servers
            .iter()
            .map(|server| server.cache.lock().expect("DNS cache mutex poisoned").len())
            .sum()
    }

    /// Cancels pending exchanges and waits for every tracked stale refresh.
    /// All clones share shutdown; they reject subsequent lookups.
    pub async fn shutdown(&self) {
        let state = &self.owner.state;
        {
            let _guard = state.refreshing.lock().expect("DNS refresh mutex poisoned");
            state.cancel.cancel();
            state.tasks.close();
        }
        state.tasks.wait().await;
    }
}

impl ServerQuery for NetworkDns {
    fn query<'a>(
        &'a self,
        server: &'a CompiledServer,
        name: &'a str,
        options: QueryOptions,
    ) -> QueryFuture<'a> {
        Box::pin(async move {
            let state = &self.owner.state;
            if !state
                .policy
                .servers
                .get(server.index)
                .is_some_and(|expected| std::ptr::eq(expected, server))
            {
                return Err(DnsError::InvalidConfig(
                    "DNS query uses a different compiled policy",
                ));
            }
            tokio::select! {
                biased;
                _ = state.cancel.cancelled() => Err(connector::cancelled().into()),
                result = tokio::time::timeout(server.timeout, state.query(server.index, name, options)) => {
                    result.map_err(|_| DnsError::Timeout)?
                }
            }
        })
    }
}

impl State {
    async fn query(
        self: &Arc<Self>,
        index: usize,
        name: &str,
        options: QueryOptions,
    ) -> Result<LookupResult> {
        let families = u8::from(options.ipv4) | (u8::from(options.ipv6) << 1);
        if families == 0 {
            return Err(DnsError::EmptyResponse);
        }
        let key = FlightKey {
            server: index,
            name: wire::fqdn(name)?,
            families,
        };
        if let Some((result, stale)) = self.cached(&key) {
            if stale {
                self.refresh(key);
            }
            return result;
        }
        // Waiting callers do not allocate flight entries until admitted.
        let _permit = self
            .queries
            .acquire()
            .await
            .map_err(|_| DnsError::Io(connector::cancelled()))?;
        if let Some((result, stale)) = self.cached(&key) {
            if stale {
                self.refresh(key);
            }
            return result;
        }
        self.fetch_coalesced(key).await
    }

    fn cached(&self, key: &FlightKey) -> Option<(Result<LookupResult>, bool)> {
        let config = &self.policy.servers[key.server].cache;
        let mut cache = self.servers[key.server]
            .cache
            .lock()
            .expect("DNS cache mutex poisoned");
        let now = Instant::now();
        let mut answers = Vec::with_capacity(2);
        let mut stale = false;
        for record_type in record_types(key.families) {
            let cached = cache.get(
                &CacheKey {
                    name: key.name.clone(),
                    record_type,
                },
                config,
                now,
            )?;
            answers.push(match cached {
                Cached::Fresh(answer) => answer,
                Cached::Stale(answer) => {
                    stale = true;
                    answer
                }
            });
        }
        let mut result = merge_answers(answers);
        if stale && let Ok(answer) = &mut result {
            answer.ttl = 1;
        }
        Some((result, stale))
    }

    async fn fetch_coalesced(&self, key: FlightKey) -> Result<LookupResult> {
        let flight = {
            let mut flights = self.flights.lock().expect("DNS flight mutex poisoned");
            flights.retain(|_, flight| flight.strong_count() > 0);
            match flights.get(&key).and_then(Weak::upgrade) {
                Some(flight) => flight,
                None => {
                    let flight = Arc::new(Flight::default());
                    flights.insert(key.clone(), Arc::downgrade(&flight));
                    flight
                }
            }
        };
        // No detached foreground worker: cancellation drops its transport and
        // releases this lock. A waiting caller can then perform its own fetch.
        let mut result = flight.result.lock().await;
        if result.is_none() {
            *result = Some(self.fetch(&key).await.map_err(Arc::new));
        }
        match result.as_ref().expect("DNS flight result set") {
            Ok(answer) => Ok(answer.clone()),
            Err(error) => Err(copy_error(error)),
        }
    }

    async fn fetch(&self, key: &FlightKey) -> Result<LookupResult> {
        let (v4, v6) = tokio::join!(
            self.fetch_family(key, RecordType::A, key.families & 1 != 0),
            self.fetch_family(key, RecordType::AAAA, key.families & 2 != 0),
        );
        let mut answers = Vec::with_capacity(2);
        // Missing replies fail even when the other family has usable addresses.
        // Actual negative replies are merged, so a positive family can win.
        let now = Instant::now();
        if let Some((answer, inserted)) = v4? {
            answers.push(age_answer(answer, inserted, now));
        }
        if let Some((answer, inserted)) = v6? {
            answers.push(age_answer(answer, inserted, now));
        }
        merge_answers(answers)
    }

    async fn fetch_family(
        &self,
        key: &FlightKey,
        record_type: RecordType,
        enabled: bool,
    ) -> Result<Option<(DnsAnswer, Instant)>> {
        if !enabled {
            return Ok(None);
        }
        let question = Question::new(&key.name, record_type)?;
        let server = &self.servers[key.server];
        let request = server.request.clone();
        let route = self.connector.route(request.clone(), &self.cancel).await?;
        if !route.matches(&request) {
            return Err(DnsError::InvalidConfig(
                "connector changed admitted DNS targets or route identity",
            ));
        }
        let message = if let Some(client) = &server.encrypted {
            client
                .query_with_dialer(&question, &self.cancel, |target| async move {
                    // EncryptedClient retains name verification and HTTP authority.
                    // Its dial target must agree with the immutable admitted pins.
                    if target.bootstrap.as_slice() != route.candidates() {
                        return Err(
                            DnsError::InvalidConfig("encrypted DNS dial targets changed").into(),
                        );
                    }
                    self.connector.connect_tcp(&route).await.map_err(Into::into)
                })
                .await
                .map_err(encrypted_error)?
        } else {
            self.classic_exchange(&route, &question, self.policy.servers[key.server].client_ip)
                .await?
        };
        let answer = answer_from_message(&message, &question)?;
        let inserted = Instant::now();
        server
            .cache
            .lock()
            .expect("DNS cache mutex poisoned")
            .insert(
                CacheKey {
                    name: key.name.clone(),
                    record_type,
                },
                answer.clone(),
                &self.policy.servers[key.server].cache,
                inserted,
            );
        Ok(Some((answer, inserted)))
    }

    async fn classic_exchange(
        &self,
        route: &CheckedRoute,
        question: &Question,
        client_ip: Option<IpAddr>,
    ) -> Result<Message> {
        let id = rand::random::<u16>();
        let query = wire::encode_query(id, question, client_ip)?;
        let response = match route.network() {
            Network::Tcp => {
                let mut stream = self.connector.connect_tcp(route).await?;
                write_tcp_message(&mut stream, &query).await?;
                let bytes = read_tcp_message(&mut stream)
                    .await?
                    .ok_or(DnsError::Malformed("EOF before DNS response"))?;
                wire::decode(&bytes)?
            }
            Network::Udp => {
                let socket = self.connector.connect_udp(route).await?;
                if socket.send(&query).await? != query.len() {
                    return Err(DnsError::Malformed("short UDP send"));
                }
                let mut buffer = vec![0; wire::MAX_MESSAGE_SIZE];
                loop {
                    let size = socket.recv(&mut buffer).await?;
                    if size > buffer.len() {
                        return Err(DnsError::Malformed("oversized UDP receive"));
                    }
                    if size < 2 || u16::from_be_bytes([buffer[0], buffer[1]]) != id {
                        continue;
                    }
                    if size >= 12 && buffer[2] & 0x02 != 0 {
                        let partial = wire::decode_question_section(&buffer[..size])?;
                        if validate_response(&partial, id, question).is_err() {
                            continue;
                        }
                        return Err(DnsError::Truncated);
                    }
                    let response = wire::decode(&buffer[..size])?;
                    if validate_response(&response, id, question).is_err() {
                        continue;
                    }
                    break response;
                }
            }
        };
        validate_response(&response, id, question)?;
        if response.header.is_truncated() {
            return Err(DnsError::Truncated);
        }
        Ok(response)
    }

    fn refresh(self: &Arc<Self>, key: FlightKey) {
        // Serialize spawn with shutdown so shutdown cannot observe an empty
        // tracker immediately before a refresh registers itself.
        let mut refreshing = self.refreshing.lock().expect("DNS refresh mutex poisoned");
        if self.cancel.is_cancelled() {
            return;
        }
        let Ok(permit) = self.refresh_slots.clone().try_acquire_owned() else {
            return;
        };
        if !refreshing.insert(key.clone()) {
            return;
        }
        let state = self.clone();
        let registration = RefreshRegistration {
            state: state.clone(),
            key: key.clone(),
        };
        self.tasks.spawn(async move {
            let _permit = permit;
            let _registration = registration;
            tokio::select! {
                biased;
                _ = state.cancel.cancelled() => {},
                _ = tokio::time::timeout(REFRESH_TIMEOUT, state.fetch_coalesced(key)) => {},
            }
        });
    }
}

struct RefreshRegistration {
    state: Arc<State>,
    key: FlightKey,
}
impl Drop for RefreshRegistration {
    fn drop(&mut self) {
        self.state
            .refreshing
            .lock()
            .expect("DNS refresh mutex poisoned")
            .remove(&self.key);
    }
}

fn record_types(families: u8) -> impl Iterator<Item = RecordType> {
    [(1, RecordType::A), (2, RecordType::AAAA)]
        .into_iter()
        .filter_map(move |(flag, kind)| (families & flag != 0).then_some(kind))
}

fn merge_answers(answers: Vec<DnsAnswer>) -> Result<LookupResult> {
    if answers.is_empty() {
        return Err(DnsError::EmptyResponse);
    }
    let mut ttl = if answers.len() == 1 {
        u32::MAX
    } else {
        super::DEFAULT_TTL
    };
    let mut ips = Vec::new();
    let mut errors = Vec::new();
    for answer in answers {
        ttl = ttl.min(answer.ttl);
        if answer.response_code != 0 {
            errors.push(DnsError::ResponseCode(answer.response_code));
        } else if answer.ips.is_empty() {
            errors.push(DnsError::EmptyResponse);
        } else {
            ips.extend(answer.ips);
        }
    }
    if !ips.is_empty() {
        return Ok(LookupResult { ips, ttl });
    }
    if errors
        .iter()
        .all(|error| matches!(error, DnsError::EmptyResponse))
    {
        return Err(DnsError::EmptyResponse);
    }
    if let Some(DnsError::ResponseCode(code)) = errors.first()
        && errors
            .iter()
            .all(|error| matches!(error, DnsError::ResponseCode(other) if other == code))
    {
        return Err(DnsError::ResponseCode(*code));
    }
    Err(DnsError::AllServersFailed(
        errors.into_iter().map(|error| error.to_string()).collect(),
    ))
}

fn age_answer(mut answer: DnsAnswer, inserted: Instant, now: Instant) -> DnsAnswer {
    // An integer TTL minus whole elapsed seconds equals ceil(remaining TTL).
    // Source foreground merging returns TTL 1 if another family took so long
    // that this reply expired before the combined result became available.
    let elapsed = now
        .saturating_duration_since(inserted)
        .as_secs()
        .min(u64::from(u32::MAX)) as u32;
    answer.ttl = answer.ttl.saturating_sub(elapsed).max(1);
    answer
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

fn encrypted_error(error: anyhow::Error) -> DnsError {
    if let Some(error) = error.downcast_ref::<DnsError>() {
        return copy_error(error);
    }
    DnsError::Io(io::Error::other(format!("{error:#}")))
}

fn copy_error(error: &DnsError) -> DnsError {
    match error {
        DnsError::Io(error) => DnsError::Io(io::Error::new(error.kind(), error.to_string())),
        DnsError::Timeout => DnsError::Timeout,
        DnsError::InvalidName(name) => DnsError::InvalidName(name.clone()),
        DnsError::Malformed(reason) => DnsError::Malformed(reason),
        DnsError::MismatchedResponse => DnsError::MismatchedResponse,
        DnsError::Truncated => DnsError::Truncated,
        DnsError::ResponseCode(code) => DnsError::ResponseCode(*code),
        DnsError::EmptyResponse => DnsError::EmptyResponse,
        DnsError::InvalidConfig(reason) => DnsError::InvalidConfig(reason),
        DnsError::Unsupported(feature) => DnsError::Unsupported(feature.clone()),
        DnsError::AliasLoop => DnsError::AliasLoop,
        DnsError::AllServersFailed(errors) => DnsError::AllServersFailed(errors.clone()),
    }
}

#[cfg(test)]
mod tests;
