use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Mutex as AsyncMutex,
    time::timeout,
};

use super::{
    CacheConfig, DEFAULT_TTL, DnsError, Result,
    cache::{Cache, CacheKey, Cached},
    wire::{self, CLASS_IN, MAX_MESSAGE_SIZE, Message, Question, RecordData, RecordType},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Upstream {
    pub address: SocketAddr,
    pub transport: Transport,
}

/// One server of a resolver's ordered fallback list: a classic UDP/TCP
/// endpoint, or an encrypted DoH/DoT client with its own exchange budget.
#[derive(Clone)]
pub enum ServerLink {
    Classic(Upstream),
    /// DNS-over-HTTPS / DNS-over-TLS; the client restores the caller's
    /// original query ID so the shared validation applies unchanged.
    Encrypted(std::sync::Arc<super::encrypted::EncryptedClient>),
    /// Go's `fakedns` nameserver: leases fake pool addresses directly,
    /// never touching the network.
    FakeDns(std::sync::Arc<super::fakedns::FakeDnsEngine>),
}

impl std::fmt::Debug for ServerLink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Classic(upstream) => formatter.debug_tuple("Classic").field(upstream).finish(),
            Self::Encrypted(client) => formatter
                .debug_tuple("Encrypted")
                .field(&client.endpoint().host())
                .finish_non_exhaustive(),
            Self::FakeDns(_) => formatter.debug_tuple("FakeDns").finish_non_exhaustive(),
        }
    }
}

impl Upstream {
    pub fn udp(address: SocketAddr) -> Self {
        Self {
            address,
            transport: Transport::Udp,
        }
    }
    pub fn tcp(address: SocketAddr) -> Self {
        Self {
            address,
            transport: Transport::Tcp,
        }
    }

    /// Numeric addresses only. Domain-valued servers need explicit bootstrap
    /// resolution by the caller; never silently use the OS resolver.
    pub fn parse(value: &str) -> Result<Self> {
        let (transport, address) = if let Some(address) = value.strip_prefix("udp://") {
            (Transport::Udp, address)
        } else if let Some(address) = value.strip_prefix("tcp://") {
            (Transport::Tcp, address)
        } else if value.contains("://") || value == "localhost" || value == "fakedns" {
            return Err(DnsError::Unsupported(format!("nameserver {value:?}")));
        } else {
            (Transport::Udp, value)
        };
        let address = address
            .parse::<SocketAddr>()
            .or_else(|_| {
                address
                    .strip_prefix('[')
                    .and_then(|address| address.strip_suffix(']'))
                    .unwrap_or(address)
                    .parse::<IpAddr>()
                    .map(|ip| SocketAddr::new(ip, 53))
            })
            .map_err(|_| {
                DnsError::Unsupported(format!(
                    "non-numeric nameserver {value:?}; bootstrap resolution required"
                ))
            })?;
        if address.port() == 0 {
            return Err(DnsError::InvalidConfig("nameserver port is zero"));
        }
        Ok(Self { address, transport })
    }
}

#[derive(Clone, Debug)]
pub enum HostEntry {
    Addresses(Vec<IpAddr>),
    Alias(String),
    ResponseCode(u16),
}

#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Ordered explicit fallback servers. NXDOMAIN/NODATA are final DNS
    /// replies; transport errors and SERVFAIL/REFUSED try the next server.
    pub servers: Vec<ServerLink>,
    /// Per-server budget, shared by UDP and its optional TCP retry.
    pub timeout: Duration,
    pub cache: CacheConfig,
    pub client_ip: Option<IpAddr>,
    /// Opt-in extension: Go's classic UDP server does not automatically retry
    /// TC replies over TCP. The default returns DnsError::Truncated.
    pub tcp_fallback: bool,
    /// Exact, case-insensitive static hosts, including address/alias/rcode forms.
    pub hosts: HashMap<String, HostEntry>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout: Duration::from_secs(5),
            cache: CacheConfig::default(),
            client_ip: None,
            tcp_fallback: false,
            hosts: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryOptions {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl QueryOptions {
    pub const IPV4: Self = Self {
        ipv4: true,
        ipv6: false,
    };
    pub const IPV6: Self = Self {
        ipv4: false,
        ipv6: true,
    };
    pub const BOTH: Self = Self {
        ipv4: true,
        ipv6: true,
    };
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self::BOTH
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAnswer {
    pub ips: Vec<IpAddr>,
    pub ttl: u32,
    /// Zero with no IPs is NODATA; three is NXDOMAIN. Both are cacheable.
    pub response_code: u16,
    pub from_cache: bool,
    pub stale: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupResult {
    pub ips: Vec<IpAddr>,
    pub ttl: u32,
}

struct Inner {
    config: ResolverConfig,
    cache: Mutex<Cache>,
    flights: Mutex<HashMap<CacheKey, Weak<AsyncMutex<()>>>>,
}

/// Cheaply cloned resolver; each query owns its socket and shares the cache.
#[derive(Clone)]
pub struct Resolver {
    inner: Arc<Inner>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // State remains structurally valid if an unrelated caller panics.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Resolver {
    pub fn new(mut config: ResolverConfig) -> Result<Self> {
        if config.timeout.is_zero() {
            return Err(DnsError::InvalidConfig("query timeout is zero"));
        }
        if config.servers.iter().any(|server| match server {
            ServerLink::Classic(upstream) => upstream.address.port() == 0,
            ServerLink::Encrypted(client) => client.endpoint().port() == 0,
            ServerLink::FakeDns(_) => false,
        }) {
            return Err(DnsError::InvalidConfig("nameserver port is zero"));
        }
        let mut normalized = HashMap::new();
        for (name, entry) in config.hosts {
            let name = wire::fqdn(&name)?.to_ascii_lowercase();
            let entry = match entry {
                HostEntry::Alias(alias) => {
                    HostEntry::Alias(wire::fqdn(&alias)?.to_ascii_lowercase())
                }
                HostEntry::ResponseCode(code) if code > 0xfff => {
                    return Err(DnsError::InvalidConfig("host response code exceeds 4095"));
                }
                entry => entry,
            };
            if normalized.insert(name, entry).is_some() {
                return Err(DnsError::InvalidConfig("duplicate normalized host mapping"));
            }
        }
        config.hosts = normalized;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                cache: Mutex::new(Cache::default()),
                flights: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn clear_cache(&self) {
        locked(&self.inner.cache).clear();
    }
    pub fn cache_len(&self) -> usize {
        locked(&self.inner.cache).len()
    }

    pub async fn lookup_ip(&self, domain: &str, options: QueryOptions) -> Result<LookupResult> {
        if !options.ipv4 && !options.ipv6 {
            return Err(DnsError::InvalidConfig("no DNS address family enabled"));
        }
        if let Ok(ip) = domain.parse::<IpAddr>() {
            if (ip.is_ipv4() && options.ipv4) || (ip.is_ipv6() && options.ipv6) {
                return Ok(LookupResult {
                    ips: vec![ip],
                    ttl: DEFAULT_TTL,
                });
            }
            return Err(DnsError::EmptyResponse);
        }
        match (options.ipv4, options.ipv6) {
            (true, false) => lookup_answer(self.query(domain, RecordType::A).await?),
            (false, true) => lookup_answer(self.query(domain, RecordType::AAAA).await?),
            (true, true) => {
                let (ipv4, ipv6) = tokio::join!(
                    self.query(domain, RecordType::A),
                    self.query(domain, RecordType::AAAA)
                );
                let mut ips = Vec::new();
                let mut ttl = DEFAULT_TTL;
                let mut errors = Vec::new();
                let mut code = None;
                let mut codes_match = true;
                for result in [ipv4, ipv6] {
                    match result {
                        Ok(answer) => {
                            ttl = ttl.min(answer.ttl);
                            if answer.response_code == 0 {
                                ips.extend(answer.ips);
                            }
                            if code.is_some_and(|code| code != answer.response_code) {
                                codes_match = false;
                            }
                            code = Some(answer.response_code);
                        }
                        Err(error) => errors.push(error.to_string()),
                    }
                }
                if !ips.is_empty() {
                    return Ok(LookupResult { ips, ttl });
                }
                if errors.is_empty() && codes_match {
                    return Err(match code {
                        Some(0) | None => DnsError::EmptyResponse,
                        Some(code) => DnsError::ResponseCode(code),
                    });
                }
                if let Some(code) = code {
                    errors.push(if code == 0 {
                        DnsError::EmptyResponse.to_string()
                    } else {
                        DnsError::ResponseCode(code).to_string()
                    });
                }
                Err(DnsError::AllServersFailed(errors))
            }
            (false, false) => unreachable!("checked above"),
        }
    }

    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        if record_type != RecordType::A && record_type != RecordType::AAAA {
            return Err(DnsError::Unsupported(format!(
                "resolver record type {}",
                record_type.0
            )));
        }
        let mut name = wire::fqdn(domain)?.to_ascii_lowercase();
        let mut visited = HashSet::new();
        for depth in 0..=5 {
            if !visited.insert(name.clone()) {
                return Err(DnsError::AliasLoop);
            }
            match self.inner.config.hosts.get(&name) {
                Some(HostEntry::Addresses(ips)) => {
                    return Ok(DnsAnswer {
                        ips: ips
                            .iter()
                            .copied()
                            .filter(|ip| {
                                (record_type == RecordType::A && ip.is_ipv4())
                                    || (record_type == RecordType::AAAA && ip.is_ipv6())
                            })
                            .collect(),
                        ttl: DEFAULT_TTL,
                        response_code: 0,
                        from_cache: false,
                        stale: false,
                    });
                }
                Some(HostEntry::ResponseCode(code)) => {
                    return Ok(DnsAnswer {
                        ips: Vec::new(),
                        ttl: DEFAULT_TTL,
                        response_code: *code,
                        from_cache: false,
                        stale: false,
                    });
                }
                Some(HostEntry::Alias(alias)) if depth < 5 => name = alias.clone(),
                Some(HostEntry::Alias(_)) => return Err(DnsError::AliasLoop),
                None => break,
            }
        }
        let key = CacheKey { name, record_type };
        let cached = locked(&self.inner.cache).get(&key, &self.inner.config.cache, Instant::now());
        match cached {
            Some(Cached::Fresh(answer)) => return Ok(answer),
            Some(Cached::Stale(answer)) => {
                let flight = self.flight(&key);
                if let Ok(guard) = flight.try_lock_owned() {
                    let resolver = self.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        let _ = resolver.fetch_and_cache(&key).await;
                    });
                }
                return Ok(answer);
            }
            None => {}
        }
        let flight = self.flight(&key);
        let _guard = flight.lock().await;
        // A concurrent caller may already have populated the same record.
        if let Some(Cached::Fresh(answer)) =
            locked(&self.inner.cache).get(&key, &self.inner.config.cache, Instant::now())
        {
            return Ok(answer);
        }
        self.fetch_and_cache(&key).await
    }

    fn flight(&self, key: &CacheKey) -> Arc<AsyncMutex<()>> {
        let mut flights = locked(&self.inner.flights);
        if let Some(flight) = flights.get(key).and_then(Weak::upgrade) {
            return flight;
        }
        // Remove completed keys so unique queries do not grow this map forever.
        flights.retain(|_, flight| flight.strong_count() != 0);
        let flight = Arc::new(AsyncMutex::new(()));
        flights.insert(key.clone(), Arc::downgrade(&flight));
        flight
    }

    async fn fetch_and_cache(&self, key: &CacheKey) -> Result<DnsAnswer> {
        let answer = self.fetch(key).await?;
        locked(&self.inner.cache).insert(
            key.clone(),
            answer.clone(),
            &self.inner.config.cache,
            Instant::now(),
        );
        Ok(answer)
    }

    async fn fetch(&self, key: &CacheKey) -> Result<DnsAnswer> {
        if self.inner.config.servers.is_empty() {
            return Err(DnsError::InvalidConfig(
                "no nameservers configured for this domain",
            ));
        }
        let question = Question::new(&key.name, key.record_type)?;
        let mut errors = Vec::new();
        let mut last_reply = None;
        for server in &self.inner.config.servers {
            // Independent ephemeral sockets plus a random transaction ID defend
            // each UDP exchange; connected sockets restrict the response source.
            let id = rand::random::<u16>();
            let bytes = wire::encode_query(id, &question, self.inner.config.client_ip)?;
            let result = timeout(self.inner.config.timeout, async {
                match server {
                    ServerLink::FakeDns(engine) => {
                        // The fake engine leases pool addresses for the
                        // queried family with Go's TTL-1 answer; the round
                        // trip through the wire encoder keeps the shared
                        // answer extraction uniform.
                        let ips = engine.fake_ip_for_domain(
                            key.name.trim_end_matches('.'),
                            key.record_type == RecordType::A,
                            key.record_type == RecordType::AAAA,
                        );
                        if ips.is_empty() {
                            Err(DnsError::EmptyResponse)
                        } else {
                            let wire = wire::encode_response(
                                id,
                                &question,
                                &ips,
                                super::fakedns::FAKE_DNS_TTL,
                                0,
                                None,
                                512,
                            )?;
                            wire::decode(&wire)
                        }
                    }
                    ServerLink::Classic(upstream) => {
                        exchange(
                            *upstream,
                            &bytes,
                            id,
                            &question,
                            self.inner.config.tcp_fallback,
                        )
                        .await
                    }
                    ServerLink::Encrypted(client) => {
                        // The encrypted client runs its own budget internally;
                        // it restores the caller's ID so validation is shared.
                        client
                            .exchange(&bytes, &tokio_util::sync::CancellationToken::new())
                            .await
                            .map_err(|error| DnsError::Unsupported(error.to_string()))
                            .and_then(|reply| {
                                let message = wire::decode(&reply)?;
                                validate_response(&message, id, &question)?;
                                Ok(message)
                            })
                    }
                }
            })
            .await;
            match result {
                Ok(Ok(message)) => {
                    let answer = answer_from_message(&message, &question)?;
                    if answer.response_code == 2 || answer.response_code == 5 {
                        last_reply = Some(answer);
                        continue;
                    }
                    return Ok(answer);
                }
                Ok(Err(error)) => errors.push(error),
                Err(_) => errors.push(DnsError::Timeout),
            }
        }
        if let Some(answer) = last_reply {
            return Ok(answer);
        }
        if errors.len() == 1 {
            return Err(errors.remove(0));
        }
        Err(DnsError::AllServersFailed(
            errors.into_iter().map(|error| error.to_string()).collect(),
        ))
    }
}

fn lookup_answer(answer: DnsAnswer) -> Result<LookupResult> {
    if answer.response_code != 0 {
        return Err(DnsError::ResponseCode(answer.response_code));
    }
    if answer.ips.is_empty() {
        return Err(DnsError::EmptyResponse);
    }
    Ok(LookupResult {
        ips: answer.ips,
        ttl: answer.ttl,
    })
}

pub(super) fn validate_response(message: &Message, id: u16, question: &Question) -> Result<()> {
    if message.header.id != id
        || !message.header.is_response()
        || message.header.opcode() != 0
        || message.questions.len() != 1
    {
        return Err(DnsError::MismatchedResponse);
    }
    let received = &message.questions[0];
    if !received.name.eq_ignore_ascii_case(&question.name)
        || received.record_type != question.record_type
        || received.class != question.class
    {
        return Err(DnsError::MismatchedResponse);
    }
    Ok(())
}

async fn exchange(
    server: Upstream,
    bytes: &[u8],
    id: u16,
    question: &Question,
    tcp_fallback: bool,
) -> Result<Message> {
    let message = match server.transport {
        Transport::Tcp => tcp_exchange(server.address, bytes).await?,
        Transport::Udp => {
            let bind = if server.address.is_ipv4() {
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(server.address).await?;
            if socket.send(bytes).await? != bytes.len() {
                return Err(DnsError::Malformed("short UDP send"));
            }
            let mut buffer = vec![0; MAX_MESSAGE_SIZE];
            loop {
                let size = socket.recv(&mut buffer).await?;
                if size < 2 || u16::from_be_bytes([buffer[0], buffer[1]]) != id {
                    continue;
                }
                // TC may accompany an incomplete RR, so inspect the flag before
                // decoding the whole packet. Still require the matching question.
                if size >= 12 && buffer[2] & 0x02 != 0 {
                    let partial = wire::decode_question_section(&buffer[..size])?;
                    if validate_response(&partial, id, question).is_err() {
                        continue;
                    }
                    if !tcp_fallback {
                        return Err(DnsError::Truncated);
                    }
                    break tcp_exchange(server.address, bytes).await?;
                }
                let response = wire::decode(&buffer[..size])?;
                if validate_response(&response, id, question).is_err() {
                    continue;
                }
                break response;
            }
        }
    };
    validate_response(&message, id, question)?;
    if message.header.is_truncated() {
        return Err(DnsError::Truncated);
    }
    Ok(message)
}

async fn tcp_exchange(address: SocketAddr, bytes: &[u8]) -> Result<Message> {
    let mut stream = TcpStream::connect(address).await?;
    write_tcp_message(&mut stream, bytes).await?;
    let response = read_tcp_message(&mut stream)
        .await?
        .ok_or(DnsError::Malformed("EOF before DNS response"))?;
    wire::decode(&response)
}

/// Read one exact two-byte-length-prefixed frame. Clean EOF is None; a partial
/// prefix or body is an I/O error. Suitable for an existing routed/TLS stream.
pub async fn read_tcp_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut prefix = [0; 2];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..]).await?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length < 12 {
        return Err(DnsError::Malformed("TCP DNS frame shorter than header"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
}

pub async fn write_tcp_message<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    if !(12..=MAX_MESSAGE_SIZE).contains(&bytes.len()) {
        return Err(DnsError::Malformed("invalid TCP DNS frame size"));
    }
    writer
        .write_all(&(bytes.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) fn answer_from_message(message: &Message, question: &Question) -> Result<DnsAnswer> {
    let mut names = HashSet::from([question.name.to_ascii_lowercase()]);
    // Follow an in-message CNAME chain; unrelated answer records are not used.
    for _ in 0..message.answers.len() {
        let mut changed = false;
        for record in &message.answers {
            if record.class == CLASS_IN
                && names.contains(&record.name.to_ascii_lowercase())
                && let RecordData::Cname(name) = &record.data
            {
                changed |= names.insert(name.to_ascii_lowercase());
            }
        }
        if !changed {
            break;
        }
    }
    let mut ips = Vec::new();
    let ttl = message
        .answers
        .iter()
        .map(|record| record.ttl.max(1))
        .min()
        .unwrap_or(DEFAULT_TTL);
    if message.response_code() == 0 {
        for record in &message.answers {
            if record.class != CLASS_IN || !names.contains(&record.name.to_ascii_lowercase()) {
                continue;
            }
            let ip = match (&record.data, question.record_type) {
                (RecordData::A(ip), RecordType::A) => Some(IpAddr::V4(*ip)),
                (RecordData::Aaaa(ip), RecordType::AAAA) if ip.to_ipv4_mapped().is_none() => {
                    Some(IpAddr::V6(*ip))
                }
                _ => None,
            };
            if let Some(ip) = ip {
                ips.push(ip);
            }
        }
    }
    Ok(DnsAnswer {
        ips,
        ttl,
        response_code: message.response_code(),
        from_cache: false,
        stale: false,
    })
}
