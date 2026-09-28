// P39 dns_app: Go DNS app composition (server selection and query routing).
#![allow(dead_code)]

//! DNS application layer porting `app/dns/dns.go`, `dnscommon.go`, the
//! selection parts of `nameserver*.go`, `hosts.go` and `infra/conf/dns.go`.
//!
//! `DnsApp` parses the full Xray JSON `dns` object, builds one cached classic
//! [`Resolver`] per configured nameserver (reusing the existing wire, resolver
//! and cache layers by import), and routes each lookup the way the Go app does:
//! static hosts first (TTL 10, family-filtered, alias unwrapping up to five
//! hops), then the domain-rule matched servers in configuration order, then
//! the fallback servers unless `skipFallback`/`disableFallback`/
//! `disableFallbackIfMatch` says otherwise, honoring `finalQuery` cutoffs and
//! falling back to the first configured server when the policy selects none.
//! Every client error (including NXDOMAIN/NODATA) lets the next client run,
//! as in Go's serial query mode.
//!
//! Options the Go app supports that are not integrated here are rejected with
//! errors naming them: `localhost`/system DNS, FakeDNS, DoH/DoT/QUIC
//! transports, `UseSystem` strategy (system route discovery), hostname
//! bootstrap for non-numeric servers, `enableParallelQuery` (policy-group
//! racing) and `useSystemHosts`. Go's error tree is flattened to
//! `DnsError` kinds; the merged failure keeps Go's
//! "returning nil for domain" wrapper text.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use super::{CacheConfig, DnsError, QueryOptions, Resolver, ResolverConfig, Upstream, wire};
use crate::geodata::{self, DomainMatcher, GeoDataStore, IpMatcher};

/// Go `app/dns.LookupIP` returns hosts answers with TTL 10.
pub const HOSTS_TTL: u32 = 10;

// ---------------------------------------------------------------------------
// Configuration (infra/conf/dns.go JSON shape)
// ---------------------------------------------------------------------------

/// JSON `dns` object. Unknown keys fail rather than silently discarding policy.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsAppConfig {
    #[serde(deserialize_with = "null_vec")]
    pub servers: Vec<NameServerConfig>,
    pub hosts: Option<BTreeMap<String, HostValue>>,
    pub client_ip: Option<IpAddr>,
    pub tag: String,
    pub query_strategy: String,
    pub disable_cache: bool,
    pub serve_stale: bool,
    #[serde(rename = "serveExpiredTTL")]
    pub serve_expired_ttl: u32,
    pub disable_fallback: bool,
    pub disable_fallback_if_match: bool,
    pub enable_parallel_query: bool,
    pub use_system_hosts: bool,
}

/// A `servers` entry: bare address string or the advanced object form.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum NameServerConfig {
    Address(String),
    Options(NameServerOptions),
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NameServerOptions {
    pub address: String,
    pub client_ip: Option<IpAddr>,
    pub port: u16,
    pub skip_fallback: bool,
    #[serde(deserialize_with = "string_list")]
    pub domains: Vec<String>,
    #[serde(rename = "expectedIPs", deserialize_with = "string_list")]
    pub expected_ips: Vec<String>,
    #[serde(rename = "expectIPs", deserialize_with = "string_list")]
    pub expect_ips: Vec<String>,
    pub query_strategy: String,
    pub tag: String,
    pub timeout_ms: u64,
    pub disable_cache: Option<bool>,
    pub serve_stale: Option<bool>,
    #[serde(rename = "serveExpiredTTL")]
    pub serve_expired_ttl: Option<u32>,
    pub final_query: bool,
    #[serde(rename = "unexpectedIPs", deserialize_with = "string_list")]
    pub unexpected_ips: Vec<String>,
}

/// A `hosts` value: one address or a list of addresses.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum HostValue {
    Address(String),
    Addresses(Vec<String>),
}

fn null_vec<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn string_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Values {
        Single(String),
        Multiple(Vec<String>),
    }
    Ok(match Option::<Values>::deserialize(deserializer)? {
        Some(Values::Single(value)) => vec![value],
        Some(Values::Multiple(values)) => values,
        None => Vec::new(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryStrategy {
    UseIp,
    UseIp4,
    UseIp6,
    UseSys,
}

/// Go `infra/conf.resolveQueryStrategy`: known aliases map to their strategy
/// and anything else (including typos) falls back to `USE_IP`.
fn resolve_query_strategy(value: &str) -> QueryStrategy {
    match value.to_ascii_lowercase().as_str() {
        "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4" | "use-ipv4"
        | "use-ip-v4" => QueryStrategy::UseIp4,
        "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6" | "use-ipv6"
        | "use-ip-v6" => QueryStrategy::UseIp6,
        "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system" => {
            QueryStrategy::UseSys
        }
        _ => QueryStrategy::UseIp,
    }
}

/// Go `app/dns.ResolveIpOptionOverride`: per-server strategy narrows the
/// effective option relative to the global one.
fn strategy_options(strategy: QueryStrategy, global: QueryOptions) -> QueryOptions {
    match strategy {
        QueryStrategy::UseIp | QueryStrategy::UseSys => global,
        QueryStrategy::UseIp4 => QueryOptions {
            ipv4: global.ipv4,
            ipv6: false,
        },
        QueryStrategy::UseIp6 => QueryOptions {
            ipv4: false,
            ipv6: global.ipv6,
        },
    }
}

fn intersect(left: QueryOptions, right: QueryOptions) -> QueryOptions {
    QueryOptions {
        ipv4: left.ipv4 && right.ipv4,
        ipv6: left.ipv6 && right.ipv6,
    }
}

fn has_family(options: QueryOptions) -> bool {
    options.ipv4 || options.ipv6
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    // Go's net.IPAddress family check treats IPv4-mapped IPv6 as IPv4.
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

/// Trim one trailing dot as Go's LookupIP does; the result must be non-empty.
fn normalize_domain(domain: &str) -> Result<String> {
    let name = domain.strip_suffix('.').unwrap_or(domain);
    ensure!(!name.is_empty(), "empty domain name");
    Ok(name.to_owned())
}

// ---------------------------------------------------------------------------
// Classic endpoint parsing (app/dns/nameserver.go NewServer, classic part)
// ---------------------------------------------------------------------------

fn parse_upstream(
    address: &str,
    port: u16,
    fake_dns: Option<&std::sync::Arc<super::fakedns::FakeDnsEngine>>,
) -> Result<super::ServerLink> {
    ensure!(!address.is_empty(), "nameserver address is not specified");
    if address.eq_ignore_ascii_case("localhost") {
        bail!(
            "DNS nameserver {address:?} (localhost system DNS) is not integrated in DnsApp; \
             configure an explicit server"
        );
    }
    if address.eq_ignore_ascii_case("fakedns") {
        // Callers supply the engine (Go's post-processing installs defaults
        // when the root fakeDns key is absent).
        return match fake_dns {
            Some(engine) => Ok(super::ServerLink::FakeDns(engine.clone())),
            None => bail!(
                "DNS nameserver {address:?} requires the FakeDNS engine,                  which is not configured"
            ),
        };
    }
    if let Some((scheme, _)) = address.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if port != 0 {
            // Go silently ignores the port field for URL servers; rejecting the
            // contradiction keeps the effective port unsurprising.
            bail!("URL nameservers must specify their port in the URL, not the port field");
        }
        return match scheme.as_str() {
            "udp" | "tcp" => {
                let upstream = Upstream::parse(address)
                    .with_context(|| format!("DNS nameserver {address:?}"))?;
                Ok(super::ServerLink::Classic(upstream))
            }
            "tcp+local" => {
                let upstream =
                    Upstream::parse(&format!("tcp://{}", &address["tcp+local://".len()..]))
                        .with_context(|| format!("DNS nameserver {address:?}"))?;
                Ok(super::ServerLink::Classic(upstream))
            }
            "https" | "https+local" | "tls" | "tls+local" => {
                Ok(super::ServerLink::Encrypted(build_encrypted(address)?))
            }
            "h2c" | "h2c+local" => bail!(
                "DNS nameserver scheme {scheme:?} (cleartext HTTP/2 DNS) is not integrated; \
                 use https"
            ),
            "quic" | "quic+local" => bail!(
                "DNS nameserver scheme {scheme:?} (DNS-over-QUIC) is rejected by design; \
                 use https or tls"
            ),
            _ => bail!("unsupported DNS nameserver scheme {scheme:?}"),
        };
    }
    let host = address
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .unwrap_or(address);
    let ip = host.parse::<IpAddr>().map_err(|_| {
        anyhow::anyhow!(
            "DNS nameserver {address:?} requires explicit hostname bootstrap, \
             which is not integrated in DnsApp"
        )
    })?;
    Ok(super::ServerLink::Classic(Upstream::udp(SocketAddr::new(
        ip,
        if port == 0 { 53 } else { port },
    ))))
}

/// Build an encrypted (DoH/DoT) client from a nameserver URL. The Go `#ip`
/// fragment pins explicit bootstrap addresses; a routed endpoint whose host
/// is a domain without a fragment needs the runtime dialer plus a resolver
/// for the server's own host, neither of which is integrated — such servers
/// fail explicitly instead of silently using the system resolver.
fn build_encrypted(address: &str) -> Result<std::sync::Arc<super::encrypted::EncryptedClient>> {
    let (url, fragment) = match address.split_once('#') {
        Some((url, fragment)) => (url, Some(fragment)),
        None => (address, None),
    };
    let bootstrap = match fragment {
        None => Vec::new(),
        Some(fragment) => fragment
            .split(',')
            .map(|ip| {
                ip.parse::<IpAddr>()
                    .with_context(|| format!("invalid bootstrap address {ip:?}"))
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let numeric_host = url
        .split_once("://")
        .map(|(_, rest)| {
            let host = rest.split(['/', ':']).next().unwrap_or_default();
            let host = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            host.parse::<IpAddr>().is_ok()
        })
        .unwrap_or(false);
    // `+local` schemes, numeric hosts and explicit bootstrap addresses all
    // dial directly (Go: the # fragment pins the endpoint), so the effective
    // endpoint is always the local mode. A routed domain endpoint without
    // pins needs the runtime dialer, which is not integrated: fail
    // explicitly.
    let local_path = url.contains("+local") || numeric_host || !bootstrap.is_empty();
    if !local_path {
        bail!(
            "routed encrypted DNS server {address:?} requires the runtime dialer,              which is not integrated; use an +local scheme, a numeric host or a              #bootstrap fragment"
        );
    }
    let effective = match url.split_once("://") {
        Some((scheme, rest)) if !scheme.ends_with("+local") => {
            format!("{scheme}+local://{rest}")
        }
        _ => url.to_owned(),
    };
    let endpoint = super::encrypted::EncryptedEndpoint::parse(&effective)
        .with_context(|| format!("DNS nameserver {address:?}"))?;
    let mut config = super::encrypted::EncryptedConfig::new(endpoint.clone());
    config.bootstrap = bootstrap;
    config.timeout = Duration::from_secs(5);
    Ok(std::sync::Arc::new(
        super::encrypted::EncryptedClient::new(config)
            .with_context(|| format!("DNS nameserver {address:?}"))?,
    ))
}

// ---------------------------------------------------------------------------
// Static hosts (app/dns/hosts.go + infra/conf/dns.go HostsWrapper)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum HostResponse {
    Ip(IpAddr),
    Alias(String),
    ResponseCode(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostLookup {
    NotFound,
    /// Recorded mappings; an empty list is a terminal empty response.
    Addresses(Vec<IpAddr>),
    /// Unmapped alias (or an alias at the source's five-hop bound).
    Alias(String),
}

#[derive(Clone, Debug, Default)]
struct StaticHosts {
    matcher: Option<DomainMatcher>,
    responses: Vec<Vec<HostResponse>>,
}

impl StaticHosts {
    fn build(geodata: &GeoDataStore, hosts: &BTreeMap<String, HostValue>) -> Result<Self> {
        let mut rules = Vec::with_capacity(hosts.len());
        let mut responses = Vec::with_capacity(hosts.len());
        // The Go input is a map with unspecified iteration order; lexical
        // order makes overlapping host mappings deterministic in Rust.
        for (rule, value) in hosts {
            rules.push(
                geodata
                    .parse_domain_rule(rule, geodata::domain::Type::Full)
                    .with_context(|| format!("DNS host mapping rule {rule:?}"))?,
            );
            responses.push(
                compile_host_response(value)
                    .with_context(|| format!("DNS host mapping {rule:?}"))?,
            );
        }
        let matcher = if rules.is_empty() {
            None
        } else {
            Some(geodata.build_domain_matcher(&rules)?)
        };
        Ok(Self { matcher, responses })
    }

    /// Go `StaticHosts.lookup`: match lowercased, propagate response-code
    /// errors, unwrap a sole alias up to `depth` hops, filter by family.
    fn lookup(&self, name: &str, options: QueryOptions, depth: usize) -> super::Result<HostLookup> {
        let Some(matcher) = &self.matcher else {
            return Ok(HostLookup::NotFound);
        };
        let indices = matcher.matching_rules(&name.to_lowercase());
        if indices.is_empty() {
            return Ok(HostLookup::NotFound);
        }
        let mut values: Vec<HostResponse> = Vec::new();
        for index in indices {
            let response = &self.responses[usize::try_from(index).expect("domain rule index")];
            for value in response {
                if let HostResponse::ResponseCode(code) = value {
                    return Err(if *code == 0 {
                        DnsError::EmptyResponse
                    } else {
                        DnsError::ResponseCode(*code)
                    });
                }
            }
            values.extend(response.iter().cloned());
        }
        if let [HostResponse::Alias(alias)] = values.as_slice() {
            if depth > 0 {
                let unwrapped = self.lookup(alias, options, depth - 1)?;
                if unwrapped != HostLookup::NotFound {
                    return Ok(unwrapped);
                }
            }
            return Ok(HostLookup::Alias(alias.clone()));
        }
        Ok(HostLookup::Addresses(
            values
                .into_iter()
                .filter_map(|value| match value {
                    HostResponse::Ip(ip)
                        if (ip.is_ipv4() && options.ipv4) || (ip.is_ipv6() && options.ipv6) =>
                    {
                        Some(ip)
                    }
                    _ => None,
                })
                .collect(),
        ))
    }
}

fn compile_host_response(value: &HostValue) -> Result<Vec<HostResponse>> {
    let values: &[String] = match value {
        HostValue::Address(value) => std::slice::from_ref(value),
        HostValue::Addresses(values) => values,
    };
    let mut ips = Vec::new();
    for value in values {
        if let Ok(ip) = value.parse::<IpAddr>() {
            ips.push(HostResponse::Ip(canonical_ip(ip)));
            continue;
        }
        // Source picks the first domain/rcode in an array and discards IPs.
        if let Some(code) = value.strip_prefix('#') {
            let code = code
                .parse::<u16>()
                .context("invalid static-host response code")?;
            ensure!(code <= 0xfff, "static-host response code exceeds 4095");
            return Ok(vec![HostResponse::ResponseCode(code)]);
        }
        wire::fqdn(value).context("invalid static-host alias domain")?;
        return Ok(vec![HostResponse::Alias(value.clone())]);
    }
    Ok(ips)
}

// ---------------------------------------------------------------------------
// DNS app (app/dns/dns.go)
// ---------------------------------------------------------------------------

/// Result of an app-level lookup, mirroring Go `LookupIP`'s return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResult {
    pub ips: Vec<IpAddr>,
    pub ttl: u32,
}

struct DnsClient {
    name: String,
    tag: String,
    resolver: Resolver,
    skip_fallback: bool,
    final_query: bool,
    /// Per-server query strategy override, already intersected with the
    /// global strategy at build time (Go's `ResolveIpOptionOverride`).
    query_options: QueryOptions,
    domains: Option<DomainMatcher>,
    expected: Option<IpMatcher>,
    unexpected: Option<IpMatcher>,
    act_prior: bool,
    act_unprior: bool,
}

impl DnsClient {
    fn matches_domain(&self, domain: &str) -> bool {
        self.domains
            .as_ref()
            .is_some_and(|matcher| matcher.match_host(domain))
    }

    /// Go `Client.QueryIP` expected/unexpected IP filtering. Returns false
    /// when the strict filters leave no address (Go returns ErrEmptyResponse).
    fn apply_ip_policy(&self, ips: &mut Vec<IpAddr>) -> bool {
        if let Some(expected) = &self.expected
            && !self.act_prior
        {
            *ips = expected.filter_ips(ips).0;
            if ips.is_empty() {
                return false;
            }
        }
        if let Some(unexpected) = &self.unexpected
            && !self.act_unprior
        {
            *ips = unexpected.filter_ips(ips).1;
            if ips.is_empty() {
                return false;
            }
        }
        if let Some(expected) = &self.expected
            && self.act_prior
        {
            let preferred = expected.filter_ips(ips).0;
            if !preferred.is_empty() {
                *ips = preferred;
            }
        }
        if let Some(unexpected) = &self.unexpected
            && self.act_unprior
        {
            let preferred = unexpected.filter_ips(ips).1;
            if !preferred.is_empty() {
                *ips = preferred;
            }
        }
        !ips.is_empty()
    }
}

/// Ported Go DNS app: hosts mapping plus per-server cached clients with the
/// source's selection, fallback and query-strategy policy.
pub struct DnsApp {
    /// The FakeDNS engine backing `fakedns` nameservers, when configured.
    fake_dns: Option<std::sync::Arc<super::fakedns::FakeDnsEngine>>,
    clients: Vec<DnsClient>,
    hosts: StaticHosts,
    /// Global query strategy option (Go `s.ipOption`).
    query_options: QueryOptions,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    tag: String,
}

impl DnsApp {
    /// The domain leased to a fake address, if the engine knows it.
    pub fn fake_dns_domain(&self, ip: IpAddr) -> Option<String> {
        self.fake_dns.as_ref()?.domain_from_ip(ip)
    }

    /// Single JSON entry point: parse the Xray `dns` object and build the
    /// app. `fake_dns` is the root `fakeDns` engine; `None` uses Go's
    /// post-processing defaults when a `fakedns` nameserver is configured.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        Self::from_value_with_fake_dns(value, None)
    }

    pub fn from_value_with_fake_dns(
        value: &serde_json::Value,
        fake_dns: Option<std::sync::Arc<super::fakedns::FakeDnsEngine>>,
    ) -> Result<Self> {
        let config = serde_json::from_value::<DnsAppConfig>(value.clone())
            .context("DNS app configuration")?;
        let geodata = GeoDataStore::from_env().context("geodata store for the DNS app")?;
        Self::from_config_with_fake_dns(&config, &geodata, fake_dns)
    }

    pub fn from_config(config: &DnsAppConfig, geodata: &GeoDataStore) -> Result<Self> {
        Self::from_config_with_fake_dns(config, geodata, None)
    }

    pub fn from_config_with_fake_dns(
        config: &DnsAppConfig,
        geodata: &GeoDataStore,
        mut fake_dns: Option<std::sync::Arc<super::fakedns::FakeDnsEngine>>,
    ) -> Result<Self> {
        // Go's FakeDNSPostProcessingStage: a fakedns nameserver without a
        // root object gets strategy defaults.
        if fake_dns.is_none()
            && config.servers.iter().any(|server| match server {
                NameServerConfig::Address(address) => address.eq_ignore_ascii_case("fakedns"),
                NameServerConfig::Options(options) => {
                    options.address.eq_ignore_ascii_case("fakedns")
                }
            })
        {
            let strategy = resolve_query_strategy(&config.query_strategy);
            let (ipv4, ipv6) = match strategy {
                QueryStrategy::UseIp4 => (true, false),
                QueryStrategy::UseIp6 => (false, true),
                _ => (true, true),
            };
            fake_dns = Some(std::sync::Arc::new(super::fakedns::FakeDnsEngine::new(
                &super::fakedns::FakeDnsSettings::defaults(ipv4, ipv6),
            )?));
        }
        ensure!(
            !config.enable_parallel_query,
            "enableParallelQuery requires policy-group racing, which is not integrated in DnsApp"
        );
        ensure!(
            !config.use_system_hosts,
            "useSystemHosts requires reading the OS hosts file, which is not integrated in DnsApp; \
             provide explicit hosts mappings"
        );
        ensure!(
            !config.servers.is_empty(),
            "no DNS servers configured; the implicit localhost (system DNS) client \
             is not integrated in DnsApp"
        );
        let global_strategy = resolve_query_strategy(&config.query_strategy);
        ensure!(
            global_strategy != QueryStrategy::UseSys,
            "queryStrategy UseSystem requires system route discovery, which is not integrated in DnsApp"
        );
        let query_options = strategy_options(global_strategy, QueryOptions::BOTH);
        let empty_hosts = BTreeMap::new();
        let hosts = StaticHosts::build(geodata, config.hosts.as_ref().unwrap_or(&empty_hosts))
            .context("failed to create hosts")?;
        // Go generateRandomTag when the config tag is empty.
        let default_tag = if config.tag.is_empty() {
            format!("xray.system.{}", uuid::Uuid::new_v4())
        } else {
            config.tag.clone()
        };

        let mut clients = Vec::with_capacity(config.servers.len());
        for (index, server) in config.servers.iter().enumerate() {
            let options = match server {
                NameServerConfig::Address(address) => NameServerOptions {
                    address: address.clone(),
                    ..NameServerOptions::default()
                },
                NameServerConfig::Options(options) => options.clone(),
            };
            let upstream = parse_upstream(&options.address, options.port, fake_dns.as_ref())
                .with_context(|| format!("DNS server {index}"))?;
            let name = match &upstream {
                super::ServerLink::Classic(upstream) => match upstream.transport {
                    super::Transport::Udp => format!("UDP://{}", upstream.address),
                    super::Transport::Tcp => format!("TCP://{}", upstream.address),
                },
                super::ServerLink::Encrypted(client) => match client.endpoint().protocol() {
                    super::encrypted::EncryptedProtocol::Https => {
                        format!("HTTPS://{}", client.endpoint().host())
                    }
                    super::encrypted::EncryptedProtocol::Tls => {
                        format!("TLS://{}", client.endpoint().host())
                    }
                },
                super::ServerLink::FakeDns(_) => "FAKEDNS://pool".to_owned(),
            };

            let strategy = resolve_query_strategy(&options.query_strategy);
            ensure!(
                strategy != QueryStrategy::UseSys,
                "DNS server {index}: queryStrategy UseSystem requires system route discovery, \
                 which is not integrated in DnsApp"
            );
            let client_options = strategy_options(strategy, query_options);
            ensure!(
                has_family(client_options),
                "no QueryStrategy available for {}",
                options.address
            );

            let domains = if options.domains.is_empty() {
                None
            } else {
                Some(
                    geodata
                        .build_domain_matcher(
                            &geodata
                                .parse_domain_rules(&options.domains, geodata::domain::Type::Substr)
                                .with_context(|| format!("DNS server {index} domain rules"))?,
                        )
                        .with_context(|| format!("DNS server {index} domain rules"))?,
                )
            };
            let expected_ips = if options.expected_ips.is_empty() {
                &options.expect_ips
            } else {
                &options.expected_ips
            };
            let (expected, act_prior) = compile_ip_filter(geodata, expected_ips)
                .with_context(|| format!("DNS server {index}"))?;
            let (unexpected, act_unprior) = compile_ip_filter(geodata, &options.unexpected_ips)
                .with_context(|| format!("DNS server {index}"))?;

            let cache = CacheConfig {
                enabled: !options.disable_cache.unwrap_or(config.disable_cache),
                serve_stale: options.serve_stale.unwrap_or(config.serve_stale),
                max_stale: Duration::from_secs(u64::from(
                    options
                        .serve_expired_ttl
                        .unwrap_or(config.serve_expired_ttl),
                )),
                ..CacheConfig::default()
            };
            let timeout = Duration::from_millis(if options.timeout_ms == 0 {
                4000
            } else {
                options.timeout_ms
            });
            ensure!(
                Instant::now().checked_add(timeout).is_some(),
                "DNS server {index} timeoutMs exceeds the platform timer range"
            );
            let resolver = Resolver::new(ResolverConfig {
                servers: vec![upstream],
                timeout,
                cache,
                client_ip: options.client_ip.or(config.client_ip),
                ..ResolverConfig::default()
            })
            .with_context(|| format!("failed to create DNS client {index}"))?;
            let tag = if options.tag.is_empty() {
                default_tag.clone()
            } else {
                options.tag.clone()
            };
            clients.push(DnsClient {
                name,
                tag,
                resolver,
                skip_fallback: options.skip_fallback,
                final_query: options.final_query,
                query_options: client_options,
                domains,
                expected,
                unexpected,
                act_prior,
                act_unprior,
            });
        }

        Ok(Self {
            clients,
            hosts,
            query_options,
            disable_fallback: config.disable_fallback,
            disable_fallback_if_match: config.disable_fallback_if_match,
            tag: default_tag,
            fake_dns,
        })
    }

    /// The app's inbound tag (Go `IsOwnLink` compares it against inbound tags).
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Total cached records across all per-server clients.
    pub fn cache_len(&self) -> usize {
        self.clients
            .iter()
            .map(|client| client.resolver.cache_len())
            .sum()
    }

    pub fn clear_cache(&self) {
        for client in &self.clients {
            client.resolver.clear_cache();
        }
    }

    /// Go `sortClients`: domain-rule matched clients in configuration order
    /// first, then unused non-`skipFallback` fallbacks, honoring `finalQuery`
    /// cutoffs; an empty selection falls back to the first configured client.
    fn sort_clients(&self, domain: &str) -> Vec<usize> {
        let mut used = vec![false; self.clients.len()];
        let mut result = Vec::new();
        let mut has_match = false;
        for (index, client) in self.clients.iter().enumerate() {
            if client.matches_domain(domain) {
                has_match = true;
                used[index] = true;
                result.push(index);
                if client.final_query {
                    return result;
                }
            }
        }
        if !(self.disable_fallback || self.disable_fallback_if_match && has_match) {
            for (index, client) in self.clients.iter().enumerate() {
                if used[index] || client.skip_fallback {
                    continue;
                }
                used[index] = true;
                result.push(index);
                if client.final_query {
                    return result;
                }
            }
        }
        if result.is_empty()
            && let Some(first) = self.clients.first()
        {
            tracing::warn!(
                domain,
                server = %first.name,
                "no DNS client selected; the domain will use the first configured DNS server"
            );
            result.push(0);
        }
        result
    }

    /// Go `DNS.LookupIP`: normalize, intersect families with the global
    /// strategy, resolve static hosts (TTL 10), then query the selected
    /// clients serially, falling through on every error or empty answer.
    pub async fn lookup_ip(&self, domain: &str, opts: QueryOptions) -> Result<DnsResult> {
        let mut name = normalize_domain(domain)?;
        let options = intersect(opts, self.query_options);
        if !has_family(options) {
            return Err(DnsError::EmptyResponse.into());
        }
        match self.hosts.lookup(&name, options, 5)? {
            HostLookup::NotFound => {}
            HostLookup::Alias(alias) => name = alias,
            HostLookup::Addresses(ips) if ips.is_empty() => {
                return Err(DnsError::EmptyResponse.into());
            }
            HostLookup::Addresses(ips) => {
                return Ok(DnsResult {
                    ips,
                    ttl: HOSTS_TTL,
                });
            }
        }
        let mut errors: Vec<DnsError> = Vec::new();
        for index in self.sort_clients(&name) {
            let client = &self.clients[index];
            let options = intersect(options, client.query_options);
            if !has_family(options) {
                // Go's client returns ErrEmptyResponse without querying.
                errors.push(DnsError::EmptyResponse);
                continue;
            }
            let answer = match client.resolver.lookup_ip(&name, options).await {
                Ok(answer) => answer,
                Err(error) => {
                    tracing::debug!(
                        domain = %name,
                        server = %client.name,
                        %error,
                        "failed to lookup ip in serial query mode"
                    );
                    errors.push(error);
                    continue;
                }
            };
            let mut answer = answer;
            answer
                .ips
                .retain(|ip| (ip.is_ipv4() && options.ipv4) || (ip.is_ipv6() && options.ipv6));
            if !client.apply_ip_policy(&mut answer.ips) {
                errors.push(DnsError::EmptyResponse);
                continue;
            }
            return Ok(DnsResult {
                ips: answer.ips,
                ttl: answer.ttl,
            });
        }
        let merged = merge_query_errors(&name, errors);
        if matches!(merged, DnsError::EmptyResponse) {
            return Err(merged.into());
        }
        Err(anyhow::Error::new(merged).context(format!("returning nil for domain {name}")))
    }
}

/// Go's `*` marker turns an IP filter into a preference; the remaining rules
/// build the matcher (Go strips `*` in `infra/conf/dns.go` Build).
fn compile_ip_filter(
    geodata: &GeoDataStore,
    values: &[String],
) -> Result<(Option<IpMatcher>, bool)> {
    let prefer = values.iter().any(|value| value == "*");
    let rules: Vec<String> = values
        .iter()
        .filter(|value| value.as_str() != "*")
        .cloned()
        .collect();
    let matcher = if rules.is_empty() {
        None
    } else {
        Some(geodata.build_ip_matcher(&geodata.parse_ip_rules(&rules)?)?)
    };
    Ok((matcher, prefer))
}

/// Go `mergeQueryErrors` flattened onto the native error kinds: no errors or
/// only empty responses yield `ErrEmptyResponse`, a uniform response code is
/// kept, anything else is reported as all servers failed.
fn merge_query_errors(domain: &str, mut errors: Vec<DnsError>) -> DnsError {
    if errors.is_empty()
        || errors
            .iter()
            .all(|error| matches!(error, DnsError::EmptyResponse))
    {
        return DnsError::EmptyResponse;
    }
    if errors.len() == 1 {
        return errors.remove(0);
    }
    if let Some(DnsError::ResponseCode(code)) = errors.first()
        && errors
            .iter()
            .all(|error| matches!(error, DnsError::ResponseCode(other) if other == code))
    {
        return DnsError::ResponseCode(*code);
    }
    tracing::debug!(domain, "all selected DNS servers failed");
    DnsError::AllServersFailed(errors.into_iter().map(|error| error.to_string()).collect())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::{
        net::{TcpListener, UdpSocket},
        task::JoinHandle,
        time::timeout,
    };

    use super::super::{
        RecordType,
        encrypted::{EncryptedConfig, EncryptedEndpoint},
        wire,
    };
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn encrypted_nameserver_parsing_follows_the_go_surface() {
        // +local, numeric hosts and #bootstrap fragments build clients.
        for address in [
            "https+local://127.0.0.1/dns-query",
            "https://dns.example/dns-query#127.0.0.1",
            "tls+local://127.0.0.1:853",
            "tls://tls.example#127.0.0.1,127.0.0.2",
        ] {
            let link = parse_upstream(address, 0, None)
                .unwrap_or_else(|error| panic!("{address}: {error:#}"));
            assert!(
                matches!(link, super::super::ServerLink::Encrypted(_)),
                "{address} did not build an encrypted client"
            );
        }
        // A routed domain endpoint without pins names the missing dialer.
        let error = parse_upstream("https://dns.example/dns-query", 0, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("runtime dialer"), "{error}");
        // QUIC stays rejected by design; h2c names its gap.
        assert!(parse_upstream("quic://dns.example", 0, None).is_err());
        assert!(parse_upstream("h2c://dns.example", 0, None).is_err());
        // The port field stays contradictory for URL servers.
        assert!(parse_upstream("https+local://127.0.0.1/dns-query", 53, None).is_err());
    }

    /// An in-process DoH fixture: one TLS+h2 connection answering every
    /// query with `answers`, recording each received question name.
    async fn doh_fixture(
        answers: Vec<IpAddr>,
    ) -> (
        crate::transport::tls::TlsSettings,
        u16,
        Arc<Mutex<Vec<String>>>,
        JoinHandle<()>,
    ) {
        let (server_tls, client_tls) = encrypted_tls_pair("h2");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let logger = log.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor =
                tokio_rustls::TlsAcceptor::from(server_tls.build_server_config().unwrap());
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            // The accept loop is the connection's driver; every request is
            // answered and the loop keeps flushing frames until the client
            // disconnects.
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                let (_parts, mut body) = request.into_parts();
                let mut query = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    query.extend_from_slice(&chunk);
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                eprintln!("DNSPROBE fixture got a {}-byte DoH query", query.len());
                let request = wire::decode(&query).unwrap();
                let question = request.questions[0].clone();
                logger.lock().unwrap().push(question.name.clone());
                let ips: Vec<IpAddr> = answers
                    .iter()
                    .copied()
                    .filter(|ip| (question.record_type == RecordType::A) == ip.is_ipv4())
                    .collect();
                let payload =
                    wire::encode_response(request.header.id, &question, &ips, 120, 0, None, 512)
                        .unwrap();
                if let Ok(mut send) = respond.send_response(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/dns-message")
                        .header("content-length", payload.len())
                        .body(())
                        .unwrap(),
                    false,
                ) {
                    let _ = send.send_data(bytes::Bytes::from(payload), true);
                }
            }
        });
        (client_tls, port, log, task)
    }

    #[tokio::test]
    async fn fakedns_nameserver_leases_and_reverse_maps() {
        timeout(std::time::Duration::from_secs(10), async {
            let app = DnsApp::from_value_with_fake_dns(
                &serde_json::json!({"servers": ["fakedns"]}),
                None,
            )
            .unwrap();
            let first = app
                .lookup_ip("origin.example", super::QueryOptions::default())
                .await
                .unwrap();
            assert_eq!(first.ips.len(), 2, "both default families lease");
            // The lease is stable across lookups.
            let second = app
                .lookup_ip("origin.example", super::QueryOptions::default())
                .await
                .unwrap();
            assert_eq!(first.ips, second.ips);
            // The engine reverse-maps the fake addresses back to the domain.
            for ip in first.ips {
                assert_eq!(app.fake_dns_domain(ip), Some("origin.example".to_owned()));
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn encrypted_resolver_link_resolves_and_caches_through_doh() {
        timeout(std::time::Duration::from_secs(10), async {
            let (client_tls, port, log, server) = doh_fixture(vec![ip("192.0.2.7")]).await;
            // The URL names the certificate's host; the bootstrap addresses
            // pin the dial to the fixture's loopback address, exactly like
            // `build_encrypted` handles Go's #ip fragment.
            let endpoint = EncryptedEndpoint::parse(&format!(
                "https+local://resolver.example:{port}/dns-query"
            ))
            .unwrap();
            let mut config = EncryptedConfig::new(endpoint);
            config.bootstrap = vec![ip("127.0.0.1")];
            config.tls = client_tls;
            config.timeout = std::time::Duration::from_secs(2);
            let client = Arc::new(super::super::encrypted::EncryptedClient::new(config).unwrap());
            let resolver = Resolver::new(ResolverConfig {
                servers: vec![super::super::ServerLink::Encrypted(client)],
                ..ResolverConfig::default()
            })
            .unwrap();
            // DoH IDs are zero on the wire and restored per exchange.
            let answer = resolver
                .query("service.example", RecordType::A)
                .await
                .unwrap();
            assert_eq!(answer.ips, vec![ip("192.0.2.7")]);
            // The cached second lookup must not reach the fixture again.
            let cached = resolver
                .query("service.example", RecordType::A)
                .await
                .unwrap();
            assert!(cached.from_cache);
            assert_eq!(log.lock().unwrap().len(), 1);
            server.abort();
        })
        .await
        .unwrap();
    }

    fn encrypted_tls_pair(
        alpn: &str,
    ) -> (
        crate::transport::tls::TlsSettings,
        crate::transport::tls::TlsSettings,
    ) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["resolver.example".into()]).unwrap();
        let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
        let server = crate::transport::tls::TlsSettings {
            alpn: vec![alpn.into()],
            certificates: vec![crate::transport::tls::TlsCertificate {
                certificate: certificate.clone(),
                key: signing_key
                    .serialize_pem()
                    .lines()
                    .map(str::to_owned)
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client = crate::transport::tls::TlsSettings {
            disable_system_root: true,
            certificates: vec![crate::transport::tls::TlsCertificate {
                certificate,
                usage: "verify".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        (server, client)
    }

    /// Local UDP DNS fixture: answers every query with `answers` filtered to
    /// the queried family, recording (name, record type) per received query.
    struct UdpFixture {
        address: SocketAddr,
        log: Arc<Mutex<Vec<(String, u16)>>>,
        task: JoinHandle<()>,
    }

    impl UdpFixture {
        async fn start(answers: Vec<IpAddr>, ttl: u32, code: u16) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let log = Arc::new(Mutex::new(Vec::new()));
            let logger = log.clone();
            let task = tokio::spawn(async move {
                let mut buffer = [0; 512];
                while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                    let Ok(query) = wire::decode(&buffer[..size]) else {
                        continue;
                    };
                    let question = query.questions[0].clone();
                    let ips: Vec<IpAddr> = answers
                        .iter()
                        .copied()
                        .filter(|ip| (question.record_type == RecordType::A) == ip.is_ipv4())
                        .collect();
                    logger
                        .lock()
                        .unwrap()
                        .push((question.name.clone(), question.record_type.0));
                    let Ok(response) = wire::encode_response(
                        query.header.id,
                        &question,
                        &ips,
                        ttl,
                        code,
                        None,
                        wire::MAX_MESSAGE_SIZE,
                    ) else {
                        continue;
                    };
                    let _ = socket.send_to(&response, peer).await;
                }
            });
            Self { address, log, task }
        }

        fn count(&self) -> usize {
            self.log.lock().unwrap().len()
        }

        fn names(&self) -> Vec<String> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
        }

        fn types(&self) -> Vec<u16> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(_, kind)| *kind)
                .collect()
        }
    }

    impl Drop for UdpFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn app(value: serde_json::Value) -> DnsApp {
        DnsApp::from_value(&value).unwrap()
    }

    #[test]
    fn selection_orders_domain_matches_first_then_fallbacks() {
        let servers = serde_json::json!([
            {"address": "192.0.2.10"},
            {"address": "192.0.2.11", "domains": ["domain:example.com"]},
            {"address": "192.0.2.12", "domains": ["keyword:example", "domain:other.test"], "skipFallback": true},
            {"address": "192.0.2.13", "domains": ["full:match.test"], "finalQuery": true}
        ]);
        let plan = app(serde_json::json!({"servers": servers}));
        // Matched servers in config order (a skipFallback server still runs
        // when its own domain rule matches), then non-skip fallbacks.
        assert_eq!(plan.sort_clients("www.example.com"), [1, 2, 0, 3]);
        assert_eq!(plan.sort_clients("unrelated.test"), [0, 1, 3]);
        // finalQuery on the only matching server truncates the list.
        assert_eq!(plan.sort_clients("match.test"), [3]);
        assert_eq!(plan.sort_clients("sub.other.test"), [2, 0, 1, 3]);
        // disableFallbackIfMatch keeps only the matched servers.
        let plan = app(serde_json::json!({"disableFallbackIfMatch": true, "servers": servers}));
        assert_eq!(plan.sort_clients("www.example.com"), [1, 2]);
        assert_eq!(plan.sort_clients("unrelated.test"), [0, 1, 3]);
        assert_eq!(plan.sort_clients("match.test"), [3]);
        // Empty selection falls back to the first configured server (Go appends
        // s.clients[0] even when it sets skipFallback).
        let plan = app(serde_json::json!({
            "disableFallback": true,
            "servers": [{"address": "192.0.2.10", "skipFallback": true}, {"address": "192.0.2.11"}]
        }));
        assert_eq!(plan.sort_clients("any.test"), [0]);
    }

    #[tokio::test]
    async fn suffix_routed_queries_hit_the_matching_server() {
        let fallback = UdpFixture::start(vec![ip("192.0.2.1")], 60, 0).await;
        let routed = UdpFixture::start(vec![ip("198.51.100.2")], 60, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [
                {"address": "127.0.0.1", "port": fallback.address.port(), "timeoutMs": 500},
                {"address": "127.0.0.1", "port": routed.address.port(), "domains": ["domain:routed.test"], "timeoutMs": 500}
            ]
        }));
        let answer = plan
            .lookup_ip("www.routed.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("198.51.100.2")]);
        assert_eq!(answer.ttl, 60);
        assert_eq!(fallback.count(), 0);
        assert_eq!(routed.names(), ["www.routed.test."]);
        let answer = plan
            .lookup_ip("plain.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("192.0.2.1")]);
        assert_eq!(fallback.names(), ["plain.test."]);
        assert_eq!(routed.count(), 1);
    }

    #[tokio::test]
    async fn skip_fallback_skips_fallback_servers_after_match_failure() {
        let nxdomain = UdpFixture::start(vec![], 60, 3).await;
        let flaky = UdpFixture::start(vec![ip("192.0.2.7")], 60, 0).await;
        // The matched server answers NXDOMAIN; the skipFallback server is not
        // consulted, so the merged error is the response code itself.
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [
                {"address": "127.0.0.1", "port": flaky.address.port(), "skipFallback": true, "timeoutMs": 500},
                {"address": "127.0.0.1", "port": nxdomain.address.port(), "domains": ["full:skip.test"], "timeoutMs": 500}
            ]
        }));
        let error = plan
            .lookup_ip("skip.test", QueryOptions::BOTH)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<DnsError>(),
                Some(DnsError::ResponseCode(3))
            ),
            "{error}"
        );
        assert_eq!(flaky.count(), 0);
        // Without skipFallback the next client answers after the NXDOMAIN,
        // as in Go's serial query mode.
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [
                {"address": "127.0.0.1", "port": flaky.address.port(), "timeoutMs": 500},
                {"address": "127.0.0.1", "port": nxdomain.address.port(), "domains": ["full:skip.test"], "timeoutMs": 500}
            ]
        }));
        let answer = plan
            .lookup_ip("skip.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("192.0.2.7")]);
        assert_eq!(flaky.count(), 1);
    }

    #[tokio::test]
    async fn hosts_entries_win_with_ttl_ten_and_family_filtering() {
        let fixture = UdpFixture::start(vec![ip("203.0.113.1"), ip("2001:db8::1")], 60, 0).await;
        let plan = app(serde_json::json!({
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}],
            "hosts": {
                "host.test": ["192.0.2.99", "2001:db8::99"],
                "domain:internal.test": "198.51.100.3",
                "alias.test": "target.test",
                "v4only.test": "192.0.2.98",
                "nx.test": "#3",
                "empty.test": []
            }
        }));
        let answer = plan
            .lookup_ip("HOST.TEST.", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("192.0.2.99"), ip("2001:db8::99")]);
        assert_eq!(answer.ttl, HOSTS_TTL);
        assert_eq!(fixture.count(), 0);
        let answer = plan
            .lookup_ip("host.test", QueryOptions::IPV4)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("192.0.2.99")]);
        // Recorded hosts with no address of the requested family, recorded
        // empty mappings and host response codes never reach the nameservers.
        for (domain, code) in [
            ("v4only.test", None),
            ("empty.test", None),
            ("nx.test", Some(3_u16)),
        ] {
            let error = plan
                .lookup_ip(domain, QueryOptions::IPV6)
                .await
                .unwrap_err();
            match code {
                None => assert!(
                    matches!(
                        error.downcast_ref::<DnsError>(),
                        Some(DnsError::EmptyResponse)
                    ),
                    "{domain}: {error}"
                ),
                Some(code) => assert!(
                    matches!(error.downcast_ref::<DnsError>(), Some(DnsError::ResponseCode(other)) if *other == code),
                    "{domain}: {error}"
                ),
            }
        }
        // Suffix rule in a hosts key.
        let answer = plan
            .lookup_ip("deep.internal.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("198.51.100.3")]);
        // Alias rewires the query to the target domain (both families).
        let answer = plan
            .lookup_ip("alias.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("203.0.113.1"), ip("2001:db8::1")]);
        assert_eq!(fixture.names(), ["target.test.", "target.test."]);
        assert_eq!(fixture.count(), 2);
    }

    #[tokio::test]
    async fn second_query_hits_the_cache_and_disable_cache_bypasses_it() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.55")], 120, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}]
        }));
        let first = plan
            .lookup_ip("cached.test", QueryOptions::BOTH)
            .await
            .unwrap();
        let second = plan
            .lookup_ip("cached.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(first.ips, second.ips);
        // Go getIPs rounds the remaining TTL upward, so the age only shaves
        // whole seconds off the original 120.
        assert!((110..=120).contains(&second.ttl), "ttl {}", second.ttl);
        assert_eq!(fixture.count(), 1);
        assert_eq!(plan.cache_len(), 1);
        plan.clear_cache();
        assert_eq!(plan.cache_len(), 0);

        // Global disableCache, re-enabled per server.
        let fixture = UdpFixture::start(vec![ip("192.0.2.56")], 120, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "disableCache": true,
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "disableCache": false, "timeoutMs": 500}]
        }));
        plan.lookup_ip("cached.test", QueryOptions::BOTH)
            .await
            .unwrap();
        plan.lookup_ip("cached.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(fixture.count(), 1);
        assert_eq!(plan.cache_len(), 1);

        let fixture = UdpFixture::start(vec![ip("192.0.2.57")], 120, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "disableCache": true,
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}]
        }));
        plan.lookup_ip("cached.test", QueryOptions::BOTH)
            .await
            .unwrap();
        plan.lookup_ip("cached.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(fixture.count(), 2);
        assert_eq!(plan.cache_len(), 0);
    }

    #[tokio::test]
    async fn query_strategy_filters_families_globally_and_per_server() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.3"), ip("2001:db8::3")], 60, 0).await;
        let plan = app(serde_json::json!({
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "queryStrategy": "UseIPv6", "timeoutMs": 500}]
        }));
        let answer = plan
            .lookup_ip("families.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("2001:db8::3")]);
        assert_eq!(fixture.types(), [28]);

        let fixture = UdpFixture::start(vec![ip("192.0.2.4"), ip("2001:db8::4")], 60, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}]
        }));
        let answer = plan
            .lookup_ip("families.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("192.0.2.4")]);
        assert_eq!(fixture.types(), [1]);
        // The caller's family intersects the global strategy: none left.
        let error = plan
            .lookup_ip("families.test", QueryOptions::IPV6)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<DnsError>(),
            Some(DnsError::EmptyResponse)
        ));
        // A per-server strategy that empties the global one is a build error
        // (Go: "no QueryStrategy available for <address>").
        let fixture = UdpFixture::start(vec![], 60, 0).await;
        let result = DnsApp::from_value(&serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [{"address": "127.0.0.1", "port": fixture.address.port(), "queryStrategy": "UseIPv6"}]
        }));
        let Err(error) = result else {
            panic!("conflicting per-server queryStrategy was accepted");
        };
        assert!(
            error.to_string().contains("no QueryStrategy available"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn expected_ips_filter_answers_and_drive_fallback() {
        let strict = UdpFixture::start(vec![ip("192.0.2.1"), ip("198.51.100.5")], 60, 0).await;
        let backup = UdpFixture::start(vec![ip("203.0.113.7")], 60, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [
                {"address": "127.0.0.1", "port": strict.address.port(), "expectIPs": "198.51.100.0/24", "timeoutMs": 500},
                {"address": "127.0.0.1", "port": backup.address.port(), "timeoutMs": 500}
            ]
        }));
        let answer = plan
            .lookup_ip("filtered.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("198.51.100.5")]);
        assert_eq!(backup.count(), 0);

        // Every answer filtered out -> ErrEmptyResponse at the client ->
        // the next fallback server answers.
        let all_unexpected = UdpFixture::start(vec![ip("192.0.2.9")], 60, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [
                {"address": "127.0.0.1", "port": all_unexpected.address.port(), "expectIPs": ["198.51.100.0/24"], "timeoutMs": 500},
                {"address": "127.0.0.1", "port": backup.address.port(), "timeoutMs": 500}
            ]
        }));
        let answer = plan
            .lookup_ip("filtered.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("203.0.113.7")]);
        assert_eq!(backup.count(), 1);

        // "*" turns the filter into a preference: unmatched answers survive.
        let preferred = UdpFixture::start(vec![ip("192.0.2.9")], 60, 0).await;
        let plan = app(serde_json::json!({
            "queryStrategy": "UseIPv4",
            "servers": [{"address": "127.0.0.1", "port": preferred.address.port(), "expectedIPs": ["*", "198.51.100.0/24"], "timeoutMs": 500}]
        }));
        let answer = plan
            .lookup_ip("filtered.test", QueryOptions::BOTH)
            .await
            .unwrap();
        assert_eq!(answer.ips, [ip("192.0.2.9")]);
    }

    #[test]
    fn unsupported_options_and_malformed_config_are_rejected() {
        for bad in [
            serde_json::json!({"servers": ["192.0.2.1"], "typo": true}),
            serde_json::json!({}),
            serde_json::json!({"servers": [], "hosts": {}}),
            serde_json::json!({"servers": ["192.0.2.1"], "enableParallelQuery": true}),
            serde_json::json!({"servers": ["192.0.2.1"], "useSystemHosts": true}),
            serde_json::json!({"servers": ["192.0.2.1"], "queryStrategy": "UseSystem"}),
            serde_json::json!({"servers": [{"address": "192.0.2.1", "queryStrategy": "UseSystem"}]}),
            serde_json::json!({"servers": ["https://dns.example/dns-query"]}),
            serde_json::json!({"servers": ["h2c://192.0.2.1/dns-query"]}),
            serde_json::json!({"servers": ["quic+local://192.0.2.1"]}),
            serde_json::json!({"servers": ["localhost"]}),
            serde_json::json!({"servers": ["dns.example"]}),
            serde_json::json!({"servers": [{"address": "tcp://192.0.2.1", "port": 53}]}),
            serde_json::json!({"servers": ["192.0.2.1"], "hosts": {"bad.test": "#4096"}}),
            serde_json::json!({"servers": ["192.0.2.1"], "hosts": {"bad.test": "not a domain!"}}),
            serde_json::json!({"servers": ["192.0.2.1"], "clientIp": "dns.example"}),
            serde_json::json!({"servers": [{"address": "192.0.2.1", "skipFallbak": true}]}),
            serde_json::json!({"servers": [{"address": "192.0.2.1", "domains": ["regexp:["]}]}),
        ] {
            assert!(DnsApp::from_value(&bad).is_err(), "accepted {bad}");
        }
        // The classic forms and alias strategies all build.
        for good in [
            serde_json::json!({"servers": ["192.0.2.1"]}),
            serde_json::json!({"servers": ["udp://192.0.2.1:5353", "tcp://192.0.2.2:53", "tcp+local://[2001:db8::1]:53", "2001:db8::2"]}),
            serde_json::json!({"servers": [{"address": "192.0.2.1", "port": 5353}], "queryStrategy": "UseIP", "tag": "dns-tag", "clientIp": "203.0.113.8", "hosts": {"a.test": "b.test"}}),
        ] {
            assert!(DnsApp::from_value(&good).is_ok(), "rejected {good}");
        }
    }

    #[tokio::test]
    async fn lookup_rejects_empty_domain_and_disabled_families() {
        let plan = app(serde_json::json!({"servers": ["192.0.2.1"]}));
        for domain in ["", "."] {
            let error = plan
                .lookup_ip(domain, QueryOptions::BOTH)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("empty domain name"), "{error}");
        }
        let error = plan
            .lookup_ip(
                "example.com",
                QueryOptions {
                    ipv4: false,
                    ipv6: false,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<DnsError>(),
            Some(DnsError::EmptyResponse)
        ));
    }
}
