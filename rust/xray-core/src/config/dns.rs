//! DNS configuration and source-compatible serial nameserver policy.
//!
//! The parent registers this module and wires `DnsConfig` into the top-level
//! configuration. `compile` is independent of sockets; `lookup_with` executes
//! the host/selection/fallback policy through a runtime-provided `ServerQuery`.
//! The provider receives effective transport, cache, client-IP and routing-tag
//! settings, and must honor them. Classic and encrypted transport configuration
//! adapters below use the existing native DNS implementations.
//!
//! Unsupported system DNS/hosts, system-route family detection, FakeDNS,
//! parallel policy-group racing, h2c, and QUIC are rejected explicitly. Routed
//! endpoints are never silently converted to local/direct DNS. Regex/geodata
//! semantics and limitations are inherited from `crate::geodata`. Compiled
//! matchers are snapshots; recompile the configuration after geodata reload.
//! Uniform empty answers and DNS response codes keep their native error kind;
//! mixed failures use `DnsError::AllServersFailed` strings, so Go's nested error
//! tree is not preserved. DoT endpoint support is the native encrypted module's
//! extension; the inspected Go nameserver factory does not expose it.

use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    dns::{
        self, CacheConfig, DnsError, LookupResult, QueryOptions, ResolverConfig, Upstream,
        encrypted::{DialMode, EncryptedConfig, EncryptedEndpoint},
        wire,
    },
    geodata::{DomainMatcher, GeoDataStore, IpMatcher, domain},
};

/// JSON `dns` object. Unknown keys fail rather than silently discarding policy.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsConfig {
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum NameServerConfig {
    Address(String),
    Options(NameServerOptions),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HostValue {
    Address(String),
    Addresses(Vec<String>),
}

fn null_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn string_list<'de, D: Deserializer<'de>>(
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

/// Intersect these with caller options; per-server strategy cannot re-enable a
/// family disabled by the global strategy. Unknown names are configuration
/// errors (a deliberate improvement over Go's fallback to `UseIP` for typos).
pub fn parse_query_strategy(value: &str) -> Result<QueryOptions> {
    Ok(match value.to_ascii_lowercase().as_str() {
        "" | "useip" | "use_ip" | "use-ip" => QueryOptions::BOTH,
        "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4" | "use-ipv4"
        | "use-ip-v4" => QueryOptions::IPV4,
        "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6" | "use-ipv6"
        | "use-ip-v6" => QueryOptions::IPV6,
        "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system" => bail!(
            "UseSystem DNS query strategy requires system-route discovery, which is not integrated"
        ),
        _ => bail!("unknown DNS queryStrategy {value:?}"),
    })
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

#[derive(Clone, Debug)]
pub enum NameServerEndpoint {
    /// Bare numeric addresses and `tcp://` preserve routed semantics. Only
    /// `tcp+local://` selects local classic DNS in the source configuration.
    Classic {
        upstream: Upstream,
        mode: DialMode,
    },
    Encrypted(EncryptedEndpoint),
}

impl NameServerEndpoint {
    pub fn mode(&self) -> DialMode {
        match self {
            Self::Classic { mode, .. } => *mode,
            Self::Encrypted(endpoint) => endpoint.mode(),
        }
    }
}

fn parse_endpoint(address: &str, port: u16) -> Result<NameServerEndpoint> {
    ensure!(!address.is_empty(), "nameserver address is not specified");
    if address.eq_ignore_ascii_case("localhost") || address.eq_ignore_ascii_case("fakedns") {
        bail!("DNS nameserver {address:?} is not integrated");
    }
    if let Some((scheme, rest)) = address.split_once("://") {
        // Go ignores the separate port for URLs; reject contradictory settings
        // rather than accept a configuration whose effective port is surprising.
        ensure!(
            port == 0,
            "URL nameservers must specify their port in the URL, not the port field"
        );
        match scheme.to_ascii_lowercase().as_str() {
            "tcp" | "tcp+local" => {
                let upstream = Upstream::parse(&format!("tcp://{rest}"))?;
                return Ok(NameServerEndpoint::Classic {
                    upstream,
                    mode: if scheme.eq_ignore_ascii_case("tcp+local") {
                        DialMode::Local
                    } else {
                        DialMode::Routed
                    },
                });
            }
            "https" | "https+local" | "tls" | "tls+local" => {
                return Ok(NameServerEndpoint::Encrypted(EncryptedEndpoint::parse(
                    &format!("{}://{rest}", scheme.to_ascii_lowercase()),
                )?));
            }
            _ => bail!("unsupported DNS nameserver scheme {scheme:?}"),
        }
    }
    let address = address
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .unwrap_or(address);
    let ip = address.parse::<IpAddr>().with_context(|| format!("DNS nameserver {address:?} requires explicit hostname bootstrap, which is not integrated for classic DNS"))?;
    Ok(NameServerEndpoint::Classic {
        upstream: Upstream::udp(SocketAddr::new(ip, if port == 0 { 53 } else { port })),
        mode: DialMode::Routed,
    })
}

#[derive(Clone, Debug)]
pub struct CompiledServer {
    pub index: usize,
    pub endpoint: NameServerEndpoint,
    pub tag: String,
    pub client_ip: Option<IpAddr>,
    pub timeout: Duration,
    pub cache: CacheConfig,
    pub query_options: QueryOptions,
    pub skip_fallback: bool,
    pub final_query: bool,
    domains: Option<DomainMatcher>,
    expected: Option<IpMatcher>,
    unexpected: Option<IpMatcher>,
    prefer_expected: bool,
    prefer_unexpected: bool,
}

impl CompiledServer {
    /// This is a configuration adapter, not authorization to bypass routing.
    /// `Resolver` itself dials directly: routed endpoints need a runtime bridge,
    /// or an explicit application decision to use direct mode.
    pub fn classic_resolver_config(&self) -> Option<ResolverConfig> {
        let NameServerEndpoint::Classic { upstream, .. } = self.endpoint else {
            return None;
        };
        Some(ResolverConfig {
            servers: vec![upstream],
            timeout: self.timeout,
            cache: self.cache.clone(),
            client_ip: self.client_ip,
            ..ResolverConfig::default()
        })
    }

    /// Build the existing encrypted transport configuration. Its bootstrap and
    /// TLS fields can be filled by the runtime; cache policy remains in `self.cache`
    /// because `EncryptedClient` is a transport and does not own a DNS cache.
    pub fn encrypted_client_config(&self) -> Option<EncryptedConfig> {
        let NameServerEndpoint::Encrypted(endpoint) = &self.endpoint else {
            return None;
        };
        let mut config = EncryptedConfig::new(endpoint.clone());
        config.timeout = self.timeout;
        config.client_ip = self.client_ip;
        Some(config)
    }

    pub fn matches_domain(&self, name: &str) -> bool {
        self.domains
            .as_ref()
            .is_some_and(|matcher| matcher.match_host(name))
    }

    /// Source filter order: strict expected, strict unexpected, preferred
    /// expected, preferred unexpected. `*` changes a filter into a preference:
    /// if it would remove every address, retain the previous nonempty answer.
    pub fn filter_answer(&self, mut answer: LookupResult) -> dns::Result<LookupResult> {
        if let Some(matcher) = &self.expected
            && !self.prefer_expected
        {
            answer.ips = matcher.filter_ips(&answer.ips).0;
        }
        if let Some(matcher) = &self.unexpected
            && !self.prefer_unexpected
        {
            answer.ips = matcher.filter_ips(&answer.ips).1;
        }
        if let Some(matcher) = &self.expected
            && self.prefer_expected
        {
            let preferred = matcher.filter_ips(&answer.ips).0;
            if !preferred.is_empty() {
                answer.ips = preferred;
            }
        }
        if let Some(matcher) = &self.unexpected
            && self.prefer_unexpected
        {
            let preferred = matcher.filter_ips(&answer.ips).1;
            if !preferred.is_empty() {
                answer.ips = preferred;
            }
        }
        if answer.ips.is_empty() {
            return Err(DnsError::EmptyResponse);
        }
        Ok(answer)
    }
}

#[derive(Clone, Debug)]
enum HostResponse {
    Ip(IpAddr),
    Alias(String),
    ResponseCode(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostLookup {
    NotFound,
    /// A recorded empty list means a terminal empty response, not fallback.
    Addresses(Vec<IpAddr>),
    /// Unmapped aliases, or aliases at the source's five-hop bound, go upstream.
    Alias(String),
}

#[derive(Clone, Debug)]
pub struct CompiledDns {
    pub servers: Vec<CompiledServer>,
    pub query_options: QueryOptions,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
    hosts: Option<DomainMatcher>,
    host_responses: Vec<Vec<HostResponse>>,
}

impl DnsConfig {
    pub fn compile(&self, geodata: &GeoDataStore) -> Result<CompiledDns> {
        ensure!(
            !self.enable_parallel_query,
            "enableParallelQuery requires policy-group racing, which is not integrated"
        );
        ensure!(
            !self.use_system_hosts,
            "useSystemHosts is not integrated; provide explicit hosts mappings"
        );
        ensure!(
            !self.servers.is_empty(),
            "explicit DNS servers are required; the implicit localhost resolver is not integrated"
        );
        let query_options = parse_query_strategy(&self.query_strategy)?;
        let tag = if self.tag.is_empty() {
            format!("xray.system.{}", uuid::Uuid::new_v4())
        } else {
            self.tag.clone()
        };
        let mut servers = Vec::with_capacity(self.servers.len());
        for (index, server) in self.servers.iter().enumerate() {
            let options = match server {
                NameServerConfig::Address(address) => NameServerOptions {
                    address: address.clone(),
                    ..NameServerOptions::default()
                },
                NameServerConfig::Options(options) => options.clone(),
            };
            let endpoint = parse_endpoint(&options.address, options.port)
                .with_context(|| format!("DNS server {index}"))?;
            let families = intersect(
                query_options,
                parse_query_strategy(&options.query_strategy)?,
            );
            ensure!(
                has_family(families),
                "DNS server {index} queryStrategy conflicts with the global queryStrategy"
            );
            let timeout = Duration::from_millis(if options.timeout_ms == 0 {
                4000
            } else {
                options.timeout_ms
            });
            ensure!(
                Instant::now().checked_add(timeout).is_some(),
                "DNS server {index} timeoutMs exceeds the platform timer range"
            );
            let domains = if options.domains.is_empty() {
                None
            } else {
                Some(geodata.build_domain_matcher(
                    &geodata.parse_domain_rules(&options.domains, domain::Type::Substr)?,
                )?)
            };
            let expected_ips = if options.expected_ips.is_empty() {
                &options.expect_ips
            } else {
                &options.expected_ips
            };
            let (expected, prefer_expected) = compile_ip_filter(geodata, expected_ips)?;
            let (unexpected, prefer_unexpected) =
                compile_ip_filter(geodata, &options.unexpected_ips)?;
            servers.push(CompiledServer {
                index,
                endpoint,
                tag: if options.tag.is_empty() {
                    tag.clone()
                } else {
                    options.tag
                },
                client_ip: options.client_ip.or(self.client_ip),
                timeout,
                cache: CacheConfig {
                    enabled: !options.disable_cache.unwrap_or(self.disable_cache),
                    serve_stale: options.serve_stale.unwrap_or(self.serve_stale),
                    max_stale: Duration::from_secs(u64::from(
                        options.serve_expired_ttl.unwrap_or(self.serve_expired_ttl),
                    )),
                    ..CacheConfig::default()
                },
                query_options: families,
                skip_fallback: options.skip_fallback,
                final_query: options.final_query,
                domains,
                expected,
                unexpected,
                prefer_expected,
                prefer_unexpected,
            });
        }
        let mut host_rules = Vec::new();
        let mut host_responses = Vec::new();
        if let Some(hosts) = &self.hosts {
            // The Go input is a map with unspecified iteration order. Use lexical
            // order to make overlapping host mappings deterministic in Rust.
            for (rule, value) in hosts {
                host_rules.push(geodata.parse_domain_rule(rule, domain::Type::Full)?);
                host_responses.push(
                    compile_host(value).with_context(|| format!("DNS host mapping {rule:?}"))?,
                );
            }
        }
        let hosts = if host_rules.is_empty() {
            None
        } else {
            Some(geodata.build_domain_matcher(&host_rules)?)
        };
        Ok(CompiledDns {
            servers,
            query_options,
            disable_fallback: self.disable_fallback,
            disable_fallback_if_match: self.disable_fallback_if_match,
            hosts,
            host_responses,
        })
    }
}

fn compile_ip_filter(store: &GeoDataStore, values: &[String]) -> Result<(Option<IpMatcher>, bool)> {
    let preferred = values.iter().any(|value| value == "*");
    let rules: Vec<_> = values
        .iter()
        .filter(|value| value.as_str() != "*")
        .cloned()
        .collect();
    let matcher = if rules.is_empty() {
        None
    } else {
        Some(store.build_ip_matcher(&store.parse_ip_rules(&rules)?)?)
    };
    Ok((matcher, preferred))
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

fn compile_host(value: &HostValue) -> Result<Vec<HostResponse>> {
    let values = match value {
        HostValue::Address(value) => std::slice::from_ref(value),
        HostValue::Addresses(values) => values.as_slice(),
    };
    let mut ips = Vec::new();
    for value in values {
        if let Ok(ip) = value.parse::<IpAddr>() {
            ips.push(HostResponse::Ip(canonical_ip(ip)));
            continue;
        }
        // Source picks the first domain/rcode in an array and discards every IP.
        if let Some(code) = value.strip_prefix('#') {
            let code: u16 = code.parse().context("invalid static-host response code")?;
            ensure!(code <= 0xfff, "static-host response code exceeds 4095");
            return Ok(vec![HostResponse::ResponseCode(code)]);
        }
        wire::fqdn(value).context("invalid DNS host alias")?;
        return Ok(vec![HostResponse::Alias(value.clone())]);
    }
    Ok(ips)
}

fn normalize_domain(domain: &str) -> dns::Result<&str> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() {
        return Err(DnsError::InvalidName(domain.into()));
    }
    Ok(domain)
}

impl CompiledDns {
    /// Select original indices in source order, with matched servers first.
    /// `finalQuery` truncates the list even if that server subsequently fails.
    /// If no server survives the fallback policy, the first configured server
    /// is used, including when its `skipFallback` is true.
    pub fn select_servers(&self, domain: &str) -> dns::Result<Vec<usize>> {
        Ok(self.select_servers_inner(normalize_domain(domain)?))
    }

    fn select_servers_inner(&self, domain: &str) -> Vec<usize> {
        let mut used = vec![false; self.servers.len()];
        let mut result = Vec::new();
        for server in &self.servers {
            if server.matches_domain(domain) {
                used[server.index] = true;
                result.push(server.index);
                if server.final_query {
                    return result;
                }
            }
        }
        if !(self.disable_fallback || self.disable_fallback_if_match && !result.is_empty()) {
            for server in &self.servers {
                if !used[server.index] && !server.skip_fallback {
                    result.push(server.index);
                    if server.final_query {
                        return result;
                    }
                }
            }
        }
        if result.is_empty() && !self.servers.is_empty() {
            result.push(0);
        }
        result
    }

    /// Resolve host rules and aliases without contacting a nameserver.
    pub fn lookup_hosts(&self, name: &str, options: QueryOptions) -> dns::Result<HostLookup> {
        let options = intersect(options, self.query_options);
        if !has_family(options) {
            return Err(DnsError::EmptyResponse);
        }
        self.lookup_hosts_inner(normalize_domain(name)?, options, 5)
    }

    fn lookup_hosts_inner(
        &self,
        name: &str,
        options: QueryOptions,
        depth: usize,
    ) -> dns::Result<HostLookup> {
        let Some(matcher) = &self.hosts else {
            return Ok(HostLookup::NotFound);
        };
        let indices = matcher.matching_rules(&name.to_lowercase());
        if indices.is_empty() {
            return Ok(HostLookup::NotFound);
        }
        let mut values = Vec::new();
        for index in indices {
            for value in &self.host_responses[index as usize] {
                if let HostResponse::ResponseCode(code) = value {
                    return Err(if *code == 0 {
                        DnsError::EmptyResponse
                    } else {
                        DnsError::ResponseCode(*code)
                    });
                }
                values.push(value);
            }
        }
        if let [HostResponse::Alias(alias)] = values.as_slice() {
            if depth > 0 {
                let result = self.lookup_hosts_inner(alias, options, depth - 1)?;
                if result != HostLookup::NotFound {
                    return Ok(result);
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
                        Some(*ip)
                    }
                    _ => None,
                })
                .collect(),
        ))
    }

    /// Execute source serial fallback across independently configured clients.
    /// Unlike a single classic Resolver's internal fallback, every error here
    /// (including NXDOMAIN/NODATA) permits trying the next selected client.
    pub async fn lookup_with<Q: ServerQuery + ?Sized>(
        &self,
        name: &str,
        requested: QueryOptions,
        query: &Q,
    ) -> dns::Result<LookupResult> {
        let mut name = normalize_domain(name)?.to_owned();
        let options = intersect(requested, self.query_options);
        if !has_family(options) {
            return Err(DnsError::EmptyResponse);
        }
        match self.lookup_hosts_inner(&name, options, 5)? {
            HostLookup::NotFound => {}
            HostLookup::Alias(alias) => name = alias,
            HostLookup::Addresses(ips) if ips.is_empty() => return Err(DnsError::EmptyResponse),
            HostLookup::Addresses(ips) => return Ok(LookupResult { ips, ttl: 10 }),
        }
        let mut errors = Vec::new();
        // Source trims the original query once, before static-host rewriting;
        // an alias's trailing dot remains visible to nameserver domain rules.
        for index in self.select_servers_inner(&name) {
            let server = &self.servers[index];
            let options = intersect(options, server.query_options);
            if !has_family(options) {
                errors.push(DnsError::EmptyResponse);
                continue;
            }
            let result =
                tokio::time::timeout(server.timeout, query.query(server, &name, options)).await;
            let result = match result {
                Ok(Ok(mut answer)) => {
                    answer.ips.retain(|ip| {
                        (ip.is_ipv4() && options.ipv4) || (ip.is_ipv6() && options.ipv6)
                    });
                    server.filter_answer(answer)
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(DnsError::Timeout),
            };
            match result {
                Ok(answer) => return Ok(answer),
                Err(error) => errors.push(error),
            }
        }
        Err(merge_errors(errors))
    }
}

fn merge_errors(mut errors: Vec<DnsError>) -> DnsError {
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
    DnsError::AllServersFailed(errors.into_iter().map(|error| error.to_string()).collect())
}

pub type QueryFuture<'a> = Pin<Box<dyn Future<Output = dns::Result<LookupResult>> + Send + 'a>>;

/// Runtime hook: dispatch to the server at `index`, honoring its tag/mode,
/// effective cache settings, client IP, query families and timeout budget.
/// Implementations may wrap native `Resolver` and `EncryptedClient`; the latter
/// additionally needs explicit bootstrap/routing and cache integration.
/// Returning an error participates in the source-compatible fallback policy.
pub trait ServerQuery: Send + Sync {
    fn query<'a>(
        &'a self,
        server: &'a CompiledServer,
        name: &'a str,
        options: QueryOptions,
    ) -> QueryFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{RecordType, Resolver};
    use std::sync::Mutex;

    fn config(value: serde_json::Value) -> DnsConfig {
        serde_json::from_value(value).unwrap()
    }
    fn compile(value: serde_json::Value) -> CompiledDns {
        config(value).compile(&GeoDataStore::new(".")).unwrap()
    }
    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
    fn answer(values: &[&str]) -> LookupResult {
        LookupResult {
            ips: values.iter().map(|value| ip(value)).collect(),
            ttl: 60,
        }
    }

    #[test]
    fn string_and_object_servers_inherit_effective_settings() {
        let plan = compile(
            serde_json::json!({"tag":"dns-tag", "queryStrategy":"UseIPv4", "clientIp":"203.0.113.9", "disableCache":true, "serveStale":true, "serveExpiredTTL":23, "servers":["192.0.2.1", {"address":"192.0.2.2","port":5353,"tag":"special","timeoutMs":90,"disableCache":false,"serveStale":false,"serveExpiredTTL":4,"clientIp":"198.51.100.9"}]}),
        );
        assert_eq!(plan.servers[0].query_options, QueryOptions::IPV4);
        assert_eq!(plan.servers[0].timeout, Duration::from_secs(4));
        assert_eq!(plan.servers[0].tag, "dns-tag");
        assert_eq!(plan.servers[0].client_ip, Some(ip("203.0.113.9")));
        assert!(!plan.servers[0].cache.enabled);
        assert!(plan.servers[0].cache.serve_stale);
        let second = &plan.servers[1];
        assert_eq!(second.tag, "special");
        assert_eq!(second.timeout, Duration::from_millis(90));
        assert!(second.cache.enabled);
        assert!(!second.cache.serve_stale);
        assert_eq!(second.cache.max_stale, Duration::from_secs(4));
        let native = second.classic_resolver_config().unwrap();
        assert_eq!(native.servers[0].address, "192.0.2.2:5353".parse().unwrap());
        assert_eq!(native.client_ip, Some(ip("198.51.100.9")));
    }

    #[test]
    fn strategy_aliases_intersect_and_conflicts_fail() {
        for value in ["UseIp4", "useipv4", "use_ip_v4", "use-ip-v4"] {
            assert_eq!(parse_query_strategy(value).unwrap(), QueryOptions::IPV4);
        }
        for value in ["UseIp6", "useipv6", "use_ip_v6", "use-ip-v6"] {
            assert_eq!(parse_query_strategy(value).unwrap(), QueryOptions::IPV6);
        }
        for value in ["UseSystem", "typo", " UseIP "] {
            assert!(parse_query_strategy(value).is_err());
        }
        assert!(config(serde_json::json!({"queryStrategy":"UseIPv4","servers":[{"address":"192.0.2.1","queryStrategy":"UseIPv6"}]})).compile(&GeoDataStore::new(".")).is_err());
    }

    #[test]
    fn selection_prioritizes_domain_matches_in_source_order() {
        let plan = compile(
            serde_json::json!({"servers":["192.0.2.1", {"address":"192.0.2.2","domains":["domain:example.com","full:example.com"]},{"address":"192.0.2.3","domains":"keyword:example","skipFallback":true}]}),
        );
        assert_eq!(plan.select_servers("EXAMPLE.COM.").unwrap(), [1, 2, 0]);
        assert_eq!(plan.select_servers("unrelated.test").unwrap(), [0, 1]);
    }

    #[test]
    fn fallback_flags_and_final_query_preserve_first_server_escape() {
        let plan = compile(
            serde_json::json!({"disableFallbackIfMatch":true,"servers":["192.0.2.1", {"address":"192.0.2.2","domains":["domain:example.com"]}]}),
        );
        assert_eq!(plan.select_servers("example.com").unwrap(), [1]);
        assert_eq!(plan.select_servers("other.test").unwrap(), [0, 1]);
        let plan = compile(
            serde_json::json!({"disableFallback":true,"servers":[{"address":"192.0.2.1","skipFallback":true}, {"address":"192.0.2.2","domains":"full:match.test","finalQuery":true},{"address":"192.0.2.3","domains":"full:match.test"}]}),
        );
        assert_eq!(plan.select_servers("match.test").unwrap(), [1]);
        assert_eq!(plan.select_servers("other.test").unwrap(), [0]);
        let plan = compile(
            serde_json::json!({"servers":[{"address":"192.0.2.1","finalQuery":true},"192.0.2.2"]}),
        );
        assert_eq!(plan.select_servers("other.test").unwrap(), [0]);
    }

    #[test]
    fn expected_unexpected_filters_and_star_preferences_follow_source_order() {
        let strict = compile(
            serde_json::json!({"servers":[{"address":"192.0.2.1","expectIPs":["10.0.0.0/8"],"unexpectedIPs":["10.1.0.0/16"]}]}),
        );
        assert_eq!(
            strict.servers[0]
                .filter_answer(answer(&["10.1.2.3", "10.2.3.4", "192.0.2.8"]))
                .unwrap()
                .ips,
            [ip("10.2.3.4")]
        );
        assert!(matches!(
            strict.servers[0].filter_answer(answer(&["192.0.2.8"])),
            Err(DnsError::EmptyResponse)
        ));
        let preferred = compile(
            serde_json::json!({"servers":[{"address":"192.0.2.1","expectedIPs":["*","10.0.0.0/8"],"unexpectedIPs":["*","10.1.0.0/16"]}]}),
        );
        assert_eq!(
            preferred.servers[0]
                .filter_answer(answer(&["192.0.2.8"]))
                .unwrap()
                .ips,
            [ip("192.0.2.8")]
        );
        assert_eq!(
            preferred.servers[0]
                .filter_answer(answer(&["10.1.2.3", "10.2.3.4", "192.0.2.8"]))
                .unwrap()
                .ips,
            [ip("10.2.3.4")]
        );
        assert_eq!(
            preferred.servers[0]
                .filter_answer(answer(&["10.1.2.3"]))
                .unwrap()
                .ips,
            [ip("10.1.2.3")]
        );
        let priority = compile(
            serde_json::json!({"servers":[{"address":"192.0.2.1","expectedIPs":"192.0.2.0/24","expectIPs":"10.0.0.0/8"}]}),
        );
        assert!(
            priority.servers[0]
                .filter_answer(answer(&["10.1.2.3"]))
                .is_err()
        );
    }

    #[test]
    fn hosts_support_rule_types_aliases_empty_lists_and_response_codes() {
        let plan = compile(
            serde_json::json!({"servers":["192.0.2.1"],"hosts":{"exact.test":["192.0.2.8","2001:db8::8"],"domain:internal.test":"198.51.100.8","alias.test":"exact.test","mixed.test":["203.0.113.8","exact.test"],"external.test":"unmapped.test","empty.test":[],"nx.test":"#3","zero.test":"#0","keyword:needle":"192.0.2.9"}}),
        );
        assert_eq!(
            plan.lookup_hosts("EXACT.TEST.", QueryOptions::IPV4)
                .unwrap(),
            HostLookup::Addresses(vec![ip("192.0.2.8")])
        );
        assert_eq!(
            plan.lookup_hosts("sub.exact.test", QueryOptions::BOTH)
                .unwrap(),
            HostLookup::NotFound
        );
        assert_eq!(
            plan.lookup_hosts("sub.internal.test", QueryOptions::BOTH)
                .unwrap(),
            HostLookup::Addresses(vec![ip("198.51.100.8")])
        );
        assert_eq!(
            plan.lookup_hosts("mixed.test", QueryOptions::IPV6).unwrap(),
            HostLookup::Addresses(vec![ip("2001:db8::8")])
        );
        assert_eq!(
            plan.lookup_hosts("external.test", QueryOptions::BOTH)
                .unwrap(),
            HostLookup::Alias("unmapped.test".into())
        );
        assert_eq!(
            plan.lookup_hosts("empty.test", QueryOptions::BOTH).unwrap(),
            HostLookup::Addresses(vec![])
        );
        assert!(matches!(
            plan.lookup_hosts("nx.test", QueryOptions::BOTH),
            Err(DnsError::ResponseCode(3))
        ));
        assert!(matches!(
            plan.lookup_hosts("zero.test", QueryOptions::BOTH),
            Err(DnsError::EmptyResponse)
        ));
        assert_eq!(
            plan.lookup_hosts("a-needle-b.test", QueryOptions::BOTH)
                .unwrap(),
            HostLookup::Addresses(vec![ip("192.0.2.9")])
        );
    }

    #[test]
    fn host_alias_cycle_stops_at_source_five_hop_bound() {
        let plan = compile(
            serde_json::json!({"servers":["192.0.2.1"],"hosts":{"a.test":"b.test","b.test":"a.test"}}),
        );
        assert!(matches!(
            plan.lookup_hosts("a.test", QueryOptions::BOTH).unwrap(),
            HostLookup::Alias(_)
        ));
    }

    #[test]
    fn encrypted_and_classic_adapters_preserve_modes_and_policy() {
        let plan = compile(
            serde_json::json!({"clientIp":"203.0.113.8","servers":["tcp://192.0.2.1:5353","tcp+local://[2001:db8::1]:53","https://dns.example/dns-query","https+local://192.0.2.3/dns-query","tls+local://192.0.2.4"]}),
        );
        assert_eq!(plan.servers[0].endpoint.mode(), DialMode::Routed);
        assert_eq!(plan.servers[1].endpoint.mode(), DialMode::Local);
        assert_eq!(plan.servers[2].endpoint.mode(), DialMode::Routed);
        assert_eq!(plan.servers[3].endpoint.mode(), DialMode::Local);
        let transport = plan.servers[2].encrypted_client_config().unwrap();
        assert_eq!(transport.endpoint.host(), "dns.example");
        assert_eq!(transport.endpoint.port(), 443);
        assert_eq!(transport.client_ip, Some(ip("203.0.113.8")));
        assert_eq!(transport.timeout, Duration::from_secs(4));
        assert!(plan.servers[2].classic_resolver_config().is_none());
        assert!(plan.servers[0].encrypted_client_config().is_none());
    }

    #[test]
    fn unsupported_features_and_unknown_json_keys_fail_explicitly() {
        for address in [
            "localhost",
            "fakedns",
            "h2c://192.0.2.1",
            "quic+local://192.0.2.1",
            "resolver.example",
            "tcp://resolver.example",
        ] {
            assert!(
                config(serde_json::json!({"servers":[address]}))
                    .compile(&GeoDataStore::new("."))
                    .is_err(),
                "{address}"
            );
        }
        for value in [
            serde_json::json!({"servers":[]}),
            serde_json::json!({"servers":["192.0.2.1"],"enableParallelQuery":true}),
            serde_json::json!({"servers":["192.0.2.1"],"useSystemHosts":true}),
            serde_json::json!({"servers":[{"address":"https://192.0.2.1/dns-query","port":53}]}),
        ] {
            assert!(config(value).compile(&GeoDataStore::new(".")).is_err());
        }
        assert!(serde_json::from_value::<DnsConfig>(serde_json::json!({"servres":[]})).is_err());
        assert!(
            serde_json::from_value::<DnsConfig>(
                serde_json::json!({"servers":[{"address":"192.0.2.1","skipFallbak":true}]})
            )
            .is_err()
        );
    }

    struct Scripted {
        calls: Mutex<Vec<(usize, String, QueryOptions)>>,
    }
    impl ServerQuery for Scripted {
        fn query<'a>(
            &'a self,
            server: &'a CompiledServer,
            name: &'a str,
            options: QueryOptions,
        ) -> QueryFuture<'a> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push((server.index, name.into(), options));
                match server.index {
                    0 => Err(DnsError::ResponseCode(3)),
                    1 => Ok(answer(&["192.0.2.9"])),
                    _ => Ok(answer(&["10.1.2.3"])),
                }
            })
        }
    }

    #[tokio::test]
    async fn serial_lookup_retries_nxdomain_and_filtered_answers() {
        let plan = compile(
            serde_json::json!({"queryStrategy":"UseIPv4","servers":["192.0.2.1",{"address":"192.0.2.2","expectedIPs":"10.0.0.0/8"},"192.0.2.3"]}),
        );
        let query = Scripted {
            calls: Mutex::new(vec![]),
        };
        assert_eq!(
            plan.lookup_with("target.test.", QueryOptions::BOTH, &query)
                .await
                .unwrap()
                .ips,
            [ip("10.1.2.3")]
        );
        let calls = query.calls.lock().unwrap();
        assert_eq!(
            calls.iter().map(|call| call.0).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert!(
            calls
                .iter()
                .all(|call| call.1 == "target.test" && call.2 == QueryOptions::IPV4)
        );
    }

    #[tokio::test]
    async fn aliased_fqdn_keeps_its_trailing_dot_for_server_rule_selection() {
        let plan = compile(
            serde_json::json!({"servers":["192.0.2.1",{"address":"192.0.2.2","domains":"full:priority.test"}],"hosts":{"alias.test":"priority.test."}}),
        );
        let query = Scripted {
            calls: Mutex::new(vec![]),
        };
        plan.lookup_with("alias.test", QueryOptions::IPV4, &query)
            .await
            .unwrap();
        let calls = query.calls.lock().unwrap();
        assert_eq!(calls.iter().map(|call| call.0).collect::<Vec<_>>(), [0, 1]);
        assert!(calls.iter().all(|call| call.1 == "priority.test."));
    }

    #[tokio::test]
    async fn static_hosts_use_ttl_ten_and_never_fallback_on_empty() {
        let plan = compile(
            serde_json::json!({"servers":["192.0.2.1"],"hosts":{"host.test":"192.0.2.8","empty.test":[]}}),
        );
        let query = Scripted {
            calls: Mutex::new(vec![]),
        };
        let answer = plan
            .lookup_with("host.test", QueryOptions::IPV4, &query)
            .await
            .unwrap();
        assert_eq!(answer.ttl, 10);
        assert!(matches!(
            plan.lookup_with("host.test", QueryOptions::IPV6, &query)
                .await,
            Err(DnsError::EmptyResponse)
        ));
        assert!(matches!(
            plan.lookup_with("empty.test", QueryOptions::BOTH, &query)
                .await,
            Err(DnsError::EmptyResponse)
        ));
        assert!(query.calls.lock().unwrap().is_empty());
    }

    struct ResolverBackend {
        clients: Vec<Resolver>,
    }
    impl ServerQuery for ResolverBackend {
        fn query<'a>(
            &'a self,
            server: &'a CompiledServer,
            name: &'a str,
            options: QueryOptions,
        ) -> QueryFuture<'a> {
            Box::pin(self.clients[server.index].lookup_ip(name, options))
        }
    }

    #[tokio::test]
    async fn real_local_udp_resolvers_follow_dns_config_fallback_and_cache() {
        use tokio::net::UdpSocket;
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ports = [
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
        ];
        let serve = |socket: UdpSocket, code: u16| {
            tokio::spawn(async move {
                let mut bytes = [0_u8; 2048];
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request = wire::decode(&bytes[..length]).unwrap();
                let question = request.questions[0].clone();
                assert_eq!(question.record_type, RecordType::A);
                let response = wire::encode_response(
                    request.header.id,
                    &question,
                    &[ip("198.51.100.7")],
                    35,
                    code,
                    None,
                    512,
                )
                .unwrap();
                socket.send_to(&response, peer).await.unwrap();
            })
        };
        let tasks = [serve(first, 3), serve(second, 0)];
        let plan = compile(
            serde_json::json!({"queryStrategy":"UseIPv4","servers":[{"address":"127.0.0.1","port":ports[0]},{"address":"127.0.0.1","port":ports[1]}]}),
        );
        // Explicit direct loopback backend for this local transport integration
        // test. Production routed dispatch must be supplied by the parent.
        let query = ResolverBackend {
            clients: plan
                .servers
                .iter()
                .map(|server| Resolver::new(server.classic_resolver_config().unwrap()).unwrap())
                .collect(),
        };
        let resolved = plan
            .lookup_with("fixture.test", QueryOptions::BOTH, &query)
            .await
            .unwrap();
        assert_eq!(resolved.ips, [ip("198.51.100.7")]);
        for task in tasks {
            task.await.unwrap();
        }
        let cached = plan
            .lookup_with("fixture.test", QueryOptions::BOTH, &query)
            .await
            .unwrap();
        assert_eq!(cached.ips, resolved.ips);
        assert_eq!(query.clients[0].cache_len(), 1);
        assert_eq!(query.clients[1].cache_len(), 1);
    }
}
