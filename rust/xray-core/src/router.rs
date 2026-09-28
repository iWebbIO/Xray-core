use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
pub mod balancer;
pub mod balancer_strategies;

use anyhow::{Context, Result, ensure};
use rand::Rng;
use serde::{Deserialize, Serialize};

use self::balancer::{Balancer, BalancerConfig, Observation, ObservationResult, Strategy};
use crate::{
    address::{Address, Destination},
    config::OutboundConfig,
    geodata::{DomainMatcher, GeoDataStore, IpMatcher, domain},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingConfig {
    pub domain_strategy: String,
    pub rules: Vec<RuleConfig>,
    /// `routing.balancers` (Go's `RouterConfig.Balancers` /
    /// app/router `BalancingRule`): health-aware outbound groups referenced
    /// by rules through [`RuleConfig::balancer_tag`]. Each element parses
    /// through [`balancer::BalancerConfig::from_json`], mirroring Go's
    /// ordinary JSON decoder for the balancer object: keys match
    /// ASCII-case-insensitively and unknown keys inside one balancer are
    /// ignored, while the surrounding routing object keeps rejecting
    /// unknown fields.
    #[serde(
        deserialize_with = "balancers_from_json",
        serialize_with = "balancers_to_json"
    )]
    pub balancers: Vec<BalancerConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleConfig {
    pub r#type: String,
    pub rule_tag: String,
    pub outbound_tag: String,
    /// Go's `balancerTag`: the rule's target is a `balancers` entry,
    /// resolved through its [`balancer::Balancer`] at dispatch time
    /// (app/router's `Rule.Balancer`). A rule sets either `outboundTag` or
    /// `balancerTag`, never both.
    pub balancer_tag: String,
    #[serde(deserialize_with = "strings")]
    pub domain: Vec<String>,
    #[serde(deserialize_with = "strings")]
    pub ip: Vec<String>,
    pub port: Option<PortSpec>,
    pub network: String,
    #[serde(deserialize_with = "strings")]
    pub inbound_tag: Vec<String>,
    #[serde(deserialize_with = "strings")]
    pub source: Vec<String>,
    #[serde(rename = "sourceIP", deserialize_with = "strings")]
    pub source_ip: Vec<String>,
    pub source_port: Option<PortSpec>,
    #[serde(deserialize_with = "strings")]
    pub user: Vec<String>,
    /// Routing by the connection's sniffed protocol (Go's `protocol` rule
    /// field, matched by app/router's ProtocolMatcher): "http", "tls",
    /// "quic" or "bittorrent". The sniffed protocol is threaded in through
    /// [`Router::select_with_route_sniffed`]; a rule with this condition
    /// matches only when the connection's sniffed protocol is set.
    #[serde(deserialize_with = "strings")]
    pub protocol: Vec<String>,
}

pub(crate) fn strings<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Values {
        Single(String),
        Multiple(Vec<String>),
    }
    Ok(match Values::deserialize(d)? {
        Values::Single(s) => vec![s],
        Values::Multiple(v) => v,
    })
}

/// One `routing.balancers` element keeps Go's ordinary-decoder leniency
/// (case-insensitive keys, unknown keys ignored), so it parses through
/// [`balancer::BalancerConfig::from_json`] instead of a strict struct.
fn balancers_from_json<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<BalancerConfig>, D::Error> {
    let values = Vec::<serde_json::Value>::deserialize(d)?;
    values
        .iter()
        .map(BalancerConfig::from_json)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| serde::de::Error::custom(error.to_string()))
}

/// Serializes back into the same JSON keys `from_json` reads (Go's
/// `BalancingRule` field names), keeping the protobuf-projection round trip
/// exact.
fn balancers_to_json<S: serde::Serializer>(
    balancers: &[BalancerConfig],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    let values: Vec<serde_json::Value> = balancers.iter().map(balancer_to_value).collect();
    values.serialize(serializer)
}

fn balancer_to_value(balancer: &BalancerConfig) -> serde_json::Value {
    let strategy = match &balancer.strategy {
        Strategy::Random => serde_json::json!({"type": "random"}),
        Strategy::RoundRobin => serde_json::json!({"type": "roundrobin"}),
        Strategy::LeastPing => serde_json::json!({"type": "leastping"}),
        Strategy::LeastLoad(settings) => serde_json::json!({
            "type": "leastload",
            "settings": {
                "expected": settings.expected,
                "tolerance": f64::from(settings.tolerance),
                "maxRTT": duration_string(settings.max_rtt),
                "baselines": settings
                    .baselines
                    .iter()
                    .map(|value| duration_string(*value))
                    .collect::<Vec<_>>(),
                "costs": settings
                    .costs
                    .iter()
                    .map(|cost| {
                        serde_json::json!({
                            "match": cost.r#match,
                            "regexp": cost.regexp,
                            "value": f64::from(cost.value),
                        })
                    })
                    .collect::<Vec<_>>(),
            },
        }),
    };
    serde_json::json!({
        "tag": balancer.tag,
        "selector": balancer.selectors,
        "strategy": strategy,
        "fallbackTag": balancer.fallback_tag,
    })
}

/// Formats a nanosecond duration the way [`balancer::parse_duration`] reads
/// it back: whole hours/minutes, then seconds with a fraction trimmed of
/// trailing zeros (Go duration strings such as `1h2m3.4s`, `1m30s`,
/// `0.4s`). Zero serializes as `0s`, which parses back to zero.
fn duration_string(nanoseconds: i64) -> String {
    if nanoseconds == 0 {
        return "0s".to_owned();
    }
    let negative = nanoseconds < 0;
    let total = nanoseconds.unsigned_abs();
    let hours = total / 3_600_000_000_000;
    let minutes = (total % 3_600_000_000_000) / 60_000_000_000;
    let seconds = (total % 60_000_000_000) / 1_000_000_000;
    let fraction = total % 1_000_000_000;
    let mut text = String::new();
    if negative {
        text.push('-');
    }
    if hours > 0 {
        text.push_str(&hours.to_string());
        text.push('h');
    }
    if minutes > 0 {
        text.push_str(&minutes.to_string());
        text.push('m');
    }
    if seconds > 0 || fraction > 0 || text.ends_with('-') {
        text.push_str(&seconds.to_string());
        if fraction > 0 {
            let digits = format!("{fraction:09}");
            text.push('.');
            text.push_str(digits.trim_end_matches('0'));
        }
        text.push('s');
    }
    text
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PortSpec {
    Number(u16),
    List(String),
}

#[derive(Clone, Debug)]
pub(crate) struct Ports(Vec<(u16, u16)>);

impl Ports {
    pub(crate) fn compile(spec: &Option<PortSpec>) -> Result<Self> {
        let mut ranges = Vec::new();
        match spec {
            None => (),
            Some(PortSpec::Number(port)) => ranges.push((*port, *port)),
            Some(PortSpec::List(list)) => {
                ensure!(!list.is_empty(), "port list cannot be empty");
                for item in list.split(',') {
                    let (start, end) = match item.trim().split_once('-') {
                        Some((start, end)) => (start.parse::<u16>()?, end.parse::<u16>()?),
                        None => {
                            let port = item.trim().parse::<u16>()?;
                            (port, port)
                        }
                    };
                    ensure!(start <= end, "reversed port range");
                    ranges.push((start, end));
                }
            }
        }
        Ok(Self(ranges))
    }
    pub(crate) fn matches(&self, port: u16) -> bool {
        self.0.is_empty() || self.0.iter().any(|(a, b)| (*a..=*b).contains(&port))
    }
}

#[derive(Debug)]
struct Rule {
    /// Outbound index for `outboundTag` rules; unused (0) for balancer rules.
    outbound: usize,
    /// The balancer a `balancerTag` rule resolves through at dispatch time
    /// (Go's `Rule.Balancer`); `None` for `outboundTag` rules.
    balancer: Option<Arc<Balancer>>,
    domains: Option<DomainMatcher>,
    ips: Option<IpMatcher>,
    ports: Ports,
    networks: Vec<String>,
    inbounds: Vec<String>,
    sources: Option<IpMatcher>,
    source_ports: Ports,
    users: Vec<String>,
    /// Sniffed protocol names from the rule's `protocol` field.
    protocols: Vec<String>,
}

pub struct RouteContext<'a> {
    pub destination: &'a Destination,
    pub source: SocketAddr,
    pub inbound_tag: &'a str,
    pub user: &'a str,
    pub network: &'a str,
}

/// Synchronous health snapshot source for balancer strategies, consumed at
/// dispatch time (Go: each strategy's `extension.Observatory` +
/// `GetObservation` per pick). The ordinary and burst observers both
/// implement it through their `snapshot` methods, which return only
/// completed measurements; an empty report keeps every strategy on its
/// documented missing-report behavior. The async gRPC
/// [`crate::api::observatory::ObservationProvider`] cannot serve the
/// synchronous select flow, so the runtime attaches this instead.
pub trait BalancerObservations: Send + Sync + 'static {
    fn observation_result(&self) -> ObservationResult;
}

impl BalancerObservations for crate::features::observatory::Observer {
    fn observation_result(&self) -> ObservationResult {
        self.snapshot()
    }
}

impl BalancerObservations for crate::features::observatory_burst::BurstObserver {
    fn observation_result(&self) -> ObservationResult {
        self.snapshot()
    }
}

pub struct Router {
    rules: Vec<Rule>,
    /// Routing outbound tags in routing order: the registry balancer
    /// candidates draw from (Go's `outbound.Manager` handler tags —
    /// configured outbounds plus the API and reverse-portal entries).
    tags: Vec<String>,
    /// Tag-to-index resolution for the outbound a balancer picks.
    indexes: HashMap<String, usize>,
    /// Compiled `routing.balancers` in configuration order.
    balancers: Vec<(String, Arc<Balancer>)>,
    /// Health snapshot source attached after compilation; `None` keeps
    /// every strategy on its documented fail-open behavior.
    observations: RwLock<Option<Arc<dyn BalancerObservations>>>,
}

impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("rules", &self.rules)
            .field("balancers", &self.balancers)
            .finish_non_exhaustive()
    }
}

impl Router {
    pub fn compile(config: &RoutingConfig, outbounds: &[OutboundConfig]) -> Result<Self> {
        Self::compile_with_store(config, outbounds, &GeoDataStore::from_env()?)
    }

    /// Compile with an explicitly located asset store. The resulting matchers
    /// own their data, so routing performs neither filesystem IO nor DNS.
    /// Recompile to apply changed data files; these are immutable snapshots.
    pub fn compile_with_store(
        config: &RoutingConfig,
        outbounds: &[OutboundConfig],
        store: &GeoDataStore,
    ) -> Result<Self> {
        ensure!(
            matches!(config.domain_strategy.to_lowercase().as_str(), "" | "asis"),
            "DNS routing strategies are not migrated yet"
        );
        let tags: Vec<String> = outbounds
            .iter()
            .map(|outbound| outbound.tag.clone())
            .collect();
        let indexes: HashMap<String, usize> = tags
            .iter()
            .enumerate()
            .map(|(index, tag)| (tag.clone(), index))
            .collect();
        // Balancers compile before rules: a rule's balancerTag resolves
        // through them (app/router ReloadRules builds the balancer map
        // first). Duplicate tags fail with Go's text.
        let mut balancers: Vec<(String, Arc<Balancer>)> = Vec::new();
        for raw in &config.balancers {
            ensure!(
                balancers.iter().all(|(tag, _)| tag != &raw.tag),
                "duplicate balancer tag"
            );
            // Go resolves a balancing fallbackTag's handler at dispatch and
            // closes the connection when the tag has no outbound ("DO NOT
            // CHANGE" in routedDispatch). The select flow returns an
            // outbound index, so an unresolvable fallbackTag is rejected
            // explicitly instead of silently rerouted; the runtime's
            // outbound set is fixed (runtime-adding outbounds is not
            // supported), so the tag can never appear later.
            ensure!(
                raw.fallback_tag.is_empty() || indexes.contains_key(&raw.fallback_tag),
                "balancer {:?} fallbackTag {:?} is not a configured outbound tag",
                raw.tag,
                raw.fallback_tag
            );
            let balancer = Balancer::new(raw.clone())?;
            balancers.push((raw.tag.clone(), Arc::new(balancer)));
        }
        let mut rules = Vec::new();
        for (index, raw) in config.rules.iter().enumerate() {
            ensure!(
                matches!(raw.r#type.as_str(), "" | "field"),
                "unsupported routing rule type"
            );
            let (outbound, balancer) = if raw.outbound_tag.is_empty() {
                ensure!(
                    !raw.balancer_tag.is_empty(),
                    "neither outboundTag nor balancerTag is specified in routing rule"
                );
                let balancer = balancers
                    .iter()
                    .find(|(tag, _)| *tag == raw.balancer_tag)
                    .map(|(_, balancer)| Arc::clone(balancer))
                    .with_context(|| format!("balancer {} not found", raw.balancer_tag))?;
                (0, Some(balancer))
            } else {
                ensure!(
                    raw.balancer_tag.is_empty(),
                    "routing rule cannot set both outboundTag and balancerTag"
                );
                let outbound = outbounds
                    .iter()
                    .position(|o| o.tag == raw.outbound_tag)
                    .with_context(|| format!("unknown outbound tag {:?}", raw.outbound_tag))?;
                (outbound, None)
            };
            let source = if raw.source_ip.is_empty() {
                &raw.source
            } else {
                &raw.source_ip
            };
            ensure!(
                !raw.domain.is_empty()
                    || !raw.ip.is_empty()
                    || raw.port.is_some()
                    || !raw.network.is_empty()
                    || !raw.inbound_tag.is_empty()
                    || !source.is_empty()
                    || raw.source_port.is_some()
                    || !raw.user.is_empty()
                    || !raw.protocol.is_empty(),
                "routing rule has no matching conditions"
            );
            for protocol in &raw.protocol {
                ensure!(
                    matches!(protocol.as_str(), "http" | "tls" | "quic" | "bittorrent"),
                    "unknown routing rule protocol {protocol:?}"
                );
            }
            let networks = if raw.network.is_empty() {
                vec![]
            } else {
                raw.network
                    .split(',')
                    .map(|v| v.trim().to_owned())
                    .collect::<Vec<_>>()
            };
            ensure!(
                networks.iter().all(|n| n == "tcp" || n == "udp"),
                "unknown routing network"
            );
            rules.push(Rule {
                outbound,
                balancer,
                domains: if raw.domain.is_empty() {
                    None
                } else {
                    Some(
                        store
                            .build_domain_matcher(
                                &store
                                    .parse_domain_rules(&raw.domain, domain::Type::Substr)
                                    .with_context(|| format!("routing rule {index} domain"))?,
                            )
                            .with_context(|| format!("routing rule {index} domain matcher"))?,
                    )
                },
                ips: ip_matcher(store, &raw.ip)
                    .with_context(|| format!("routing rule {index} IP matcher"))?,
                ports: Ports::compile(&raw.port)?,
                networks,
                inbounds: raw.inbound_tag.clone(),
                sources: ip_matcher(store, source)
                    .with_context(|| format!("routing rule {index} source IP matcher"))?,
                source_ports: Ports::compile(&raw.source_port)?,
                users: raw.user.clone(),
                protocols: raw.protocol.clone(),
            });
        }
        Ok(Self {
            rules,
            tags,
            indexes,
            balancers,
            observations: RwLock::new(None),
        })
    }

    pub fn select(&self, context: &RouteContext<'_>) -> usize {
        self.select_with_route(context).0
    }

    pub fn select_with_route(&self, context: &RouteContext<'_>) -> (usize, bool) {
        self.select_with_route_sniffed(context, None)
    }

    /// Selects with the connection's sniffed protocol threaded in (Go's
    /// `routing.Context.GetProtocol` + app/router's ProtocolMatcher).
    /// `None` keeps the pre-sniffing behavior: a rule with a `protocol`
    /// condition never matches (exactly Go, where an un-sniffed connection
    /// has an empty protocol). The sniffed protocol is one of
    /// "http1"/"http2", "tls", "quic" or "bittorrent"; rules match by Go's
    /// prefix semantics, so a `"http"` rule matches a sniffed `"http1"`.
    ///
    /// A matching `balancerTag` rule resolves its outbound through the
    /// balancer at selection time (Go's `Rule.GetTag` →
    /// `Balancer.PickOutbound`); the returned index is the balancer's chosen
    /// outbound, its `fallbackTag` outbound on balancing failure, or the
    /// default outbound when the balancer fails with no fallback — exactly
    /// Go's PickRoute error path, which routedDispatch serves from the
    /// default handler.
    pub fn select_with_route_sniffed(
        &self,
        context: &RouteContext<'_>,
        sniffed_protocol: Option<&str>,
    ) -> (usize, bool) {
        self.rules
            .iter()
            .find(|rule| rule.matches(context, sniffed_protocol))
            .map_or((0, false), |rule| self.target(rule))
    }

    /// Resolves a matched rule's target to an outbound index.
    fn target(&self, rule: &Rule) -> (usize, bool) {
        let Some(balancer) = rule.balancer.as_ref() else {
            return (rule.outbound, true);
        };
        let snapshot = self.observation_snapshot();
        let observation = match &snapshot {
            Some(result) => Observation::Ready(&result.status),
            None => Observation::Missing,
        };
        match balancer.pick(&self.tags, observation, |length| {
            rand::thread_rng().gen_range(0..length)
        }) {
            Ok(decision) => match self.indexes.get(&decision.tag) {
                Some(index) => (*index, true),
                // Candidates come from the compiled tag registry and the
                // fallbackTag is validated at compile time, so only a
                // management override (not wired) can name an unregistered
                // tag. Go closes such connections ("non existing outTag");
                // the index-only selection contract cannot express that, so
                // the connection degrades to the default outbound, loudly.
                None => {
                    tracing::warn!(
                        tag = %decision.tag,
                        "balancer picked an unregistered outbound tag; using the default outbound"
                    );
                    (0, false)
                }
            },
            // No fallbackTag and the strategy failed: Go's PickRoute error
            // path serves the default outbound ("default route for ...").
            Err(error) => {
                tracing::debug!(%error, "balancer selection failed; using the default outbound");
                (0, false)
            }
        }
    }

    /// The latest completed observation round, or `None` while no source is
    /// attached (Go's strategies hold a nil observatory until the feature
    /// injection succeeds).
    fn observation_snapshot(&self) -> Option<ObservationResult> {
        self.observations
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(|source| source.observation_result())
    }

    /// Attaches the health snapshot source after compilation. The Router is
    /// compiled inside `Config::compile`, before any observatory exists, and
    /// shared as `Arc<Router>`, so the runtime attaches its observatory
    /// through `&self` once built, e.g.
    /// `dispatcher.router.set_balancer_observations(source)`.
    pub fn set_balancer_observations(&self, source: Arc<dyn BalancerObservations>) {
        *self
            .observations
            .write()
            .unwrap_or_else(|error| error.into_inner()) = Some(source);
    }

    /// Construction-time form of [`Router::set_balancer_observations`] for
    /// callers that build the Router themselves.
    pub fn with_balancer_observations(self, source: Arc<dyn BalancerObservations>) -> Self {
        self.set_balancer_observations(source);
        self
    }

    /// Whether any balancer needs health reports (Go's RequireFeatures
    /// gate: `fallbackTag`, `leastPing` or `leastLoad`).
    pub fn balancers_require_observatory(&self) -> bool {
        self.balancers
            .iter()
            .any(|(_, balancer)| balancer.config().requires_observatory())
    }

    /// Go's `core.RequireFeatures(extension.Observatory)` for balancing:
    /// attaches the runtime's observer snapshot, failing when a balancer
    /// needs health reports but the configuration provides no observatory.
    /// The runtime calls this after building the observatory (ordinary or
    /// burst), passing `None` when neither is configured.
    pub fn attach_observatory(&self, source: Option<Arc<dyn BalancerObservations>>) -> Result<()> {
        if let Some(source) = source {
            self.set_balancer_observations(source);
            return Ok(());
        }
        let missing: Vec<&str> = self
            .balancers
            .iter()
            .filter(|(_, balancer)| balancer.config().requires_observatory())
            .map(|(tag, _)| tag.as_str())
            .collect();
        ensure!(
            missing.is_empty(),
            "balancer(s) {missing:?} require an observatory (fallbackTag, leastPing or leastLoad strategy) but none is configured"
        );
        Ok(())
    }
}

fn ip_matcher(store: &GeoDataStore, values: &[String]) -> Result<Option<IpMatcher>> {
    if values.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            store.build_ip_matcher(&store.parse_ip_rules(values)?)?,
        ))
    }
}

impl Rule {
    fn matches(&self, context: &RouteContext<'_>, sniffed_protocol: Option<&str>) -> bool {
        let domain_matches =
            self.domains
                .as_ref()
                .is_none_or(|matcher| match &context.destination.address {
                    Address::Domain(host) => !host.is_empty() && matcher.match_host(host),
                    _ => false,
                });
        let ip_matches =
            self.ips
                .as_ref()
                .is_none_or(|matcher| match context.destination.address {
                    Address::Ip(ip) => matcher.match_ip(ip),
                    _ => false,
                });
        // Go's ProtocolMatcher: the sniffed protocol must be set and have a
        // rule entry as a prefix ("http" matches "http1"/"http2").
        let protocol_matches = self.protocols.is_empty()
            || sniffed_protocol.is_some_and(|sniffed| {
                self.protocols
                    .iter()
                    .any(|protocol| sniffed.starts_with(protocol))
            });
        domain_matches
            && ip_matches
            && self.ports.matches(context.destination.port)
            && (self.networks.is_empty() || self.networks.iter().any(|n| n == context.network))
            && (self.inbounds.is_empty() || self.inbounds.iter().any(|n| n == context.inbound_tag))
            && self
                .sources
                .as_ref()
                .is_none_or(|matcher| matcher.match_ip(context.source.ip()))
            && self.source_ports.matches(context.source.port())
            && (self.users.is_empty() || self.users.iter().any(|n| n == context.user))
            && protocol_matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::{fs, path::PathBuf};

    struct Assets(PathBuf);

    impl Assets {
        fn new() -> Self {
            let directory =
                std::env::temp_dir().join(format!("xray-router-geodata-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            // Reuse independently encoded protobuf fixtures, not data generated
            // by the matcher under test. Each route reads real on-disk assets.
            let ips = decode_hex(include_str!("geodata/fixtures/geoip.hex"));
            let sites = decode_hex(include_str!("geodata/fixtures/geosite.hex"));
            for (name, bytes) in [
                ("geoip.dat", &ips),
                ("custom-ip.dat", &ips),
                ("geosite.dat", &sites),
                ("custom-site.dat", &sites),
            ] {
                fs::write(directory.join(name), bytes).unwrap();
            }
            Self(directory)
        }

        fn store(&self) -> GeoDataStore {
            GeoDataStore::new(&self.0)
        }
    }

    impl Drop for Assets {
        fn drop(&mut self) {
            for name in [
                "geoip.dat",
                "custom-ip.dat",
                "geosite.dat",
                "custom-site.dat",
            ] {
                let _ = fs::remove_file(self.0.join(name));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let clean: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        clean
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn geodata_config(rules: serde_json::Value) -> Config {
        serde_json::from_value(serde_json::json!({
            "outbounds": [
                {"tag":"direct", "protocol":"freedom"},
                {"tag":"blocked", "protocol":"blackhole"},
                {"tag":"other", "protocol":"blackhole"},
            ],
            "routing": {"rules": rules},
        }))
        .unwrap()
    }

    fn select(router: &Router, host: &str, source: &str) -> (usize, bool) {
        let destination = Destination::new(host, 443).unwrap();
        router.select_with_route(&RouteContext {
            destination: &destination,
            source: SocketAddr::new(source.parse().unwrap(), 1500),
            inbound_tag: "edge",
            user: "alice",
            network: "tcp",
        })
    }
    #[test]
    fn rules_are_ordered_and_conditions_are_conjunctive() {
        let config = Config::from_json(r#"{
            "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
            "routing":{"rules":[{"domain":["domain:example.org"],"port":"443,8000-8080","source":["127.0.0.0/8"],"outboundTag":"blocked"}]}
        }"#).unwrap();
        let router = Router::compile(&config.routing, &config.outbounds).unwrap();
        for (host, port, expected) in [
            ("example.org", 443, 1),
            ("www.EXAMPLE.org", 8080, 1),
            ("badexample.org", 443, 0),
            ("example.org", 80, 0),
        ] {
            let dest = Destination::new(host, port).unwrap();
            assert_eq!(
                router.select(&RouteContext {
                    destination: &dest,
                    source: "127.0.0.1:5678".parse().unwrap(),
                    inbound_tag: "",
                    user: "",
                    network: "tcp"
                }),
                expected
            );
        }
    }
    #[test]
    fn unsupported_or_missing_routing_targets_fail() {
        for rule in [
            r#"{"ip":["192.0.2.1/33"],"outboundTag":"direct"}"#,
            r#"{"network":"tcp","outboundTag":"missing"}"#,
            r#"{"outboundTag":"direct"}"#,
        ] {
            let config = Config::from_json(&format!(r#"{{"outbounds":[{{"tag":"direct","protocol":"freedom"}}],"routing":{{"rules":[{rule}]}}}}"#)).unwrap();
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn on_disk_geosite_attributes_and_geoip_sources_keep_all_conditions() {
        let assets = Assets::new();
        let config = geodata_config(serde_json::json!([{
            "domain": ["geosite:sites@ADS@FLAG"],
            "sourceIP": ["geoip:private"],
            "port": 443,
            "sourcePort": "1000-2000",
            "network": "tcp",
            "inboundTag": ["edge"],
            "user": ["alice"],
            "outboundTag": "blocked",
        }]));
        let router =
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                .unwrap();
        for (host, source, port, source_port, inbound, user, network, expected) in [
            (
                "Sub.EXAMPLE.com",
                "10.1.2.3",
                443,
                1500,
                "edge",
                "alice",
                "tcp",
                1,
            ),
            (
                "example.com",
                "fd12::1",
                443,
                1500,
                "edge",
                "alice",
                "tcp",
                1,
            ),
            (
                "exact.example",
                "10.1.2.3",
                443,
                1500,
                "edge",
                "alice",
                "tcp",
                0,
            ),
            (
                "example.com",
                "192.0.2.1",
                443,
                1500,
                "edge",
                "alice",
                "tcp",
                0,
            ),
            (
                "example.com",
                "10.1.2.3",
                80,
                1500,
                "edge",
                "alice",
                "tcp",
                0,
            ),
            (
                "example.com",
                "10.1.2.3",
                443,
                999,
                "edge",
                "alice",
                "tcp",
                0,
            ),
            (
                "example.com",
                "10.1.2.3",
                443,
                1500,
                "wrong",
                "alice",
                "tcp",
                0,
            ),
            (
                "example.com",
                "10.1.2.3",
                443,
                1500,
                "edge",
                "bob",
                "tcp",
                0,
            ),
            (
                "example.com",
                "10.1.2.3",
                443,
                1500,
                "edge",
                "alice",
                "udp",
                0,
            ),
        ] {
            let destination = Destination::new(host, port).unwrap();
            assert_eq!(
                router.select(&RouteContext {
                    destination: &destination,
                    source: SocketAddr::new(source.parse().unwrap(), source_port),
                    inbound_tag: inbound,
                    user,
                    network,
                }),
                expected,
                "{host} {source}:{source_port} {inbound} {user} {network}"
            );
        }
    }

    #[test]
    fn external_domain_aliases_and_custom_rules_are_ored_in_order() {
        let assets = Assets::new();
        for rule in [
            "ext:custom-site.dat:sites@flag",
            "ext-site:custom-site.dat:sites@flag",
            "ext-domain:custom-site.dat:sites@flag",
        ] {
            let config = geodata_config(serde_json::json!([
                {"domain": [rule, "full:independent.example"], "outboundTag":"blocked"},
                {"domain": ["keyword:example"], "outboundTag":"other"},
            ]));
            let router =
                Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                    .unwrap();
            assert_eq!(select(&router, "www.EXAMPLE.com", "127.0.0.1"), (1, true));
            assert_eq!(
                select(&router, "independent.example", "127.0.0.1"),
                (1, true)
            );
            assert_eq!(select(&router, "exact.example", "127.0.0.1"), (2, true));
            assert_eq!(select(&router, "unlisted.test", "127.0.0.1"), (0, false));
        }
    }

    #[test]
    fn external_geoip_targets_and_source_alias_are_supported() {
        let assets = Assets::new();
        for rule in [
            "geoip:v4",
            "ext:custom-ip.dat:v4",
            "ext-ip:custom-ip.dat:v4",
        ] {
            let config = geodata_config(serde_json::json!([{
                "ip": [rule, "198.51.100.9"], "source": ["geoip:private"], "outboundTag":"blocked",
            }]));
            let router =
                Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                    .unwrap();
            assert_eq!(select(&router, "192.0.2.8", "10.0.0.1"), (1, true));
            assert_eq!(select(&router, "198.51.100.9", "fd00::1"), (1, true));
            assert_eq!(select(&router, "198.51.100.10", "10.0.0.1"), (0, false));
            assert_eq!(select(&router, "192.0.2.8", "127.0.0.1"), (0, false));
        }
    }

    #[test]
    fn negative_geoip_rules_keep_group_union_and_address_family_semantics() {
        let assets = Assets::new();
        let config = geodata_config(serde_json::json!([{
            "ip": ["geoip:!v4", "!ext:custom-ip.dat:private"], "outboundTag":"blocked",
        }]));
        let router =
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                .unwrap();
        for host in ["192.0.2.1", "10.2.3.4", "fd00::1"] {
            assert_eq!(select(&router, host, "127.0.0.1"), (0, false), "{host}");
        }
        for host in ["198.51.100.1", "2001:db8::1"] {
            assert_eq!(select(&router, host, "127.0.0.1"), (1, true), "{host}");
        }
        let v4_only =
            geodata_config(serde_json::json!([{"ip":["!geoip:v4"],"outboundTag":"blocked"}]));
        let router =
            Router::compile_with_store(&v4_only.routing, &v4_only.outbounds, &assets.store())
                .unwrap();
        assert_eq!(select(&router, "2001:db8::1", "127.0.0.1"), (0, false));
        assert_eq!(select(&router, "::ffff:192.0.2.1", "127.0.0.1"), (0, false));
        assert_eq!(
            select(&router, "::ffff:198.51.100.1", "127.0.0.1"),
            (1, true)
        );
    }

    #[test]
    fn empty_loaded_datasets_are_false_conditions_not_missing_conditions() {
        let assets = Assets::new();
        for rule in [
            serde_json::json!({"domain":["geosite:sites@absent"],"outboundTag":"blocked"}),
            serde_json::json!({"ip":["geoip:empty"],"outboundTag":"blocked"}),
            serde_json::json!({"sourceIP":["geoip:!empty"],"outboundTag":"blocked"}),
        ] {
            let config = geodata_config(serde_json::json!([rule]));
            let router =
                Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                    .unwrap();
            for host in ["example.com", "192.0.2.1", "2001:db8::1"] {
                assert_eq!(select(&router, host, "10.0.0.1"), (0, false));
            }
        }
    }

    #[test]
    fn dotless_rules_and_asis_do_not_resolve_domains_for_ip_conditions() {
        let assets = Assets::new();
        let config = geodata_config(serde_json::json!([
            {"domain":["dotless:"],"outboundTag":"blocked"},
            {"domain":["domain:example.com"],"ip":["geoip:v4"],"outboundTag":"other"},
        ]));
        let router =
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                .unwrap();
        assert_eq!(select(&router, "INTRANET", "127.0.0.1"), (1, true));
        assert_eq!(select(&router, "intranet.example", "127.0.0.1"), (0, false));
        assert_eq!(select(&router, "example.com", "127.0.0.1"), (0, false));
        assert_eq!(select(&router, "192.0.2.1", "127.0.0.1"), (0, false));
        let invalid =
            geodata_config(serde_json::json!([{"domain":["dotless:a.b"],"outboundTag":"blocked"}]));
        assert!(
            Router::compile_with_store(&invalid.routing, &invalid.outbounds, &assets.store())
                .is_err()
        );
    }

    #[test]
    fn malformed_or_missing_geodata_fails_during_compilation() {
        let assets = Assets::new();
        for rule in [
            serde_json::json!({"domain":["geosite:missing"],"outboundTag":"blocked"}),
            serde_json::json!({"domain":["ext:missing.dat:sites"],"outboundTag":"blocked"}),
            serde_json::json!({"ip":["geoip:missing"],"outboundTag":"blocked"}),
            serde_json::json!({"sourceIP":["ext:custom-ip.dat"],"outboundTag":"blocked"}),
        ] {
            let config = geodata_config(serde_json::json!([rule]));
            assert!(
                Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                    .is_err()
            );
        }
        fs::write(assets.0.join("geosite.dat"), [0xff, 0xff, 0x01]).unwrap();
        let config = geodata_config(
            serde_json::json!([{"domain":["geosite:sites"],"outboundTag":"blocked"}]),
        );
        assert!(
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                .is_err()
        );
    }

    #[test]
    fn unsupported_dns_strategies_remain_rejected_and_balancers_parse() {
        let assets = Assets::new();
        let mut config =
            geodata_config(serde_json::json!([{"network":"tcp","outboundTag":"blocked"}]));
        for strategy in ["IPIfNonMatch", "IPOnDemand", "unknown"] {
            config.routing.domain_strategy = strategy.into();
            assert!(
                Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                    .is_err()
            );
        }
        // routing.balancers and rules' balancerTag are accepted now; unknown
        // strategies keep Go's rejection text.
        let routing: RoutingConfig = serde_json::from_value(serde_json::json!({
            "balancers": [
                {"tag":"pool","selector":["node-"],"strategy":{"type":"ROUNDROBIN","settings":{}},"fallbackTag":"blocked"},
            ]
        }))
        .unwrap();
        assert_eq!(
            routing.balancers,
            [BalancerConfig {
                tag: "pool".into(),
                selectors: vec!["node-".into()],
                fallback_tag: "blocked".into(),
                strategy: Strategy::RoundRobin,
            }]
        );
        let rule: RuleConfig = serde_json::from_value(serde_json::json!({
            "network":"tcp","balancerTag":"pool"
        }))
        .unwrap();
        assert_eq!(rule.balancer_tag, "pool");
        assert!(rule.outbound_tag.is_empty());
        let error = serde_json::from_value::<RoutingConfig>(serde_json::json!({
            "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"sticky"}}]
        }))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unknown balancing strategy: sticky"),
            "{error}"
        );
    }

    #[test]
    fn balancer_rules_target_exactly_one_kind_and_resolve_at_dispatch() {
        let assets = Assets::new();
        let config = geodata_config(serde_json::json!([{"domain":["example.org"]}]));
        for (rule, message) in [
            (
                serde_json::json!({"domain":["example.org"]}),
                "neither outboundTag nor balancerTag is specified in routing rule",
            ),
            (
                serde_json::json!({"domain":["example.org"],"outboundTag":"direct","balancerTag":"pool"}),
                "routing rule cannot set both outboundTag and balancerTag",
            ),
            (
                serde_json::json!({"domain":["example.org"],"balancerTag":"missing"}),
                "balancer missing not found",
            ),
        ] {
            let mut config = config.clone();
            config.routing.rules = vec![serde_json::from_value(rule).unwrap()];
            config.routing.balancers = vec![BalancerConfig {
                tag: "pool".into(),
                selectors: vec!["node-".into()],
                fallback_tag: String::new(),
                strategy: Strategy::Random,
            }];
            let error =
                Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                    .unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
        let mut config = config.clone();
        config.routing.rules = vec![
            serde_json::from_value(serde_json::json!({
                "domain":["example.org"],"balancerTag":"pool"
            }))
            .unwrap(),
        ];
        config.routing.balancers = vec![
            BalancerConfig {
                tag: "pool".into(),
                selectors: vec!["node-".into()],
                fallback_tag: String::new(),
                strategy: Strategy::Random,
            },
            BalancerConfig {
                tag: "pool".into(),
                selectors: vec!["node-".into()],
                fallback_tag: String::new(),
                strategy: Strategy::Random,
            },
        ];
        assert!(
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                .unwrap_err()
                .to_string()
                .contains("duplicate balancer tag")
        );
    }

    #[test]
    fn unresolvable_balancer_fallback_tags_fail_compilation_and_round_trip_serializes() {
        let assets = Assets::new();
        let mut config = geodata_config(serde_json::json!([
            {"domain":["example.org"],"balancerTag":"pool"}
        ]));
        config.routing.balancers = vec![BalancerConfig {
            tag: "pool".into(),
            selectors: vec!["node-".into()],
            fallback_tag: "missing".into(),
            strategy: Strategy::LeastPing,
        }];
        assert!(
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store())
                .unwrap_err()
                .to_string()
                .contains("fallbackTag")
        );
        // Least-load durations serialize back into the keys from_json reads.
        config.routing.balancers = vec![BalancerConfig {
            tag: "pool".into(),
            selectors: vec!["node-".into()],
            fallback_tag: "blocked".into(),
            strategy: Strategy::LeastLoad(xray_proto::xray::app::router::StrategyLeastLoadConfig {
                expected: 3,
                tolerance: 0.5,
                max_rtt: 1_500_000_000,
                baselines: vec![400_000_000, 1_400_000_000],
                costs: vec![xray_proto::xray::app::router::StrategyWeight {
                    r#match: "x8".into(),
                    regexp: true,
                    value: 8.0,
                }],
            }),
        }];
        assert!(
            Router::compile_with_store(&config.routing, &config.outbounds, &assets.store()).is_ok()
        );
        let value = serde_json::to_value(&config.routing).unwrap();
        let reparsed: RoutingConfig = serde_json::from_value(value).unwrap();
        assert_eq!(reparsed.balancers, config.routing.balancers);
        for (nanoseconds, text) in [
            (0, "0s"),
            (1, "0.000000001s"),
            (400_000_000, "0.4s"),
            (1_500_000_000, "1.5s"),
            (3_723_400_000_000, "1h2m3.4s"),
            (90_000_000_000, "1m30s"),
            (-1_500_000_000, "-1.5s"),
        ] {
            assert_eq!(duration_string(nanoseconds), text);
            assert_eq!(
                balancer::parse_duration(&duration_string(nanoseconds)).unwrap(),
                nanoseconds
            );
        }
    }
}
