//! Final outbound admission, following proxy/freedom/freedom.go.
//! Resolve once and dial only checked addresses to avoid a DNS check/dial race.
use crate::{
    address::{Address, Destination},
    dns::QueryOptions,
    geodata::{GeoDataStore, IpMatcher},
    router::{PortSpec, Ports},
};
use anyhow::{Context, Result, ensure};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
    time::Duration,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleConfig {
    pub action: String,
    #[serde(deserialize_with = "crate::router::strings")]
    pub network: Vec<String>,
    pub port: Option<PortSpec>,
    #[serde(deserialize_with = "crate::router::strings")]
    pub ip: Vec<String>,
    pub block_delay: Option<Delay>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Delay {
    Seconds(u32),
    Range(String),
}
impl Delay {
    fn bounds(&self) -> Result<(u64, u64)> {
        let (min, max) = match self {
            Self::Seconds(n) => (u64::from(*n), u64::from(*n)),
            Self::Range(s) => match s.split_once('-') {
                Some((min, max)) => (min.parse()?, max.parse()?),
                None => {
                    let n = s.parse()?;
                    (n, n)
                }
            },
        };
        ensure!(
            min <= i32::MAX as u64 && max <= i32::MAX as u64,
            "blockDelay exceeds int32 range"
        );
        Ok((min.min(max), min.max(max)))
    }
}

#[derive(Clone, Debug)]
struct Rule {
    block: bool,
    networks: Vec<String>,
    ports: Ports,
    ips: Option<IpMatcher>,
    delay: (u64, u64),
}
#[derive(Clone, Debug, Default)]
pub struct FinalRules(Vec<Rule>);

/// Freedom `domainStrategy` from `infra/conf/freedom.go`, matched
/// case-insensitively. The non-AsIs strategies resolve the target through the
/// configured DNS app (or the system resolver when no `dns` app exists) in
/// `runtime/admission.rs`, following proxy/freedom/freedom.go and
/// transport/internet's `LookupForIP`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    UseIp,
    UseIp4,
    UseIp6,
    UseIp46,
    UseIp64,
    ForceIp,
    ForceIp4,
    ForceIp6,
    ForceIp46,
    ForceIp64,
}

impl DomainStrategy {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name.to_ascii_lowercase().as_str() {
            "" | "asis" => Self::AsIs,
            "useip" => Self::UseIp,
            "useipv4" => Self::UseIp4,
            "useipv6" => Self::UseIp6,
            "useipv4v6" => Self::UseIp46,
            "useipv6v4" => Self::UseIp64,
            "forceip" => Self::ForceIp,
            "forceipv4" => Self::ForceIp4,
            "forceipv6" => Self::ForceIp6,
            "forceipv4v6" => Self::ForceIp46,
            "forceipv6v4" => Self::ForceIp64,
            other => anyhow::bail!("unsupported domain strategy: {other}"),
        })
    }

    /// Go `DomainStrategy.HasStrategy`: every strategy but `AsIs` resolves.
    pub(crate) fn has_strategy(self) -> bool {
        !matches!(self, Self::AsIs)
    }

    /// Query families of the first lookup, from Go's `strategy` table columns
    /// (`PreferIP4`/`PreferIP6`): the `*IP`/`*IPv6`-only strategies enable one
    /// family, `UseIP`/`ForceIP` enable both, and the pair strategies enable
    /// their preferred family first.
    pub(crate) fn preferred_families(self) -> QueryOptions {
        match self {
            Self::AsIs | Self::UseIp | Self::ForceIp => QueryOptions::BOTH,
            Self::UseIp4 | Self::UseIp46 | Self::ForceIp4 | Self::ForceIp46 => QueryOptions::IPV4,
            Self::UseIp6 | Self::UseIp64 | Self::ForceIp6 | Self::ForceIp64 => QueryOptions::IPV6,
        }
    }

    /// Second-lookup families when the first yields nothing (Go `HasFallback`
    /// with `FallbackIP4`/`FallbackIP6`); the pair strategies fall back to the
    /// other family, everything else has no fallback.
    pub(crate) fn fallback_families(self) -> Option<QueryOptions> {
        match self {
            Self::UseIp46 | Self::ForceIp46 => Some(QueryOptions::IPV6),
            Self::UseIp64 | Self::ForceIp64 => Some(QueryOptions::IPV4),
            _ => None,
        }
    }

    /// Go `ForceIP`: the connection fails when resolution yields nothing
    /// instead of dialing by domain.
    pub(crate) fn is_force(self) -> bool {
        matches!(
            self,
            Self::ForceIp | Self::ForceIp4 | Self::ForceIp6 | Self::ForceIp46 | Self::ForceIp64
        )
    }
}

#[derive(Debug)]
pub enum Admission {
    Allowed(Option<Vec<SocketAddr>>),
    Blocked(Duration),
}

impl FinalRules {
    pub fn compile(config: &[RuleConfig]) -> Result<Self> {
        let store = GeoDataStore::from_env()?;
        let mut rules = Vec::new();
        for raw in config {
            let block = match raw.action.to_ascii_lowercase().as_str() {
                "allow" => false,
                "block" => true,
                _ => anyhow::bail!("unknown freedom final rule action {:?}", raw.action),
            };
            let networks = raw
                .network
                .iter()
                .flat_map(|s| s.split(','))
                .map(|s| s.trim().to_owned())
                .collect::<Vec<_>>();
            ensure!(
                networks.iter().all(|n| matches!(n.as_str(), "tcp" | "udp")),
                "unknown final rule network"
            );
            let ips = if raw.ip.is_empty() {
                None
            } else {
                Some(store.build_ip_matcher(&store.parse_ip_rules(&raw.ip)?)?)
            };
            rules.push(Rule {
                block,
                networks,
                ports: Ports::compile(&raw.port)?,
                ips,
                delay: raw
                    .block_delay
                    .as_ref()
                    .map(Delay::bounds)
                    .transpose()?
                    .unwrap_or((30, 90)),
            });
        }
        Ok(Self(rules))
    }

    pub fn block_delay(
        &self,
        inbound: &str,
        network: &str,
        address: IpAddr,
        port: u16,
    ) -> Option<Duration> {
        for rule in &self.0 {
            if (rule.networks.is_empty() || rule.networks.iter().any(|n| n == network))
                && rule.ports.matches(port)
                && rule.ips.as_ref().is_none_or(|ips| ips.match_ip(address))
            {
                return rule.block.then(|| {
                    Duration::from_secs(rand::thread_rng().gen_range(rule.delay.0..=rule.delay.1))
                });
            }
        }
        let private_default = matches!(
            inbound,
            "vless" | "vmess" | "trojan" | "hysteria" | "wireguard"
        ) || inbound.starts_with("shadowsocks");
        if inbound == "vless-reverse" || private_default && private_ip(address) {
            Some(Duration::from_secs(rand::thread_rng().gen_range(30..=90)))
        } else {
            None
        }
    }

    pub async fn admit(&self, inbound: &str, destination: &Destination) -> Result<Admission> {
        let needs_check = !self.0.is_empty()
            || matches!(
                inbound,
                "vless-reverse" | "vless" | "vmess" | "trojan" | "hysteria" | "wireguard"
            )
            || inbound.starts_with("shadowsocks");
        if !needs_check {
            return Ok(Admission::Allowed(None));
        }
        let addresses = match &destination.address {
            Address::Ip(ip) => vec![SocketAddr::new(*ip, destination.port)],
            Address::Domain(host) => tokio::net::lookup_host((host.as_str(), destination.port))
                .await
                .context("resolve freedom final-rule target")?
                .collect::<Vec<_>>(),
        };
        self.admit_resolved(inbound, addresses)
    }

    /// Final-rule scan over already-resolved addresses — the system-resolved
    /// `AsIs` path above and the `domainStrategy` resolution in
    /// `runtime/admission.rs`. One blocked address blocks the connection;
    /// blocked answers are never skipped to find a permitted one.
    pub fn admit_resolved(&self, inbound: &str, addresses: Vec<SocketAddr>) -> Result<Admission> {
        ensure!(
            !addresses.is_empty(),
            "freedom target resolved to no addresses"
        );
        for addr in &addresses {
            if let Some(delay) = self.block_delay(inbound, "tcp", addr.ip(), addr.port()) {
                return Ok(Admission::Blocked(delay));
            }
        }
        Ok(Admission::Allowed(Some(addresses)))
    }
}

fn private_ip(mut ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        ip = IpAddr::V4(v4);
    }
    static NETWORKS: OnceLock<Vec<ipnet::IpNet>> = OnceLock::new();
    NETWORKS
        .get_or_init(|| {
            [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/3",
                "::/127",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
            ]
            .into_iter()
            .map(|s| s.parse().expect("source CIDR"))
            .collect()
        })
        .iter()
        .any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_strategy_table_matches_go() {
        // (strategy, preferred families, fallback, force) per Go's
        // `strategy` table in transport/internet/config.go.
        for (name, preferred, fallback, force) in [
            ("AsIs", None, None, false),
            ("UseIP", Some(QueryOptions::BOTH), None, false),
            ("UseIPv4", Some(QueryOptions::IPV4), None, false),
            ("UseIPv6", Some(QueryOptions::IPV6), None, false),
            (
                "UseIPv4v6",
                Some(QueryOptions::IPV4),
                Some(QueryOptions::IPV6),
                false,
            ),
            (
                "UseIPv6v4",
                Some(QueryOptions::IPV6),
                Some(QueryOptions::IPV4),
                false,
            ),
            ("ForceIP", Some(QueryOptions::BOTH), None, true),
            ("ForceIPv4", Some(QueryOptions::IPV4), None, true),
            ("ForceIPv6", Some(QueryOptions::IPV6), None, true),
            (
                "ForceIPv4v6",
                Some(QueryOptions::IPV4),
                Some(QueryOptions::IPV6),
                true,
            ),
            (
                "ForceIPv6v4",
                Some(QueryOptions::IPV6),
                Some(QueryOptions::IPV4),
                true,
            ),
        ] {
            let strategy = DomainStrategy::parse(name).unwrap();
            assert_eq!(strategy.has_strategy(), name != "AsIs", "{name}");
            assert_eq!(
                strategy.preferred_families(),
                preferred.unwrap_or(QueryOptions::BOTH),
                "{name}"
            );
            assert_eq!(strategy.fallback_families(), fallback, "{name}");
            assert_eq!(strategy.is_force(), force, "{name}");
        }
        assert_eq!(DomainStrategy::parse("asis").unwrap(), DomainStrategy::AsIs);
        assert!(DomainStrategy::parse("UseSystem").is_err());
    }
    #[test]
    fn default_is_source_protocol_dependent_and_covers_mapped_ips() {
        let rules = FinalRules::default();
        for name in [
            "vless",
            "vmess",
            "trojan",
            "hysteria",
            "wireguard",
            "shadowsocks-2022",
        ] {
            for ip in [
                "127.0.0.1",
                "::1",
                "::ffff:127.0.0.1",
                "100.64.0.1",
                "203.0.113.1",
                "fc00::1",
                "224.0.0.1",
            ] {
                assert!(
                    rules
                        .block_delay(name, "tcp", ip.parse().unwrap(), 443)
                        .is_some(),
                    "{name} {ip}"
                );
            }
            assert!(
                rules
                    .block_delay(name, "tcp", "8.8.8.8".parse().unwrap(), 443)
                    .is_none()
            );
        }
        assert!(
            rules
                .block_delay("socks", "tcp", "127.0.0.1".parse().unwrap(), 80)
                .is_none()
        );
        assert!(
            rules
                .block_delay("vless-reverse", "tcp", "8.8.8.8".parse().unwrap(), 443)
                .is_some()
        );
    }
    #[test]
    fn first_rule_and_all_conditions_override_default() {
        let config: Vec<RuleConfig> = serde_json::from_value(serde_json::json!([
            {"action":"allow","network":"tcp","ip":["127.0.0.0/8"],"port":"8080-8081"},
            {"action":"block","blockDelay":"0"}
        ]))
        .unwrap();
        let rules = FinalRules::compile(&config).unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        assert!(rules.block_delay("vless", "tcp", ip, 8080).is_none());
        assert_eq!(
            rules.block_delay("vless", "udp", ip, 8080),
            Some(Duration::ZERO)
        );
        assert_eq!(
            rules.block_delay("vless", "tcp", ip, 8082),
            Some(Duration::ZERO)
        );
    }
    #[tokio::test]
    async fn resolved_localhost_is_checked_before_dial() {
        let target = Destination::new("localhost", 443).unwrap();
        assert!(matches!(
            FinalRules::default().admit("vless", &target).await.unwrap(),
            Admission::Blocked(_)
        ));
        let rules = FinalRules::compile(
            &serde_json::from_value::<Vec<RuleConfig>>(
                serde_json::json!([{"action":"allow","port":443}]),
            )
            .unwrap(),
        )
        .unwrap();
        let Admission::Allowed(Some(addresses)) = rules.admit("vless", &target).await.unwrap()
        else {
            panic!("not admitted")
        };
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|a| a.port() == 443));
    }
}
