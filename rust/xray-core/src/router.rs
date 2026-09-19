use std::net::SocketAddr;
pub mod balancer;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

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
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleConfig {
    pub r#type: String,
    pub rule_tag: String,
    pub outbound_tag: String,
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
    outbound: usize,
    domains: Option<DomainMatcher>,
    ips: Option<IpMatcher>,
    ports: Ports,
    networks: Vec<String>,
    inbounds: Vec<String>,
    sources: Option<IpMatcher>,
    source_ports: Ports,
    users: Vec<String>,
}

pub struct RouteContext<'a> {
    pub destination: &'a Destination,
    pub source: SocketAddr,
    pub inbound_tag: &'a str,
    pub user: &'a str,
    pub network: &'a str,
}

#[derive(Debug)]
pub struct Router {
    rules: Vec<Rule>,
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
        let mut rules = Vec::new();
        for (index, raw) in config.rules.iter().enumerate() {
            ensure!(
                matches!(raw.r#type.as_str(), "" | "field"),
                "unsupported routing rule type"
            );
            ensure!(
                !raw.outbound_tag.is_empty(),
                "routing rule requires outboundTag"
            );
            let outbound = outbounds
                .iter()
                .position(|o| o.tag == raw.outbound_tag)
                .with_context(|| format!("unknown outbound tag {:?}", raw.outbound_tag))?;
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
                    || !raw.user.is_empty(),
                "routing rule has no matching conditions"
            );
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
            });
        }
        Ok(Self { rules })
    }

    pub fn select(&self, context: &RouteContext<'_>) -> usize {
        self.select_with_route(context).0
    }

    pub fn select_with_route(&self, context: &RouteContext<'_>) -> (usize, bool) {
        self.rules
            .iter()
            .find(|rule| rule.matches(context))
            .map_or((0, false), |rule| (rule.outbound, true))
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
    fn matches(&self, context: &RouteContext<'_>) -> bool {
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
    fn unsupported_dns_strategies_and_balancers_remain_rejected() {
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
        assert!(
            serde_json::from_value::<RoutingConfig>(
                serde_json::json!({"balancers":[{"tag":"balance"}]})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<RuleConfig>(
                serde_json::json!({"network":"tcp","balancerTag":"balance"})
            )
            .is_err()
        );
    }
}
