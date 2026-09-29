use std::{collections::HashSet, net::IpAddr};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    address::Destination,
    router::{Router, RoutingConfig},
};

pub mod dns;
pub mod legacy;
pub mod observatory;
pub mod protobuf;
pub mod protobuf_encode;
mod proxies;
mod reality;
mod vmess;
pub mod yaml_compat;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log: Option<crate::logging::LogConfig>,
    pub policy: Option<crate::features::PolicyConfig>,
    pub stats: Option<StatsConfig>,
    pub api: Option<ApiConfig>,
    pub observatory: Option<observatory::ObservatoryConfig>,
    /// Raw `dns` app object; compiled by `dns::app::DnsApp::from_value`.
    pub dns: Option<Value>,
    /// Raw `reverse` app object; compiled by `reverse::ReverseConfig::from_value`.
    pub reverse: Option<Value>,
    /// Raw `burstObservatory` object; compiled by
    /// `features::observatory_burst::BurstObservatoryConfig::from_value`.
    #[serde(rename = "burstObservatory")]
    pub burst_observatory: Option<Value>,
    /// The root `fakeDns` pools (Go's FakeDNSConfig).
    #[serde(rename = "fakeDns")]
    pub fake_dns: Option<crate::dns::fakedns::FakeDnsSettings>,
    /// Go's root `env` map: consumed by the CLI loader like Go's Build; the
    /// field only tolerates the key for direct Config parses.
    pub env: Option<std::collections::BTreeMap<String, String>>,
    /// Go's root `version` guard: refuse to run outside [min, max].
    pub version: Option<VersionConfig>,
    /// Go's root `geodata` asset paths.
    pub geodata: Option<GeodataConfig>,
    /// Go's root `metrics` (pprof HTTP). The pprof profiler is not
    /// integrated in this runtime build; the key is accepted and fails at
    /// compile time with a named error.
    pub metrics: Option<Value>,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
}

pub use crate::logging::LogConfig;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatsConfig {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub tag: String,
    pub listen: String,
    pub services: Vec<String>,
}
impl ApiConfig {
    fn validate(&self) -> Result<()> {
        ensure!(!self.tag.is_empty(), "API tag cannot be empty");
        let mut seen = HashSet::new();
        for service in &self.services {
            let service = service.to_ascii_lowercase();
            ensure!(
                matches!(
                    service.as_str(),
                    "statsservice"
                        | "loggerservice"
                        | "observatoryservice"
                        | "handlerservice"
                        | "routingservice"
                        | "reflectionservice"
                ),
                "API service {service:?} is not integrated yet"
            );
            ensure!(seen.insert(service), "duplicate API service");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboundConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(default = "default_listen")]
    pub listen: ListenAddress,
    /// Go's zero-default port: absent binds an ephemeral port. The TUN and
    /// unix inbounds bind no TCP listener; the runtime checks the inbound
    /// variant before this is ever read.
    #[serde(default = "default_port")]
    pub port: PortSpec,
    pub protocol: String,
    #[serde(default = "empty_object")]
    pub settings: Value,
    #[serde(default)]
    pub stream_settings: StreamSettings,
    /// The inbound's `sniffing` object (Go's proxyman ReceiverConfig
    /// sniffing). Validated eagerly by `compile_inbound`; the runtime
    /// compiles it via `runtime::sniffing::SniffingRequest::compile` — see
    /// that module's contract doc for the wiring.
    #[serde(default)]
    pub sniffing: Option<SniffingConfig>,
}

/// Go's `SniffingConfig` (infra/conf/xray.go): the `sniffing` object of an
/// inbound. The serde shape is exactly Go's keys — `enabled`,
/// `destOverride`, `domainsExcluded`, `ipsExcluded`, `metadataOnly`,
/// `routeOnly` — and unknown keys are rejected; every list accepts either a
/// single string or an array, like Go's StringList. `destOverride` accepts
/// "http", "tls"/"https"/"ssl" and "quic"; "fakedns"/"fakedns+others" fails
/// explicitly (the fake DNS engine is not migrated).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SniffingConfig {
    pub enabled: bool,
    #[serde(deserialize_with = "string_list")]
    pub dest_override: Vec<String>,
    #[serde(deserialize_with = "string_list")]
    pub domains_excluded: Vec<String>,
    #[serde(deserialize_with = "string_list")]
    pub ips_excluded: Vec<String>,
    pub metadata_only: bool,
    pub route_only: bool,
}

impl SniffingConfig {
    /// Go `SniffingConfig.Build` validation, at parse time: `destOverride`
    /// must name a migrated sniffer (fakedns fails explicitly — it is not
    /// migrated) and the exclusion lists must be legal domain/IP rules.
    /// Runs even when sniffing is disabled, exactly like Go's Build.
    pub(crate) fn validate(&self) -> Result<()> {
        for protocol in &self.dest_override {
            match protocol.to_ascii_lowercase().as_str() {
                "http" | "tls" | "https" | "ssl" | "quic" => {}
                "fakedns" | "fakedns+others" => bail!("fakedns sniffing is not migrated yet"),
                other => bail!("unknown sniffing protocol {other:?}"),
            }
        }
        if !self.domains_excluded.is_empty() || !self.ips_excluded.is_empty() {
            let store = crate::geodata::GeoDataStore::from_env()?;
            if !self.domains_excluded.is_empty() {
                store.parse_domain_rules(
                    &self.domains_excluded,
                    crate::geodata::domain::Type::Substr,
                )?;
            }
            if !self.ips_excluded.is_empty() {
                store.parse_ip_rules(&self.ips_excluded)?;
            }
        }
        Ok(())
    }
}

/// Go's StringList: a single string or an array of strings.
fn string_list<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Values {
        Single(String),
        Multiple(Vec<String>),
    }
    Ok(match Values::deserialize(d)? {
        Values::Single(value) => vec![value],
        Values::Multiple(values) => values,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutboundConfig {
    #[serde(default)]
    pub tag: String,
    pub protocol: String,
    #[serde(default = "empty_object")]
    pub settings: Value,
    #[serde(default)]
    pub stream_settings: StreamSettings,
    #[serde(default)]
    pub mux: Option<MuxSettings>,
}

/// Go's `VersionConfig` (`infra/conf/version.go`): the core version must
/// fall within [min, max] (empty bounds are unbounded).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct VersionConfig {
    pub min: String,
    pub max: String,
}

/// Go's `GeodataConfig` asset paths (`infra/conf/geodata.go`): per-asset
/// paths overriding the environment locations. The cron/outbound download
/// scheduler is not integrated and fails with a named error.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeodataConfig {
    pub cron: Option<String>,
    pub outbound: String,
    pub assets: Vec<GeodataAsset>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeodataAsset {
    pub file: String,
    pub tag: Option<String>,
    /// One of `geoip`/`geosite` (Go's type inference by filename prefix).
    pub kind: Option<String>,
}

/// Go's `MuxConfig` (infra/conf/xray.go): Mux.Cool multiplexing over the
/// outbound's own proxy connections.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MuxSettings {
    pub enabled: bool,
    pub concurrency: i16,
    #[serde(rename = "xudpConcurrency")]
    pub xudp_concurrency: i16,
    #[serde(rename = "xudpProxyUDP443")]
    pub xudp_proxy_udp443: String,
}

/// Stream limits of one Mux.Cool carrier connection (Go ClientStrategy).
#[derive(Clone, Copy, Debug)]
pub struct PoolLimits {
    pub max_concurrency: usize,
    pub max_connections: usize,
}

/// Go's `xudpProxyUDP443` policy for UDP/443 traffic on mux outbounds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Udp443Policy {
    #[default]
    Reject,
    Allow,
    Skip,
}

/// The compiled multiplexing plan of one outbound (Go proxyman/outbound
/// Handler: one TCP carrier pool, one XUDP carrier pool, and the UDP/443
/// policy; a `None` pool means that traffic bypasses mux).
#[derive(Clone, Debug)]
pub(crate) struct MuxPlan {
    pub tcp: Option<PoolLimits>,
    pub xudp: Option<PoolLimits>,
    pub udp443: Udp443Policy,
}

impl MuxSettings {
    /// Go's `MuxConfig.Build` plus the handler's strategy defaults:
    /// concurrency < 0 disables TCP mux, 0 becomes 8; xudpConcurrency < 0
    /// disables XUDP, 0 leaves XUDP off (UDP rides the plain mux pool);
    /// `xudpProxyUDP443` defaults to reject and must name a known policy.
    pub(crate) fn compile(&self, protocol: &str) -> Result<Option<MuxPlan>> {
        if !self.enabled {
            return Ok(None);
        }
        anyhow::ensure!(
            protocol != "masque",
            "masque outbound does not support \"mux\""
        );
        let udp443 = match self.xudp_proxy_udp443.as_str() {
            "" => Udp443Policy::Reject,
            "reject" => Udp443Policy::Reject,
            "allow" => Udp443Policy::Allow,
            "skip" => Udp443Policy::Skip,
            other => anyhow::bail!("unknown \"xudpProxyUDP443\": {other}"),
        };
        let limits = |concurrency: i16, default: usize| -> Option<PoolLimits> {
            match concurrency {
                negative if negative < 0 => None,
                0 => Some(PoolLimits {
                    max_concurrency: default,
                    max_connections: 128,
                }),
                positive => Some(PoolLimits {
                    max_concurrency: positive as usize,
                    max_connections: 128,
                }),
            }
        };
        Ok(Some(MuxPlan {
            tcp: limits(self.concurrency, 8),
            xudp: limits(self.xudp_concurrency, 8),
            udp443,
        }))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct StreamSettings {
    pub network: String,
    pub security: String,
    pub tls_settings: Option<Value>,
    pub reality_settings: Option<Value>,
    #[serde(alias = "splithttpSettings")]
    pub xhttp_settings: Option<Value>,
    pub ws_settings: Option<Value>,
    pub httpupgrade_settings: Option<Value>,
    pub grpc_settings: Option<Value>,
    pub kcp_settings: Option<Value>,
    pub masque_settings: Option<Value>,
    pub hysteria_settings: Option<Value>,
    pub finalmask: Option<Value>,
    #[serde(alias = "rawSettings")]
    pub tcp_settings: Option<Value>,
    pub xdrive_settings: Option<Value>,
}

impl StreamSettings {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                self.network.as_str(),
                "" | "tcp"
                    | "raw"
                    | "xhttp"
                    | "splithttp"
                    | "ws"
                    | "websocket"
                    | "httpupgrade"
                    | "grpc"
                    | "kcp"
                    | "mkcp"
                    | "masque"
                    | "hysteria"
                    | "xdrive"
            ),
            "transport {:?} is not migrated yet",
            self.network
        );
        ensure!(
            matches!(self.security.as_str(), "" | "none" | "tls" | "reality"),
            "security {:?} is not migrated yet",
            self.security
        );
        ensure!(
            self.reality_settings.is_none() || self.security == "reality",
            "realitySettings requires security reality"
        );
        ensure!(
            self.ws_settings.is_none() || matches!(self.network.as_str(), "ws" | "websocket"),
            "wsSettings requires the WebSocket transport"
        );
        ensure!(
            self.httpupgrade_settings.is_none() || self.network == "httpupgrade",
            "httpupgradeSettings requires the HTTP Upgrade transport"
        );
        ensure!(
            self.grpc_settings.is_none() || self.network == "grpc",
            "grpcSettings requires the gRPC transport"
        );
        ensure!(
            self.kcp_settings.is_none() || matches!(self.network.as_str(), "kcp" | "mkcp"),
            "kcpSettings requires the KCP transport"
        );
        ensure!(
            self.masque_settings.is_none() || self.network == "masque",
            "masqueSettings requires the masque transport"
        );
        ensure!(
            self.xdrive_settings.is_none() || self.network == "xdrive",
            "xdriveSettings requires the xdrive transport"
        );
        if self.network == "xdrive" {
            ensure!(
                matches!(self.security.as_str(), "" | "none"),
                "the xdrive transport requires security none;                  no TLS layer rides the object store"
            );
            let settings = self
                .xdrive_settings
                .as_ref()
                .context("the xdrive transport requires xdriveSettings")?;
            let parsed = crate::transport::xdrive::stream::XdriveSettings::from_value(settings)
                .context("xdriveSettings")?;
            parsed.validate().context("xdriveSettings")?;
        }
        if let Some(settings) = &self.tcp_settings {
            ensure!(
                matches!(self.network.as_str(), "" | "tcp" | "raw"),
                "tcpSettings requires the plain TCP transport"
            );
            match settings.get("header") {
                None | Some(Value::Null) => bail!(
                    "the TCP header config must be an object, not null                      (Go: type not found in JSON context)"
                ),
                Some(header) => {
                    let parsed = crate::transport::headers::HeaderSettings::from_value(header)
                        .context("tcpSettings.header")?;
                    crate::transport::headers::HeaderCodec::compile(&parsed)
                        .context("tcpSettings.header")?;
                }
            }
        }
        ensure!(
            self.hysteria_settings.is_none() || self.network == "hysteria",
            "hysteriaSettings requires the hysteria transport"
        );
        ensure!(
            self.network != "hysteria" || self.hysteria_settings.is_some(),
            "the hysteria transport requires hysteriaSettings"
        );
        ensure!(
            self.network != "hysteria" || self.security == "tls",
            "the hysteria transport requires \"security\": \"tls\""
        );
        if let Some(finalmask) = &self.finalmask {
            crate::transport::finalmask::FinalMaskSettings::from_value(finalmask)
                .context("finalmask")?
                .validate()
                .context("finalmask")?;
        }
        ensure!(
            !matches!(self.network.as_str(), "kcp" | "mkcp") || self.security != "reality",
            "KCP does not support REALITY security"
        );
        ensure!(
            self.network != "masque" || self.security == "tls",
            "the masque transport requires \"security\": \"tls\""
        );
        Ok(())
    }

    /// The parsed `xdriveSettings` (None when absent); validated like Go's
    /// XDriveConfig.Build. The async storage compile runs at bind/dial time.
    pub(crate) fn xdrive_settings(
        &self,
    ) -> Result<Option<crate::transport::xdrive::stream::XdriveSettings>> {
        let Some(value) = &self.xdrive_settings else {
            return Ok(None);
        };
        let settings = crate::transport::xdrive::stream::XdriveSettings::from_value(value)
            .context("xdriveSettings")?;
        settings.validate().context("xdriveSettings")?;
        Ok(Some(settings))
    }

    /// The compiled `tcpSettings.header` codec (None when tcpSettings or
    /// its header object is absent); validated like Go's TCPConfig.Build.
    pub(crate) fn tcp_header(&self) -> Result<Option<crate::transport::headers::HeaderCodec>> {
        let Some(settings) = &self.tcp_settings else {
            return Ok(None);
        };
        let Some(header) = settings.get("header") else {
            return Ok(None);
        };
        let parsed = crate::transport::headers::HeaderSettings::from_value(header)
            .context("tcpSettings.header")?;
        Ok(Some(
            crate::transport::headers::HeaderCodec::compile(&parsed)
                .context("tcpSettings.header")?,
        ))
    }

    /// The compiled `finalmask.quicParams` (Go's nil defaults when absent);
    /// validated like Go's StreamConfig.Build.
    pub(crate) fn quic_params(&self) -> Result<crate::transport::finalmask::QuicParams> {
        match &self.finalmask {
            Some(value) => crate::transport::finalmask::FinalMaskSettings::from_value(value)
                .context("finalmask")?
                .compile()
                .context("finalmask"),
            None => Ok(crate::transport::finalmask::QuicParams::default()),
        }
    }

    fn layers(
        &self,
    ) -> Result<(
        Option<crate::transport::tls::TlsSettings>,
        Option<crate::transport::xhttp::Config>,
    )> {
        self.validate()?;
        let xhttp = if matches!(self.network.as_str(), "xhttp" | "splithttp") {
            Some(crate::transport::xhttp::Config::from_json(
                self.xhttp_settings.as_ref().unwrap_or(&empty_object()),
            )?)
        } else {
            ensure!(
                self.xhttp_settings.is_none(),
                "xhttpSettings requires the xhttp transport"
            );
            None
        };
        let tls = if self.security == "tls" {
            let mut settings: crate::transport::tls::TlsSettings =
                serde_json::from_value(self.tls_settings.clone().unwrap_or_else(empty_object))
                    .context("invalid TLS settings")?;
            if self.network == "grpc" || self.network == "masque" {
                if settings.alpn.is_empty() {
                    settings.alpn.push("h2".into());
                }
                ensure!(
                    settings.alpn.iter().all(|protocol| protocol == "h2"),
                    "gRPC/MASQUE TLS requires h2-only ALPN"
                );
            } else if xhttp.is_some()
                || matches!(self.network.as_str(), "ws" | "websocket" | "httpupgrade")
            {
                if settings.alpn.is_empty() {
                    settings.alpn.push("http/1.1".into());
                }
                ensure!(
                    settings.alpn.iter().all(|p| p == "http/1.1"),
                    "this native HTTP transport currently requires HTTP/1.1 ALPN"
                );
            }
            settings.validate()?;
            Some(settings)
        } else {
            ensure!(
                self.tls_settings.is_none(),
                "tlsSettings requires security tls"
            );
            None
        };
        Ok((tls, xhttp))
    }

    pub(crate) fn inbound_transport(&self) -> Result<crate::transport::InboundTransport> {
        let (tls, xhttp) = self.layers()?;
        // REALITY replaces the TLS layer: the inbound parser enforces every
        // Go constraint on `realitySettings` (dest, serverNames, privateKey,
        // shortIds, xver, version bounds).
        let reality = if self.security == "reality" {
            let value = self
                .reality_settings
                .as_ref()
                .context("REALITY inbound requires realitySettings")?;
            Some(crate::transport::reality_inbound::InboundConfig::from_value(value)?)
        } else {
            None
        };
        Ok(crate::transport::InboundTransport {
            tls: tls
                .as_ref()
                .map(crate::transport::tls::TlsServer::new)
                .transpose()?,
            tcp_header: self.tcp_header()?,
            xdrive: self.xdrive_settings()?,
            reality,
            xhttp: xhttp.map(crate::transport::xhttp::Server::new),
            websocket: self.websocket()?,
            httpupgrade: self.httpupgrade()?,
            grpc: self.grpc()?,
            kcp: self.kcp()?,
        })
    }

    pub(crate) fn outbound_transport(&self) -> Result<crate::transport::OutboundTransport> {
        let (tls, xhttp) = self.layers()?;
        let reality = if self.security == "reality" {
            let mut config = reality::client(
                self.reality_settings.clone().unwrap_or_else(empty_object),
                matches!(
                    self.network.as_str(),
                    "ws" | "websocket" | "httpupgrade" | "xhttp" | "splithttp"
                ),
            )?;
            if self.network == "grpc" {
                config.alpn = vec![b"h2".to_vec()];
            }
            Some(config)
        } else {
            None
        };
        let masque = if self.network == "masque" {
            Some(crate::transport::masque::Settings::from_value(
                self.masque_settings.as_ref().unwrap_or(&empty_object()),
            )?)
        } else {
            None
        };
        Ok(crate::transport::OutboundTransport {
            tls: tls
                .as_ref()
                .map(crate::transport::tls::TlsClient::new)
                .transpose()?,
            tcp_header: self.tcp_header()?,
            xdrive: self.xdrive_settings()?,
            server_name: tls
                .as_ref()
                .map(|settings| settings.server_name.clone())
                .unwrap_or_else(|| {
                    reality
                        .as_ref()
                        .map(|config| config.server_name.clone())
                        .unwrap_or_default()
                }),
            reality,
            masque,
            masque_tls: if self.network == "masque" {
                tls.clone()
            } else {
                None
            },
            xhttp,
            websocket: self.websocket()?,
            httpupgrade: self.httpupgrade()?,
            grpc: self.grpc()?,
            kcp: self.kcp()?,
        })
    }

    fn kcp(&self) -> Result<Option<crate::transport::kcp::Config>> {
        if matches!(self.network.as_str(), "kcp" | "mkcp") {
            Ok(Some(crate::transport::kcp::Config::from_json(
                self.kcp_settings.as_ref().unwrap_or(&empty_object()),
            )?))
        } else {
            Ok(None)
        }
    }

    fn grpc(&self) -> Result<Option<crate::transport::grpc::Config>> {
        if self.network != "grpc" {
            return Ok(None);
        }
        let config: crate::transport::grpc::Config =
            serde_json::from_value(self.grpc_settings.clone().unwrap_or_else(empty_object))
                .context("invalid gRPC settings")?;
        config.validate().context("unsupported gRPC settings")?;
        Ok(Some(config))
    }

    fn websocket(&self) -> Result<Option<crate::transport::websocket::Config>> {
        if matches!(self.network.as_str(), "ws" | "websocket") {
            Ok(Some(crate::transport::websocket::Config::from_json(
                self.ws_settings.as_ref().unwrap_or(&empty_object()),
            )?))
        } else {
            Ok(None)
        }
    }

    fn httpupgrade(&self) -> Result<Option<crate::transport::httpupgrade::HttpUpgradeConfig>> {
        if self.network == "httpupgrade" {
            Ok(Some(
                crate::transport::httpupgrade::HttpUpgradeConfig::from_json(
                    self.httpupgrade_settings
                        .as_ref()
                        .unwrap_or(&empty_object()),
                )?,
            ))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Account {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SocksSettings {
    pub auth: String,
    pub accounts: Vec<Account>,
    pub users: Option<Vec<Account>>,
    pub udp: bool,
    pub ip: Option<IpAddr>,
    pub user_level: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpSettings {
    pub accounts: Vec<Account>,
    pub users: Option<Vec<Account>>,
    pub allow_transparent: bool,
    pub user_level: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct DokodemoSettings {
    address: Option<String>,
    rewrite_address: Option<String>,
    port: u16,
    rewrite_port: u16,
    network: Option<String>,
    allowed_network: Option<String>,
    follow_redirect: bool,
    user_level: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct FreedomSettings {
    domain_strategy: String,
    target_strategy: String,
    redirect: String,
    user_level: u32,
    final_rules: Vec<crate::protocol::freedom::RuleConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BlackholeSettings {
    response: Option<BlackholeResponse>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct BlackholeResponse {
    r#type: String,
    custom_response_data: String,
}

#[derive(Clone)]
pub enum Inbound {
    Vmess(crate::protocol::vmess::stream::SharedAuthenticator),
    Socks(SocksSettings),
    Http(HttpSettings),
    Dokodemo {
        destination: Destination,
        /// `network: "tcp,udp"` relays datagrams to the fixed destination.
        udp: bool,
    },
    Vless {
        accounts: Vec<crate::protocol::vless::Account>,
        /// Inbound `decryption`: `none` keeps the plaintext header exchange,
        /// `mlkem768x25519plus` wraps the whole VLESS session in the shared
        /// encrypted session (replay history must span connections).
        decryption: Option<std::sync::Arc<crate::protocol::vless_encryption::ServerDecryption>>,
    },
    Trojan {
        accounts: Vec<crate::protocol::trojan::Account>,
        /// Trojan's protocol has no network gate: command 3 (UDP over the
        /// Trojan connection) is always available.
        udp: bool,
    },
    Shadowsocks {
        account: crate::protocol::shadowsocks_session::Account,
        /// `network: "tcp,udp"` opts into the legacy AEAD UDP relay.
        udp: bool,
    },
    Shadowsocks2022 {
        account: crate::protocol::shadowsocks2022::Account,
        /// `network: "tcp,udp"` opts into the 2022 UDP listener; the absent
        /// field means TCP only, exactly like Go's nil NetworkList.
        udp: bool,
    },
    /// The DNS proxy inbound: a terminal handler answering DNS queries (and
    /// optionally forwarding non-DNS streams).
    Dns(crate::protocol::dns_proxy::DnsProxySettings),
    /// The hysteria inbound's proxy settings (version-2 users); the QUIC
    /// listener pieces (TLS, hysteriaSettings, quicParams) compile from the
    /// stream settings in the runtime.
    Hysteria {
        users: Vec<crate::protocol::hysteria_runtime::HysteriaUser>,
    },
    /// The TUN device inbound: the compiled entry owns the device and
    /// netstack configuration; serve() runs it outside the listener loop.
    /// Boxed: the entry embeds the seam's Inbound value (its dispatch
    /// identity), which would otherwise recurse through this enum.
    Tun {
        entry: std::sync::Arc<crate::runtime::tun_inbound::TunInbound>,
    },
    /// The WireGuard server inbound: the compiled entry (settings, device,
    /// bind); the runtime sets one listen address per port.
    Wireguard {
        entry: crate::runtime::wireguard_inbound::WireguardInbound,
    },
}

#[derive(Clone, Debug)]
pub enum Outbound {
    Api,
    Vmess {
        server: Destination,
        account: crate::protocol::vmess::Account,
        security: crate::protocol::vmess::Security,
    },
    Shadowsocks {
        server: Destination,
        account: crate::protocol::shadowsocks_session::Account,
    },
    Shadowsocks2022 {
        server: Destination,
        account: crate::protocol::shadowsocks2022::Account,
    },
    Freedom {
        /// `domainStrategy`/`targetStrategy`; non-AsIs values resolve through
        /// the configured DNS app (or the system resolver when absent).
        strategy: crate::protocol::freedom::DomainStrategy,
        redirect: Option<Destination>,
        final_rules: crate::protocol::freedom::FinalRules,
    },
    Blackhole {
        response: Vec<u8>,
    },
    Socks {
        server: Destination,
        account: Option<Account>,
    },
    Http {
        server: Destination,
        account: Option<Account>,
    },
    Vless {
        server: Destination,
        account: crate::protocol::vless::Account,
        /// Outbound account `encryption`: `none` is the plaintext session and
        /// `mlkem768x25519plus` the hybrid encrypted session.
        encryption: Option<std::sync::Arc<crate::protocol::vless_encryption::ClientEncryption>>,
    },
    Trojan {
        server: Destination,
        account: crate::protocol::trojan::Account,
    },
    Masque {
        settings: crate::protocol::masque::Settings,
        server: Destination,
    },
    Wireguard {
        settings: crate::protocol::wireguard::WireGuardConfig,
    },
    Dns {
        settings: crate::protocol::dns_proxy::DnsProxySettings,
    },
    /// Go registers loopback as an outbound only; the inbound arm rejects it.
    Loopback {
        settings: crate::protocol::loopback::LoopbackSettings,
    },
    Hysteria {
        /// The assembled dialer: server destination, TLS client config,
        /// hysteriaSettings auth, and the quicParams congestion/tuning.
        dialer: std::sync::Arc<crate::transport::hysteria_endpoint::HysteriaClientDialer>,
    },
}

pub(crate) struct ValidatedConfig {
    pub observatory: Option<observatory::CompiledObservatory>,
    pub burst: Option<crate::features::observatory_burst::BurstSettings>,
    pub dns: Option<std::sync::Arc<crate::dns::app::DnsApp>>,
    pub reverse: Option<crate::reverse::bridge::ReverseConfig>,
    pub inbounds: Vec<(InboundConfig, Inbound, crate::transport::InboundTransport)>,
    pub outbounds: Vec<Outbound>,
    pub outbound_transports: Vec<crate::transport::OutboundTransport>,
    /// Mux.Cool plans aligned with `outbounds` (None = no multiplexing).
    pub mux: Vec<Option<MuxPlan>>,
    /// The FakeDNS engine (root `fakeDns`, or defaults when a fakedns
    /// nameserver is configured).
    pub fake_dns: Option<std::sync::Arc<crate::dns::fakedns::FakeDnsEngine>>,
    pub router: Router,
}

/// Go's `compareVersions`: dot-separated numeric parts, missing parts are
/// zero, non-numeric parts are errors.
fn compare_versions(left: &str, right: &str) -> Result<std::cmp::Ordering> {
    let parse = |value: &str| -> Result<Vec<u64>> {
        value
            .split('.')
            .map(|part| {
                part.parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid version {value:?}"))
            })
            .collect()
    };
    let (mut left, mut right) = (parse(left)?, parse(right)?);
    let length = left.len().max(right.len());
    left.resize(length, 0);
    right.resize(length, 0);
    Ok(left.cmp(&right))
}

fn default_port() -> PortSpec {
    PortSpec::from_spec("0").expect("port zero parses")
}

/// An inbound's `listen` value: an IP address (the TCP/UDP listener binds)
/// or a filesystem path / abstract name (the unix domain socket listener
/// binds — Go's system_listener.go UnixAddr branch). A path listen requires
/// the dokodemo inbound (Go's unix forwarder); everything else names the
/// conflict.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListenAddress {
    Ip(IpAddr),
    Path(String),
}

impl std::fmt::Display for ListenAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(formatter, "{ip}"),
            Self::Path(path) => write!(formatter, "{path}"),
        }
    }
}

impl ListenAddress {
    /// The IP the socket listeners bind; a path listen fails by name.
    pub fn ip(&self) -> Result<IpAddr> {
        match self {
            Self::Ip(ip) => Ok(*ip),
            Self::Path(path) => bail!(
                "the unix listen address {path:?} requires the dokodemo-door inbound;                  IP listeners cannot bind a socket path"
            ),
        }
    }

    /// The unix socket path (plain, `@abstract`, or `@@padded`), if any.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Path(path) => Some(path),
            Self::Ip(_) => None,
        }
    }
}

fn default_listen() -> ListenAddress {
    ListenAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

fn empty_object() -> Value {
    serde_json::json!({})
}

/// Go's `PortList`: a port number, `"3000"`, or a `"3000-4000"` range; the
/// runtime binds one listener per port.
#[derive(Clone, Debug)]
pub struct PortSpec(Vec<u16>);

impl PortSpec {
    pub fn ports(&self) -> &[u16] {
        &self.0
    }

    /// Parse the Go port forms: a number, "3000", or "3000-4000" (the
    /// RoutingService and the CLI feed these strings).
    pub fn from_spec(spec: &str) -> Result<Self> {
        let ports = match spec.split_once('-') {
            None => vec![
                spec.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("invalid port {spec:?}"))?,
            ],
            Some((start, end)) => {
                let (start, end) = (
                    start
                        .parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("invalid port {spec:?}"))?,
                    end.parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("invalid port {spec:?}"))?,
                );
                anyhow::ensure!(start <= end, "invalid port range {spec:?}");
                (start..=end).collect()
            }
        };
        Ok(Self(ports))
    }

    /// A single-port spec (test/programmatic construction).
    pub fn single(port: u16) -> Self {
        Self(vec![port])
    }
}

impl serde::Serialize for PortSpec {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0.as_slice() {
            [port] => port.serialize(serializer),
            [first, rest @ ..] if !rest.is_empty() => {
                format!("{first}-{}", rest[rest.len() - 1]).serialize(serializer)
            }
            _ => serializer.serialize_none(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for PortSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let ports = match value {
            Value::Number(n) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .map(|port| vec![port]),
            Value::String(text) => match text.split_once('-') {
                None => text.parse::<u16>().ok().map(|port| vec![port]),
                Some((start, end)) => match (start.parse::<u16>(), end.parse::<u16>()) {
                    (Ok(start), Ok(end)) if start <= end => Some((start..=end).collect::<Vec<_>>()),
                    _ => None,
                },
            },
            _ => None,
        };
        ports.map(Self).ok_or_else(|| {
            serde::de::Error::custom("expected a port number or \"a-b\" range within 0..65535")
        })
    }
}

impl Config {
    pub fn from_json(input: &str) -> Result<Self> {
        serde_json::from_str(&strip_comments(input)?)
            .context("invalid or unsupported Xray configuration")
    }

    pub fn validate(&self) -> Result<()> {
        self.compile().map(|_| ())
    }

    pub(crate) fn compile(&self) -> Result<ValidatedConfig> {
        if let Some(log) = &self.log {
            log.build().context("invalid log configuration")?;
        }
        if let Some(api) = &self.api {
            api.validate()?;
            ensure!(
                !api.services
                    .iter()
                    .any(|service| service.eq_ignore_ascii_case("ObservatoryService"))
                    || self.observatory.is_some()
                    || self.burst_observatory.is_some(),
                "ObservatoryService requires a configured observatory or burstObservatory"
            );
        }
        let observatory = self
            .observatory
            .as_ref()
            .map(observatory::ObservatoryConfig::compile)
            .transpose()?;
        let burst = match &self.burst_observatory {
            Some(value) => Some(
                crate::features::observatory_burst::BurstObservatoryConfig::from_value(value)?
                    .build()?,
            ),
            None => None,
        };
        // The DNS app is built eagerly so `xray run --test` reports server,
        // hosts and strategy errors before any listener opens. A fakedns
        // nameserver without a root object gets Go's strategy defaults.
        let fakedns_in_use = self
            .dns
            .as_ref()
            .and_then(|value| value.get("servers"))
            .and_then(|servers| servers.as_array())
            .is_some_and(|servers| {
                servers.iter().any(|server| {
                    let address = match server {
                        Value::String(address) => address.clone(),
                        Value::Object(options) => options
                            .get("address")
                            .and_then(|address| address.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                        _ => String::new(),
                    };
                    address.eq_ignore_ascii_case("fakedns")
                })
            });
        let fake_dns_engine = match &self.fake_dns {
            Some(settings) => Some(std::sync::Arc::new(
                crate::dns::fakedns::FakeDnsEngine::new(settings)?,
            )),
            None if fakedns_in_use => {
                let strategy = self
                    .dns
                    .as_ref()
                    .and_then(|value| value.get("queryStrategy"))
                    .and_then(|strategy| strategy.as_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let (ipv4, ipv6) = match strategy.as_str() {
                    "useipv4" | "useip4" => (true, false),
                    "useipv6" | "useip6" => (false, true),
                    _ => (true, true),
                };
                Some(std::sync::Arc::new(
                    crate::dns::fakedns::FakeDnsEngine::new(
                        &crate::dns::fakedns::FakeDnsSettings::defaults(ipv4, ipv6),
                    )?,
                ))
            }
            None => None,
        };
        let dns = self
            .dns
            .as_ref()
            .map(|value| {
                crate::dns::app::DnsApp::from_value_with_fake_dns(value, fake_dns_engine.clone())
            })
            .transpose()?
            .map(std::sync::Arc::new);
        let reverse = match &self.reverse {
            Some(value) => Some(crate::reverse::bridge::ReverseConfig::from_value(value)?),
            None => None,
        };
        let mut inbound_tags = HashSet::new();
        let mut inbounds = Vec::new();
        for raw in &self.inbounds {
            ensure!(
                raw.tag.is_empty() || inbound_tags.insert(raw.tag.as_str()),
                "duplicate inbound tag {:?}",
                raw.tag
            );
            let (inbound, transport) =
                compile_inbound(raw).with_context(|| format!("inbound {:?}", raw.tag))?;
            // Port 0 binds an ephemeral port (the OS assigns one), matching
            // the runtime tests' convention; explicit ranges validate in the
            // PortSpec parser.
            inbounds.push((raw.clone(), inbound, transport));
        }
        ensure!(
            !self.outbounds.is_empty(),
            "at least one outbound is required"
        );
        let mut outbound_tags = HashSet::new();
        let mut outbounds = Vec::new();
        let mut outbound_transports = Vec::new();
        let mut mux = Vec::new();
        for raw in &self.outbounds {
            ensure!(
                raw.tag.is_empty() || outbound_tags.insert(raw.tag.as_str()),
                "duplicate outbound tag {:?}",
                raw.tag
            );
            let transport = raw
                .stream_settings
                .outbound_transport()
                .with_context(|| format!("outbound {:?}", raw.tag))?;
            outbound_transports.push(transport);
            let plan = match &raw.mux {
                Some(settings) => settings.compile(&raw.protocol)?,
                None => None,
            };
            mux.push(plan);
            outbounds.push(match raw.protocol.as_str() {
                "direct" | "freedom" => {
                    let settings: FreedomSettings = serde_json::from_value(raw.settings.clone()).context("freedom settings")?;
                    let strategy = if settings.target_strategy.is_empty() { &settings.domain_strategy } else { &settings.target_strategy };
                    let strategy = crate::protocol::freedom::DomainStrategy::parse(strategy)?;
                    Outbound::Freedom { strategy, redirect: if settings.redirect.is_empty() { None } else { Some(Destination::parse_authority(&settings.redirect, None)?) }, final_rules: crate::protocol::freedom::FinalRules::compile(&settings.final_rules)? }
                }
                "block" | "blackhole" => {
                    let settings: BlackholeSettings = serde_json::from_value(raw.settings.clone()).context("blackhole settings")?;
                    let response = settings.response.unwrap_or_default();
                    let response = match response.r#type.to_ascii_lowercase().as_str() {
                        "" | "none" => vec![],
                        "http" => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\n\r\n".to_vec(),
                        "custom" => STANDARD.decode(response.custom_response_data).context("invalid blackhole response base64")?,
                        other => bail!("unknown blackhole response {other:?}"),
                    };
                    Outbound::Blackhole { response }
                }
                "socks" | "http" | "vless" | "trojan" | "shadowsocks" => proxies::outbound(&raw.protocol, &raw.settings)?,
                "vmess" => vmess::outbound(&raw.settings)?,
                "masque" => {
                    let settings = crate::protocol::masque::Settings::from_value(&raw.settings)
                        .context("MASQUE outbound settings")?;
                    // Go's proxy constructor rejects anything but the masque
                    // transport secured with TLS, at compile time.
                    crate::protocol::masque::check_stream_settings(
                        &raw.stream_settings.network,
                        &raw.stream_settings.security,
                    )?;
                    let server = settings.server_destination()?;
                    Outbound::Masque { settings, server }
                }
                "dns" => {
                    let settings = crate::protocol::dns_proxy::DnsProxySettings::from_value(
                        &raw.settings,
                    )
                    .context("dns outbound settings")?;
                    crate::protocol::dns_proxy::DnsProxy::compile(&settings)
                        .context("dns outbound settings")?;
                    Outbound::Dns { settings }
                }
                "loopback" => {
                    let settings = crate::protocol::loopback::LoopbackSettings::from_value(
                        &raw.settings,
                    )
                    .context("loopback outbound settings")?;
                    Outbound::Loopback { settings }
                }
                "wireguard" => {
                    let settings: crate::protocol::wireguard::WireGuardConfig =
                        serde_json::from_value(raw.settings.clone())
                            .context("WireGuard outbound settings")?;
                    // Build once here so invalid keys and peers fail before any
                    // listener opens; the runtime keeps the raw settings value.
                    settings
                        .build(crate::protocol::wireguard::Role::Client)
                        .context("WireGuard outbound settings")?;
                    Outbound::Wireguard { settings }
                }
                "hysteria" => {
                    let settings =
                        crate::protocol::hysteria_runtime::HysteriaOutboundSettings::from_value(
                            &raw.settings,
                        )
                        .context("hysteria outbound settings")?;
                    settings
                        .validate()
                        .context("hysteria outbound settings")?;
                    ensure!(
                        raw.stream_settings.network == "hysteria",
                        "the hysteria outbound requires streamSettings.network \"hysteria\""
                    );
                    let transport_settings =
                        crate::transport::hysteria_endpoint::HysteriaTransportSettings::from_value(
                            raw.stream_settings
                                .hysteria_settings
                                .as_ref()
                                .context("the hysteria outbound requires hysteriaSettings")?,
                        )
                        .context("hysteriaSettings")?;
                    transport_settings
                        .validate()
                        .context("hysteriaSettings")?;
                    let tls = stream_tls_settings(&raw.stream_settings)?;
                    let server = settings.server()?;
                    // The QUIC server name falls back to the dialed host like
                    // Go's TLSConfig (ServerName empty means the address).
                    let server_name = if tls.server_name.is_empty() {
                        match &server.address {
                            crate::address::Address::Domain(host) => host.clone(),
                            crate::address::Address::Ip(ip) => ip.to_string(),
                        }
                    } else {
                        tls.server_name.clone()
                    };
                    let client_tls = tls
                        .build_client_config()
                        .context("hysteria outbound tlsSettings")?;
                    let quic = raw.stream_settings.quic_params()?;
                    let congestion = congestion_or_reject(&quic)?;
                    let dialer = crate::protocol::hysteria_runtime::client_dialer(
                        &server,
                        &server_name,
                        (*client_tls).clone(),
                        &transport_settings.auth,
                        quic.brutal_down_bps,
                        congestion,
                    )
                    .with_quic_params(quic);
                    Outbound::Hysteria {
                        dialer: std::sync::Arc::new(dialer),
                    }
                }
                other => bail!("outbound protocol {other:?} is not migrated yet"),
            });
        }
        let mut routing_outbounds = self.outbounds.clone();
        if let Some(api) = &self.api {
            ensure!(
                !outbound_tags.contains(api.tag.as_str()),
                "API tag conflicts with outbound"
            );
            outbounds.push(Outbound::Api);
            outbound_transports.push(crate::transport::OutboundTransport::default());
            mux.push(None);
            routing_outbounds.push(OutboundConfig {
                tag: api.tag.clone(),
                protocol: "internal-api".into(),
                settings: empty_object(),
                stream_settings: StreamSettings::default(),
                mux: None,
            });
        }
        // Reverse portal tags are routing outbounds exactly like Go's portal
        // handlers in the outbound manager (app/reverse/portal.go Start), so
        // routing rules may select them.
        if let Some(reverse) = &reverse {
            for portal in &reverse.portals {
                ensure!(
                    !outbound_tags.contains(portal.tag.as_str()),
                    "reverse portal tag {:?} conflicts with another outbound tag",
                    portal.tag
                );
                routing_outbounds.push(OutboundConfig {
                    tag: portal.tag.clone(),
                    protocol: "reverse-portal".into(),
                    settings: empty_object(),
                    stream_settings: StreamSettings::default(),
                    mux: None,
                });
            }
        }
        // Go's app/version: refuse to run outside [min, max] against the
        // core version (semantic triples, each part optional).
        if let Some(version) = &self.version {
            let core = env!("CARGO_PKG_VERSION");
            for (bound, name) in [(&version.min, "min"), (&version.max, "max")] {
                if !bound.is_empty() && compare_versions(core, bound).is_err_and(|_| true) {
                    bail!("invalid version bound {bound:?} in {name}");
                }
            }
            if !version.min.is_empty()
                && compare_versions(core, &version.min)
                    .is_ok_and(|ordering| ordering == std::cmp::Ordering::Less)
            {
                bail!(
                    "this config must be run on version {} or higher",
                    version.min
                );
            }
            if !version.max.is_empty()
                && compare_versions(core, &version.max)
                    .is_ok_and(|ordering| ordering == std::cmp::Ordering::Greater)
            {
                bail!(
                    "this config must be run on version {} or lower",
                    version.max
                );
            }
        }
        // Go's app/geodata: the download/swap scheduler is a separate app;
        // paths are honored through the environment, and cron/outbound
        // name the missing scheduler explicitly.
        if let Some(geodata) = &self.geodata {
            let scheduler_requested = geodata.cron.is_some()
                || !geodata.outbound.is_empty()
                || !geodata.assets.is_empty();
            if scheduler_requested {
                bail!(
                    "the geodata download/swap scheduler is not integrated in this runtime build;                      provide assets through the geodata environment paths"
                );
            }
        }
        // Go's app/metrics serves pprof over HTTP; the profiler is absent.
        if let Some(metrics) = &self.metrics {
            let _ = metrics;
            bail!("the metrics pprof endpoint is not integrated in this runtime build");
        }
        let router = Router::compile(&self.routing, &routing_outbounds)?;
        Ok(ValidatedConfig {
            observatory,
            burst,
            dns,
            reverse,
            inbounds,
            outbounds,
            outbound_transports,
            mux,
            fake_dns: fake_dns_engine,
            router,
        })
    }
}

/// Compile one inbound: parse its transport settings and protocol accounts.
/// Shared by `Config::compile` and the HandlerService runtime registry, which
/// validates dynamically added inbounds through the same rules.
/// The TLS settings a QUIC transport (hysteria, masque) dials or binds with:
/// validated and compiled once here so a certificate problem fails at config
/// parse, exactly where Go's transport constructor fails.
fn stream_tls_settings(stream: &StreamSettings) -> Result<crate::transport::tls::TlsSettings> {
    ensure!(
        stream.security == "tls",
        "the transport requires \"security\": \"tls\""
    );
    let settings: crate::transport::tls::TlsSettings =
        serde_json::from_value(stream.tls_settings.clone().unwrap_or_else(empty_object))
            .context("tlsSettings")?;
    Ok(settings)
}

/// The quicParams congestion selection: reno compiles to Quinn's NewReno;
/// the pinned BBR profiles and Brutal are named rejections (never a silent
/// downgrade). The peer's advertised receive bandwidth arrives per
/// connection at runtime, so the negotiation runs over the configured
/// up/down pair.
pub(crate) fn congestion_or_reject(
    quic: &crate::transport::finalmask::QuicParams,
) -> Result<crate::transport::hysteria::NativeCongestion> {
    let mode = crate::transport::hysteria::CongestionMode::from_name(&quic.congestion)?;
    let profile = crate::transport::hysteria::BbrProfile::from_name(&quic.bbr_profile)?;
    crate::transport::hysteria::negotiate_congestion(
        mode,
        profile,
        quic.brutal_up_bps,
        quic.brutal_down_bps,
        quic.brutal_disable_loss_compensation,
    )
    .supported_native_controller()
}

pub(crate) fn compile_inbound(
    raw: &InboundConfig,
) -> Result<(Inbound, crate::transport::InboundTransport)> {
    if let Some(sniffing) = &raw.sniffing {
        sniffing.validate().context("inbound sniffing settings")?;
    }
    // A path `listen` binds a unix domain socket: only the dokodemo
    // forwarder may own one (Go's unix listener serves dokodemo).
    if let Some(path) = raw.listen.path() {
        ensure!(
            matches!(raw.protocol.as_str(), "dokodemo-door" | "tunnel"),
            "the unix listen address {path:?} requires the dokodemo-door inbound"
        );
    }
    let transport = raw.stream_settings.inbound_transport()?;
    let inbound = match raw.protocol.as_str() {
        // Go registers `mixed` as the SOCKS server config: same handler.
        "mixed" | "socks" => {
            let mut settings: SocksSettings =
                serde_json::from_value(raw.settings.clone()).context("SOCKS inbound settings")?;
            ensure!(
                matches!(settings.auth.as_str(), "" | "noauth" | "password"),
                "unknown SOCKS authentication method"
            );
            if !settings.accounts.is_empty() {
                settings.users = None;
            }
            if let Some(users) = settings.users.take() {
                settings.accounts = users;
            }
            if settings.auth == "password" {
                ensure!(
                    !settings.accounts.is_empty(),
                    "SOCKS password authentication requires accounts"
                );
                for account in &settings.accounts {
                    ensure!(
                        (1..=255).contains(&account.user.len())
                            && (1..=255).contains(&account.pass.len()),
                        "SOCKS credentials must contain 1..255 bytes"
                    );
                }
            }
            Inbound::Socks(settings)
        }
        "http" => {
            let mut settings: HttpSettings =
                serde_json::from_value(raw.settings.clone()).context("HTTP inbound settings")?;
            ensure!(
                !settings.allow_transparent,
                "transparent HTTP is not migrated yet"
            );
            if !settings.accounts.is_empty() {
                settings.users = None;
            }
            if let Some(users) = settings.users.take() {
                settings.accounts = users;
            }
            Inbound::Http(settings)
        }
        "tunnel" | "dokodemo-door" => {
            let settings: DokodemoSettings =
                serde_json::from_value(raw.settings.clone()).context("dokodemo settings")?;
            ensure!(
                !settings.follow_redirect,
                "transparent socket redirection is not migrated yet"
            );
            let network = settings
                .network
                .or(settings.allowed_network)
                .unwrap_or_else(|| "tcp".to_owned());
            // Go's NetworkList: comma-separated tcp/udp/unix entries. The
            // unix entry rides the unix LISTENER (a path `listen`); over a
            // unix connection dokodemo forwards as TCP (dokodemo.go:76), so
            // it contributes no UDP here.
            let mut udp = false;
            for entry in network.split(',') {
                match entry {
                    "tcp" | "unix" => (),
                    "udp" => udp = true,
                    other => bail!("unknown dokodemo network {other:?}"),
                }
            }
            ensure!(
                network.split(',').any(|entry| entry != "udp"),
                "udp-only dokodemo-door is not supported; use tcp,udp"
            );
            let host = settings
                .address
                .or(settings.rewrite_address)
                .context("dokodemo requires address")?;
            let port = if settings.port == 0 {
                settings.rewrite_port
            } else {
                settings.port
            };
            Inbound::Dokodemo {
                destination: Destination::new(&host, port)?,
                udp,
            }
        }
        "vless" | "trojan" | "shadowsocks" => proxies::inbound(&raw.protocol, &raw.settings)?,
        "vmess" => vmess::inbound(&raw.settings)?,
        "hysteria" => {
            let settings = crate::protocol::hysteria_runtime::HysteriaInboundSettings::from_value(
                &raw.settings,
            )
            .context("hysteria inbound settings")?;
            settings.validate().context("hysteria inbound settings")?;
            // The transport pieces the QUIC listener compiles from the stream
            // settings fail here, at parse time, like Go's proxy constructor
            // ("not hysteria transport") and hub.Listen.
            ensure!(
                raw.stream_settings.network == "hysteria",
                "the hysteria inbound requires streamSettings.network \"hysteria\""
            );
            let transport_settings =
                crate::transport::hysteria_endpoint::HysteriaTransportSettings::from_value(
                    raw.stream_settings
                        .hysteria_settings
                        .as_ref()
                        .context("the hysteria inbound requires hysteriaSettings")?,
                )
                .context("hysteriaSettings")?;
            transport_settings.validate().context("hysteriaSettings")?;
            // The rustls server config must compile before startup (the
            // runtime rebuilds it from the same settings when it binds).
            let server_tls = stream_tls_settings(&raw.stream_settings)?;
            let _ = server_tls.build_server_config()?;
            let quic = raw.stream_settings.quic_params()?;
            // The transport auth secret or the proxy users must authenticate
            // someone (Go's hub validator-or-auth check), and the masquerade
            // plus congestion compile exactly as hub.Listen would.
            crate::transport::hysteria_endpoint::HysteriaServerOptions {
                users: settings.effective_users().to_vec(),
                auth: transport_settings.auth.clone(),
                masquerade: transport_settings.masquerade.compile()?,
                udp_idle_timeout: transport_settings.udp_idle_timeout(),
                receive_bytes_per_second: quic.brutal_down_bps,
                congestion: congestion_or_reject(&quic)?,
                quic: quic.clone(),
            }
            .validate()
            .context("hysteria inbound settings")?;
            Inbound::Hysteria {
                users: settings.effective_users().to_vec(),
            }
        }
        "tun" => {
            let entry = crate::runtime::tun_inbound::compile_inbound(&raw.settings)
                .context("tun inbound settings")?;
            Inbound::Tun {
                entry: std::sync::Arc::new(entry),
            }
        }
        "wireguard" => {
            let entry = crate::runtime::wireguard_inbound::compile_inbound(&raw.settings)
                .context("WireGuard inbound settings")?;
            Inbound::Wireguard { entry }
        }
        "dns" => {
            let settings = crate::protocol::dns_proxy::DnsProxySettings::from_value(&raw.settings)
                .context("dns inbound settings")?;
            crate::protocol::dns_proxy::DnsProxy::compile(&settings)
                .context("dns inbound settings")?;
            Inbound::Dns(settings)
        }
        "loopback" => {
            bail!("loopback is an outbound protocol only; Go registers no loopback inbound")
        }
        other => bail!("inbound protocol {other:?} is not migrated yet"),
    };
    Ok((inbound, transport))
}

/// Strip Java/Python-style comments without changing byte offsets or line numbers.
pub fn strip_comments(input: &str) -> Result<String> {
    let mut bytes = input.as_bytes().to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'#' | b'/' if bytes[i] == b'#' || bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    bytes[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                bytes[i] = b' ';
                bytes[i + 1] = b' ';
                i += 2;
                let mut closed = false;
                while i < bytes.len() {
                    if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        bytes[i] = b' ';
                        bytes[i + 1] = b' ';
                        i += 2;
                        closed = true;
                        break;
                    }
                    if bytes[i] != b'\n' && bytes[i] != b'\r' {
                        bytes[i] = b' ';
                    }
                    i += 1;
                }
                ensure!(closed, "unterminated block comment");
            }
            _ => i += 1,
        }
    }
    Ok(String::from_utf8(bytes).expect("comments are replaced by ASCII spaces"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comments_do_not_corrupt_strings_or_line_numbers() {
        let input = "{ /* é */\n\"url\": \"http://host/#a\", // comment\n\"text\": \"\\\"/*ok*/\" # comment\n}";
        let output = strip_comments(input).unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["url"], "http://host/#a");
        assert_eq!(value["text"], "\"/*ok*/");
        assert_eq!(input.len(), output.len());
        assert_eq!(input.lines().count(), output.lines().count());
        assert!(strip_comments("{/* never ends").is_err());
    }
    #[test]
    fn rejects_unimplemented_security_instead_of_downgrading() {
        let config = Config::from_json(
            r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"reality"}}]}"#,
        )
        .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("outbound")
        );
        let config = Config::from_json(
            r#"{"outbounds":[{"protocol":"freedom","settings":{"fragment":{}}}]}"#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn root_version_env_geodata_and_metrics_follow_go() {
        let config = Config::from_json(
            r#"{"version":{"min":"0.0.0","max":"999.0.0"},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        config.validate().unwrap();
        // A min bound above the core version refuses to run.
        let config = Config::from_json(
            r#"{"version":{"min":"999.0.0"},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("999.0.0 or higher"), "{error}");
        // A max below the core version refuses too.
        let config = Config::from_json(
            r#"{"version":{"max":"0.0.1"},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        assert!(config.validate().unwrap_err().to_string().contains("lower"));
        // env is tolerated (the CLI loader consumes it).
        Config::from_json(r#"{"env":{"A":"a"},"outbounds":[{"protocol":"freedom"}]}"#)
            .unwrap()
            .validate()
            .unwrap();
        // geodata's scheduler and the metrics app name their gaps explicitly.
        let config = Config::from_json(
            r#"{"geodata":{"cron":"0 0 * * *"},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("geodata")
        );
        let config = Config::from_json(
            r#"{"metrics":{"tag":"metrics","listen":"127.0.0.1:0"},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("metrics")
        );
    }

    #[test]
    fn user_policy_levels_parse_across_proxies() {
        // Non-zero user levels are accepted everywhere Go accepts them; the
        // runtime selects the session policy through the request's level.
        let cases = [
            (
                "vless",
                r#"{"decryption":"none","clients":[{"id":"example","level":3}]}"#,
            ),
            ("trojan", r#"{"clients":[{"password":"pw","level":3}]}"#),
            (
                "shadowsocks",
                r#"{"method":"aes-256-gcm","password":"pw","level":3}"#,
            ),
            (
                "shadowsocks",
                r#"{"method":"2022-blake3-aes-256-gcm","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","level":3}"#,
            ),
        ];
        for (protocol, settings) in cases {
            let config = Config::from_json(&format!(
                r#"{{"inbounds":[{{"listen":"127.0.0.1","port":1080,"protocol":"{protocol}","settings":{settings}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#
            ))
            .unwrap_or_else(|error| panic!("{protocol}: {error:#}"));
            config
                .validate()
                .unwrap_or_else(|error| panic!("{protocol}: {error:#}"));
        }
    }

    #[test]
    fn root_apps_parse_and_reject_go_visibly() {
        // The `dns` root key is accepted and compiled by the DNS app; an empty
        // server list is rejected with the app's own error, not an unknown
        // field error.
        let config = Config::from_json(
            r#"{"dns":{"servers":["1.1.1.1"]},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        assert!(config.validate().is_ok());
        let config =
            Config::from_json(r#"{"dns":{"servers":[]},"outbounds":[{"protocol":"freedom"}]}"#)
                .unwrap();
        assert!(config.validate().is_err());
        // `reverse` is a recognized root key compiled by ReverseConfig.
        let config = Config::from_json(
            r#"{"reverse":{"portals":[{"tag":"portal","domain":"test.example"}]},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        assert!(config.validate().is_ok());
        assert!(Config::from_json(r#"{"unknownRoot":1}"#).is_err());
        // burstObservatory without pingConfig fails like Go's builder.
        let config = Config::from_json(
            r#"{"burstObservatory":{"subjectSelector":["a"]},"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }
}

#[cfg(test)]
mod tun_wireguard_config_tests {
    use super::*;

    const SERVER_PRIVATE: &str = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=";
    const CLIENT_PUBLIC: &str = "osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=";

    /// The `tun` inbound arm compiles through the real config surface: no
    /// port key is present (Go's tun binds no listener) and validation
    /// reaches the runtime entry.
    #[test]
    fn tun_inbound_parses_without_a_port_and_compiles() {
        let config = Config::from_json(
            r#"{"inbounds":[{"listen":"127.0.0.1","tag":"tun-in","protocol":"tun",
                 "settings":{"name":"test-tun","gateway":["172.19.0.1/30"],"mtu":1500}}],
               "outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        config.validate().expect("the tun inbound compiles");
        // An invalid option names itself at parse time.
        let rejected = Config::from_json(
            r#"{"inbounds":[{"protocol":"tun",
                 "settings":{"name":"x","gateway":["172.19.0.1/30"],"mtu":100}}],
               "outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        let error = rejected.validate().unwrap_err();
        assert!(format!("{error:#}").contains("mtu"), "{error:#}");
    }

    /// The `wireguard` inbound arm compiles with one UDP endpoint per port.
    #[test]
    fn wireguard_inbound_parses_and_compiles() {
        let settings = format!(
            r#"{{"secretKey":"{SERVER_PRIVATE}","address":["10.0.0.1"],
                "peers":[{{"publicKey":"{CLIENT_PUBLIC}","allowedIPs":["10.0.0.2/32"]}}]}}"#
        );
        let config = Config::from_json(&format!(
            r#"{{"inbounds":[{{"listen":"127.0.0.1","port":51820,"tag":"wg-in",
                "protocol":"wireguard","settings":{settings}}}],
              "outbounds":[{{"protocol":"freedom"}}]}}"#
        ))
        .unwrap();
        config.validate().expect("the wireguard inbound compiles");
    }
}
