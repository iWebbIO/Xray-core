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
                    "statsservice" | "loggerservice" | "observatoryservice" | "handlerservice"
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
    pub listen: IpAddr,
    #[serde(deserialize_with = "port_value")]
    pub port: u16,
    pub protocol: String,
    #[serde(default = "empty_object")]
    pub settings: Value,
    #[serde(default)]
    pub stream_settings: StreamSettings,
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
            !matches!(self.network.as_str(), "kcp" | "mkcp") || self.security != "reality",
            "KCP does not support REALITY security"
        );
        ensure!(
            self.network != "masque" || self.security == "tls",
            "the masque transport requires \"security\": \"tls\""
        );
        Ok(())
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
    Dokodemo(Destination),
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
    Shadowsocks(crate::protocol::shadowsocks_session::Account),
    Shadowsocks2022 {
        account: crate::protocol::shadowsocks2022::Account,
        /// `network: "tcp,udp"` opts into the 2022 UDP listener; the absent
        /// field means TCP only, exactly like Go's nil NetworkList.
        udp: bool,
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
}

pub(crate) struct ValidatedConfig {
    pub observatory: Option<observatory::CompiledObservatory>,
    pub burst: Option<crate::features::observatory_burst::BurstSettings>,
    pub dns: Option<std::sync::Arc<crate::dns::app::DnsApp>>,
    pub reverse: Option<crate::reverse::bridge::ReverseConfig>,
    pub inbounds: Vec<(InboundConfig, Inbound, crate::transport::InboundTransport)>,
    pub outbounds: Vec<Outbound>,
    pub outbound_transports: Vec<crate::transport::OutboundTransport>,
    pub router: Router,
}

fn default_listen() -> IpAddr {
    IpAddr::from([0, 0, 0, 0])
}
fn empty_object() -> Value {
    serde_json::json!({})
}

fn port_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    let value = Value::deserialize(deserializer)?;
    let parsed = match value {
        Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    };
    parsed.ok_or_else(|| {
        serde::de::Error::custom(
            "expected a port number in 0..65535; port ranges are not migrated yet",
        )
    })
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
        // hosts and strategy errors before any listener opens.
        let dns = self
            .dns
            .as_ref()
            .map(crate::dns::app::DnsApp::from_value)
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
            inbounds.push((raw.clone(), inbound, transport));
        }
        ensure!(
            !self.outbounds.is_empty(),
            "at least one outbound is required"
        );
        let mut outbound_tags = HashSet::new();
        let mut outbounds = Vec::new();
        let mut outbound_transports = Vec::new();
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
            outbounds.push(match raw.protocol.as_str() {
                "freedom" => {
                    let settings: FreedomSettings = serde_json::from_value(raw.settings.clone()).context("freedom settings")?;
                    let strategy = if settings.target_strategy.is_empty() { &settings.domain_strategy } else { &settings.target_strategy };
                    let strategy = crate::protocol::freedom::DomainStrategy::parse(strategy)?;
                    ensure!(settings.user_level == 0, "user policy levels are not migrated yet");
                    Outbound::Freedom { strategy, redirect: if settings.redirect.is_empty() { None } else { Some(Destination::parse_authority(&settings.redirect, None)?) }, final_rules: crate::protocol::freedom::FinalRules::compile(&settings.final_rules)? }
                }
                "blackhole" => {
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
            routing_outbounds.push(OutboundConfig {
                tag: api.tag.clone(),
                protocol: "internal-api".into(),
                settings: empty_object(),
                stream_settings: StreamSettings::default(),
            });
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
            router,
        })
    }
}

/// Compile one inbound: parse its transport settings and protocol accounts.
/// Shared by `Config::compile` and the HandlerService runtime registry, which
/// validates dynamically added inbounds through the same rules.
pub(crate) fn compile_inbound(
    raw: &InboundConfig,
) -> Result<(Inbound, crate::transport::InboundTransport)> {
    let transport = raw.stream_settings.inbound_transport()?;
    let inbound = match raw.protocol.as_str() {
        "socks" => {
            let mut settings: SocksSettings =
                serde_json::from_value(raw.settings.clone()).context("SOCKS inbound settings")?;
            ensure!(
                matches!(settings.auth.as_str(), "" | "noauth" | "password"),
                "unknown SOCKS authentication method"
            );
            ensure!(
                settings.user_level == 0,
                "user policy levels are not migrated yet"
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
                settings.user_level == 0,
                "user policy levels are not migrated yet"
            );
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
        "dokodemo-door" => {
            let settings: DokodemoSettings =
                serde_json::from_value(raw.settings.clone()).context("dokodemo settings")?;
            ensure!(
                !settings.follow_redirect,
                "transparent socket redirection is not migrated yet"
            );
            ensure!(
                settings.user_level == 0,
                "user policy levels are not migrated yet"
            );
            let network = settings
                .network
                .or(settings.allowed_network)
                .unwrap_or_else(|| "tcp".to_owned());
            ensure!(network == "tcp", "dokodemo UDP is not migrated yet");
            let host = settings
                .address
                .or(settings.rewrite_address)
                .context("dokodemo requires address")?;
            let port = if settings.port == 0 {
                settings.rewrite_port
            } else {
                settings.port
            };
            Inbound::Dokodemo(Destination::new(&host, port)?)
        }
        "vless" | "trojan" | "shadowsocks" => proxies::inbound(&raw.protocol, &raw.settings)?,
        "vmess" => vmess::inbound(&raw.settings)?,
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
