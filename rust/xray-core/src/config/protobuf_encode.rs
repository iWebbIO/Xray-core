// Config-to-protobuf encoder: the exact inverse of `config/protobuf.rs`,
// powering `xray convert pb` (main/commands/all/convert/protobuf.go).
#![allow(dead_code)]
//! One validated JSON [`Config`] becomes the bytes of the `xray.core.Config`
//! message Go's `proto.Marshal` writes to a `.pb` file. The decoder in
//! `config/protobuf.rs` is the specification: every proto shape it fails
//! closed on (`supported_rest`/`bail!`) is refused here with a named error on
//! the corresponding JSON key, so a config that validates round-trips:
//! `to_bytes(config) -> from_bytes(bytes) -> an equivalent config`. No field
//! is ever silently dropped to fit the wire format.

use std::net::IpAddr;

use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use prost::Message;
use serde::Deserialize;
use serde_json::Value;

use crate::proto::xray::{self as p, common::serial::TypedMessage};
use crate::router::{PortSpec as RulePortSpec, RuleConfig, RoutingConfig};

use super::{
    ApiConfig, Config, DokodemoSettings, FreedomSettings, HttpSettings, InboundConfig,
    ListenAddress, LogConfig, OutboundConfig, SocksSettings, StreamSettings,
};

/// Encode one validated JSON [`Config`] into the `xray.core.Config`
/// protobuf message. Everything the decoder cannot consume fails with a
/// named error here, never a lossy encoding.
pub fn to_core_config(config: &Config) -> Result<p::core::Config> {
    // Root keys whose apps the decoder refuses ("is not integrated") are
    // refused by name instead of emitting a config the runtime could not
    // read back.
    if config.dns.is_some() {
        bail!("the \"dns\" app has no representation in the protobuf decoder envelope (xray.app.dns.Config is not integrated)");
    }
    if config.reverse.is_some() {
        bail!("\"reverse\" has no representation in the protobuf decoder envelope (the reverse app is not integrated)");
    }
    if config.burst_observatory.is_some() {
        bail!("\"burstObservatory\" has no representation in the protobuf decoder envelope (the burst observatory app is not integrated)");
    }
    if config.fake_dns.is_some() {
        bail!("\"fakeDns\" has no representation in the protobuf decoder envelope (the fakedns app is not integrated)");
    }
    if config.metrics.is_some() {
        bail!("\"metrics\" has no representation in the protobuf decoder envelope (the pprof app is not integrated)");
    }
    if config.version.is_some() {
        bail!("\"version\" has no representation in the protobuf decoder envelope (the version app is not integrated)");
    }
    if config.geodata.is_some() {
        bail!("\"geodata\" has no representation in the protobuf decoder envelope (the geodata scheduler app is not integrated)");
    }
    if let Some(env) = &config.env {
        ensure!(
            env.is_empty(),
            "the \"env\" map is consumed by the config loader before encoding; the protobuf carries no environment"
        );
    }
    ensure!(
        config.routing.balancers.is_empty(),
        "routing \"balancers\" have no representation in the protobuf decoder envelope (balancing rules are not integrated)"
    );
    // Go's Build always emits the logger first (DefaultLogConfig when the
    // JSON has no log object), then dispatcher/proxyman, then the optional
    // apps in infra/conf/xray.go's order.
    let mut app = vec![
        TypedMessage::pack(&log_app(config.log.as_ref())),
        TypedMessage::pack(&p::app::dispatcher::Config::default()),
        TypedMessage::pack(&p::app::proxyman::InboundConfig::default()),
        TypedMessage::pack(&p::app::proxyman::OutboundConfig::default()),
    ];
    if let Some(api) = &config.api {
        app.push(TypedMessage::pack(&api_app(api)?));
    }
    if config.stats.is_some() {
        app.push(TypedMessage::pack(&p::app::stats::Config::default()));
    }
    if !config.routing.rules.is_empty() || !config.routing.domain_strategy.is_empty() {
        app.push(TypedMessage::pack(&routing_app(&config.routing)?));
    }
    if let Some(policy) = &config.policy {
        app.push(TypedMessage::pack(&policy_app(policy)?));
    }
    if let Some(observatory) = &config.observatory {
        app.push(TypedMessage::pack(&observatory_app(observatory)?));
    }
    Ok(p::core::Config {
        app,
        inbound: config
            .inbounds
            .iter()
            .map(inbound_handler)
            .collect::<Result<_>>()?,
        outbound: config
            .outbounds
            .iter()
            .map(outbound_handler)
            .collect::<Result<_>>()?,
        extension: Vec::new(),
    })
}

/// Marshal to the bytes the `xray convert pb` command writes.
pub fn to_bytes(config: &Config) -> Result<Vec<u8>> {
    Ok(to_core_config(config)?.encode_to_vec())
}

// ---------------------------------------------------------------------------
// Handler wrappers
// ---------------------------------------------------------------------------

fn inbound_handler(raw: &InboundConfig) -> Result<p::core::InboundHandlerConfig> {
    let listen = match &raw.listen {
        ListenAddress::Ip(ip) => *ip,
        ListenAddress::Path(path) => bail!(
            "the unix listen address {path:?} has no protobuf representation (the decoder integrates IP listeners only)"
        ),
    };
    let port = single_port(&raw.port, &raw.tag)?;
    let receiver = p::app::proxyman::ReceiverConfig {
        port_list: Some(p::common::net::PortList {
            range: vec![p::common::net::PortRange {
                from: u32::from(port),
                to: u32::from(port),
            }],
        }),
        listen: Some(ip_or_domain(&listen.to_string(), "inbound listen")?),
        stream_settings: stream_config(&raw.stream_settings)?,
        receive_original_destination: false,
        sniffing_settings: raw
            .sniffing
            .as_ref()
            .map(sniffing_config)
            .transpose()?,
    };
    Ok(p::core::InboundHandlerConfig {
        tag: raw.tag.clone(),
        receiver_settings: Some(TypedMessage::pack(&receiver)),
        proxy_settings: Some(inbound_proxy(&raw.protocol, &raw.settings)?),
    })
}

fn outbound_handler(raw: &OutboundConfig) -> Result<p::core::OutboundHandlerConfig> {
    // A disabled mux message is tolerated (and dropped) by the decoder, like
    // the unused defaults Go carries in configs from its builder; an enabled
    // mux is refused because the decoder's sender envelope has no place for
    // it.
    let mux = match &raw.mux {
        None => None,
        Some(mux) if !mux.enabled => Some(p::app::proxyman::MultiplexingConfig {
            enabled: false,
            concurrency: i32::from(mux.concurrency),
            xudp_concurrency: i32::from(mux.xudp_concurrency),
            xudp_proxy_udp443: match mux.xudp_proxy_udp443.as_str() {
                "" | "reject" => "reject".into(),
                policy @ ("allow" | "skip") => policy.into(),
                other => bail!("unknown \"xudpProxyUDP443\": {other}"),
            },
        }),
        Some(_) => bail!(
            "outbound \"mux\" has no representation in the protobuf decoder envelope (multiplexing settings are not integrated)"
        ),
    };
    let sender = p::app::proxyman::SenderConfig {
        stream_settings: stream_config(&raw.stream_settings)?,
        multiplex_settings: mux,
        ..Default::default()
    };
    Ok(p::core::OutboundHandlerConfig {
        tag: raw.tag.clone(),
        sender_settings: Some(TypedMessage::pack(&sender)),
        proxy_settings: Some(outbound_proxy(&raw.protocol, &raw.settings)?),
        ..Default::default()
    })
}

fn single_port(spec: &super::PortSpec, tag: &str) -> Result<u16> {
    let ports = spec.ports();
    if let [port] = ports {
        return Ok(*port);
    }
    let shown = match (ports.first(), ports.last()) {
        (Some(first), Some(last)) if first == last => first.to_string(),
        (Some(first), Some(last)) => format!("{first}-{last}"),
        _ => "list".to_owned(),
    };
    bail!(
        "inbound {tag:?} port {shown} cannot be represented: the protobuf decoder integrates exactly one port per listener"
    );
}

/// An address string: an IP becomes the `ip` oneof arm (IPv4-mapped IPv6
/// collapses to four bytes like Go's `ParseAddress`); anything else is a
/// domain, which must be non-empty so the decoder can retain its type.
fn ip_or_domain(address: &str, context: &str) -> Result<p::common::net::IpOrDomain> {
    let address = match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(value)) => p::common::net::ip_or_domain::Address::Ip(value.octets().to_vec()),
        Ok(IpAddr::V6(value)) => match value.to_ipv4_mapped() {
            Some(v4) => p::common::net::ip_or_domain::Address::Ip(v4.octets().to_vec()),
            None => p::common::net::ip_or_domain::Address::Ip(value.octets().to_vec()),
        },
        Err(_) => {
            ensure!(
                !address.is_empty(),
                "{context} address cannot be empty (the protobuf domain would be empty)"
            );
            p::common::net::ip_or_domain::Address::Domain(address.to_owned())
        }
    };
    Ok(p::common::net::IpOrDomain {
        address: Some(address),
    })
}

fn user_message(
    email: &str,
    level: u32,
    account: TypedMessage,
) -> p::common::protocol::User {
    p::common::protocol::User {
        level,
        email: email.to_owned(),
        account: Some(account),
    }
}

fn server_endpoint(
    address: &str,
    port: u16,
    user: Option<p::common::protocol::User>,
    context: &str,
) -> Result<p::common::protocol::ServerEndpoint> {
    Ok(p::common::protocol::ServerEndpoint {
        address: Some(ip_or_domain(address, context)?),
        port: u32::from(port),
        user,
    })
}

// ---------------------------------------------------------------------------
// Inbound proxy settings
// ---------------------------------------------------------------------------

fn inbound_proxy(protocol: &str, settings: &Value) -> Result<TypedMessage> {
    match protocol {
        "socks" | "mixed" => Ok(TypedMessage::pack(&socks_inbound(settings)?)),
        "http" => Ok(TypedMessage::pack(&http_inbound(settings)?)),
        "dokodemo-door" | "tunnel" => Ok(TypedMessage::pack(&dokodemo_inbound(settings)?)),
        "vless" => Ok(TypedMessage::pack(&vless_inbound(settings)?)),
        "vmess" => Ok(TypedMessage::pack(&vmess_inbound(settings)?)),
        "trojan" => Ok(TypedMessage::pack(&trojan_inbound(settings)?)),
        "shadowsocks" => Ok(TypedMessage::pack(&shadowsocks_inbound(settings)?)),
        "hysteria" => bail!(
            "the hysteria inbound has no representation in the protobuf decoder envelope (xray.proxy.hysteria.Config is not integrated)"
        ),
        "tun" => bail!(
            "the tun inbound has no representation in the protobuf decoder envelope (xray.proxy.tun.Config is not integrated)"
        ),
        "wireguard" => bail!(
            "the wireguard inbound has no representation in the protobuf decoder envelope (xray.proxy.wireguard.Config is not integrated)"
        ),
        "dns" => bail!(
            "the dns inbound has no representation in the protobuf decoder envelope (xray.proxy.dns.Config is not integrated)"
        ),
        "loopback" => bail!(
            "loopback is an outbound protocol only; Go registers no loopback inbound"
        ),
        other => bail!(
            "inbound protocol {other:?} is not integrated in the protobuf decoder envelope"
        ),
    }
}

/// The effective accounts of a SOCKS/HTTP inbound: the `accounts` list wins
/// over `users`, exactly like `compile_inbound`.
fn password_accounts<A>(accounts: &mut Vec<A>, users: &mut Option<Vec<A>>) -> Vec<A> {
    if !accounts.is_empty() {
        std::mem::take(accounts)
    } else {
        users.take().unwrap_or_default()
    }
}

fn socks_inbound(settings: &Value) -> Result<p::proxy::socks::ServerConfig> {
    let mut raw: SocksSettings =
        serde_json::from_value(settings.clone()).context("SOCKS inbound settings")?;
    let auth = match raw.auth.as_str() {
        "" | "noauth" => 0,
        "password" => 1,
        other => bail!("unknown SOCKS authentication method {other:?}"),
    };
    let accounts = password_accounts(&mut raw.accounts, &mut raw.users);
    let mut proto_accounts = std::collections::HashMap::new();
    for account in accounts {
        proto_accounts.insert(account.user, account.pass);
    }
    Ok(p::proxy::socks::ServerConfig {
        auth_type: auth,
        accounts: proto_accounts,
        address: match raw.ip {
            Some(ip) => Some(ip_or_domain(&ip.to_string(), "SOCKS inbound ip")?),
            None => None,
        },
        udp_enabled: raw.udp,
        user_level: raw.user_level,
    })
}

fn http_inbound(settings: &Value) -> Result<p::proxy::http::ServerConfig> {
    let mut raw: HttpSettings =
        serde_json::from_value(settings.clone()).context("HTTP inbound settings")?;
    ensure!(
        !raw.allow_transparent,
        "allowTransparent is not carried by the protobuf decoder envelope (transparent HTTP is not migrated)"
    );
    let accounts = password_accounts(&mut raw.accounts, &mut raw.users);
    let mut proto_accounts = std::collections::HashMap::new();
    for account in accounts {
        proto_accounts.insert(account.user, account.pass);
    }
    Ok(p::proxy::http::ServerConfig {
        accounts: proto_accounts,
        allow_transparent: false,
        user_level: raw.user_level,
    })
}

fn dokodemo_inbound(settings: &Value) -> Result<p::proxy::dokodemo::Config> {
    let raw: DokodemoSettings =
        serde_json::from_value(settings.clone()).context("dokodemo inbound settings")?;
    ensure!(
        !raw.follow_redirect,
        "dokodemo followRedirect is not carried by the protobuf decoder envelope (transparent socket redirection is not migrated)"
    );
    let address = raw
        .address
        .clone()
        .or(raw.rewrite_address.clone())
        .context("dokodemo requires address")?;
    let port = if raw.port == 0 {
        raw.rewrite_port
    } else {
        raw.port
    };
    Ok(p::proxy::dokodemo::Config {
        allowed_networks: dokodemo_network(raw.network.as_ref().or(raw.allowed_network.as_ref()))?,
        rewrite_address: Some(ip_or_domain(&address, "dokodemo address")?),
        rewrite_port: u32::from(port),
        follow_redirect: false,
        user_level: raw.user_level,
        ..Default::default()
    })
}

/// The dokodemo `network` list: `tcp`/`udp` entries in order; `unix` is
/// refused (the proto `Network_UNIX` value is not integrated in the decoder)
/// and udp-only is refused, exactly like `compile_inbound`.
fn dokodemo_network(network: Option<&String>) -> Result<Vec<i32>> {
    let Some(network) = network else {
        return Ok(vec![2]);
    };
    let mut values = Vec::new();
    for entry in network.split(',') {
        match entry {
            "tcp" => values.push(2),
            "udp" => values.push(3),
            "unix" => bail!(
                "dokodemo network entry \"unix\" is not carried by the protobuf decoder envelope (Network_UNIX is not integrated)"
            ),
            other => bail!("unknown dokodemo network {other:?}"),
        }
    }
    ensure!(
        values.iter().any(|value| *value != 3),
        "udp-only dokodemo-door is not supported; use tcp,udp"
    );
    Ok(values)
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessUser {
    id: String,
    email: String,
    level: u32,
    flow: String,
    encryption: String,
    seed: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessInbound {
    clients: Option<Vec<VlessUser>>,
    users: Vec<VlessUser>,
    decryption: String,
    flow: String,
    fallbacks: Vec<Value>,
}

/// One VLESS user → `protocol.User` with a `vless.Account`. The account's
/// encryption/decryption strings are carried verbatim: the decoder rejects
/// the transformed xorMode/seconds/padding fields Go's builder produces, so
/// the full JSON spelling is the only form that survives the round trip.
fn vless_user(raw: &VlessUser, outbound: bool) -> Result<p::common::protocol::User> {
    ensure!(raw.seed.is_empty(), "VLESS seed flow is not migrated yet");
    ensure!(
        raw.flow.is_empty()
            || matches!(
                raw.flow.as_str(),
                "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
            ),
        "VLESS users: \"flow\" doesn't support {:?} in this version",
        raw.flow
    );
    if !outbound {
        ensure!(
            raw.encryption.is_empty(),
            "VLESS users: \"encryption\" should not be in inbound settings"
        );
    }
    Ok(user_message(
        &raw.email,
        raw.level,
        TypedMessage::pack(&p::proxy::vless::Account {
            id: raw.id.clone(),
            flow: raw.flow.clone(),
            encryption: if raw.encryption == "none" {
                String::new()
            } else {
                raw.encryption.clone()
            },
            ..Default::default()
        }),
    ))
}

fn vless_inbound(settings: &Value) -> Result<p::proxy::vless::inbound::Config> {
    let raw: VlessInbound =
        serde_json::from_value(settings.clone()).context("VLESS inbound settings")?;
    ensure!(
        raw.flow.is_empty(),
        "VLESS inbound settings have no \"flow\" field; set flow per client"
    );
    ensure!(raw.fallbacks.is_empty(), "VLESS fallbacks are not migrated yet");
    let users = raw.clients.unwrap_or(raw.users);
    Ok(p::proxy::vless::inbound::Config {
        users: users
            .iter()
            .map(|user| vless_user(user, false))
            .collect::<Result<_>>()?,
        decryption: if raw.decryption == "none" {
            String::new()
        } else {
            raw.decryption
        },
        ..Default::default()
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmessUser {
    id: String,
    email: String,
    level: u32,
    security: String,
    experiments: String,
    #[serde(rename = "alterId")]
    alter_id: u32,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmessDefaults {
    level: u32,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmessInbound {
    clients: Option<Vec<VmessUser>>,
    users: Vec<VmessUser>,
    default: Option<VmessDefaults>,
}

fn vmess_security(security: &str) -> Result<i32> {
    Ok(match security.to_ascii_lowercase().as_str() {
        "" | "auto" => 2,
        "aes-128-gcm" => 3,
        "chacha20-poly1305" => 4,
        other => bail!("unsupported VMess security {other:?}"),
    })
}

fn vmess_user(raw: &VmessUser) -> Result<p::common::protocol::User> {
    ensure!(raw.level == 0, "VMess policy levels are not migrated yet");
    ensure!(
        raw.alter_id == 0,
        "legacy VMess alterId authentication is not supported"
    );
    ensure!(
        raw.experiments.is_empty(),
        "VMess experiments are not migrated yet"
    );
    Ok(user_message(
        &raw.email,
        raw.level,
        TypedMessage::pack(&p::proxy::vmess::Account {
            id: raw.id.clone(),
            security_settings: Some(p::common::protocol::SecurityConfig {
                r#type: vmess_security(&raw.security)?,
            }),
            ..Default::default()
        }),
    ))
}

fn vmess_inbound(settings: &Value) -> Result<p::proxy::vmess::inbound::Config> {
    let raw: VmessInbound =
        serde_json::from_value(settings.clone()).context("VMess inbound settings")?;
    if let Some(default) = &raw.default {
        ensure!(
            default.level == 0,
            "VMess default policy levels are not migrated yet"
        );
    }
    let users = raw.clients.unwrap_or(raw.users);
    Ok(p::proxy::vmess::inbound::Config {
        user: users.iter().map(vmess_user).collect::<Result<_>>()?,
        default: raw
            .default
            .as_ref()
            .map(|default| p::proxy::vmess::inbound::DefaultConfig {
                level: default.level,
            }),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanUser {
    password: String,
    email: String,
    level: u32,
    flow: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanInbound {
    clients: Option<Vec<TrojanUser>>,
    users: Vec<TrojanUser>,
    fallbacks: Vec<Value>,
}

fn trojan_user(raw: &TrojanUser) -> Result<p::common::protocol::User> {
    ensure!(!raw.password.is_empty(), "Trojan password is required");
    ensure!(
        raw.flow.is_empty(),
        "Trojan flow has been removed from the reference implementation"
    );
    Ok(user_message(
        &raw.email,
        raw.level,
        TypedMessage::pack(&p::proxy::trojan::Account {
            password: raw.password.clone(),
        }),
    ))
}

fn trojan_inbound(settings: &Value) -> Result<p::proxy::trojan::ServerConfig> {
    let raw: TrojanInbound =
        serde_json::from_value(settings.clone()).context("Trojan inbound settings")?;
    ensure!(
        raw.fallbacks.is_empty(),
        "Trojan fallbacks are not migrated yet"
    );
    let users = raw.clients.unwrap_or(raw.users);
    Ok(p::proxy::trojan::ServerConfig {
        users: users.iter().map(trojan_user).collect::<Result<_>>()?,
        ..Default::default()
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowsocksUser {
    method: String,
    password: String,
    email: String,
    level: u32,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowsocksInbound {
    method: String,
    password: String,
    email: String,
    level: u32,
    network: String,
    clients: Option<Vec<ShadowsocksUser>>,
    users: Option<Vec<ShadowsocksUser>>,
}

/// The legacy AEAD cipher numbers; XCHACHA20_POLY1305 (8) is refused because
/// the decoder's account mapping does not carry it.
fn shadowsocks_cipher(method: &str) -> Result<i32> {
    Ok(match method.to_ascii_lowercase().as_str() {
        "aes-128-gcm" | "aead_aes_128_gcm" => 5,
        "aes-256-gcm" | "aead_aes_256_gcm" => 6,
        "chacha20-poly1305" | "aead_chacha20_poly1305" | "chacha20-ietf-poly1305" => 7,
        "xchacha20-poly1305" | "aead_xchacha20_poly1305" | "xchacha20-ietf-poly1305" => bail!(
            "Shadowsocks method {method:?} is not carried by the protobuf decoder envelope (XCHACHA20_POLY1305 accounts are rejected)"
        ),
        other => bail!("unknown Shadowsocks cipher {other:?}"),
    })
}

/// The inbound `network` list: `""`/`"tcp"` bind TCP only, `"tcp,udp"` opts
/// into UDP, and anything else is refused exactly like `compile_inbound`.
fn shadowsocks_network(network: &str) -> Result<Vec<i32>> {
    Ok(match network {
        "" | "tcp" => vec![2],
        "tcp,udp" => vec![2, 3],
        "udp" => bail!("udp-only Shadowsocks inbound is not supported; use tcp,udp"),
        other => bail!("unknown Shadowsocks network {other:?}"),
    })
}

fn shadowsocks_inbound(settings: &Value) -> Result<TypedMessage> {
    let raw: ShadowsocksInbound =
        serde_json::from_value(settings.clone()).context("Shadowsocks inbound settings")?;
    let network = shadowsocks_network(&raw.network)?;
    if let Some(users) = raw.clients.or(raw.users) {
        // Multi-user admission (including every 2022 multi-user shape) has no
        // proto message in the decoder's envelope.
        ensure!(
            users.len() == 1,
            "Shadowsocks multi-user admission is not migrated yet (the protobuf decoder carries neither the legacy multi-user list nor the 2022 multi-user/relay server configs)"
        );
        let user = &users[0];
        ensure!(
            !user.method.starts_with("2022-"),
            "Shadowsocks 2022 multi-user inbound settings are not carried by the protobuf decoder envelope (xray.proxy.shadowsocks_2022.MultiUserServerConfig is not integrated)"
        );
        ensure!(
            !user.password.is_empty(),
            "Shadowsocks password is not specified."
        );
        return Ok(TypedMessage::pack(&p::proxy::shadowsocks::ServerConfig {
            users: vec![user_message(
                &user.email,
                user.level,
                TypedMessage::pack(&p::proxy::shadowsocks::Account {
                    password: user.password.clone(),
                    cipher_type: shadowsocks_cipher(&user.method)?,
                    iv_check: false,
                }),
            )],
            network,
        }));
    }
    if raw.method.starts_with("2022-") {
        return Ok(TypedMessage::pack(&p::proxy::shadowsocks_2022::ServerConfig {
            method: raw.method,
            key: raw.password,
            email: raw.email,
            level: i32::try_from(raw.level)
                .context("Shadowsocks 2022 level exceeds the protobuf int32")?,
            network,
        }));
    }
    ensure!(
        !raw.password.is_empty(),
        "Shadowsocks password is not specified."
    );
    Ok(TypedMessage::pack(&p::proxy::shadowsocks::ServerConfig {
        users: vec![user_message(
            &raw.email,
            raw.level,
            TypedMessage::pack(&p::proxy::shadowsocks::Account {
                password: raw.password,
                cipher_type: shadowsocks_cipher(&raw.method)?,
                iv_check: false,
            }),
        )],
        network,
    }))
}

// ---------------------------------------------------------------------------
// Outbound proxy settings
// ---------------------------------------------------------------------------

fn outbound_proxy(protocol: &str, settings: &Value) -> Result<TypedMessage> {
    match protocol {
        "freedom" | "direct" => Ok(TypedMessage::pack(&freedom_outbound(settings)?)),
        "blackhole" | "block" => Ok(TypedMessage::pack(&blackhole_outbound(settings)?)),
        "socks" => Ok(TypedMessage::pack(&socks_outbound(settings)?)),
        "http" => Ok(TypedMessage::pack(&http_outbound(settings)?)),
        "vless" => Ok(TypedMessage::pack(&vless_outbound(settings)?)),
        "vmess" => Ok(TypedMessage::pack(&vmess_outbound(settings)?)),
        "trojan" => Ok(TypedMessage::pack(&trojan_outbound(settings)?)),
        "shadowsocks" => Ok(TypedMessage::pack(&shadowsocks_outbound(settings)?)),
        "masque" => bail!(
            "the masque outbound has no representation in the protobuf decoder envelope (xray.proxy.masque.ClientConfig is not integrated)"
        ),
        "dns" => bail!(
            "the dns outbound has no representation in the protobuf decoder envelope (xray.proxy.dns.Config is not integrated)"
        ),
        "loopback" => bail!(
            "the loopback outbound has no representation in the protobuf decoder envelope (xray.proxy.loopback.Config is not integrated)"
        ),
        "wireguard" => bail!(
            "the wireguard outbound has no representation in the protobuf decoder envelope (xray.proxy.wireguard.Config is not integrated)"
        ),
        "hysteria" => bail!(
            "the hysteria outbound has no representation in the protobuf decoder envelope (xray.proxy.hysteria.Config is not integrated)"
        ),
        other => bail!(
            "outbound protocol {other:?} is not integrated in the protobuf decoder envelope"
        ),
    }
}

fn freedom_outbound(settings: &Value) -> Result<p::proxy::freedom::Config> {
    let raw: FreedomSettings =
        serde_json::from_value(settings.clone()).context("freedom settings")?;
    // Go's FreedomConfig.Build: targetStrategy falls back to domainStrategy;
    // the freedom message's own field carries the result (the sockopt mirror
    // the current Go builder also writes is rejected by the decoder).
    let strategy = if raw.target_strategy.is_empty() {
        &raw.domain_strategy
    } else {
        &raw.target_strategy
    };
    let strategy = match strategy.to_ascii_lowercase().as_str() {
        "" | "asis" => 0,
        "useip" => 1,
        "useipv4" => 2,
        "useipv6" => 3,
        "useipv4v6" => 4,
        "useipv6v4" => 5,
        "forceip" => 6,
        "forceipv4" => 7,
        "forceipv6" => 8,
        "forceipv4v6" => 9,
        "forceipv6v4" => 10,
        other => bail!("unsupported domain strategy: {other}"),
    };
    let mut out = p::proxy::freedom::Config {
        domain_strategy: strategy,
        user_level: raw.user_level,
        ..Default::default()
    };
    if !raw.redirect.is_empty() {
        let (host, port) = split_authority(&raw.redirect)?;
        ensure!(
            !host.is_empty() && port != 0,
            "freedom redirect {:?} is not carried by the protobuf decoder envelope (address-only redirects are rejected)",
            raw.redirect
        );
        out.destination_override = Some(p::proxy::freedom::DestinationOverride {
            server: Some(server_endpoint(&host, port, None, "freedom redirect")?),
        });
    }
    out.final_rules = raw
        .final_rules
        .iter()
        .map(freedom_final_rule)
        .collect::<Result<_>>()?;
    Ok(out)
}

/// Split `host:port` like Go's `net.SplitHostPort` for the freedom `redirect`.
fn split_authority(redirect: &str) -> Result<(String, u16)> {
    if let Some(rest) = redirect.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .with_context(|| format!("invalid redirect address {redirect:?}"))?;
        let port = tail
            .strip_prefix(':')
            .with_context(|| format!("invalid redirect address {redirect:?}"))?;
        let port = port
            .parse::<u16>()
            .with_context(|| format!("invalid redirect port {port:?}"))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = redirect
        .rsplit_once(':')
        .with_context(|| format!("invalid redirect address {redirect:?}"))?;
    ensure!(
        !host.contains(':'),
        "invalid redirect address {redirect:?}: the IPv6 host must be bracketed"
    );
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid redirect port {port:?}"))?;
    Ok((host.to_owned(), port))
}

fn freedom_final_rule(
    rule: &crate::protocol::freedom::RuleConfig,
) -> Result<p::proxy::freedom::FinalRuleConfig> {
    let action = match rule.action.to_ascii_lowercase().as_str() {
        "allow" => 0,
        "block" => 1,
        other => bail!("unknown freedom final rule action {other:?}"),
    };
    let mut networks = Vec::new();
    for entry in rule
        .network
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
    {
        match entry {
            "tcp" => networks.push(2),
            "udp" => networks.push(3),
            "" => (),
            other => bail!("unknown freedom final rule network {other:?}"),
        }
    }
    let block_delay = rule
        .block_delay
        .as_ref()
        .map(|delay| {
            let (min, max) = match delay {
                crate::protocol::freedom::Delay::Seconds(seconds) => {
                    (u64::from(*seconds), u64::from(*seconds))
                }
                crate::protocol::freedom::Delay::Range(range) => match range.split_once('-') {
                    Some((min, max)) => (
                        min.parse::<u64>()
                            .with_context(|| format!("invalid blockDelay {range:?}"))?,
                        max.parse::<u64>()
                            .with_context(|| format!("invalid blockDelay {range:?}"))?,
                    ),
                    None => {
                        let seconds = range
                            .parse::<u64>()
                            .with_context(|| format!("invalid blockDelay {range:?}"))?;
                        (seconds, seconds)
                    }
                },
            };
            ensure!(
                min <= i64::from(i32::MAX) as u64 && max <= i64::from(i32::MAX) as u64,
                "blockDelay exceeds int32 range"
            );
            Ok(p::proxy::freedom::Range { min, max })
        })
        .transpose()?;
    Ok(p::proxy::freedom::FinalRuleConfig {
        action,
        networks,
        port_list: rule
            .port
            .as_ref()
            .map(rule_port_list)
            .transpose()?
            .map(|range| p::common::net::PortList { range }),
        ip: rule.ip.iter().map(|value| ip_rule(value)).collect::<Result<_>>()?,
        block_delay,
    })
}

fn blackhole_outbound(settings: &Value) -> Result<p::proxy::blackhole::Config> {
    let raw: super::BlackholeSettings =
        serde_json::from_value(settings.clone()).context("blackhole settings")?;
    let Some(response) = raw.response else {
        return Ok(p::proxy::blackhole::Config::default());
    };
    let response = match response.r#type.to_ascii_lowercase().as_str() {
        "" | "none" => p::proxy::blackhole::Response {
            r#type: "none".into(),
            custom_response_data: Vec::new(),
        },
        "http" => p::proxy::blackhole::Response {
            r#type: "http".into(),
            custom_response_data: Vec::new(),
        },
        "custom" => p::proxy::blackhole::Response {
            r#type: "custom".into(),
            custom_response_data: STANDARD
                .decode(response.custom_response_data)
                .context("invalid blackhole response base64")?,
        },
        other => bail!("unknown blackhole response {other:?}"),
    };
    Ok(p::proxy::blackhole::Config {
        response: Some(response),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PasswordUser {
    user: String,
    pass: String,
    level: u32,
    email: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PasswordServer {
    address: String,
    port: u16,
    users: Vec<PasswordUser>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PasswordOutbound {
    address: Option<String>,
    port: u16,
    user: String,
    pass: String,
    level: u32,
    email: String,
    servers: Vec<PasswordServer>,
}

impl PasswordOutbound {
    /// One effective server: the flat form synthesizes it (a non-empty `user`
    /// carries the single account, exactly like Go's client builders).
    fn server(self) -> Result<PasswordServer> {
        Ok(match self.address {
            Some(address) => PasswordServer {
                address,
                port: self.port,
                users: if self.user.is_empty() {
                    Vec::new()
                } else {
                    vec![PasswordUser {
                        user: self.user,
                        pass: self.pass,
                        level: self.level,
                        email: self.email,
                    }]
                },
            },
            None => {
                ensure!(
                    self.servers.len() == 1,
                    "SOCKS/HTTP requires exactly one server"
                );
                self.servers.into_iter().next().unwrap()
            }
        })
    }
}

fn socks_outbound(settings: &Value) -> Result<p::proxy::socks::ClientConfig> {
    let raw: PasswordOutbound =
        serde_json::from_value(settings.clone()).context("SOCKS outbound settings")?;
    let server = raw.server()?;
    ensure!(
        server.users.len() <= 1,
        "SOCKS/HTTP supports at most one outbound account"
    );
    let user = server
        .users
        .first()
        .map(|user| {
            ensure!(
                (1..=255).contains(&user.user.len()) && (1..=255).contains(&user.pass.len()),
                "SOCKS credentials must contain 1..255 bytes"
            );
            Ok::<_, anyhow::Error>(user_message(
                &user.email,
                user.level,
                TypedMessage::pack(&p::proxy::socks::Account {
                    username: user.user.clone(),
                    password: user.pass.clone(),
                }),
            ))
        })
        .transpose()?;
    Ok(p::proxy::socks::ClientConfig {
        server: Some(server_endpoint(&server.address, server.port, user, "SOCKS server")?),
    })
}

fn http_outbound(settings: &Value) -> Result<p::proxy::http::ClientConfig> {
    let raw: PasswordOutbound =
        serde_json::from_value(settings.clone()).context("HTTP outbound settings")?;
    let server = raw.server()?;
    ensure!(
        server.users.len() <= 1,
        "SOCKS/HTTP supports at most one outbound account"
    );
    let user = server.users.first().map(|user| {
        user_message(
            &user.email,
            user.level,
            TypedMessage::pack(&p::proxy::http::Account {
                username: user.user.clone(),
                password: user.pass.clone(),
            }),
        )
    });
    Ok(p::proxy::http::ClientConfig {
        server: Some(server_endpoint(&server.address, server.port, user, "HTTP server")?),
        // Custom HTTP headers are refused by the decoder's envelope.
        header: Vec::new(),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessServer {
    address: String,
    port: u16,
    users: Vec<VlessUser>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessOutbound {
    address: Option<String>,
    port: u16,
    id: String,
    email: String,
    level: u32,
    flow: String,
    encryption: String,
    seed: String,
    vnext: Vec<VlessServer>,
}

fn vless_outbound(settings: &Value) -> Result<p::proxy::vless::outbound::Config> {
    let raw: VlessOutbound =
        serde_json::from_value(settings.clone()).context("VLESS outbound settings")?;
    let server = match raw.address {
        Some(address) => VlessServer {
            address,
            port: raw.port,
            users: vec![VlessUser {
                id: raw.id,
                email: raw.email,
                level: raw.level,
                flow: raw.flow,
                encryption: raw.encryption,
                seed: raw.seed,
            }],
        },
        None => {
            ensure!(raw.vnext.len() == 1, "VLESS requires exactly one vnext server");
            raw.vnext.into_iter().next().unwrap()
        }
    };
    ensure!(
        server.users.len() == 1,
        "VLESS requires exactly one outbound user"
    );
    let user = vless_user(&server.users[0], true)?;
    Ok(p::proxy::vless::outbound::Config {
        vnext: Some(server_endpoint(
            &server.address,
            server.port,
            Some(user),
            "VLESS vnext",
        )?),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmessServer {
    address: String,
    port: u16,
    users: Vec<VmessUser>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmessOutbound {
    address: Option<String>,
    port: u16,
    id: String,
    email: String,
    level: u32,
    security: String,
    experiments: String,
    #[serde(rename = "alterId")]
    alter_id: u32,
    vnext: Vec<VmessServer>,
}

fn vmess_outbound(settings: &Value) -> Result<p::proxy::vmess::outbound::Config> {
    let raw: VmessOutbound =
        serde_json::from_value(settings.clone()).context("VMess outbound settings")?;
    let server = match raw.address {
        Some(address) => VmessServer {
            address,
            port: raw.port,
            users: vec![VmessUser {
                id: raw.id,
                email: raw.email,
                level: raw.level,
                security: raw.security,
                experiments: raw.experiments,
                alter_id: raw.alter_id,
            }],
        },
        None => {
            ensure!(raw.vnext.len() == 1, "VMess requires exactly one server");
            raw.vnext.into_iter().next().unwrap()
        }
    };
    ensure!(
        server.users.len() == 1,
        "VMess requires exactly one outbound user"
    );
    let user = vmess_user(&server.users[0])?;
    Ok(p::proxy::vmess::outbound::Config {
        receiver: Some(server_endpoint(
            &server.address,
            server.port,
            Some(user),
            "VMess vnext",
        )?),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanServer {
    address: String,
    port: u16,
    password: String,
    email: String,
    level: u32,
    flow: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanOutbound {
    address: Option<String>,
    port: u16,
    password: String,
    email: String,
    level: u32,
    flow: String,
    servers: Vec<TrojanServer>,
}

fn trojan_outbound(settings: &Value) -> Result<p::proxy::trojan::ClientConfig> {
    let raw: TrojanOutbound =
        serde_json::from_value(settings.clone()).context("Trojan outbound settings")?;
    let server = match raw.address {
        Some(address) => TrojanServer {
            address,
            port: raw.port,
            password: raw.password,
            email: raw.email,
            level: raw.level,
            flow: raw.flow,
        },
        None => {
            ensure!(raw.servers.len() == 1, "Trojan requires exactly one server");
            raw.servers.into_iter().next().unwrap()
        }
    };
    let user = trojan_user(&TrojanUser {
        password: server.password,
        email: server.email,
        level: server.level,
        flow: server.flow,
    })?;
    Ok(p::proxy::trojan::ClientConfig {
        server: Some(server_endpoint(
            &server.address,
            server.port,
            Some(user),
            "Trojan server",
        )?),
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowsocksServer {
    address: String,
    port: u16,
    method: String,
    password: String,
    email: String,
    level: u32,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowsocksOutbound {
    address: Option<String>,
    port: u16,
    method: String,
    password: String,
    email: String,
    level: u32,
    servers: Vec<ShadowsocksServer>,
}

fn shadowsocks_outbound(settings: &Value) -> Result<TypedMessage> {
    let raw: ShadowsocksOutbound =
        serde_json::from_value(settings.clone()).context("Shadowsocks outbound settings")?;
    let server = match raw.address {
        Some(address) => ShadowsocksServer {
            address,
            port: raw.port,
            method: raw.method,
            password: raw.password,
            email: raw.email,
            level: raw.level,
        },
        None => {
            ensure!(
                raw.servers.len() == 1,
                "Shadowsocks requires exactly one server"
            );
            raw.servers.into_iter().next().unwrap()
        }
    };
    if server.method.starts_with("2022-") {
        // The 2022 client message carries address/port/method/key only; the
        // account identity fields have no place in it.
        ensure!(
            server.email.is_empty(),
            "Shadowsocks 2022 outbound \"email\" has no representation in the protobuf decoder envelope (the 2022 client message carries address/port/method/password only)"
        );
        ensure!(
            server.level == 0,
            "Shadowsocks 2022 outbound \"level\" has no representation in the protobuf decoder envelope (the 2022 client message carries address/port/method/password only)"
        );
        return Ok(TypedMessage::pack(&p::proxy::shadowsocks_2022::ClientConfig {
            address: Some(ip_or_domain(&server.address, "Shadowsocks 2022 server address")?),
            port: u32::from(server.port),
            method: server.method,
            key: server.password,
        }));
    }
    ensure!(
        !server.password.is_empty(),
        "Shadowsocks password is not specified."
    );
    Ok(TypedMessage::pack(&p::proxy::shadowsocks::ClientConfig {
        server: Some(server_endpoint(
            &server.address,
            server.port,
            Some(user_message(
                &server.email,
                server.level,
                TypedMessage::pack(&p::proxy::shadowsocks::Account {
                    password: server.password,
                    cipher_type: shadowsocks_cipher(&server.method)?,
                    iv_check: false,
                }),
            )),
            "Shadowsocks server",
        )?),
    }))
}

// ---------------------------------------------------------------------------
// Stream settings (transports and security)
// ---------------------------------------------------------------------------

fn stream_config(stream: &StreamSettings) -> Result<Option<p::transport::internet::StreamConfig>> {
    // Keys and transports outside the decoder's envelope fail by name.
    ensure!(
        stream.masque_settings.is_none(),
        "masque transport settings are not carried by the protobuf decoder envelope (the masque transport is not integrated)"
    );
    ensure!(
        stream.hysteria_settings.is_none(),
        "hysteria transport settings are not carried by the protobuf decoder envelope (the hysteria transport is not integrated)"
    );
    ensure!(
        stream.finalmask.is_none(),
        "\"finalmask\" is not carried by the protobuf decoder envelope (the decoder rejects masks and QUIC parameters)"
    );
    let network = stream.network.as_str();
    let protocol = match network {
        "" | "tcp" | "raw" => "tcp",
        "ws" | "websocket" => "websocket",
        "httpupgrade" => "httpupgrade",
        "grpc" => "grpc",
        "kcp" | "mkcp" => "mkcp",
        "xhttp" | "splithttp" => "splithttp",
        "masque" => bail!(
            "the masque transport is not carried by the protobuf decoder envelope (it is not integrated)"
        ),
        "hysteria" => bail!(
            "the hysteria transport is not carried by the protobuf decoder envelope (it is not integrated)"
        ),
        other => bail!("unknown transport {other:?}"),
    };
    // Consistency between each settings object and the selected transport,
    // mirroring `StreamSettings::validate`, so an unvalidated input cannot
    // produce a mixed shape.
    ensure!(
        stream.ws_settings.is_none() || matches!(network, "ws" | "websocket"),
        "wsSettings requires the WebSocket transport"
    );
    ensure!(
        stream.httpupgrade_settings.is_none() || network == "httpupgrade",
        "httpupgradeSettings requires the HTTP Upgrade transport"
    );
    ensure!(
        stream.grpc_settings.is_none() || network == "grpc",
        "grpcSettings requires the gRPC transport"
    );
    ensure!(
        stream.kcp_settings.is_none() || matches!(network, "kcp" | "mkcp"),
        "kcpSettings requires the KCP transport"
    );
    ensure!(
        stream.xhttp_settings.is_none() || matches!(network, "xhttp" | "splithttp"),
        "xhttpSettings requires the xhttp transport"
    );
    ensure!(
        stream.tls_settings.is_none() || stream.security == "tls",
        "tlsSettings requires security \"tls\""
    );
    ensure!(
        stream.reality_settings.is_none() || stream.security == "reality",
        "realitySettings requires security \"reality\""
    );
    if network.is_empty()
        && stream.security.is_empty()
        && stream.tls_settings.is_none()
        && stream.reality_settings.is_none()
        && stream.xhttp_settings.is_none()
        && stream.ws_settings.is_none()
        && stream.httpupgrade_settings.is_none()
        && stream.grpc_settings.is_none()
        && stream.kcp_settings.is_none()
        && stream.tcp_settings.is_none()
    {
        // An all-default streamSettings is absent from the proto, exactly like
        // Go's builder when the JSON key is missing.
        return Ok(None);
    }
    let mut config = p::transport::internet::StreamConfig {
        protocol_name: protocol.to_owned(),
        ..Default::default()
    };
    let transport = match protocol {
        "tcp" => {
            // The decoder's TCP arm accepts only the default settings
            // message (it rejects header settings and PROXY protocol), and
            // the native runtime requires tcpSettings.header — so any
            // tcpSettings object is outside the envelope.
            ensure!(
                stream.tcp_settings.is_none(),
                "tcpSettings are not carried by the protobuf decoder envelope (the decoder rejects the TCP header settings)"
            );
            None
        }
        "websocket" => stream
            .ws_settings
            .as_ref()
            .map(websocket_settings)
            .transpose()?,
        "httpupgrade" => stream
            .httpupgrade_settings
            .as_ref()
            .map(httpupgrade_settings)
            .transpose()?,
        "grpc" => stream
            .grpc_settings
            .as_ref()
            .map(grpc_settings)
            .transpose()?,
        "mkcp" => stream
            .kcp_settings
            .as_ref()
            .map(kcp_settings)
            .transpose()?,
        _ => stream
            .xhttp_settings
            .as_ref()
            .map(xhttp_settings)
            .transpose()?,
    };
    if let Some(settings) = transport {
        config.transport_settings = vec![p::transport::internet::TransportConfig {
            protocol_name: protocol.to_owned(),
            settings: Some(settings),
        }];
    }
    match stream.security.as_str() {
        "" | "none" => (),
        "tls" => {
            let tls = tls_config(
                stream
                    .tls_settings
                    .as_ref()
                    .unwrap_or(&serde_json::json!({})),
            )?;
            config.security_type = "xray.transport.internet.tls.Config".into();
            config.security_settings = vec![TypedMessage::pack(&tls)];
        }
        "reality" => {
            let reality = reality_config(
                stream
                    .reality_settings
                    .as_ref()
                    .context("REALITY requires realitySettings")?,
            )?;
            config.security_type = "xray.transport.internet.reality.Config".into();
            config.security_settings = vec![TypedMessage::pack(&reality)];
        }
        other => bail!("unknown security {other:?}"),
    }
    Ok(Some(config))
}

/// `wsSettings` → the websocket message, through the native parser so the
/// `?ed=` extraction and the legacy `headers.host` migration match Go.
fn websocket_settings(value: &Value) -> Result<TypedMessage> {
    let parsed = crate::transport::websocket::Config::from_json(value)
        .map_err(|error| anyhow::anyhow!("invalid WebSocket settings: {error}"))?;
    Ok(TypedMessage::pack(&p::transport::internet::websocket::Config {
        host: parsed.host,
        path: parsed.path,
        header: parsed.headers.into_iter().collect(),
        ed: u32::try_from(parsed.early_data_limit)
            .context("WebSocket early-data limit exceeds the protobuf uint32")?,
        heartbeat_period: u32::try_from(parsed.heartbeat_period.as_secs())
            .context("WebSocket heartbeat period exceeds the protobuf uint32")?,
        accept_proxy_protocol: false,
    }))
}

fn httpupgrade_settings(value: &Value) -> Result<TypedMessage> {
    let parsed = crate::transport::httpupgrade::HttpUpgradeConfig::from_json(value)
        .map_err(|error| anyhow::anyhow!("invalid HTTP Upgrade settings: {error}"))?;
    Ok(TypedMessage::pack(&p::transport::internet::httpupgrade::Config {
        host: parsed.host,
        path: parsed.path,
        header: parsed.headers.into_iter().collect(),
        ed: parsed.early_data,
        accept_proxy_protocol: false,
    }))
}

/// `kcpSettings` → the mkcp message with Go's defaults materialized (Go's
/// builder starts from `CreateTransportConfig`, so the six numeric fields
/// are always present on the wire).
fn kcp_settings(value: &Value) -> Result<TypedMessage> {
    let parsed = crate::transport::kcp::Config::from_json(value)?;
    Ok(TypedMessage::pack(&p::transport::internet::kcp::Config {
        mtu: u32::try_from(parsed.mtu).context("KCP MTU exceeds the protobuf uint32")?,
        tti: parsed.tti_ms,
        uplink_capacity: parsed.uplink_capacity,
        downlink_capacity: parsed.downlink_capacity,
        cwnd_multiplier: parsed.cwnd_multiplier,
        max_sending_window: u32::try_from(parsed.max_sending_window)
            .context("KCP maxSendingWindow exceeds the protobuf uint32")?,
    }))
}

/// `grpcSettings` → the gRPC message; the native gate rejects keepalive
/// settings the decoder carries but the round trip could not re-validate.
fn grpc_settings(value: &Value) -> Result<TypedMessage> {
    let raw: crate::transport::grpc::Config =
        serde_json::from_value(value.clone()).context("invalid gRPC settings")?;
    raw.validate()
        .map_err(|error| anyhow::anyhow!("unsupported gRPC settings: {error}"))?;
    Ok(TypedMessage::pack(
        &p::transport::internet::grpc::encoding::Config {
            authority: raw.authority,
            service_name: raw.service_name,
            multi_mode: raw.multi_mode,
            // Go's GRPCConfig.Build clamps nonpositive values to zero.
            idle_timeout: raw.idle_timeout.max(0),
            health_check_timeout: raw.health_check_timeout.max(0),
            permit_without_stream: raw.permit_without_stream,
            initial_windows_size: raw.initial_windows_size.max(0),
            user_agent: raw.user_agent,
        },
    ))
}

/// One `from-to` range in either the number or string form the native XHTTP
/// parser accepts; zero is the parser's default (absent).
#[derive(Deserialize)]
#[serde(untagged)]
enum RangeJson {
    Number(i64),
    Text(String),
}

fn range(value: Option<&RangeJson>, key: &str) -> Result<Option<p::transport::internet::splithttp::RangeConfig>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let (from, to) = match value {
        RangeJson::Number(number) => (*number, *number),
        RangeJson::Text(text) => match text.parse::<i64>() {
            Ok(number) => (number, number),
            Err(_) => {
                let separator = text
                    .char_indices()
                    .skip(1)
                    .find(|(_, ch)| *ch == '-')
                    .map(|(index, _)| index)
                    .with_context(|| format!("invalid {key} range {text:?}"))?;
                (
                    text[..separator]
                        .parse::<i64>()
                        .with_context(|| format!("invalid {key} range {text:?}"))?,
                    text[separator + 1..]
                        .parse::<i64>()
                        .with_context(|| format!("invalid {key} range {text:?}"))?,
                )
            }
        },
    };
    if from == 0 && to == 0 {
        return Ok(None);
    }
    ensure!(
        to != 0,
        "{key} range with a zero upper bound is not carried by the protobuf decoder envelope (the decoder drops it)"
    );
    Ok(Some(p::transport::internet::splithttp::RangeConfig {
        from: i32::try_from(from).with_context(|| format!("{key} range exceeds int32"))?,
        to: i32::try_from(to).with_context(|| format!("{key} range exceeds int32"))?,
    }))
}

/// `xhttpSettings` under the decoder's key set: the keys the decoder refuses
/// (xmux/downloadSettings/sessionIDTable/sessionIDLength) are unknown here
/// and named by serde, and `extra` merges like Go's builder.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct XhttpJson {
    host: String,
    path: String,
    mode: String,
    headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "noGRPCHeader")]
    no_grpc_header: bool,
    #[serde(rename = "noSSEHeader")]
    no_sse_header: bool,
    #[serde(rename = "xPaddingBytes")]
    x_padding_bytes: Option<RangeJson>,
    #[serde(rename = "xPaddingObfsMode")]
    x_padding_obfs_mode: bool,
    #[serde(rename = "xPaddingKey")]
    x_padding_key: String,
    #[serde(rename = "xPaddingHeader")]
    x_padding_header: String,
    #[serde(rename = "xPaddingPlacement")]
    x_padding_placement: String,
    #[serde(rename = "xPaddingMethod")]
    x_padding_method: String,
    #[serde(rename = "uplinkHTTPMethod")]
    uplink_http_method: String,
    #[serde(rename = "sessionIDPlacement")]
    session_id_placement: String,
    #[serde(rename = "sessionIDKey")]
    session_id_key: String,
    #[serde(rename = "seqPlacement")]
    seq_placement: String,
    #[serde(rename = "seqKey")]
    seq_key: String,
    #[serde(rename = "uplinkDataPlacement")]
    uplink_data_placement: String,
    #[serde(rename = "uplinkDataKey")]
    uplink_data_key: String,
    #[serde(rename = "uplinkChunkSize")]
    uplink_chunk_size: Option<RangeJson>,
    #[serde(rename = "scMaxEachPostBytes")]
    sc_max_each_post_bytes: Option<RangeJson>,
    #[serde(rename = "scMinPostsIntervalMs")]
    sc_min_posts_interval_ms: Option<RangeJson>,
    #[serde(rename = "scStreamUpServerSecs")]
    sc_stream_up_server_secs: Option<RangeJson>,
    #[serde(rename = "scMaxBufferedPosts")]
    sc_max_buffered_posts: i64,
    #[serde(rename = "serverMaxHeaderBytes")]
    server_max_header_bytes: i32,
}

fn xhttp_settings(value: &Value) -> Result<TypedMessage> {
    let object = value
        .as_object()
        .context("xhttpSettings must be an object")?;
    // Go replaces the settings with `extra`, retaining only host/path/mode.
    let mut merged = if let Some(extra) = object.get("extra").filter(|value| !value.is_null()) {
        let mut extra = extra
            .as_object()
            .context("xhttpSettings extra must be an object")?
            .clone();
        for key in ["host", "path", "mode"] {
            extra.insert(
                key.into(),
                object
                    .get(key)
                    .cloned()
                    .unwrap_or(Value::String(String::new())),
            );
        }
        extra
    } else {
        object.clone()
    };
    // Null values are absent, like the native parser.
    merged.retain(|_, value| !value.is_null());
    let raw: XhttpJson = serde_json::from_value(Value::Object(merged)).context("invalid XHTTP settings")?;
    ensure!(
        raw.x_padding_method.is_empty() || raw.x_padding_method == "repeat-x",
        "xPaddingMethod {:?} is not carried by the protobuf decoder envelope (native XHTTP tokenish HPACK padding is not implemented)",
        raw.x_padding_method
    );
    ensure!(
        raw.sc_max_buffered_posts >= 0,
        "scMaxBufferedPosts cannot be negative"
    );
    ensure!(
        raw.server_max_header_bytes >= 0,
        "serverMaxHeaderBytes cannot be negative"
    );
    Ok(TypedMessage::pack(&p::transport::internet::splithttp::Config {
        host: raw.host,
        path: raw.path,
        mode: raw.mode,
        headers: raw.headers.unwrap_or_default().into_iter().collect(),
        no_grpc_header: raw.no_grpc_header,
        no_sse_header: raw.no_sse_header,
        x_padding_obfs_mode: raw.x_padding_obfs_mode,
        x_padding_key: raw.x_padding_key,
        x_padding_header: raw.x_padding_header,
        x_padding_placement: raw.x_padding_placement,
        x_padding_method: raw.x_padding_method,
        uplink_http_method: raw.uplink_http_method,
        session_id_placement: raw.session_id_placement,
        session_id_key: raw.session_id_key,
        seq_placement: raw.seq_placement,
        seq_key: raw.seq_key,
        uplink_data_placement: raw.uplink_data_placement,
        uplink_data_key: raw.uplink_data_key,
        x_padding_bytes: range(raw.x_padding_bytes.as_ref(), "xPaddingBytes")?,
        sc_max_each_post_bytes: range(raw.sc_max_each_post_bytes.as_ref(), "scMaxEachPostBytes")?,
        sc_min_posts_interval_ms: range(raw.sc_min_posts_interval_ms.as_ref(), "scMinPostsIntervalMs")?,
        sc_stream_up_server_secs: range(
            raw.sc_stream_up_server_secs.as_ref(),
            "scStreamUpServerSecs",
        )?,
        uplink_chunk_size: range(raw.uplink_chunk_size.as_ref(), "uplinkChunkSize")?,
        sc_max_buffered_posts: raw.sc_max_buffered_posts,
        server_max_header_bytes: raw.server_max_header_bytes,
        // The decoder rejects xmux/downloadSettings and the custom session-ID
        // fields; they stay at their defaults.
        ..Default::default()
    }))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringListJson {
    List(Vec<String>),
    Text(String),
}

fn string_list(value: Option<StringListJson>) -> Vec<String> {
    match value {
        Some(StringListJson::List(list)) => list,
        Some(StringListJson::Text(text)) => text.split(',').map(str::to_owned).collect(),
        None => Vec::new(),
    }
}

/// `tlsSettings` under the decoder's key set: the verification/ECH keys the
/// decoder rejects are unknown here and named by serde.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TlsJson {
    #[serde(rename = "allowInsecure")]
    allow_insecure: bool,
    certificates: Vec<TlsCertJson>,
    #[serde(rename = "serverName")]
    server_name: String,
    alpn: Option<StringListJson>,
    #[serde(rename = "enableSessionResumption")]
    enable_session_resumption: bool,
    #[serde(rename = "disableSystemRoot")]
    disable_system_root: bool,
    #[serde(rename = "minVersion")]
    min_version: String,
    #[serde(rename = "maxVersion")]
    max_version: String,
    #[serde(rename = "cipherSuites")]
    cipher_suites: String,
    fingerprint: String,
    #[serde(rename = "rejectUnknownSni")]
    reject_unknown_sni: bool,
    #[serde(rename = "curvePreferences")]
    curve_preferences: Option<StringListJson>,
    #[serde(rename = "masterKeyLog")]
    master_key_log: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TlsCertJson {
    #[serde(rename = "certificateFile")]
    certificate_file: String,
    certificate: Vec<String>,
    #[serde(rename = "keyFile")]
    key_file: String,
    key: Vec<String>,
    usage: String,
    #[serde(rename = "ocspStapling")]
    ocsp_stapling: u64,
    #[serde(rename = "oneTimeLoading")]
    one_time_loading: bool,
    #[serde(rename = "buildChain")]
    build_chain: bool,
}

fn tls_config(value: &Value) -> Result<p::transport::internet::tls::Config> {
    let raw: TlsJson = serde_json::from_value(value.clone()).context("invalid TLS settings")?;
    ensure!(
        !raw.allow_insecure,
        "TLS allowInsecure has been removed; configure a trusted certificate instead"
    );
    Ok(p::transport::internet::tls::Config {
        server_name: raw.server_name,
        next_protocol: string_list(raw.alpn),
        enable_session_resumption: raw.enable_session_resumption,
        disable_system_root: raw.disable_system_root,
        min_version: raw.min_version,
        max_version: raw.max_version,
        cipher_suites: raw.cipher_suites,
        fingerprint: raw.fingerprint.to_ascii_lowercase(),
        reject_unknown_sni: raw.reject_unknown_sni,
        master_key_log: raw.master_key_log,
        curve_preferences: string_list(raw.curve_preferences),
        certificate: raw
            .certificates
            .iter()
            .map(tls_certificate)
            .collect::<Result<_>>()?,
        ..Default::default()
    })
}

/// One `certificates` entry → the TLS certificate message, mirroring Go's
/// `TLSCertConfig.Build`: files are read and embedded as the initial PEM
/// snapshot (Go embeds the snapshot even when reload paths exist), and
/// `oneTimeLoading` defaults to true when no paths are given.
fn tls_certificate(cert: &TlsCertJson) -> Result<p::transport::internet::tls::Certificate> {
    let certificate = if !cert.certificate_file.is_empty() {
        std::fs::read(&cert.certificate_file)
            .with_context(|| format!("cannot read the TLS certificate file {:?}", cert.certificate_file))?
    } else if !cert.certificate.is_empty() {
        cert.certificate.join("\n").into_bytes()
    } else {
        bail!(
            "TLS certificate with neither \"certificate\" nor \"certificateFile\" cannot be represented (both file and bytes are empty)"
        );
    };
    let key = if !cert.key_file.is_empty() {
        Some(
            std::fs::read(&cert.key_file)
                .with_context(|| format!("cannot read the TLS key file {:?}", cert.key_file))?,
        )
    } else if !cert.key.is_empty() {
        Some(cert.key.join("\n").into_bytes())
    } else {
        None
    };
    let usage = match cert.usage.to_ascii_lowercase().as_str() {
        "" | "encipherment" => 0,
        "verify" => 1,
        "issue" => bail!(
            "TLS certificate usage \"issue\" is not implemented in the native TLS transport; the decoder carries it but the round trip would not re-validate"
        ),
        other => bail!("TLS certificate usage {other:?} is not supported"),
    };
    ensure!(
        cert.ocsp_stapling == 0,
        "TLS certificate ocspStapling is not implemented in the native TLS transport"
    );
    Ok(p::transport::internet::tls::Certificate {
        certificate,
        key: key.unwrap_or_default(),
        usage,
        ocsp_stapling: cert.ocsp_stapling,
        certificate_path: cert.certificate_file.clone(),
        key_path: cert.key_file.clone(),
        one_time_loading: (cert.certificate_file.is_empty() && cert.key_file.is_empty())
            || cert.one_time_loading,
        build_chain: cert.build_chain,
    })
}

/// `realitySettings` under the decoder's client key set: the server keys
/// (dest/serverNames/privateKey/shortIds/...) are unknown here and named by
/// serde, which is how inbound REALITY is refused.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct RealityClientJson {
    show: bool,
    fingerprint: String,
    server_name: String,
    spider_x: String,
    master_key_log: String,
    password: String,
    public_key: String,
    short_id: String,
    mldsa65_verify: String,
}

fn reality_config(value: &Value) -> Result<p::transport::internet::reality::Config> {
    let raw: RealityClientJson =
        serde_json::from_value(value.clone()).context("invalid REALITY client settings")?;
    let key_input = if raw.password.is_empty() {
        raw.public_key.clone()
    } else {
        raw.password.clone()
    };
    let public_key = URL_SAFE_NO_PAD
        .decode(key_input)
        .context("invalid REALITY public key base64")?;
    ensure!(
        public_key.len() == 32,
        "REALITY public key must contain 32 bytes"
    );
    let short_id = crate::transport::reality::decode_short_id(&raw.short_id)
        .map_err(|error| anyhow::anyhow!("invalid REALITY shortId: {error:?}"))?;
    let mldsa65_verify = if raw.mldsa65_verify.is_empty() {
        Vec::new()
    } else {
        let key = URL_SAFE_NO_PAD
            .decode(&raw.mldsa65_verify)
            .context("invalid REALITY ML-DSA verification key base64")?;
        ensure!(
            key.len() == 1952,
            "REALITY ML-DSA-65 verification key must contain 1952 bytes"
        );
        key
    };
    // spiderX is carried verbatim: Go's builder also parses its query into
    // spiderY, which the decoder rejects, so the verbatim string (empty in
    // every validated config — the native client has no spider camouflage)
    // is the only form that survives the round trip.
    Ok(p::transport::internet::reality::Config {
        show: raw.show,
        fingerprint: raw.fingerprint.to_ascii_lowercase(),
        server_name: raw.server_name,
        spider_x: raw.spider_x,
        master_key_log: raw.master_key_log,
        public_key,
        short_id: short_id.to_vec(),
        mldsa65_verify,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

fn log_app(log: Option<&LogConfig>) -> p::app::log::Config {
    let Some(log) = log else {
        // Go's DefaultLogConfig: access disabled, error on the console at
        // warning severity.
        return p::app::log::Config {
            access_log_type: 0,
            error_log_type: 1,
            error_log_level: 2,
            ..Default::default()
        };
    };
    let destination = |value: &str| match value {
        "none" => (0, String::new()),
        "" => (1, String::new()),
        path => (2, path.to_owned()),
    };
    let (access_type, access_path) = destination(&log.access);
    let (error_type, error_path) = destination(&log.error);
    let mut out = p::app::log::Config {
        access_log_type: access_type,
        access_log_path: access_path,
        error_log_type: error_type,
        error_log_path: error_path,
        enable_dns_log: log.dns_log,
        mask_address: log.mask_address.clone(),
        error_log_level: 0,
    };
    match log.loglevel.to_ascii_lowercase().as_str() {
        "debug" => out.error_log_level = 4,
        "info" => out.error_log_level = 3,
        "error" => out.error_log_level = 1,
        "none" => {
            out.access_log_type = 0;
            out.error_log_type = 0;
        }
        _ => out.error_log_level = 2,
    }
    out
}

fn policy_app(policy: &crate::features::PolicyConfig) -> Result<p::app::policy::Config> {
    let mut out = p::app::policy::Config::default();
    for (level, entry) in &policy.levels {
        // A null level entry is ignored, as in Go's PolicyConfig.Build.
        let Some(entry) = entry else { continue };
        let buffer = match entry.buffer_size {
            None => None,
            Some(-1) => Some(p::app::policy::policy::Buffer { connection: -1 }),
            Some(kib) => {
                ensure!(
                    (0..=2_097_151).contains(&kib),
                    "policy level {level} bufferSize {kib} KiB exceeds the protobuf int32 byte field"
                );
                Some(p::app::policy::policy::Buffer {
                    connection: kib * 1024,
                })
            }
        };
        out.level.insert(
            *level,
            p::app::policy::Policy {
                timeout: Some(p::app::policy::policy::Timeout {
                    handshake: entry
                        .handshake
                        .map(|value| p::app::policy::Second { value }),
                    connection_idle: entry
                        .conn_idle
                        .map(|value| p::app::policy::Second { value }),
                    uplink_only: entry
                        .uplink_only
                        .map(|value| p::app::policy::Second { value }),
                    downlink_only: entry
                        .downlink_only
                        .map(|value| p::app::policy::Second { value }),
                }),
                stats: Some(p::app::policy::policy::Stats {
                    user_uplink: entry.stats_user_uplink,
                    user_downlink: entry.stats_user_downlink,
                    user_online: entry.stats_user_online,
                }),
                buffer,
            },
        );
    }
    if let Some(system) = &policy.system {
        out.system = Some(p::app::policy::SystemPolicy {
            stats: Some(p::app::policy::system_policy::Stats {
                inbound_uplink: system.stats_inbound_uplink,
                inbound_downlink: system.stats_inbound_downlink,
                outbound_uplink: system.stats_outbound_uplink,
                outbound_downlink: system.stats_outbound_downlink,
            }),
        });
    }
    Ok(out)
}

fn api_app(api: &ApiConfig) -> Result<p::app::commander::Config> {
    ensure!(!api.tag.is_empty(), "API tag cannot be empty");
    let mut services = Vec::new();
    for service in &api.services {
        match service.to_ascii_lowercase().as_str() {
            "statsservice" => {
                services.push(TypedMessage::pack(&p::app::stats::command::Config::default()))
            }
            "loggerservice" => {
                services.push(TypedMessage::pack(&p::app::log::command::Config::default()))
            }
            "observatoryservice" => services.push(TypedMessage::pack(
                &p::core::app::observatory::command::Config::default(),
            )),
            "handlerservice" => bail!(
                "API service \"HandlerService\" is not carried by the protobuf decoder envelope (xray.app.proxyman.command.Config is not integrated)"
            ),
            "routingservice" => bail!(
                "API service \"RoutingService\" is not carried by the protobuf decoder envelope (xray.app.router.command.Config is not integrated)"
            ),
            "reflectionservice" => bail!(
                "API service \"ReflectionService\" is not carried by the protobuf decoder envelope (xray.app.commander.ReflectionConfig is not integrated)"
            ),
            other => bail!("unknown API service {other:?}"),
        }
    }
    Ok(p::app::commander::Config {
        tag: api.tag.clone(),
        listen: api.listen.clone(),
        service: services,
    })
}

fn observatory_app(
    observatory: &super::observatory::ObservatoryConfig,
) -> Result<p::core::app::observatory::Config> {
    let interval = crate::router::balancer::parse_duration(&observatory.probe_interval)
        .context("invalid observatory probeInterval")?;
    Ok(p::core::app::observatory::Config {
        subject_selector: observatory.subject_selector.clone(),
        probe_url: observatory.probe_url.clone(),
        probe_interval: interval,
        enable_concurrency: observatory.enable_concurrency,
    })
}

fn routing_app(routing: &RoutingConfig) -> Result<p::app::router::Config> {
    let strategy = match routing.domain_strategy.to_lowercase().as_str() {
        "" | "asis" => 0,
        "ipifnonmatch" | "ipondemand" => bail!(
            "routing domainStrategy {:?} is not migrated in the native router; the decoder carries it but the round trip would not re-validate",
            routing.domain_strategy
        ),
        other => bail!("unknown routing domainStrategy {other:?}"),
    };
    Ok(p::app::router::Config {
        domain_strategy: strategy,
        rule: routing
            .rules
            .iter()
            .map(routing_rule)
            .collect::<Result<_>>()?,
        balancing_rule: Vec::new(),
    })
}

fn routing_rule(rule: &RuleConfig) -> Result<p::app::router::RoutingRule> {
    ensure!(
        matches!(rule.r#type.as_str(), "" | "field"),
        "routing rule type {:?} is not carried by the protobuf decoder envelope",
        rule.r#type
    );
    ensure!(
        rule.balancer_tag.is_empty(),
        "routing rule \"balancerTag\" is not carried by the protobuf decoder envelope (balancing routes are not integrated)"
    );
    ensure!(
        !rule.outbound_tag.is_empty(),
        "routing rule requires \"outboundTag\" (neither outboundTag nor balancerTag is specified)"
    );
    ensure!(
        rule.protocol.is_empty(),
        "routing rule \"protocol\" conditions are not carried by the protobuf decoder envelope (the routing rule's protocol field is rejected)"
    );
    let mut networks = Vec::new();
    for entry in rule.network.split(',') {
        match entry {
            "" => (),
            "tcp" => networks.push(2),
            "udp" => networks.push(3),
            other => bail!("unknown routing network {other:?}"),
        }
    }
    // Go's parseFieldRule: `sourceIP` falls back to `source`.
    let source = if rule.source_ip.is_empty() {
        &rule.source
    } else {
        &rule.source_ip
    };
    Ok(p::app::router::RoutingRule {
        target_tag: Some(p::app::router::routing_rule::TargetTag::Tag(
            rule.outbound_tag.clone(),
        )),
        rule_tag: rule.rule_tag.clone(),
        domain: rule
            .domain
            .iter()
            .map(|value| domain_rule(value))
            .collect::<Result<_>>()?,
        ip: rule.ip.iter().map(|value| ip_rule(value)).collect::<Result<_>>()?,
        source_ip: source.iter().map(|value| ip_rule(value)).collect::<Result<_>>()?,
        networks,
        port_list: rule
            .port
            .as_ref()
            .map(rule_port_list)
            .transpose()?
            .map(|range| p::common::net::PortList { range }),
        source_port_list: rule
            .source_port
            .as_ref()
            .map(rule_port_list)
            .transpose()?
            .map(|range| p::common::net::PortList { range }),
        user_email: rule.user.clone(),
        inbound_tag: rule.inbound_tag.clone(),
        ..Default::default()
    })
}

fn rule_port_list(spec: &RulePortSpec) -> Result<Vec<p::common::net::PortRange>> {
    match spec {
        RulePortSpec::Number(port) => Ok(vec![p::common::net::PortRange {
            from: u32::from(*port),
            to: u32::from(*port),
        }]),
        RulePortSpec::List(list) => list
            .split(',')
            .map(|item| {
                let (from, to) = match item.trim().split_once('-') {
                    Some((from, to)) => (
                        from.trim()
                            .parse::<u16>()
                            .with_context(|| format!("invalid port {item:?}"))?,
                        to.trim()
                            .parse::<u16>()
                            .with_context(|| format!("invalid port {item:?}"))?,
                    ),
                    None => {
                        let port = item
                            .trim()
                            .parse::<u16>()
                            .with_context(|| format!("invalid port {item:?}"))?;
                        (port, port)
                    }
                };
                ensure!(from <= to, "reversed port range {item:?}");
                Ok(p::common::net::PortRange {
                    from: u32::from(from),
                    to: u32::from(to),
                })
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Geodata rule parsing (the inverse of the decoder's domain_rule/ip_rule)
// ---------------------------------------------------------------------------

/// Cut leading `!` prefixes, toggling the reverse flag for each one.
fn cut_reverse(rule: &str) -> (&str, bool) {
    let mut rest = rule;
    let mut reverse = false;
    while let Some(tail) = rest.strip_prefix('!') {
        rest = tail;
        reverse = !reverse;
    }
    (rest, reverse)
}

/// One routing `domain` entry → `DomainRule`, following Go's
/// `geodata.ParseDomainRule` (the default match type is Substr, Go's choice
/// for routing rules and sniffing exclusions).
fn domain_rule(rule: &str) -> Result<p::common::geodata::DomainRule> {
    let external = if let Some(code) = rule.strip_prefix("geosite:") {
        Some(format!("geosite.dat:{code}"))
    } else {
        ["ext-domain:", "ext-site:", "ext:"]
            .iter()
            .find_map(|prefix| rule.strip_prefix(prefix))
            .map(str::to_owned)
    };
    let value = if let Some(spec) = external {
        let (file, code) = spec
            .split_once(':')
            .with_context(|| format!("illegal domain rule {rule:?}: syntax error"))?;
        ensure!(!file.is_empty(), "illegal domain rule {rule:?}: empty file");
        ensure!(
            !code.ends_with('@') && !code.contains("@@"),
            "illegal domain rule {rule:?}: empty attr"
        );
        let (code, attrs) = code.split_once('@').unwrap_or((code, ""));
        ensure!(!code.is_empty(), "illegal domain rule {rule:?}: empty code");
        let code = code.to_uppercase();
        // The decoder refuses selectors it cannot format back.
        ensure!(
            !code.contains(':') && !code.contains('@') && !file.contains(':'),
            "domain rule {rule:?} is not representable in the protobuf decoder envelope (unrepresentable geosite selector)"
        );
        p::common::geodata::domain_rule::Value::Geosite(p::common::geodata::GeoSiteRule {
            file: file.to_owned(),
            code,
            attrs: attrs.to_lowercase(),
        })
    } else if let Some(value) = rule.strip_prefix("regexp:") {
        custom_domain(1, value)
    } else if let Some(value) = rule.strip_prefix("domain:") {
        custom_domain(2, value)
    } else if let Some(value) = rule.strip_prefix("full:") {
        custom_domain(3, value)
    } else if let Some(value) = rule.strip_prefix("keyword:") {
        custom_domain(0, value)
    } else if let Some(substr) = rule.strip_prefix("dotless:") {
        ensure!(
            !substr.contains('.'),
            "illegal domain rule {rule:?}: substr in dotless rule should not contain a dot"
        );
        let value = if substr.is_empty() {
            "^[^.]*$".to_owned()
        } else {
            format!("^[^.]*{substr}[^.]*$")
        };
        custom_domain(1, &value)
    } else {
        custom_domain(0, rule)
    };
    Ok(p::common::geodata::DomainRule { value: Some(value) })
}

fn custom_domain(kind: i32, value: &str) -> p::common::geodata::domain_rule::Value {
    p::common::geodata::domain_rule::Value::Custom(p::common::geodata::Domain {
        r#type: kind,
        value: value.to_owned(),
        ..Default::default()
    })
}

/// One routing `ip`/`source` entry → `IPRule`, following Go's
/// `geodata.ParseIPRule` (geoip/ext codes uppercased, CIDRs with the
/// family's full prefix when absent, IPv4-mapped IPv6 collapsed).
fn ip_rule(rule: &str) -> Result<p::common::geodata::IpRule> {
    let (rest, mut reverse) = cut_reverse(rule);
    let rest = if let Some(code) = rest.strip_prefix("geoip:") {
        format!("ext:geoip.dat:{code}")
    } else {
        rest.to_owned()
    };
    let external = ["ext-ip:", "ext:"]
        .iter()
        .find_map(|prefix| rest.strip_prefix(prefix));
    let value = if let Some(spec) = external {
        let (file, code) = spec
            .split_once(':')
            .with_context(|| format!("illegal IP rule {rule:?}: syntax error"))?;
        ensure!(!file.is_empty(), "illegal IP rule {rule:?}: empty file");
        let (code, code_reverse) = cut_reverse(code);
        reverse ^= code_reverse;
        ensure!(!code.is_empty(), "illegal IP rule {rule:?}: empty code");
        let code = code.to_uppercase();
        ensure!(
            !code.contains(':') && !code.starts_with('!') && !file.contains(':'),
            "IP rule {rule:?} is not representable in the protobuf decoder envelope (unrepresentable geoip selector)"
        );
        p::common::geodata::ip_rule::Value::Geoip(p::common::geodata::GeoIpRule {
            file: file.to_owned(),
            code,
            reverse_match: reverse,
        })
    } else {
        let (ip, prefix) = rest.split_once('/').unwrap_or((rest.as_str(), ""));
        let address = ip
            .parse::<IpAddr>()
            .with_context(|| format!("illegal IP rule {rule:?}: unsupported address family"))?;
        let (bytes, max) = match address {
            IpAddr::V4(value) => (value.octets().to_vec(), 32u32),
            IpAddr::V6(value) => match value.to_ipv4_mapped() {
                Some(v4) => (v4.octets().to_vec(), 32),
                None => (value.octets().to_vec(), 128),
            },
        };
        let prefix = if prefix.is_empty() {
            max
        } else {
            let prefix = prefix
                .parse::<u32>()
                .with_context(|| format!("illegal IP rule {rule:?}: invalid CIDR prefix length {prefix:?}"))?;
            ensure!(
                prefix <= max,
                "illegal IP rule {rule:?}: CIDR prefix length {prefix} exceeds max {max}"
            );
            prefix
        };
        p::common::geodata::ip_rule::Value::Custom(p::common::geodata::CidrRule {
            cidr: Some(p::common::geodata::Cidr { ip: bytes, prefix }),
            reverse_match: reverse,
        })
    };
    Ok(p::common::geodata::IpRule { value: Some(value) })
}

fn sniffing_config(sniffing: &super::SniffingConfig) -> Result<p::app::proxyman::SniffingConfig> {
    let mut dest_override = Vec::new();
    for protocol in &sniffing.dest_override {
        match protocol.to_ascii_lowercase().as_str() {
            "http" => dest_override.push("http".to_owned()),
            "tls" | "https" | "ssl" => dest_override.push("tls".to_owned()),
            "quic" => dest_override.push("quic".to_owned()),
            "fakedns" | "fakedns+others" => bail!("fakedns sniffing is not migrated yet"),
            other => bail!("unknown sniffing protocol {other:?}"),
        }
    }
    ensure!(
        sniffing.domains_excluded.is_empty(),
        "sniffing \"domainsExcluded\" rules are not carried by the protobuf decoder envelope (the decoder rejects them)"
    );
    ensure!(
        sniffing.ips_excluded.is_empty(),
        "sniffing \"ipsExcluded\" rules are not carried by the protobuf decoder envelope (the decoder rejects them)"
    );
    Ok(p::app::proxyman::SniffingConfig {
        enabled: sniffing.enabled,
        destination_override: dest_override,
        metadata_only: sniffing.metadata_only,
        route_only: sniffing.route_only,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Full round trip: parse, validate, encode, decode, re-validate.
    fn roundtrip(json: &str) -> Config {
        let config = Config::from_json(json).expect("parse");
        config.validate().expect("validate");
        let bytes = to_bytes(&config).expect("encode");
        let decoded = crate::config::protobuf::from_bytes(&bytes).expect("decode");
        decoded.validate().expect("re-validate");
        decoded
    }

    fn rejection(json: &str, expected: &str) {
        let config = Config::from_json(json)
            .unwrap_or_else(|error| panic!("{json}: parse: {error}"));
        // The whole context chain, so nested serde errors name their field.
        let error = format!("{:#}", to_bytes(&config).unwrap_err());
        assert!(
            error.contains(expected),
            "{json}: {error:?} does not name {expected:?}"
        );
    }

    const ID: &str = "407b5891-80b8-4f87-b899-6f82e3a17025";

    #[test]
    fn socks_inbound_and_freedom_outbound_roundtrip() {
        let decoded = roundtrip(
            r#"{"inbounds":[{"listen":"127.0.0.1","port":10800,"tag":"socks-in","protocol":"socks",
                 "settings":{"auth":"password","accounts":[{"user":"alice","pass":"secret"},{"user":"bob","pass":"hunter2"}],"udp":true,"ip":"127.0.0.1","userLevel":3},
                 "sniffing":{"enabled":true,"destOverride":["http","quic"],"metadataOnly":true,"routeOnly":true}}],
               "outbounds":[{"tag":"direct","protocol":"freedom",
                 "settings":{"domainStrategy":"UseIPv4","redirect":"192.0.2.10:8080","userLevel":2,
                   "finalRules":[{"action":"block","network":["tcp"],"ip":["10.0.0.0/8"],"port":"80-90","blockDelay":"5-10"},
                                 {"action":"allow"}]}}]}"#,
        );
        let inbound = &decoded.inbounds[0];
        assert_eq!(inbound.protocol, "socks");
        assert_eq!(inbound.tag, "socks-in");
        assert_eq!(inbound.listen.to_string(), "127.0.0.1");
        assert_eq!(inbound.port.ports(), [10800]);
        assert_eq!(inbound.settings["auth"], "password");
        // The proto map sorts the accounts by user.
        assert_eq!(
            inbound.settings["accounts"],
            json!([{"user":"alice","pass":"secret"},{"user":"bob","pass":"hunter2"}])
        );
        assert_eq!(inbound.settings["udp"], true);
        assert_eq!(inbound.settings["ip"], "127.0.0.1");
        assert_eq!(inbound.settings["userLevel"], 3);
        let sniffing = inbound.sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, ["http", "quic"]);
        assert!(sniffing.metadata_only);
        assert!(sniffing.route_only);
        let outbound = &decoded.outbounds[0];
        assert_eq!(outbound.protocol, "freedom");
        assert_eq!(outbound.tag, "direct");
        assert_eq!(outbound.settings["domainStrategy"], "UseIPv4");
        assert_eq!(outbound.settings["redirect"], "192.0.2.10:8080");
        assert_eq!(outbound.settings["userLevel"], 2);
        assert_eq!(outbound.settings["finalRules"][0]["action"], "block");
        assert_eq!(outbound.settings["finalRules"][0]["network"], ["tcp"]);
        assert_eq!(outbound.settings["finalRules"][0]["ip"], ["10.0.0.0/8"]);
        assert_eq!(outbound.settings["finalRules"][0]["port"], "80-90");
        assert_eq!(outbound.settings["finalRules"][0]["blockDelay"], "5-10");
        assert_eq!(outbound.settings["finalRules"][1]["action"], "allow");
    }

    #[test]
    fn vless_roundtrip_with_ws_tls_and_reality() {
        let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let seed = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let decrypted = roundtrip(&format!(
            r#"{{"inbounds":[{{"listen":"0.0.0.0","port":443,"tag":"vless-in","protocol":"vless",
                 "settings":{{"decryption":"mlkem768x25519plus.native.0-0s.{seed}","clients":[{{"id":"{ID}","email":"u@example.test","level":2,"flow":"xtls-rprx-vision"}}]}}}}],

               "outbounds":[
                 {{"tag":"ws-tls","protocol":"vless","streamSettings":{{"network":"ws","security":"tls",
                   "wsSettings":{{"path":"/ws?ed=2048&token=fixture","host":"example.test","headers":{{"X-Token":"value"}},"heartbeatPeriod":17}},
                   "tlsSettings":{{"serverName":"example.test","alpn":["http/1.1"]}}}},
                   "settings":{{"vnext":[{{"address":"example.test","port":443,"users":[{{"id":"{ID}","encryption":"none","flow":"xtls-rprx-vision","email":"u@example.test","level":1}}]}}]}}}},
                 {{"tag":"reality","protocol":"vless","streamSettings":{{"network":"tcp","security":"reality",
                   "realitySettings":{{"fingerprint":"native","serverName":"example.test","publicKey":"{key}","shortId":"0102030405060708"}}}},
                   "settings":{{"address":"example.test","port":443,"id":"{ID}","encryption":"none"}}}}]}}"#
        ));
        let inbound = &decrypted.inbounds[0];
        assert_eq!(inbound.protocol, "vless");
        // The decryption string is carried verbatim (the decoder rejects the
        // transformed xorMode/seconds/padding fields).
        assert_eq!(
            inbound.settings["decryption"],
            format!("mlkem768x25519plus.native.0-0s.{seed}")
        );
        assert_eq!(inbound.settings["clients"][0]["id"], ID);
        assert_eq!(inbound.settings["clients"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(inbound.settings["clients"][0]["email"], "u@example.test");
        assert_eq!(inbound.settings["clients"][0]["level"], 2);
        let ws = &decrypted.outbounds[0];
        assert_eq!(ws.tag, "ws-tls");
        assert_eq!(ws.settings["vnext"][0]["address"], "example.test");
        assert_eq!(ws.settings["vnext"][0]["port"], 443);
        assert_eq!(ws.settings["vnext"][0]["users"][0]["id"], ID);
        assert_eq!(ws.settings["vnext"][0]["users"][0]["encryption"], "none");
        let stream = &ws.stream_settings;
        assert_eq!(stream.network, "websocket");
        assert_eq!(stream.security, "tls");
        // The decoder re-appends the extracted early-data parameter.
        assert!(stream.ws_settings.as_ref().unwrap()["path"]
            .as_str()
            .unwrap()
            .contains("ed=2048"));
        assert_eq!(
            stream.tls_settings.as_ref().unwrap()["serverName"],
            "example.test"
        );
        let reality = &decrypted.outbounds[1];
        assert_eq!(reality.tag, "reality");
        assert_eq!(reality.stream_settings.security, "reality");
        let settings = reality.stream_settings.reality_settings.as_ref().unwrap();
        assert_eq!(settings["fingerprint"], "native");
        assert_eq!(settings["serverName"], "example.test");
        assert_eq!(settings["publicKey"], key);
        assert_eq!(settings["shortId"], "0102030405060708");
    }

    #[test]
    fn vmess_trojan_shadowsocks_roundtrip() {
        let key2022 = STANDARD.encode([7u8; 32]);
        let decoded = roundtrip(&format!(
            r#"{{"inbounds":[
                 {{"listen":"127.0.0.1","port":10801,"protocol":"vmess","tag":"vmess-in",
                   "settings":{{"clients":[{{"id":"{ID}","email":"vm@example.test","security":"auto"}}],"default":{{"level":0}}}}}},
                 {{"listen":"127.0.0.1","port":10802,"protocol":"trojan","tag":"trojan-in",
                   "settings":{{"clients":[{{"password":"trojan-fixture","email":"tj@example.test","level":4}}]}}}},
                 {{"listen":"127.0.0.1","port":10803,"protocol":"shadowsocks","tag":"ss-legacy",
                   "settings":{{"method":"aes-256-gcm","password":"legacy-fixture","email":"ss@example.test","level":1,"network":"tcp,udp"}}}},
                 {{"listen":"127.0.0.1","port":10804,"protocol":"shadowsocks","tag":"ss-2022",
                   "settings":{{"method":"2022-blake3-aes-256-gcm","password":"{key2022}","email":"ss22@example.test","level":2,"network":"tcp"}}}}],
               "outbounds":[
                 {{"tag":"vmess-out","protocol":"vmess","settings":{{"vnext":[{{"address":"vm.example.test","port":443,
                   "users":[{{"id":"{ID}","security":"chacha20-poly1305","email":"vm@example.test"}}]}}]}}}},
                 {{"tag":"trojan-out","protocol":"trojan","settings":{{"servers":[{{"address":"tj.example.test","port":443,"password":"trojan-fixture","email":"tj@example.test","level":3}}]}}}},
                 {{"tag":"ss-out","protocol":"shadowsocks","settings":{{"servers":[{{"address":"ss.example.test","port":8388,"method":"aes-128-gcm","password":"legacy-fixture","email":"ss@example.test","level":1}}]}}}},
                 {{"tag":"ss2022-out","protocol":"shadowsocks","settings":{{"address":"ss22.example.test","port":8388,"method":"2022-blake3-aes-256-gcm","password":"{key2022}"}}}}]}}"#
        ));
        let vmess = &decoded.inbounds[0];
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.settings["clients"][0]["id"], ID);
        assert_eq!(vmess.settings["clients"][0]["security"], "auto");
        assert_eq!(vmess.settings["default"]["level"], 0);
        let trojan = &decoded.inbounds[1];
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.settings["clients"][0]["password"], "trojan-fixture");
        assert_eq!(trojan.settings["clients"][0]["level"], 4);
        let legacy = &decoded.inbounds[2];
        assert_eq!(legacy.protocol, "shadowsocks");
        assert_eq!(legacy.settings["clients"][0]["method"], "aes-256-gcm");
        assert_eq!(legacy.settings["clients"][0]["password"], "legacy-fixture");
        assert_eq!(legacy.settings["network"], "tcp,udp");
        let ss2022 = &decoded.inbounds[3];
        assert_eq!(ss2022.protocol, "shadowsocks");
        assert_eq!(ss2022.settings["method"], "2022-blake3-aes-256-gcm");
        assert_eq!(ss2022.settings["password"], key2022);
        assert_eq!(ss2022.settings["email"], "ss22@example.test");
        assert_eq!(ss2022.settings["level"], 2);
        assert_eq!(ss2022.settings["network"], "tcp");
        let out = &decoded.outbounds[0];
        assert_eq!(out.protocol, "vmess");
        assert_eq!(
            out.settings["vnext"][0]["users"][0]["security"],
            "chacha20-poly1305"
        );
        let out = &decoded.outbounds[1];
        assert_eq!(out.protocol, "trojan");
        assert_eq!(out.settings["servers"][0]["password"], "trojan-fixture");
        assert_eq!(out.settings["servers"][0]["level"], 3);
        let out = &decoded.outbounds[2];
        assert_eq!(out.settings["servers"][0]["method"], "aes-128-gcm");
        let out = &decoded.outbounds[3];
        assert_eq!(out.settings["address"], "ss22.example.test");
        assert_eq!(out.settings["method"], "2022-blake3-aes-256-gcm");
    }

    #[test]
    fn dokodemo_http_and_blackhole_roundtrip() {
        let decoded = roundtrip(
            r#"{"inbounds":[
                 {"listen":"127.0.0.1","port":10805,"tag":"doko","protocol":"dokodemo-door",
                  "settings":{"address":"dst.example.test","port":443,"network":"tcp,udp","userLevel":1}},
                 {"listen":"127.0.0.1","port":10806,"tag":"http","protocol":"http",
                  "settings":{"accounts":[{"user":"alice","pass":"secret"}]}}],
               "outbounds":[{"tag":"block","protocol":"blackhole",
                 "settings":{"response":{"type":"custom","customResponseData":"Zm9vYmFy"}}}]}"#,
        );
        let doko = &decoded.inbounds[0];
        assert_eq!(doko.protocol, "dokodemo-door");
        assert_eq!(doko.settings["address"], "dst.example.test");
        assert_eq!(doko.settings["port"], 443);
        assert_eq!(doko.settings["network"], "tcp,udp");
        assert_eq!(doko.settings["userLevel"], 1);
        let http = &decoded.inbounds[1];
        assert_eq!(http.protocol, "http");
        assert_eq!(
            http.settings["accounts"],
            json!([{"user":"alice","pass":"secret"}])
        );
        let block = &decoded.outbounds[0];
        assert_eq!(block.protocol, "blackhole");
        assert_eq!(block.settings["response"]["type"], "custom");
        assert_eq!(block.settings["response"]["customResponseData"], "Zm9vYmFy");
    }

    #[test]
    fn transports_roundtrip() {
        let decoded = roundtrip(&format!(
            r#"{{"inbounds":[{{"listen":"127.0.0.1","port":10807,"protocol":"vless",
                 "settings":{{"decryption":"none","clients":[{{"id":"{ID}"}}]}}}}],
               "outbounds":[
                 {{"tag":"grpc","protocol":"vmess","streamSettings":{{"network":"grpc","grpcSettings":{{"serviceName":"svc","authority":"grpc.example.test","multiMode":true,"user_agent":"agent/1"}}}},
                   "settings":{{"address":"grpc.example.test","port":443,"id":"{ID}","security":"auto"}}}},
                 {{"tag":"kcp","protocol":"vless","streamSettings":{{"network":"kcp","kcpSettings":{{"mtu":1400,"tti":50}}}},
                   "settings":{{"address":"kcp.example.test","port":443,"id":"{ID}","encryption":"none"}}}},
                 {{"tag":"upgrade","protocol":"trojan","streamSettings":{{"network":"httpupgrade","httpupgradeSettings":{{"path":"/up?ed=256","host":"up.example.test"}}}},
                   "settings":{{"address":"up.example.test","port":443,"password":"pw"}}}},
                 {{"tag":"xhttp","protocol":"vless","streamSettings":{{"network":"xhttp","xhttpSettings":{{"mode":"packet-up","xPaddingBytes":"100-200","headers":{{"X-Pad":"1"}},"noGRPCHeader":true,"scMaxEachPostBytes":"1000000"}}}},
                   "settings":{{"address":"xh.example.test","port":443,"id":"{ID}","encryption":"none"}}}},
                 {{"tag":"raw","protocol":"freedom","streamSettings":{{"network":"tcp"}}}}]}}"#
        ));
        let grpc = &decoded.outbounds[0].stream_settings;
        assert_eq!(grpc.network, "grpc");
        let settings = grpc.grpc_settings.as_ref().unwrap();
        assert_eq!(settings["serviceName"], "svc");
        assert_eq!(settings["authority"], "grpc.example.test");
        assert_eq!(settings["multiMode"], true);
        assert_eq!(settings["user_agent"], "agent/1");
        let kcp = &decoded.outbounds[1].stream_settings;
        assert_eq!(kcp.network, "mkcp");
        let settings = kcp.kcp_settings.as_ref().unwrap();
        assert_eq!(settings["mtu"], 1400);
        assert_eq!(settings["tti"], 50);
        // Go materializes the KCP defaults in the message.
        assert_eq!(settings["uplinkCapacity"], 5);
        assert_eq!(settings["downlinkCapacity"], 20);
        assert_eq!(settings["cwndMultiplier"], 1);
        assert_eq!(settings["maxSendingWindow"], 2 * 1024 * 1024);
        let upgrade = &decoded.outbounds[2].stream_settings;
        assert_eq!(upgrade.network, "httpupgrade");
        let settings = upgrade.httpupgrade_settings.as_ref().unwrap();
        assert!(settings["path"].as_str().unwrap().contains("ed=256"));
        assert_eq!(settings["host"], "up.example.test");
        let xhttp = &decoded.outbounds[3].stream_settings;
        assert_eq!(xhttp.network, "splithttp");
        let settings = xhttp.xhttp_settings.as_ref().unwrap();
        assert_eq!(settings["mode"], "packet-up");
        assert_eq!(settings["xPaddingBytes"], "100-200");
        assert_eq!(settings["headers"]["X-Pad"], "1");
        assert_eq!(settings["noGRPCHeader"], true);
        assert_eq!(settings["scMaxEachPostBytes"], "1000000");
        let raw = &decoded.outbounds[4].stream_settings;
        assert_eq!(raw.network, "tcp");
        assert!(raw.tcp_settings.is_none());
    }

    #[test]
    fn apps_roundtrip_log_policy_stats_api_routing_observatory() {
        let decoded = roundtrip(
            r#"{"log":{"loglevel":"info","access":"none","error":"error.log","dnsLog":true},
               "stats":{},
               "policy":{"levels":{"0":{"handshake":4,"connIdle":300,"statsUserUplink":true,"bufferSize":2},
                                    "3":{"uplinkOnly":0,"bufferSize":-1}},
                          "system":{"statsInboundUplink":true,"statsOutboundDownlink":true}},
               "api":{"tag":"api","listen":"127.0.0.1:15490","services":["StatsService","LoggerService","ObservatoryService"]},
               "observatory":{"subjectSelector":["direct"],"probeURL":"http://probe.example/status","probeInterval":"1m","enableConcurrency":true},
               "routing":{"domainStrategy":"AsIs","rules":[
                 {"type":"field","ruleTag":"rule0","outboundTag":"direct",
                  "domain":["full:example.test","keyword:example","example.test"],
                  "ip":["10.0.0.0/8","!1.2.3.4/32","1.2.3.4"],
                  "port":"80-90","sourcePort":"1000","network":"tcp,udp",
                  "source":["192.0.2.0/24"],"user":["u@example.test"],"inboundTag":["socks-in"]},
                 {"type":"field","outboundTag":"api","ip":["2001:db8::/32"]}]},
               "inbounds":[{"listen":"127.0.0.1","port":10808,"tag":"socks-in","protocol":"socks","settings":{}}],
               "outbounds":[{"tag":"direct","protocol":"freedom"},
                            {"tag":"blocked","protocol":"blackhole"}]}"#,
        );
        let log = decoded.log.as_ref().unwrap();
        assert_eq!(log.loglevel, "info");
        assert_eq!(log.access, "none");
        assert_eq!(log.error, "error.log");
        assert!(log.dns_log);
        assert!(decoded.stats.is_some());
        let policy = decoded.policy.as_ref().unwrap();
        let level0 = policy.levels[&0].as_ref().unwrap();
        assert_eq!(level0.handshake, Some(4));
        assert_eq!(level0.conn_idle, Some(300));
        assert!(level0.stats_user_uplink);
        assert_eq!(level0.buffer_size, Some(2));
        let level3 = policy.levels[&3].as_ref().unwrap();
        assert_eq!(level3.uplink_only, Some(0));
        assert_eq!(level3.conn_idle, None);
        assert_eq!(level3.buffer_size, Some(-1));
        let system = policy.system.as_ref().unwrap();
        assert!(system.stats_inbound_uplink);
        assert!(system.stats_outbound_downlink);
        assert!(!system.stats_inbound_downlink);
        let api = decoded.api.as_ref().unwrap();
        assert_eq!(api.tag, "api");
        assert_eq!(api.listen, "127.0.0.1:15490");
        assert_eq!(
            api.services,
            ["StatsService", "LoggerService", "ObservatoryService"]
        );
        let observatory = decoded.observatory.as_ref().unwrap();
        assert_eq!(observatory.subject_selector, ["direct"]);
        assert_eq!(observatory.probe_url, "http://probe.example/status");
        assert_eq!(observatory.probe_interval, "60000000000ns");
        assert!(observatory.enable_concurrency);
        let routing = &decoded.routing;
        assert_eq!(routing.domain_strategy, "AsIs");
        assert_eq!(routing.rules[0].rule_tag, "rule0");
        assert_eq!(routing.rules[0].outbound_tag, "direct");
        assert_eq!(
            routing.rules[0].domain,
            ["full:example.test", "keyword:example", "keyword:example.test"]
        );
        assert_eq!(
            routing.rules[0].ip,
            ["10.0.0.0/8", "!1.2.3.4/32", "1.2.3.4/32"]
        );
        assert!(matches!(&routing.rules[0].port, Some(RulePortSpec::List(list)) if list == "80-90"));
        assert_eq!(routing.rules[1].ip, ["2001:db8::/32"]);
    }

    #[test]
    fn absent_log_defaults_like_go_and_empty_routing_emits_no_app() {
        let decoded = roundtrip(
            r#"{"inbounds":[{"listen":"127.0.0.1","port":10809,"protocol":"socks","settings":{}}],
               "outbounds":[{"protocol":"freedom"}]}"#,
        );
        // Go always emits the logger app: DefaultLogConfig.
        let log = decoded.log.as_ref().unwrap();
        assert_eq!(log.loglevel, "warning");
        assert_eq!(log.access, "none");
        assert_eq!(log.error, "");
        // An empty routing object emits no router app at all.
        assert!(decoded.routing.rules.is_empty());
        assert_eq!(decoded.routing.domain_strategy, "");
    }

    const CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB2DCCAX+gAwIBAgIQY11wsHA83Wkn9isHTro/izAKBggqhkjOPQQDAjA0MRww
GgYDVQQKExNYcmF5IFJ1c3QgTWlncmF0aW9uMRQwEgYDVQQDEwtDTEkgRml4dHVy
ZTAeFw0yNjA5MTkxNzU2MTZaFw0yNjEyMTgxODU2MTZaMDQxHDAaBgNVBAoTE1hy
YXkgUnVzdCBNaWdyYXRpb24xFDASBgNVBAMTC0NMSSBGaXh0dXJlMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEukB+qaL8N1zXmCMW8dBg1IlgnA7RBX8Og+dXY9aQ
+jwAeKfqNJAfuaiCLACVncW/i0n7GdLxoFum5B6N7JmjC6NzMHEwDgYDVR0PAQH/
BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFKE/u8Cae2BuRwniBBly8ioTH68MMBoGA1UdEQQTMBGCD2ZpeHR1cmUu
ZXhhbXBsZTAKBggqhkjOPQQDAgNHADBEAiAfcX+L8duSuBYCBzbvu69wz1BAnCNk
2rkAdHB2Dvx2oQIgHSaEEM4jtLzhPo2NjcvSjZCxoWvcWNGN3vchEMBuz49Q=
-----END CERTIFICATE-----";

    #[test]
    fn tls_certificates_roundtrip_inline_and_from_files() {
        let pem_lines: Vec<&str> = CA_PEM.lines().collect();
        // Inline lines: Go embeds the snapshot with oneTimeLoading set.
        let inline = serde_json::to_string(&json!({
            "outbounds": [
                {
                    "tag": "ca",
                    "protocol": "freedom",
                    "streamSettings": {
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "fixture.example",
                            "certificates": [
                                {"usage": "verify", "certificate": pem_lines},
                            ],
                        },
                    },
                },
            ],
        }))
        .unwrap();
        let decoded = roundtrip(&inline);
        let tls = decoded.outbounds[0]
            .stream_settings
            .tls_settings
            .as_ref()
            .unwrap();
        let certificate = tls["certificates"][0]["certificate"]
            .as_array()
            .unwrap()
            .join("\n");
        assert_eq!(certificate, CA_PEM);
        assert_eq!(tls["certificates"][0]["usage"], "verify");
        assert_eq!(tls["serverName"], "fixture.example");
        // Paths: Go reads and embeds the initial snapshot; the decoder
        // verifies the files still match before keeping the path form.
        let path = std::env::temp_dir().join(format!(
            "xray-protobuf-encode-{}.pem",
            std::process::id()
        ));
        std::fs::write(&path, CA_PEM).expect("write the certificate fixture");
        let from_file = serde_json::to_string(&json!({
            "outbounds": [
                {
                    "tag": "ca",
                    "protocol": "freedom",
                    "streamSettings": {
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "fixture.example",
                            "certificates": [
                                {
                                    "usage": "verify",
                                    "certificateFile": path.display().to_string(),
                                },
                            ],
                        },
                    },
                },
            ],
        }))
        .unwrap();
        let decoded = roundtrip(&from_file);
        let tls = decoded.outbounds[0]
            .stream_settings
            .tls_settings
            .as_ref()
            .unwrap();
        // A verify-usage certificate always comes back inline: the decoder's
        // reload form is for encipherment certificates only.
        assert_eq!(
            tls["certificates"][0]["certificate"]
                .as_array()
                .unwrap()
                .join("\n"),
            CA_PEM
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn domain_and_ip_rules_follow_go_parsing() {
        // geosite: → ext:geosite.dat with an uppercased code.
        assert!(matches!(
            domain_rule("geosite:cn").unwrap().value,
            Some(p::common::geodata::domain_rule::Value::Geosite(ref rule))
                if rule.file == "geosite.dat" && rule.code == "CN" && rule.attrs.is_empty()
        ));
        assert!(matches!(
            domain_rule("ext:custom.dat:code@ATTRS").unwrap().value,
            Some(p::common::geodata::domain_rule::Value::Geosite(ref rule))
                if rule.file == "custom.dat" && rule.code == "CODE" && rule.attrs == "attrs"
        ));
        for (rule, kind, value) in [
            ("keyword:x", 0, "x"),
            ("regexp:^a.*b$", 1, "^a.*b$"),
            ("domain:x", 2, "x"),
            ("full:x", 3, "x"),
            ("plain.example", 0, "plain.example"),
        ] {
            assert!(matches!(
                domain_rule(rule).unwrap().value,
                Some(p::common::geodata::domain_rule::Value::Custom(ref domain))
                    if domain.r#type == kind && domain.value == value
            ), "{rule}");
        }
        assert!(matches!(
            domain_rule("dotless:x").unwrap().value,
            Some(p::common::geodata::domain_rule::Value::Custom(ref domain))
                if domain.r#type == 1 && domain.value == "^[^.]*x[^.]*$"
        ));
        assert!(domain_rule("dotless:a.b").is_err());
        assert!(domain_rule("ext:file:code@").is_err());
        assert!(domain_rule("ext:file:a:b").is_err());

        assert!(matches!(
            ip_rule("geoip:cn").unwrap().value,
            Some(p::common::geodata::ip_rule::Value::Geoip(ref rule))
                if rule.file == "geoip.dat" && rule.code == "CN" && !rule.reverse_match
        ));
        assert!(matches!(
            ip_rule("!ext:geoip.dat:!cn").unwrap().value,
            Some(p::common::geodata::ip_rule::Value::Geoip(ref rule))
                if rule.code == "CN" && !rule.reverse_match
        ));
        assert!(matches!(
            ip_rule("10.0.0.0/8").unwrap().value,
            Some(p::common::geodata::ip_rule::Value::Custom(ref rule))
                if rule.cidr.as_ref().unwrap().prefix == 8
        ));
        // A bare IP gets its family's full prefix, like the decoder emits.
        assert!(matches!(
            ip_rule("1.2.3.4").unwrap().value,
            Some(p::common::geodata::ip_rule::Value::Custom(ref rule))
                if rule.cidr.as_ref().unwrap().prefix == 32
        ));
        assert!(matches!(
            ip_rule("!2001:db8::/32").unwrap().value,
            Some(p::common::geodata::ip_rule::Value::Custom(ref rule))
                if rule.reverse_match && rule.cidr.as_ref().unwrap().prefix == 32
        ));
        // IPv4-mapped IPv6 collapses to four bytes like Go's ParseAddress.
        assert!(matches!(
            ip_rule("::ffff:1.2.3.4/32").unwrap().value,
            Some(p::common::geodata::ip_rule::Value::Custom(ref rule))
                if rule.cidr.as_ref().unwrap().ip.len() == 4
        ));
        assert!(ip_rule("::ffff:1.2.3.4/120").is_err());
        assert!(ip_rule("example.test").is_err());
        assert!(ip_rule("10.0.0.0/40").is_err());
    }

    /// One named rejection per JSON surface the decoder envelope excludes.
    #[test]
    fn rejects_outside_the_decoder_envelope() {
        let cases: Vec<(&str, &str)> = vec![
            // Inbound shapes.
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"dokodemo-door","settings":{"address":"d","port":1,"network":"unix"}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "unix",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"dokodemo-door","settings":{"address":"d","port":1,"followRedirect":true}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "followRedirect",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"hysteria","settings":{},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{}}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "hysteria",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"tun","settings":{"name":"x","gateway":["172.19.0.1/30"],"mtu":1500}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "tun",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"wireguard","settings":{}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "wireguard",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"dns","settings":{}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "dns inbound",
            ),
            (
                r#"{"inbounds":[{"listen":"/tmp/x.sock","port":0,"protocol":"dokodemo-door","settings":{"address":"d","port":1}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "unix listen",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":"3000-4000","protocol":"socks","settings":{}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "exactly one port",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"407b5891-80b8-4f87-b899-6f82e3a17025","encryption":"x"}]}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "encryption",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"vmess","settings":{"clients":[{"id":"407b5891-80b8-4f87-b899-6f82e3a17025","experiments":"x"}]}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "experiments",
            ),
            // Outbound shapes.
            (
                r#"{"outbounds":[{"protocol":"masque","settings":{"address":"m","port":1},"streamSettings":{"network":"masque","security":"tls","masqueSettings":{}}}]}"#,
                "masque",
            ),
            (
                r#"{"outbounds":[{"protocol":"dns","settings":{}}]}"#,
                "dns outbound",
            ),
            (
                r#"{"outbounds":[{"protocol":"loopback","settings":{}}]}"#,
                "loopback",
            ),
            (
                r#"{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"x","address":["10.0.0.1"],"peers":[]}}]}"#,
                "wireguard",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","mux":{"enabled":true}}]}"#,
                "mux",
            ),
            (
                r#"{"outbounds":[{"protocol":"shadowsocks","settings":{"address":"s","port":1,"method":"xchacha20-poly1305","password":"x"}}]}"#,
                "XCHACHA20",
            ),
            (
                r#"{"outbounds":[{"protocol":"shadowsocks","settings":{"address":"s","port":1,"method":"2022-blake3-aes-256-gcm","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","email":"a@b"}}]}"#,
                "email",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","settings":{"redirect":"example.test:0"}}]}"#,
                "redirect",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","settings":{"fragment":{}}}]}"#,
                "fragment",
            ),
            // Stream settings.
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{}}}]}"#,
                "hysteria transport",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"tcp","finalmask":{"quicParams":{}}}}]}"#,
                "finalmask",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"none"}}}}]}"#,
                "tcpSettings",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"ws","security":"tls","wsSettings":{"acceptProxyProtocol":true}}}]}"#,
                "acceptProxyProtocol",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"grpc","grpcSettings":{"idle_timeout":90}}}]}"#,
                "keepalive",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"xhttp","xhttpSettings":{"xmux":{"maxConnections":"3"}}}}]}"#,
                "xmux",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"xhttp","xhttpSettings":{"downloadSettings":{}}}}]}"#,
                "downloadSettings",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"xhttp","xhttpSettings":{"xPaddingBytes":"100-0"}}}}]}"#,
                "zero upper bound",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"x:443","serverNames":["a"],"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","shortIds":["01"]}}}]}"#,
                "dest",
            ),
            // TLS fields the decoder or the runtime does not carry.
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"echServerKeys":"x"}}}]}"#,
                "echServerKeys",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"pinnedPeerCertSha256":"x"}}}]}"#,
                "pinnedPeerCertSha256",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"verifyPeerCertByName":"x"}}}]}"#,
                "verifyPeerCertByName",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]}"#,
                "allowInsecure",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificate":["x"],"usage":"issue"}]}}}]}"#,
                "issue",
            ),
            (
                r#"{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificate":["x"],"ocspStapling":5}]}}}]}"#,
                "ocspStapling",
            ),
            // Sniffing exclusions.
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"socks","settings":{},"sniffing":{"enabled":true,"domainsExcluded":["a.com"]}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "domainsExcluded",
            ),
            (
                r#"{"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"socks","settings":{},"sniffing":{"enabled":true,"ipsExcluded":["10.0.0.0/8"]}}],"outbounds":[{"protocol":"freedom"}]}"#,
                "ipsExcluded",
            ),
            // Routing surface.
            (
                r#"{"routing":{"domainStrategy":"IPIfNonMatch"},"outbounds":[{"protocol":"freedom"}]}"#,
                "domainStrategy",
            ),
            (
                r#"{"routing":{"balancers":[{"tag":"b","selector":["a"],"strategy":{"type":"random"}}]},"outbounds":[{"protocol":"freedom"}]}"#,
                "balancers",
            ),
            (
                r#"{"routing":{"rules":[{"type":"field","balancerTag":"b"}]},"outbounds":[{"protocol":"freedom"}]}"#,
                "balancerTag",
            ),
            (
                r#"{"routing":{"rules":[{"type":"field","outboundTag":"direct","protocol":["http"]}]},"outbounds":[{"protocol":"freedom"}]}"#,
                "protocol",
            ),
            // Root apps without a decoder arm.
            (
                r#"{"dns":{"servers":["1.1.1.1"]},"outbounds":[{"protocol":"freedom"}]}"#,
                "dns",
            ),
            (
                r#"{"reverse":{"portals":[{"tag":"p","domain":"d"}]},"outbounds":[{"protocol":"freedom"}]}"#,
                "reverse",
            ),
            (
                r#"{"burstObservatory":{"subjectSelector":["a"],"pingConfig":{}},"outbounds":[{"protocol":"freedom"}]}"#,
                "burstObservatory",
            ),
            (
                r#"{"fakeDns":{"ipPool":"198.18.0.0/15","poolSize":32768},"outbounds":[{"protocol":"freedom"}]}"#,
                "fakeDns",
            ),
            (
                r#"{"metrics":{"tag":"m","listen":"127.0.0.1:1"},"outbounds":[{"protocol":"freedom"}]}"#,
                "metrics",
            ),
            (
                r#"{"version":{"min":"1.0.0"},"outbounds":[{"protocol":"freedom"}]}"#,
                "version",
            ),
            (
                r#"{"geodata":{"cron":"0 0 * * *"},"outbounds":[{"protocol":"freedom"}]}"#,
                "geodata",
            ),
            (
                r#"{"env":{"XRAY_LOCATION_ASSET":"."},"outbounds":[{"protocol":"freedom"}]}"#,
                "env",
            ),
            // API services without a decoder arm.
            (
                r#"{"api":{"tag":"api","listen":"127.0.0.1:1","services":["HandlerService"]},"outbounds":[{"protocol":"freedom"}]}"#,
                "HandlerService",
            ),
        ];
        for (json, expected) in cases {
            rejection(json, expected);
        }
    }
}
