//! Native conversion of the reference core.Config protobuf into the runtime model.
//!
//! Conversion does not start listeners or open logs. Call `Config::validate` (as
//! for JSON) before use. Nondefault settings with no native representation fail
//! closed instead of disappearing during conversion.

use std::{collections::HashSet, mem::take, net::IpAddr};

use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use prost::Message;
use serde_json::{Map, Value, json};

use crate::proto::xray::{self as p, common::serial::TypedMessage};

use super::Config;

fn unpack<M: Message + prost::Name + Default>(message: &TypedMessage) -> Result<M> {
    message
        .unpack()
        .with_context(|| format!("decode protobuf {}", message.r#type))
}

fn supported_rest<M: Default + PartialEq>(rest: M, context: &str) -> Result<()> {
    ensure!(
        rest == M::default(),
        "{context} contains unsupported protobuf settings"
    );
    Ok(())
}

macro_rules! fields {
    ($output:ident, $source:ident; $($key:literal => $field:ident),* $(,)?) => {
        $($output.insert($key.into(), json!(take(&mut $source.$field)));)*
    };
}

/// Decode a binary `xray.core.Config` without invoking Go or any subprocess.
pub fn from_bytes(bytes: &[u8]) -> Result<Config> {
    let source = p::core::Config::decode(bytes).context("invalid Xray protobuf configuration")?;
    ensure!(
        source.extension.is_empty(),
        "protobuf extensions are not integrated"
    );
    let mut output = json!({"inbounds":[], "outbounds":[]});
    let mut apps = HashSet::new();
    for app in source.app {
        ensure!(
            apps.insert(app.r#type.clone()),
            "duplicate protobuf app {}",
            app.r#type
        );
        match app.r#type.as_str() {
            "xray.app.dispatcher.Config" => {
                let mut value: p::app::dispatcher::Config = unpack(&app)?;
                if let Some(session) = value.settings.take() {
                    supported_rest(session, "dispatcher session")?;
                }
                supported_rest(value, "dispatcher")?;
            }
            "xray.app.proxyman.InboundConfig" => supported_rest(
                unpack::<p::app::proxyman::InboundConfig>(&app)?,
                "inbound manager",
            )?,
            "xray.app.proxyman.OutboundConfig" => supported_rest(
                unpack::<p::app::proxyman::OutboundConfig>(&app)?,
                "outbound manager",
            )?,
            "xray.app.stats.Config" => {
                supported_rest(unpack::<p::app::stats::Config>(&app)?, "stats")?;
                output["stats"] = json!({});
            }
            "xray.app.log.Config" => output["log"] = logging(unpack(&app)?)?,
            "xray.app.policy.Config" => output["policy"] = policy(unpack(&app)?)?,
            "xray.app.router.Config" => output["routing"] = routing(unpack(&app)?)?,
            "xray.app.commander.Config" => output["api"] = api(unpack(&app)?)?,
            "xray.core.app.observatory.Config" => {
                output["observatory"] = observatory(unpack(&app)?)?
            }
            other => bail!("protobuf app {other:?} is not integrated"),
        }
    }
    output["inbounds"] = Value::Array(
        source
            .inbound
            .into_iter()
            .map(inbound)
            .collect::<Result<_>>()?,
    );
    output["outbounds"] = Value::Array(
        source
            .outbound
            .into_iter()
            .map(outbound)
            .collect::<Result<_>>()?,
    );
    serde_json::from_value(output)
        .context("protobuf configuration cannot be represented by the native runtime")
}

fn ip(bytes: &[u8]) -> Result<IpAddr> {
    match bytes.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _ => bail!("protobuf IP address must have 4 or 16 bytes"),
    }
}

fn address(value: p::common::net::IpOrDomain) -> Result<String> {
    use p::common::net::ip_or_domain::Address;
    match value.address.context("protobuf address is absent")? {
        Address::Ip(bytes) => {
            let address = match ip(&bytes)? {
                IpAddr::V6(value) => value
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(value)),
                value => value,
            };
            Ok(address.to_string())
        }
        Address::Domain(domain) => {
            ensure!(!domain.is_empty(), "empty protobuf domain");
            ensure!(
                domain.parse::<IpAddr>().is_err(),
                "a protobuf domain containing an IP literal cannot retain its address type in the native configuration"
            );
            Ok(domain)
        }
    }
}

fn port(value: u32) -> Result<u16> {
    u16::try_from(value).context("protobuf port exceeds 65535")
}

fn ports(value: p::common::net::PortList) -> Result<String> {
    ensure!(
        !value.range.is_empty(),
        "empty protobuf port list is not representable"
    );
    value
        .range
        .into_iter()
        .map(|range| {
            let from = port(range.from)?;
            let to = port(range.to)?;
            ensure!(from <= to, "reversed protobuf port range");
            Ok(if from == to {
                from.to_string()
            } else {
                format!("{from}-{to}")
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(|ranges| ranges.join(","))
}

fn networks(values: Vec<i32>) -> Result<String> {
    values
        .into_iter()
        .map(|value| match value {
            2 => Ok("tcp"),
            3 => Ok("udp"),
            _ => bail!("unsupported protobuf network {value}"),
        })
        .collect::<Result<Vec<_>>>()
        .map(|values| values.join(","))
}

fn inbound(mut handler: p::core::InboundHandlerConfig) -> Result<Value> {
    let receiver = handler
        .receiver_settings
        .take()
        .context("protobuf inbound receiver settings are required")?;
    let mut receiver: p::app::proxyman::ReceiverConfig = unpack(&receiver)?;
    let port_list = receiver
        .port_list
        .take()
        .context("protobuf inbound port list is required")?;
    ensure!(
        port_list.range.len() == 1 && port_list.range[0].from == port_list.range[0].to,
        "protobuf inbound requires exactly one port; multi-port listeners are not integrated"
    );
    let listen = receiver
        .listen
        .take()
        .map(address)
        .transpose()?
        .unwrap_or_else(|| "0.0.0.0".into());
    let _: IpAddr = listen
        .parse()
        .context("protobuf domain/unix inbound listeners are not integrated")?;
    let stream = stream(receiver.stream_settings.take())?;
    supported_rest(receiver, "inbound receiver (sniffing/original destination)")?;
    let proxy = handler
        .proxy_settings
        .take()
        .context("protobuf inbound proxy settings are required")?;
    let (protocol, settings) = inbound_proxy(&proxy)?;
    let result = json!({"tag":take(&mut handler.tag), "listen":listen, "port":port(port_list.range[0].from)?,
        "protocol":protocol, "settings":settings, "streamSettings":stream});
    supported_rest(handler, "inbound handler")?;
    Ok(result)
}

fn outbound(mut handler: p::core::OutboundHandlerConfig) -> Result<Value> {
    let stream = if let Some(sender) = handler.sender_settings.take() {
        let mut sender: p::app::proxyman::SenderConfig = unpack(&sender)?;
        let stream = stream(sender.stream_settings.take())?;
        // Disabled mux still carries its unused defaults in configs from Go.
        if sender
            .multiplex_settings
            .as_ref()
            .is_some_and(|mux| !mux.enabled)
        {
            sender.multiplex_settings = None;
        }
        supported_rest(sender, "outbound sender (bind/strategy/mux)")?;
        stream
    } else {
        json!({})
    };
    let proxy = handler
        .proxy_settings
        .take()
        .context("protobuf outbound proxy settings are required")?;
    let (protocol, settings) = outbound_proxy(&proxy)?;
    let result = json!({"tag":take(&mut handler.tag),"protocol":protocol,"settings":settings,"streamSettings":stream});
    // Source schema explicitly marks these metadata fields unused.
    handler.expire = 0;
    handler.comment.clear();
    supported_rest(handler, "outbound handler")?;
    Ok(result)
}

fn inbound_proxy(typed: &TypedMessage) -> Result<(&'static str, Value)> {
    match typed.r#type.as_str() {
        "xray.proxy.socks.ServerConfig" => {
            let mut value: p::proxy::socks::ServerConfig = unpack(typed)?;
            let auth = match take(&mut value.auth_type) {
                0 => "noauth",
                1 => "password",
                n => bail!("invalid SOCKS auth type {n}"),
            };
            let mut result = json!({"auth":auth,"accounts":passwords(take(&mut value.accounts)),"udp":take(&mut value.udp_enabled),"userLevel":take(&mut value.user_level)});
            if let Some(addr) = value.address.take() {
                result["ip"] = json!(address(addr)?);
            }
            supported_rest(value, "SOCKS inbound")?;
            Ok(("socks", result))
        }
        "xray.proxy.http.ServerConfig" => {
            let mut value: p::proxy::http::ServerConfig = unpack(typed)?;
            let result = json!({"accounts":passwords(take(&mut value.accounts)),"allowTransparent":take(&mut value.allow_transparent),"userLevel":take(&mut value.user_level)});
            supported_rest(value, "HTTP inbound")?;
            Ok(("http", result))
        }
        "xray.proxy.dokodemo.Config" => {
            let mut value: p::proxy::dokodemo::Config = unpack(typed)?;
            let result = json!({"address":address(value.rewrite_address.take().context("dokodemo address is required")?)?,
                "port":port(take(&mut value.rewrite_port))?,"network":networks(take(&mut value.allowed_networks))?,
                "followRedirect":take(&mut value.follow_redirect),"userLevel":take(&mut value.user_level)});
            supported_rest(value, "dokodemo inbound port-map")?;
            Ok(("dokodemo-door", result))
        }
        "xray.proxy.vless.inbound.Config" => {
            let mut value: p::proxy::vless::inbound::Config = unpack(typed)?;
            let clients = take(&mut value.users)
                .into_iter()
                .map(|u| user(u, "vless", false))
                .collect::<Result<Vec<_>>>()?;
            let decryption = take(&mut value.decryption);
            let result = json!({"clients":clients,"decryption":if decryption.is_empty() {"none".into()} else {decryption}});
            supported_rest(value, "VLESS inbound (fallbacks/encryption)")?;
            Ok(("vless", result))
        }
        "xray.proxy.vmess.inbound.Config" => {
            let mut value: p::proxy::vmess::inbound::Config = unpack(typed)?;
            let clients = take(&mut value.user)
                .into_iter()
                .map(|u| user(u, "vmess", false))
                .collect::<Result<Vec<_>>>()?;
            let mut result = json!({"clients":clients});
            if let Some(default) = value.default.take() {
                result["default"] = json!({"level":default.level});
            }
            supported_rest(value, "VMess inbound")?;
            Ok(("vmess", result))
        }
        "xray.proxy.trojan.ServerConfig" => {
            let mut value: p::proxy::trojan::ServerConfig = unpack(typed)?;
            let clients = take(&mut value.users)
                .into_iter()
                .map(|u| user(u, "trojan", false))
                .collect::<Result<Vec<_>>>()?;
            supported_rest(value, "Trojan inbound fallbacks")?;
            Ok(("trojan", json!({"clients":clients})))
        }
        "xray.proxy.shadowsocks.ServerConfig" => {
            let mut value: p::proxy::shadowsocks::ServerConfig = unpack(typed)?;
            let clients = take(&mut value.users)
                .into_iter()
                .map(|u| user(u, "shadowsocks", false))
                .collect::<Result<Vec<_>>>()?;
            let network = networks(take(&mut value.network))?;
            // A missing network list enables no listener in Go; JSON defaults TCP.
            ensure!(
                !network.is_empty(),
                "Shadowsocks protobuf network list is empty"
            );
            supported_rest(value, "Shadowsocks inbound")?;
            Ok(("shadowsocks", json!({"clients":clients,"network":network})))
        }
        "xray.proxy.shadowsocks_2022.ServerConfig" => {
            let mut value: p::proxy::shadowsocks_2022::ServerConfig = unpack(typed)?;
            ensure!(
                value.level >= 0,
                "negative Shadowsocks 2022 protobuf user level"
            );
            let network = networks(take(&mut value.network))?;
            ensure!(
                !network.is_empty(),
                "Shadowsocks 2022 protobuf network list is empty"
            );
            let result = json!({"method":take(&mut value.method),"password":take(&mut value.key),
                "email":take(&mut value.email),"level":take(&mut value.level),"network":network});
            supported_rest(value, "Shadowsocks 2022 inbound")?;
            Ok(("shadowsocks", result))
        }
        other => bail!("protobuf inbound {other:?} is not integrated"),
    }
}

fn passwords(values: std::collections::HashMap<String, String>) -> Vec<Value> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values
        .into_iter()
        .map(|(user, pass)| json!({"user":user,"pass":pass}))
        .collect()
}

fn user(mut value: p::common::protocol::User, protocol: &str, outbound: bool) -> Result<Value> {
    let account = value
        .account
        .take()
        .context("protobuf user account is required")?;
    let mut result = json!({"email":take(&mut value.email),"level":take(&mut value.level)});
    supported_rest(value, "user")?;
    match protocol {
        "vless" => {
            let mut account: p::proxy::vless::Account = unpack(&account)?;
            result["id"] = json!(take(&mut account.id));
            result["flow"] = json!(take(&mut account.flow));
            let encryption = take(&mut account.encryption);
            // The Go handler treats both empty and "none" as plaintext, while
            // the native JSON interface requires the explicit "none" value.
            result["encryption"] = json!(if outbound && encryption.is_empty() {
                "none".into()
            } else {
                encryption
            });
            supported_rest(account, "VLESS account encryption/reverse/test settings")?;
        }
        "vmess" => {
            let mut account: p::proxy::vmess::Account = unpack(&account)?;
            result["id"] = json!(take(&mut account.id));
            let security = account
                .security_settings
                .take()
                .map(|s| s.r#type)
                .unwrap_or(2);
            result["security"] = json!(match security {
                2 => "auto",
                3 => "aes-128-gcm",
                4 => "chacha20-poly1305",
                n => bail!("unsupported VMess protobuf security {n}"),
            });
            supported_rest(account, "VMess account experiments")?;
        }
        "trojan" => {
            let mut account: p::proxy::trojan::Account = unpack(&account)?;
            result["password"] = json!(take(&mut account.password));
            supported_rest(account, "Trojan account")?;
        }
        "shadowsocks" => {
            let mut account: p::proxy::shadowsocks::Account = unpack(&account)?;
            result["password"] = json!(take(&mut account.password));
            result["method"] = json!(match take(&mut account.cipher_type) {
                5 => "aes-128-gcm",
                6 => "aes-256-gcm",
                7 => "chacha20-ietf-poly1305",
                n => bail!("unsupported Shadowsocks protobuf cipher {n}"),
            });
            supported_rest(account, "Shadowsocks account IV checking")?;
        }
        "socks" => {
            let mut account: p::proxy::socks::Account = unpack(&account)?;
            result["user"] = json!(take(&mut account.username));
            result["pass"] = json!(take(&mut account.password));
            supported_rest(account, "SOCKS account")?;
        }
        "http" => {
            let mut account: p::proxy::http::Account = unpack(&account)?;
            result["user"] = json!(take(&mut account.username));
            result["pass"] = json!(take(&mut account.password));
            supported_rest(account, "HTTP account")?;
        }
        _ => unreachable!(),
    }
    Ok(result)
}

fn endpoint(value: Option<p::common::protocol::ServerEndpoint>, protocol: &str) -> Result<Value> {
    let mut value = value.context("protobuf outbound server is required")?;
    let mut result = json!({"address":address(value.address.take().context("protobuf server address is required")?)?,"port":port(take(&mut value.port))?});
    let user = value
        .user
        .take()
        .map(|u| user(u, protocol, true))
        .transpose()?;
    if matches!(protocol, "vless" | "vmess") {
        result["users"] = json!([user.context("protobuf outbound user is required")?]);
    } else if matches!(protocol, "socks" | "http") {
        result["users"] = json!(user.into_iter().collect::<Vec<_>>());
    } else {
        for (key, value) in user
            .context("protobuf outbound user is required")?
            .as_object()
            .unwrap()
        {
            result[key] = value.clone();
        }
    }
    supported_rest(value, "outbound server")?;
    Ok(result)
}

fn outbound_proxy(typed: &TypedMessage) -> Result<(&'static str, Value)> {
    match typed.r#type.as_str() {
        "xray.proxy.freedom.Config" => {
            let mut value: p::proxy::freedom::Config = unpack(typed)?;
            let mut result = json!({"domainStrategy":domain_strategy(take(&mut value.domain_strategy))?,"userLevel":take(&mut value.user_level)});
            if let Some(mut dest) = value.destination_override.take() {
                let mut server = dest
                    .server
                    .take()
                    .context("freedom destination override server is absent")?;
                let host = address(
                    server
                        .address
                        .take()
                        .context("freedom destination override address is absent")?,
                )?;
                let port = port(take(&mut server.port))?;
                ensure!(
                    port != 0,
                    "address-only freedom redirects are not integrated"
                );
                result["redirect"] = json!(if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                });
                supported_rest(server, "freedom redirect server")?;
                supported_rest(dest, "freedom destination override")?;
            }
            result["finalRules"] = Value::Array(
                take(&mut value.final_rules)
                    .into_iter()
                    .map(final_rule)
                    .collect::<Result<_>>()?,
            );
            supported_rest(value, "freedom fragmentation/noise/proxy protocol")?;
            Ok(("freedom", result))
        }
        "xray.proxy.blackhole.Config" => {
            let mut value: p::proxy::blackhole::Config = unpack(typed)?;
            let result = if let Some(response) = value.response.take() {
                json!({"response":{"type":response.r#type,"customResponseData":STANDARD.encode(response.custom_response_data)}})
            } else {
                json!({})
            };
            supported_rest(value, "blackhole")?;
            Ok(("blackhole", result))
        }
        "xray.proxy.vless.outbound.Config" => {
            let mut value: p::proxy::vless::outbound::Config = unpack(typed)?;
            let server = endpoint(value.vnext.take(), "vless")?;
            supported_rest(value, "VLESS outbound")?;
            Ok(("vless", json!({"vnext":[server]})))
        }
        "xray.proxy.vmess.outbound.Config" => {
            let mut value: p::proxy::vmess::outbound::Config = unpack(typed)?;
            let server = endpoint(value.receiver.take(), "vmess")?;
            supported_rest(value, "VMess outbound")?;
            Ok(("vmess", json!({"vnext":[server]})))
        }
        "xray.proxy.trojan.ClientConfig" => {
            let mut value: p::proxy::trojan::ClientConfig = unpack(typed)?;
            let server = endpoint(value.server.take(), "trojan")?;
            supported_rest(value, "Trojan outbound")?;
            Ok(("trojan", json!({"servers":[server]})))
        }
        "xray.proxy.shadowsocks.ClientConfig" => {
            let mut value: p::proxy::shadowsocks::ClientConfig = unpack(typed)?;
            let server = endpoint(value.server.take(), "shadowsocks")?;
            supported_rest(value, "Shadowsocks outbound")?;
            Ok(("shadowsocks", json!({"servers":[server]})))
        }
        "xray.proxy.shadowsocks_2022.ClientConfig" => {
            let mut value: p::proxy::shadowsocks_2022::ClientConfig = unpack(typed)?;
            let result = json!({"address":address(value.address.take().context("Shadowsocks 2022 server address is absent")?)?,
                "port":port(take(&mut value.port))?,"method":take(&mut value.method),"password":take(&mut value.key)});
            supported_rest(value, "Shadowsocks 2022 outbound")?;
            Ok(("shadowsocks", result))
        }
        "xray.proxy.socks.ClientConfig" => {
            let mut value: p::proxy::socks::ClientConfig = unpack(typed)?;
            let server = endpoint(value.server.take(), "socks")?;
            supported_rest(value, "SOCKS outbound")?;
            Ok(("socks", json!({"servers":[server]})))
        }
        "xray.proxy.http.ClientConfig" => {
            let mut value: p::proxy::http::ClientConfig = unpack(typed)?;
            let server = endpoint(value.server.take(), "http")?;
            supported_rest(value, "HTTP outbound custom headers")?;
            Ok(("http", json!({"servers":[server]})))
        }
        other => bail!("protobuf outbound {other:?} is not integrated"),
    }
}

fn domain_strategy(value: i32) -> Result<&'static str> {
    Ok(match value {
        0 => "AsIs",
        1 => "UseIP",
        2 => "UseIPv4",
        3 => "UseIPv6",
        4 => "UseIPv4v6",
        5 => "UseIPv6v4",
        6 => "ForceIP",
        7 => "ForceIPv4",
        8 => "ForceIPv6",
        9 => "ForceIPv4v6",
        10 => "ForceIPv6v4",
        other => bail!("unknown protobuf domain strategy {other}"),
    })
}

fn stream(value: Option<p::transport::internet::StreamConfig>) -> Result<Value> {
    let Some(mut value) = value else {
        return Ok(json!({}));
    };
    let protocol = take(&mut value.protocol_name);
    let protocol = if protocol.is_empty() {
        "tcp".to_owned()
    } else {
        protocol
    };
    ensure!(
        matches!(
            protocol.as_str(),
            "tcp"
                | "raw"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
                | "kcp"
                | "mkcp"
        ),
        "protobuf transport {protocol:?} is not integrated"
    );
    let mut result = json!({"network":protocol});
    let mut seen = false;
    for mut config in take(&mut value.transport_settings) {
        let name = take(&mut config.protocol_name);
        let same_network = name == protocol
            || matches!(
                (name.as_str(), protocol.as_str()),
                ("tcp", "raw")
                    | ("raw", "tcp")
                    | ("xhttp", "splithttp")
                    | ("splithttp", "xhttp")
                    | ("websocket", "ws")
                    | ("ws", "websocket")
                    | ("kcp", "mkcp")
                    | ("mkcp", "kcp")
            );
        ensure!(
            same_network && !seen,
            "inactive or duplicate protobuf transport settings {name:?}"
        );
        seen = true;
        let settings = config
            .settings
            .take()
            .context("protobuf transport settings are absent")?;
        supported_rest(config, "transport")?;
        let (key, settings) = transport(&name, &settings)?;
        if let Some(key) = key {
            result[key] = settings;
        }
    }
    let security = take(&mut value.security_type);
    let mut security_settings = take(&mut value.security_settings);
    ensure!(
        security_settings.len() <= 1,
        "multiple protobuf security settings are not supported"
    );
    match security.as_str() {
        "" => ensure!(
            security_settings.is_empty(),
            "inactive protobuf security settings are not supported"
        ),
        "xray.transport.internet.tls.Config" => {
            result["security"] = json!("tls");
            result["tlsSettings"] = tls(security_settings
                .pop()
                .map(|s| unpack(&s))
                .transpose()?
                .unwrap_or_default())?;
        }
        "xray.transport.internet.reality.Config" => {
            result["security"] = json!("reality");
            result["realitySettings"] = reality(
                security_settings
                    .pop()
                    .map(|s| unpack(&s))
                    .transpose()?
                    .unwrap_or_default(),
            )?;
        }
        other => bail!("protobuf security {other:?} is not integrated"),
    }
    supported_rest(
        value,
        "stream (address/port override, socket options, masks, QUIC)",
    )?;
    Ok(result)
}

fn transport(name: &str, settings: &TypedMessage) -> Result<(Option<&'static str>, Value)> {
    match name {
        "tcp" | "raw" => {
            let value: p::transport::internet::tcp::Config = unpack(settings)?;
            supported_rest(value, "TCP headers/proxy protocol")?;
            Ok((None, json!({})))
        }
        "websocket" | "ws" => {
            let mut value: p::transport::internet::websocket::Config = unpack(settings)?;
            let result = json!({"host":take(&mut value.host),"path":early_data_path(take(&mut value.path),take(&mut value.ed),true)?,
                "headers":take(&mut value.header),"heartbeatPeriod":take(&mut value.heartbeat_period)});
            supported_rest(value, "WebSocket proxy protocol")?;
            Ok((Some("wsSettings"), result))
        }
        "httpupgrade" => {
            let mut value: p::transport::internet::httpupgrade::Config = unpack(settings)?;
            let result = json!({"host":take(&mut value.host),"path":early_data_path(take(&mut value.path),take(&mut value.ed),false)?,"headers":take(&mut value.header)});
            supported_rest(value, "HTTPUpgrade proxy protocol")?;
            Ok((Some("httpupgradeSettings"), result))
        }
        "grpc" => {
            let mut value: p::transport::internet::grpc::encoding::Config = unpack(settings)?;
            let mut result = Map::new();
            fields!(result,value; "authority"=>authority,"serviceName"=>service_name,"multiMode"=>multi_mode,
                "idle_timeout"=>idle_timeout,"health_check_timeout"=>health_check_timeout,"permit_without_stream"=>permit_without_stream,
                "initial_windows_size"=>initial_windows_size,"user_agent"=>user_agent);
            supported_rest(value, "gRPC")?;
            Ok((Some("grpcSettings"), result.into()))
        }
        "kcp" | "mkcp" => {
            let mut value: p::transport::internet::kcp::Config = unpack(settings)?;
            let mut result = Map::new();
            fields!(result,value; "mtu"=>mtu,"tti"=>tti,"uplinkCapacity"=>uplink_capacity,"downlinkCapacity"=>downlink_capacity,
                "cwndMultiplier"=>cwnd_multiplier,"maxSendingWindow"=>max_sending_window);
            supported_rest(value, "KCP")?;
            Ok((Some("kcpSettings"), result.into()))
        }
        "splithttp" | "xhttp" => Ok((Some("xhttpSettings"), xhttp(unpack(settings)?)?)),
        other => bail!("protobuf transport {other:?} is not integrated"),
    }
}

fn early_data_path(mut path: String, ed: u32, websocket: bool) -> Result<String> {
    // These native parsers consume the JSON ?ed= convention, while protobuf
    // stores Ed separately after the Go builder has removed that query item.
    let original = path.clone();
    if ed != 0 {
        ensure!(
            !path.contains('#'),
            "protobuf early-data path fragments are not supported"
        );
        path.push(if path.contains('?') { '&' } else { '?' });
        path.push_str(&format!("ed={ed}"));
    }
    let parsed = if websocket {
        let parsed = crate::transport::websocket::Config::from_json(&json!({"path":path}))?;
        (parsed.path, parsed.early_data_limit as u32)
    } else {
        let parsed =
            crate::transport::httpupgrade::HttpUpgradeConfig::from_json(&json!({"path":path}))?;
        (parsed.path, parsed.early_data)
    };
    ensure!(
        parsed == (original, ed),
        "protobuf early-data path cannot be represented without changing its query or early-data behavior"
    );
    Ok(path)
}

fn xhttp(mut value: p::transport::internet::splithttp::Config) -> Result<Value> {
    let mut output = Map::new();
    fields!(output,value; "host"=>host,"path"=>path,"mode"=>mode,"headers"=>headers,"noGRPCHeader"=>no_grpc_header,
        "noSSEHeader"=>no_sse_header,"xPaddingObfsMode"=>x_padding_obfs_mode,"xPaddingKey"=>x_padding_key,
        "xPaddingHeader"=>x_padding_header,"xPaddingPlacement"=>x_padding_placement,"xPaddingMethod"=>x_padding_method,
        "uplinkHTTPMethod"=>uplink_http_method,"sessionIDPlacement"=>session_id_placement,"sessionIDKey"=>session_id_key,
        "seqPlacement"=>seq_placement,"seqKey"=>seq_key,"uplinkDataPlacement"=>uplink_data_placement,"uplinkDataKey"=>uplink_data_key);
    for (key, range) in [
        ("xPaddingBytes", value.x_padding_bytes.take()),
        ("scMaxEachPostBytes", value.sc_max_each_post_bytes.take()),
        (
            "scMinPostsIntervalMs",
            value.sc_min_posts_interval_ms.take(),
        ),
        (
            "scStreamUpServerSecs",
            value.sc_stream_up_server_secs.take(),
        ),
        ("uplinkChunkSize", value.uplink_chunk_size.take()),
    ] {
        if let Some(range) = range.filter(|range| range.to != 0) {
            output.insert(key.into(), json!(format!("{}-{}", range.from, range.to)));
        }
    }
    // Both reference getters and JSON normalize zero to their defaults.
    if value.sc_max_buffered_posts != 0 {
        output.insert(
            "scMaxBufferedPosts".into(),
            json!(value.sc_max_buffered_posts),
        );
    }
    value.sc_max_buffered_posts = 0;
    if value.server_max_header_bytes != 0 {
        output.insert(
            "serverMaxHeaderBytes".into(),
            json!(value.server_max_header_bytes),
        );
    }
    value.server_max_header_bytes = 0;
    supported_rest(value, "XHTTP xmux/downloadSettings/custom session IDs")?;
    Ok(output.into())
}

fn tls(mut value: p::transport::internet::tls::Config) -> Result<Value> {
    let mut output = Map::new();
    fields!(output,value; "serverName"=>server_name,"alpn"=>next_protocol,"enableSessionResumption"=>enable_session_resumption,
        "disableSystemRoot"=>disable_system_root,"minVersion"=>min_version,"maxVersion"=>max_version,"cipherSuites"=>cipher_suites,
        "fingerprint"=>fingerprint,"rejectUnknownSni"=>reject_unknown_sni,"masterKeyLog"=>master_key_log,"curvePreferences"=>curve_preferences);
    let certs = take(&mut value.certificate).into_iter().map(|mut cert| {
        let usage = match take(&mut cert.usage) { 0=>"encipherment",1=>"verify",2=>"issue",n=>bail!("unknown TLS certificate usage {n}") };
        // Go embeds the initial PEM snapshot even when reload paths exist.
        // Preserve that snapshot for one-time/verification certificates. For
        // reloadable key pairs the native model accepts paths only: verify
        // both current files against the snapshot before choosing that model.
        let reload = usage == "encipherment" && !cert.one_time_loading
            && !cert.certificate_path.is_empty() && !cert.key_path.is_empty();
        if reload {
            for (path,snapshot,label) in [(&cert.certificate_path,&cert.certificate,"certificate"),(&cert.key_path,&cert.key,"private key")] {
                let current = std::fs::read(path).with_context(||format!("cannot verify protobuf TLS {label} reload source {path:?}"))?;
                ensure!(current == *snapshot,"protobuf TLS {label} reload source differs from embedded snapshot; native conversion cannot preserve its initial certificate");
            }
            cert.certificate.clear();
            cert.key.clear();
        } else {
            cert.certificate_path.clear();
            cert.key_path.clear();
        }
        let pem = |bytes: Vec<u8>| -> Result<Vec<String>> { Ok(String::from_utf8(bytes).context("protobuf TLS certificate/key must contain PEM text")?.lines().map(str::to_owned).collect()) };
        let mut result = Map::new();
        result.insert("usage".into(),json!(usage));
        result.insert("certificate".into(),json!(pem(take(&mut cert.certificate))?));
        result.insert("key".into(),json!(pem(take(&mut cert.key))?));
        fields!(result,cert; "certificateFile"=>certificate_path,"keyFile"=>key_path,"ocspStapling"=>ocsp_stapling,
            "oneTimeLoading"=>one_time_loading,"buildChain"=>build_chain);
        supported_rest(cert,"TLS certificate")?;
        Ok(Value::Object(result))
    }).collect::<Result<Vec<_>>>()?;
    output.insert("certificates".into(), json!(certs));
    supported_rest(value, "TLS ECH/certificate pins/name overrides")?;
    Ok(output.into())
}

fn reality(mut value: p::transport::internet::reality::Config) -> Result<Value> {
    let mut output = Map::new();
    fields!(output,value; "show"=>show,"fingerprint"=>fingerprint,"serverName"=>server_name,"spiderX"=>spider_x,"masterKeyLog"=>master_key_log);
    output.insert(
        "publicKey".into(),
        json!(URL_SAFE_NO_PAD.encode(take(&mut value.public_key))),
    );
    output.insert(
        "shortId".into(),
        json!(
            take(&mut value.short_id)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
    );
    output.insert(
        "mldsa65Verify".into(),
        json!(URL_SAFE_NO_PAD.encode(take(&mut value.mldsa65_verify))),
    );
    supported_rest(value, "REALITY server/spider settings")?;
    Ok(output.into())
}

fn logging(mut value: p::app::log::Config) -> Result<Value> {
    let destination = |kind: i32, path: String| -> Result<String> {
        match kind {
            0 => {
                ensure!(
                    path.is_empty(),
                    "unused protobuf log path is not representable"
                );
                Ok("none".into())
            }
            1 => {
                ensure!(
                    path.is_empty(),
                    "console protobuf log path is not representable"
                );
                Ok(String::new())
            }
            2 => {
                ensure!(!path.is_empty(), "protobuf file log path is empty");
                Ok(path)
            }
            _ => bail!("protobuf event/unknown log destination is not integrated"),
        }
    };
    let loglevel = match take(&mut value.error_log_level) {
        0 if value.error_log_type == 0 => "warning", // No error logger observes this level.
        1 => "error",
        2 => "warning",
        3 => "info",
        4 => "debug",
        n => bail!("protobuf log severity {n} cannot be represented by the JSON logger"),
    };
    let result = json!({"loglevel":loglevel,"access":destination(take(&mut value.access_log_type),take(&mut value.access_log_path))?,
        "error":destination(take(&mut value.error_log_type),take(&mut value.error_log_path))?,
        "dnsLog":take(&mut value.enable_dns_log),"maskAddress":take(&mut value.mask_address)});
    supported_rest(value, "logging")?;
    Ok(result)
}

fn policy(mut value: p::app::policy::Config) -> Result<Value> {
    let mut levels = Map::new();
    for (level, mut policy) in take(&mut value.level) {
        let mut out = Map::new();
        if let Some(mut timeout) = policy.timeout.take() {
            for (key, seconds) in [
                ("handshake", timeout.handshake.take()),
                ("connIdle", timeout.connection_idle.take()),
                ("uplinkOnly", timeout.uplink_only.take()),
                ("downlinkOnly", timeout.downlink_only.take()),
            ] {
                if let Some(seconds) = seconds {
                    out.insert(key.into(), json!(seconds.value));
                }
            }
            supported_rest(timeout, "policy timeouts")?;
        }
        if let Some(stats) = policy.stats.take() {
            out.insert("statsUserUplink".into(), json!(stats.user_uplink));
            out.insert("statsUserDownlink".into(), json!(stats.user_downlink));
            out.insert("statsUserOnline".into(), json!(stats.user_online));
        }
        if let Some(buffer) = policy.buffer.take() {
            ensure!(
                buffer.connection == -1 || buffer.connection >= 0 && buffer.connection % 1024 == 0,
                "protobuf policy buffer bytes must be -1 or an exact nonnegative KiB multiple"
            );
            out.insert(
                "bufferSize".into(),
                json!(if buffer.connection == -1 {
                    -1
                } else {
                    buffer.connection / 1024
                }),
            );
        }
        supported_rest(policy, "level policy")?;
        levels.insert(level.to_string(), out.into());
    }
    let mut result = json!({"levels":levels});
    if let Some(mut system) = value.system.take() {
        let stats = system.stats.take().unwrap_or_default();
        result["system"] = json!({"statsInboundUplink":stats.inbound_uplink,"statsInboundDownlink":stats.inbound_downlink,
            "statsOutboundUplink":stats.outbound_uplink,"statsOutboundDownlink":stats.outbound_downlink});
        supported_rest(system, "system policy")?;
    }
    supported_rest(value, "policy")?;
    Ok(result)
}

fn api(mut value: p::app::commander::Config) -> Result<Value> {
    let mut services = Vec::new();
    for service in take(&mut value.service) {
        let name = match service.r#type.as_str() {
            "xray.app.stats.command.Config" => {
                supported_rest(
                    unpack::<p::app::stats::command::Config>(&service)?,
                    "stats API",
                )?;
                "StatsService"
            }
            "xray.app.log.command.Config" => {
                supported_rest(
                    unpack::<p::app::log::command::Config>(&service)?,
                    "logger API",
                )?;
                "LoggerService"
            }
            "xray.core.app.observatory.command.Config" => {
                supported_rest(
                    unpack::<p::core::app::observatory::command::Config>(&service)?,
                    "observatory API",
                )?;
                "ObservatoryService"
            }
            other => bail!("protobuf API service {other:?} is not integrated"),
        };
        services.push(name);
    }
    let result =
        json!({"tag":take(&mut value.tag),"listen":take(&mut value.listen),"services":services});
    supported_rest(value, "API")?;
    Ok(result)
}

fn observatory(mut value: p::core::app::observatory::Config) -> Result<Value> {
    let result = json!({"subjectSelector":take(&mut value.subject_selector),"probeURL":take(&mut value.probe_url),
        "probeInterval":format!("{}ns",take(&mut value.probe_interval)),"enableConcurrency":take(&mut value.enable_concurrency)});
    supported_rest(value, "ordinary observatory")?;
    Ok(result)
}

fn domain_rule(value: p::common::geodata::DomainRule) -> Result<String> {
    use p::common::geodata::domain_rule::Value;
    Ok(match value.value.context("empty protobuf domain rule")? {
        Value::Geosite(rule) => {
            ensure!(
                !rule.code.contains([':', '@']) && !rule.file.contains(':'),
                "unrepresentable protobuf geosite selector"
            );
            let suffix = if rule.attrs.is_empty() {
                String::new()
            } else {
                format!("@{}", rule.attrs)
            };
            format!("ext:{}:{}{suffix}", rule.file, rule.code)
        }
        Value::Custom(domain) => {
            ensure!(
                domain.attribute.is_empty(),
                "custom protobuf domain attributes are not representable"
            );
            let prefix = match domain.r#type {
                0 => "keyword",
                1 => "regexp",
                2 => "domain",
                3 => "full",
                n => bail!("unknown protobuf domain match type {n}"),
            };
            format!("{prefix}:{}", domain.value)
        }
    })
}

fn ip_rule(value: p::common::geodata::IpRule) -> Result<String> {
    use p::common::geodata::ip_rule::Value;
    Ok(match value.value.context("empty protobuf IP rule")? {
        Value::Geoip(rule) => {
            ensure!(
                !rule.file.contains(':') && !rule.code.contains(':') && !rule.code.starts_with('!'),
                "unrepresentable protobuf geoip selector"
            );
            format!(
                "{}ext:{}:{}",
                if rule.reverse_match { "!" } else { "" },
                rule.file,
                rule.code
            )
        }
        Value::Custom(rule) => {
            let cidr = rule.cidr.context("protobuf CIDR is absent")?;
            let address = ip(&cidr.ip)?;
            ensure!(
                cidr.prefix <= if address.is_ipv4() { 32 } else { 128 },
                "invalid protobuf CIDR prefix"
            );
            format!(
                "{}{address}/{}",
                if rule.reverse_match { "!" } else { "" },
                cidr.prefix
            )
        }
    })
}

fn routing(mut value: p::app::router::Config) -> Result<Value> {
    let strategy = match take(&mut value.domain_strategy) {
        0 => "AsIs",
        2 => "IPIfNonMatch",
        3 => "IPOnDemand",
        n => bail!("unknown protobuf routing domain strategy {n}"),
    };
    let mut rules = Vec::new();
    for mut rule in take(&mut value.rule) {
        let target = match rule
            .target_tag
            .take()
            .context("protobuf route target is absent")?
        {
            p::app::router::routing_rule::TargetTag::Tag(tag) => tag,
            p::app::router::routing_rule::TargetTag::BalancingTag(_) => {
                bail!("protobuf balancing routes are not integrated")
            }
        };
        let mut result = json!({"type":"field","ruleTag":take(&mut rule.rule_tag),"outboundTag":target,
            "domain":take(&mut rule.domain).into_iter().map(domain_rule).collect::<Result<Vec<_>>>()?,
            "ip":take(&mut rule.ip).into_iter().map(ip_rule).collect::<Result<Vec<_>>>()?,
            "source":take(&mut rule.source_ip).into_iter().map(ip_rule).collect::<Result<Vec<_>>>()?,
            "network":networks(take(&mut rule.networks))?,"user":take(&mut rule.user_email),"inboundTag":take(&mut rule.inbound_tag)});
        if let Some(list) = rule.port_list.take() {
            result["port"] = json!(ports(list)?);
        }
        if let Some(list) = rule.source_port_list.take() {
            result["sourcePort"] = json!(ports(list)?);
        }
        supported_rest(
            rule,
            "routing rule protocol/attributes/local/process/webhook/VLESS fields",
        )?;
        rules.push(result);
    }
    supported_rest(value, "routing balancers")?;
    Ok(json!({"domainStrategy":strategy,"rules":rules}))
}

fn final_rule(mut rule: p::proxy::freedom::FinalRuleConfig) -> Result<Value> {
    let action = match take(&mut rule.action) {
        0 => "allow",
        1 => "block",
        n => bail!("unknown protobuf final rule action {n}"),
    };
    let network = networks(take(&mut rule.networks))?;
    let network = if network.is_empty() {
        vec![]
    } else {
        network.split(',').collect::<Vec<_>>()
    };
    let mut result = json!({"action":action,"network":network,
        "ip":take(&mut rule.ip).into_iter().map(ip_rule).collect::<Result<Vec<_>>>()?});
    if let Some(list) = rule.port_list.take() {
        result["port"] = json!(ports(list)?);
    }
    if let Some(delay) = rule.block_delay.take() {
        result["blockDelay"] = json!(format!("{}-{}", delay.min, delay.max));
    }
    supported_rest(rule, "freedom final rule")?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn only_app<M: Message + prost::Name>(app: M) -> Vec<u8> {
        p::core::Config {
            app: vec![TypedMessage::pack(&app)],
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn independent_wire_fixture_and_truncation() {
        // core.Config.outbound { tag:"direct", proxy_settings {
        // type:"xray.proxy.freedom.Config", value:<empty> } }. Hand-authored
        // wire bytes intentionally avoid encoder/decoder circularity.
        let bytes = b"\x12\x27\x0a\x06direct\x1a\x1d\x0a\x19xray.proxy.freedom.Config\x12\x00";
        let config = from_bytes(bytes).unwrap();
        assert_eq!(config.outbounds.len(), 1);
        assert_eq!(config.outbounds[0].tag, "direct");
        assert_eq!(config.outbounds[0].protocol, "freedom");
        assert_eq!(config.outbounds[0].settings["domainStrategy"], "AsIs");
        for length in 1..bytes.len() {
            assert!(from_bytes(&bytes[..length]).is_err(), "{length}");
        }
        assert!(from_bytes(b"\xff").is_err());
    }

    #[test]
    #[allow(invalid_from_utf8)] // deliberately asserting the binary fixture is not UTF-8
    fn real_go_binary_fixture_validates_and_preserves_binary_data() {
        let bytes = include_bytes!("../../../fixtures/protobuf/basic.pb");
        assert!(std::str::from_utf8(bytes).is_err());
        let config = from_bytes(bytes).unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds[0].listen.to_string(), "127.0.0.1");
        assert_eq!(config.inbounds[0].port, 10800);
        assert_eq!(
            config.outbounds[1].settings["response"]["customResponseData"],
            "/wABgA=="
        );
        assert_eq!(
            config.policy.unwrap().levels[&0]
                .as_ref()
                .unwrap()
                .handshake,
            Some(0)
        );
        assert_eq!(
            config.api.unwrap().services,
            vec!["StatsService", "LoggerService"]
        );
        assert_eq!(config.routing.rules[0].domain, vec!["full:example.test"]);
    }

    fn typed_user<M: Message + prost::Name>(account: M) -> p::common::protocol::User {
        p::common::protocol::User {
            account: Some(TypedMessage::pack(&account)),
            email: "fixture@example.test".into(),
            ..Default::default()
        }
    }

    fn server(user: Option<p::common::protocol::User>) -> p::common::protocol::ServerEndpoint {
        p::common::protocol::ServerEndpoint {
            address: Some(p::common::net::IpOrDomain {
                address: Some(p::common::net::ip_or_domain::Address::Ip(vec![
                    127, 0, 0, 1,
                ])),
            }),
            port: 443,
            user,
        }
    }

    #[test]
    fn supported_proxy_settings_pass_native_validation() {
        const ID: &str = "407b5891-80b8-4f87-b899-6f82e3a17025";
        let vless = typed_user(p::proxy::vless::Account {
            id: ID.into(),
            ..Default::default()
        });
        let vmess = typed_user(p::proxy::vmess::Account {
            id: ID.into(),
            ..Default::default()
        });
        let trojan = typed_user(p::proxy::trojan::Account {
            password: "owned fixture".into(),
        });
        let ss = typed_user(p::proxy::shadowsocks::Account {
            password: "owned fixture".into(),
            cipher_type: 5,
            ..Default::default()
        });
        let ss2022_key = STANDARD.encode([42; 16]);
        let inbound_proxies = vec![
            TypedMessage::pack(&p::proxy::socks::ServerConfig::default()),
            TypedMessage::pack(&p::proxy::http::ServerConfig::default()),
            TypedMessage::pack(&p::proxy::dokodemo::Config {
                rewrite_address: server(None).address,
                rewrite_port: 443,
                allowed_networks: vec![2],
                ..Default::default()
            }),
            TypedMessage::pack(&p::proxy::vless::inbound::Config {
                users: vec![vless.clone()],
                ..Default::default()
            }),
            TypedMessage::pack(&p::proxy::vmess::inbound::Config {
                user: vec![vmess.clone()],
                ..Default::default()
            }),
            TypedMessage::pack(&p::proxy::trojan::ServerConfig {
                users: vec![trojan.clone()],
                ..Default::default()
            }),
            TypedMessage::pack(&p::proxy::shadowsocks::ServerConfig {
                users: vec![ss.clone()],
                network: vec![2],
            }),
            TypedMessage::pack(&p::proxy::shadowsocks_2022::ServerConfig {
                method: "2022-blake3-aes-128-gcm".into(),
                key: ss2022_key.clone(),
                network: vec![2],
                ..Default::default()
            }),
        ];
        for proxy in inbound_proxies {
            let label = proxy.r#type.clone();
            let source = p::core::Config {
                inbound: vec![p::core::InboundHandlerConfig {
                    receiver_settings: Some(TypedMessage::pack(
                        &p::app::proxyman::ReceiverConfig {
                            port_list: Some(p::common::net::PortList {
                                range: vec![p::common::net::PortRange { from: 0, to: 0 }],
                            }),
                            ..Default::default()
                        },
                    )),
                    proxy_settings: Some(proxy),
                    ..Default::default()
                }],
                outbound: vec![p::core::OutboundHandlerConfig {
                    proxy_settings: Some(TypedMessage::pack(&p::proxy::freedom::Config::default())),
                    ..Default::default()
                }],
                ..Default::default()
            };
            let config = from_bytes(&source.encode_to_vec()).unwrap();
            assert_eq!(config.inbounds[0].listen.to_string(), "0.0.0.0");
            config
                .validate()
                .unwrap_or_else(|error| panic!("{label}: {error:#}"));
        }
        let outbound_proxies = vec![
            TypedMessage::pack(&p::proxy::socks::ClientConfig {
                server: Some(server(Some(typed_user(p::proxy::socks::Account {
                    username: "fixture".into(),
                    password: "password".into(),
                })))),
            }),
            TypedMessage::pack(&p::proxy::http::ClientConfig {
                server: Some(server(None)),
                ..Default::default()
            }),
            TypedMessage::pack(&p::proxy::vless::outbound::Config {
                vnext: Some(server(Some(vless))),
            }),
            TypedMessage::pack(&p::proxy::vmess::outbound::Config {
                receiver: Some(server(Some(vmess))),
            }),
            TypedMessage::pack(&p::proxy::trojan::ClientConfig {
                server: Some(server(Some(trojan))),
            }),
            TypedMessage::pack(&p::proxy::shadowsocks::ClientConfig {
                server: Some(server(Some(ss))),
            }),
            TypedMessage::pack(&p::proxy::shadowsocks_2022::ClientConfig {
                address: server(None).address,
                port: 443,
                method: "2022-blake3-aes-128-gcm".into(),
                key: ss2022_key,
            }),
        ];
        for proxy in outbound_proxies {
            let label = proxy.r#type.clone();
            let source = p::core::Config {
                outbound: vec![p::core::OutboundHandlerConfig {
                    proxy_settings: Some(proxy),
                    ..Default::default()
                }],
                ..Default::default()
            };
            from_bytes(&source.encode_to_vec())
                .unwrap()
                .validate()
                .unwrap_or_else(|error| panic!("{label}: {error:#}"));
        }
    }

    #[test]
    fn transport_settings_keep_early_data_and_default_ranges() {
        let ws = p::transport::internet::websocket::Config {
            path: "/ws?token=fixture".into(),
            ed: 2048,
            heartbeat_period: 17,
            ..Default::default()
        };
        let (_, value) = transport("websocket", &TypedMessage::pack(&ws)).unwrap();
        let native = crate::transport::websocket::Config::from_json(&value).unwrap();
        assert_eq!(native.path, ws.path);
        assert_eq!(native.early_data_limit, 2048);
        assert_eq!(native.heartbeat_period.as_secs(), 17);
        let upgrade = p::transport::internet::httpupgrade::Config {
            path: "/up?token=fixture".into(),
            ed: 1,
            ..Default::default()
        };
        let (_, value) = transport("httpupgrade", &TypedMessage::pack(&upgrade)).unwrap();
        let native = crate::transport::httpupgrade::HttpUpgradeConfig::from_json(&value).unwrap();
        assert_eq!(native.path, upgrade.path);
        assert_eq!(native.early_data, 1);
        for path in ["/x?ed=5", "/x?%65d=5", "/x?z=2&a=1"] {
            assert!(early_data_path(path.into(), 100, true).is_err(), "{path}");
        }
        let value = xhttp(p::transport::internet::splithttp::Config {
            x_padding_bytes: Some(Default::default()),
            ..Default::default()
        })
        .unwrap();
        assert!(value.get("xPaddingBytes").is_none());
        crate::transport::xhttp::Config::from_json(&value).unwrap();
        let (_, value) = transport(
            "kcp",
            &TypedMessage::pack(&p::transport::internet::kcp::Config {
                mtu: 1350,
                tti: 50,
                uplink_capacity: 5,
                downlink_capacity: 20,
                cwnd_multiplier: 1,
                max_sending_window: 2 * 1024 * 1024,
            }),
        )
        .unwrap();
        crate::transport::kcp::Config::from_json(&value).unwrap();
    }

    #[test]
    fn optional_policy_zero_and_byte_units_are_preserved() {
        let mut policy = p::app::policy::Config::default();
        policy.level.insert(
            3,
            p::app::policy::Policy {
                timeout: Some(p::app::policy::policy::Timeout {
                    handshake: Some(p::app::policy::Second { value: 0 }),
                    ..Default::default()
                }),
                buffer: Some(p::app::policy::policy::Buffer { connection: 2048 }),
                ..Default::default()
            },
        );
        let result = from_bytes(&only_app(policy.clone()))
            .unwrap()
            .policy
            .unwrap();
        let level = result.levels[&3].as_ref().unwrap();
        assert_eq!(level.handshake, Some(0));
        assert_eq!(level.conn_idle, None);
        assert_eq!(level.buffer_size, Some(2));
        policy
            .level
            .get_mut(&3)
            .unwrap()
            .buffer
            .as_mut()
            .unwrap()
            .connection = 1025;
        assert!(
            from_bytes(&only_app(policy))
                .unwrap_err()
                .to_string()
                .contains("KiB")
        );
    }

    #[test]
    fn observatory_duration_preserves_signed_nanoseconds_and_zero() {
        for interval in [0, 1, 1_500_000_001, -1, i64::MIN, i64::MAX] {
            let config = from_bytes(&only_app(p::core::app::observatory::Config {
                subject_selector: vec!["direct".into()],
                probe_url: "http://probe.example/status".into(),
                probe_interval: interval,
                enable_concurrency: true,
            }))
            .unwrap()
            .observatory
            .unwrap();
            assert_eq!(config.probe_interval, format!("{interval}ns"));
            assert_eq!(config.subject_selector, vec!["direct"]);
            assert!(config.enable_concurrency);
        }
    }

    #[test]
    fn wrong_types_unknown_apps_and_unsupported_fields_fail_closed() {
        let bad = p::core::Config {
            app: vec![TypedMessage {
                r#type: "unknown.Config".into(),
                value: vec![],
            }],
            ..Default::default()
        };
        assert!(from_bytes(&bad.encode_to_vec()).is_err());
        let mut handler = p::core::OutboundHandlerConfig {
            proxy_settings: Some(TypedMessage::pack(&p::proxy::freedom::Config::default())),
            sender_settings: Some(TypedMessage::pack(
                &p::app::proxyman::ReceiverConfig::default(),
            )),
            ..Default::default()
        };
        assert!(outbound(handler.clone()).is_err());
        handler.sender_settings = Some(TypedMessage::pack(&p::app::proxyman::SenderConfig {
            via_cidr: "192.0.2.0/24".into(),
            ..Default::default()
        }));
        assert!(
            outbound(handler)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
        let freedom = p::proxy::freedom::Config {
            proxy_protocol: 1,
            ..Default::default()
        };
        assert!(outbound_proxy(&TypedMessage::pack(&freedom)).is_err());
        let tls = p::transport::internet::tls::Config {
            pinned_peer_cert_sha256: vec![vec![0; 32]],
            ..Default::default()
        };
        assert!(super::tls(tls).is_err());
        let mapped = p::common::net::IpOrDomain {
            address: Some(p::common::net::ip_or_domain::Address::Ip(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1,
            ])),
        };
        assert_eq!(address(mapped).unwrap(), "127.0.0.1");
        let numeric_domain = p::common::net::IpOrDomain {
            address: Some(p::common::net::ip_or_domain::Address::Domain(
                "127.0.0.1".into(),
            )),
        };
        assert!(address(numeric_domain).is_err());
    }

    #[test]
    fn present_empty_logging_disables_both_destinations() {
        let config = from_bytes(&only_app(p::app::log::Config::default())).unwrap();
        let log = config.log.unwrap();
        assert_eq!(log.access, "none");
        assert_eq!(log.error, "none");
        let unknown = p::app::log::Config {
            error_log_type: 1,
            ..Default::default()
        };
        assert!(from_bytes(&only_app(unknown)).is_err());
        assert!(from_bytes(&[]).unwrap().log.is_none());
    }

    #[test]
    fn routing_and_transport_fields_retain_meaning() {
        let route = p::app::router::RoutingRule {
            target_tag: Some(p::app::router::routing_rule::TargetTag::Tag(
                "direct".into(),
            )),
            domain: vec![p::common::geodata::DomainRule {
                value: Some(p::common::geodata::domain_rule::Value::Custom(
                    p::common::geodata::Domain {
                        r#type: 3,
                        value: "example.test".into(),
                        ..Default::default()
                    },
                )),
            }],
            port_list: Some(p::common::net::PortList {
                range: vec![p::common::net::PortRange { from: 80, to: 443 }],
            }),
            ..Default::default()
        };
        let config = from_bytes(&only_app(p::app::router::Config {
            rule: vec![route],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(config.routing.rules[0].domain, vec!["full:example.test"]);
        let xhttp = super::xhttp(p::transport::internet::splithttp::Config {
            mode: "stream-one".into(),
            sc_stream_up_server_secs: Some(p::transport::internet::splithttp::RangeConfig {
                from: -2,
                to: -1,
            }),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(xhttp["scStreamUpServerSecs"], "-2--1");
        assert_eq!(xhttp["mode"], "stream-one");
    }
}
