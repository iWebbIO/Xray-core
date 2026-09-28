use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;

use super::{Account, Inbound, Outbound};
use crate::{
    address::Destination,
    protocol::{trojan, vless, vless_encryption},
    user::parse_id,
};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PasswordUser {
    user: String,
    pass: String,
    level: u32,
    email: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PasswordServer {
    address: String,
    port: u16,
    users: Vec<PasswordUser>,
}

#[derive(Clone, Debug, Default, Deserialize)]
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessUser {
    id: String,
    email: String,
    level: u32,
    flow: String,
    encryption: String,
    seed: String,
}

impl VlessUser {
    fn compile(&self, outbound: bool) -> Result<vless::Account> {
        ensure!(self.level == 0, "user policy levels are not migrated yet");
        ensure!(self.seed.is_empty(), "VLESS seed flow is not migrated yet");
        // Go accepts only the two Vision spellings (infra/conf/vless.go).
        ensure!(
            self.flow.is_empty()
                || matches!(
                    self.flow.as_str(),
                    "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
                ),
            "VLESS users: \"flow\" doesn't support {:?} in this version",
            self.flow
        );
        if !outbound {
            ensure!(
                self.encryption.is_empty(),
                "VLESS users: \"encryption\" should not be in inbound settings"
            );
        }
        Ok(vless::Account {
            id: *parse_id(&self.id)?.as_bytes(),
            email: self.email.clone(),
            flow: self.flow.clone(),
        })
    }

    /// Outbound account encryption: `none` yields the plaintext session while
    /// valid `mlkem768x25519plus` profiles yield the shared encrypted session.
    /// An empty value keeps Go's explicit `please add/set "encryption":"none"`.
    fn compile_encryption(&self) -> Result<Option<Arc<vless_encryption::ClientEncryption>>> {
        if self.encryption == "none" {
            return Ok(None);
        }
        Ok(Some(Arc::new(
            vless_encryption::ClientEncryption::parse(&self.encryption)
                .context("VLESS users: unsupported \"encryption\"")?,
        )))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessInbound {
    clients: Option<Vec<VlessUser>>,
    users: Vec<VlessUser>,
    decryption: String,
    flow: String,
    fallbacks: Vec<Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VlessServer {
    address: String,
    port: u16,
    users: Vec<VlessUser>,
}

#[derive(Clone, Debug, Default, Deserialize)]
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanUser {
    password: String,
    email: String,
    level: u32,
    flow: String,
}

impl TrojanUser {
    fn compile(&self) -> Result<trojan::Account> {
        ensure!(!self.password.is_empty(), "Trojan password is required");
        ensure!(
            self.flow.is_empty(),
            "Trojan flow has been removed from the reference implementation"
        );
        ensure!(self.level == 0, "user policy levels are not migrated yet");
        Ok(trojan::Account::new(&self.password, self.email.clone()))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanInbound {
    clients: Option<Vec<TrojanUser>>,
    users: Vec<TrojanUser>,
    fallbacks: Vec<Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrojanServer {
    address: String,
    port: u16,
    password: String,
    email: String,
    level: u32,
    flow: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowsocksUser {
    method: String,
    password: String,
    email: String,
    level: u32,
}
impl ShadowsocksUser {
    fn compile(&self) -> Result<crate::protocol::shadowsocks_session::Account> {
        ensure!(self.level == 0, "user policy levels are not migrated yet");
        crate::protocol::shadowsocks_session::Account::new(
            self.method.parse()?,
            &self.password,
            self.email.clone(),
        )
    }

    fn compile_2022(&self) -> Result<crate::protocol::shadowsocks2022::Account> {
        ensure!(self.level == 0, "user policy levels are not migrated yet");
        crate::protocol::shadowsocks2022::Account::new(
            self.method.parse()?,
            &self.password,
            self.email.clone(),
        )
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
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
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ShadowsocksServer {
    address: String,
    port: u16,
    method: String,
    password: String,
    email: String,
    level: u32,
}
#[derive(Clone, Debug, Default, Deserialize)]
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

pub(super) fn inbound(protocol: &str, settings: &Value) -> Result<Inbound> {
    match protocol {
        "shadowsocks" => {
            let settings: ShadowsocksInbound =
                serde_json::from_value(settings.clone()).context("Shadowsocks inbound settings")?;
            let udp = match settings.network.as_str() {
                // Go's nil NetworkList defaults to TCP only; `tcp,udp` opts in.
                "" | "tcp" => false,
                "tcp,udp" => true,
                "udp" => bail!("udp-only Shadowsocks inbound is not supported; use tcp,udp"),
                other => bail!("unknown Shadowsocks network {other:?}"),
            };
            let user = if let Some(users) = settings.clients.or(settings.users) {
                ensure!(
                    users.len() == 1,
                    "Shadowsocks multi-user admission is not migrated yet"
                );
                users.into_iter().next().unwrap()
            } else {
                ShadowsocksUser {
                    method: settings.method,
                    password: settings.password,
                    email: settings.email,
                    level: settings.level,
                }
            };
            if user.method.starts_with("2022-") {
                Ok(Inbound::Shadowsocks2022 {
                    account: user.compile_2022()?,
                    udp,
                })
            } else {
                Ok(Inbound::Shadowsocks {
                    account: user.compile()?,
                    udp,
                })
            }
        }
        "vless" => {
            let settings: VlessInbound =
                serde_json::from_value(settings.clone()).context("VLESS inbound settings")?;
            let decryption = match settings.decryption.as_str() {
                "none" => None,
                // parse("") produces Go's `please add/set "decryption":"none"`.
                other => Some(Arc::new(
                    vless_encryption::ServerDecryption::parse(other)
                        .context("VLESS inbound decryption")?,
                )),
            };
            ensure!(
                settings.flow.is_empty(),
                "VLESS inbound settings have no \"flow\" field; set flow per client"
            );
            ensure!(
                settings.fallbacks.is_empty(),
                "VLESS fallbacks are not migrated yet"
            );
            let users = settings.clients.unwrap_or(settings.users);
            let accounts = users
                .iter()
                .map(|user| user.compile(false))
                .collect::<Result<Vec<_>>>()?;
            let mut ids = std::collections::HashSet::new();
            ensure!(
                accounts.iter().all(|account| ids.insert(account.id)),
                "duplicate VLESS user ID"
            );
            Ok(Inbound::Vless {
                accounts,
                decryption,
            })
        }
        "trojan" => {
            let settings: TrojanInbound =
                serde_json::from_value(settings.clone()).context("Trojan inbound settings")?;
            ensure!(
                settings.fallbacks.is_empty(),
                "Trojan fallbacks are not migrated yet"
            );
            let users = settings.clients.unwrap_or(settings.users);
            // Go's Trojan inbound has no network gate: command 3 (UDP over
            // the Trojan connection) is always part of the protocol.
            Ok(Inbound::Trojan {
                accounts: users
                    .iter()
                    .map(TrojanUser::compile)
                    .collect::<Result<_>>()?,
                udp: true,
            })
        }
        _ => unreachable!("caller selects supported proxy type"),
    }
}

pub(super) fn outbound(protocol: &str, settings: &Value) -> Result<Outbound> {
    match protocol {
        "shadowsocks" => {
            let settings: ShadowsocksOutbound = serde_json::from_value(settings.clone())
                .context("Shadowsocks outbound settings")?;
            let server = if let Some(address) = settings.address {
                ShadowsocksServer {
                    address,
                    port: settings.port,
                    method: settings.method,
                    password: settings.password,
                    email: settings.email,
                    level: settings.level,
                }
            } else {
                ensure!(
                    settings.servers.len() == 1,
                    "Shadowsocks requires exactly one server"
                );
                settings.servers.into_iter().next().unwrap()
            };
            let user = ShadowsocksUser {
                method: server.method,
                password: server.password,
                email: server.email,
                level: server.level,
            };
            let server = Destination::new(&server.address, server.port)?;
            if user.method.starts_with("2022-") {
                Ok(Outbound::Shadowsocks2022 {
                    server,
                    account: user.compile_2022()?,
                })
            } else {
                Ok(Outbound::Shadowsocks {
                    server,
                    account: user.compile()?,
                })
            }
        }
        "socks" | "http" => {
            let settings: PasswordOutbound =
                serde_json::from_value(settings.clone()).context("SOCKS/HTTP outbound settings")?;
            let server = if let Some(address) = settings.address {
                let users = if settings.user.is_empty() {
                    vec![]
                } else {
                    vec![PasswordUser {
                        user: settings.user,
                        pass: settings.pass,
                        email: settings.email,
                        level: settings.level,
                    }]
                };
                PasswordServer {
                    address,
                    port: settings.port,
                    users,
                }
            } else {
                ensure!(
                    settings.servers.len() == 1,
                    "SOCKS/HTTP requires exactly one server"
                );
                settings.servers.into_iter().next().unwrap()
            };
            ensure!(
                server.users.len() <= 1,
                "SOCKS/HTTP supports at most one outbound account"
            );
            let account = server
                .users
                .into_iter()
                .next()
                .map(|user| {
                    ensure!(user.level == 0, "user policy levels are not migrated yet");
                    let _email = user.email;
                    if protocol == "socks" {
                        ensure!(
                            (1..=255).contains(&user.user.len())
                                && (1..=255).contains(&user.pass.len()),
                            "SOCKS credentials must contain 1..255 bytes"
                        );
                    }
                    Ok(Account {
                        user: user.user,
                        pass: user.pass,
                    })
                })
                .transpose()?;
            let server = Destination::new(&server.address, server.port)?;
            Ok(if protocol == "socks" {
                Outbound::Socks { server, account }
            } else {
                Outbound::Http { server, account }
            })
        }
        "vless" => {
            let settings: VlessOutbound =
                serde_json::from_value(settings.clone()).context("VLESS outbound settings")?;
            let server = if let Some(address) = settings.address {
                VlessServer {
                    address,
                    port: settings.port,
                    users: vec![VlessUser {
                        id: settings.id,
                        email: settings.email,
                        level: settings.level,
                        flow: settings.flow,
                        encryption: settings.encryption,
                        seed: settings.seed,
                    }],
                }
            } else {
                ensure!(
                    settings.vnext.len() == 1,
                    "VLESS requires exactly one vnext server"
                );
                settings.vnext.into_iter().next().unwrap()
            };
            ensure!(
                server.users.len() == 1,
                "VLESS requires exactly one outbound user"
            );
            let user = &server.users[0];
            Ok(Outbound::Vless {
                server: Destination::new(&server.address, server.port)?,
                account: user.compile(true)?,
                encryption: user.compile_encryption()?,
            })
        }
        "trojan" => {
            let settings: TrojanOutbound =
                serde_json::from_value(settings.clone()).context("Trojan outbound settings")?;
            let server = if let Some(address) = settings.address {
                TrojanServer {
                    address,
                    port: settings.port,
                    password: settings.password,
                    email: settings.email,
                    level: settings.level,
                    flow: settings.flow,
                }
            } else {
                ensure!(
                    settings.servers.len() == 1,
                    "Trojan requires exactly one server"
                );
                settings.servers.into_iter().next().unwrap()
            };
            let account = TrojanUser {
                password: server.password,
                email: server.email,
                level: server.level,
                flow: server.flow,
            }
            .compile()?;
            Ok(Outbound::Trojan {
                server: Destination::new(&server.address, server.port)?,
                account,
            })
        }
        _ => unreachable!("caller selects supported proxy type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;

    #[test]
    fn shadowsocks_2022_selects_native_accounts_and_rejects_unsupported_modes() {
        for (method, key_len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
        ] {
            let password = STANDARD.encode(vec![7; key_len]);
            let settings = json!({"method":method,"password":password,"email":"ss2022@test"});
            match inbound("shadowsocks", &settings).unwrap() {
                Inbound::Shadowsocks2022 { account, .. } => {
                    assert_eq!(account.email(), "ss2022@test")
                }
                _ => panic!("2022 cipher compiled as another protocol"),
            }
            let server =
                json!({"address":"example.org","port":443,"method":method,"password":password});
            assert!(matches!(
                outbound("shadowsocks", &server).unwrap(),
                Outbound::Shadowsocks2022 { .. }
            ));
            assert!(matches!(
                outbound("shadowsocks", &json!({"servers":[server]})).unwrap(),
                Outbound::Shadowsocks2022 { .. }
            ));
            for (field, value) in [
                ("password", json!("AA==")),
                ("password", json!(format!("{password}:{password}"))),
                ("network", json!("udp")),
                ("level", json!(1)),
            ] {
                let mut invalid = settings.clone();
                invalid[field] = value;
                assert!(inbound("shadowsocks", &invalid).is_err(), "{field}");
            }
        }
    }

    #[test]
    fn vless_flow_and_encryption_follow_go_validation() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL};

        // Missing/empty encryption keeps Go's explicit "add/set none" error.
        assert!(
            outbound(
                "vless",
                &json!({"address":"127.0.0.1","port":443,"id":"example"})
            )
            .is_err()
        );
        assert!(
            outbound(
                "vless",
                &json!({"address":"127.0.0.1","port":443,"id":"example","encryption":""})
            )
            .is_err()
        );
        // The two Vision spellings Go accepts, with plaintext sessions.
        for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            let Ok(Outbound::Vless {
                account,
                encryption,
                ..
            }) = outbound(
                "vless",
                &json!({"address":"127.0.0.1","port":443,"id":"example","encryption":"none","flow":flow}),
            )
            else {
                panic!("vision flow {flow} rejected");
            };
            assert_eq!(account.flow, flow);
            assert!(encryption.is_none());
        }
        // Unknown flow values keep Go's rejection text.
        assert!(outbound(
            "vless",
            &json!({"address":"127.0.0.1","port":443,"id":"example","encryption":"none","flow":"xtls-rprx-direct"})
        )
        .is_err());
        // A valid hybrid profile compiles into the encrypted session.
        let key = BASE64URL.encode([7u8; 32]);
        let encryption = format!("mlkem768x25519plus.native.1rtt.{key}");
        assert!(matches!(
            outbound(
                "vless",
                &json!({"address":"127.0.0.1","port":443,"id":"example","encryption":encryption})
            ),
            Ok(Outbound::Vless {
                encryption: Some(_),
                ..
            })
        ));
        // Inbound decryption mirrors the outbound account encryption surface.
        let seed = BASE64URL.encode([9u8; 32]);
        let decryption = format!("mlkem768x25519plus.native.0-0s.{seed}");
        assert!(matches!(
            inbound(
                "vless",
                &json!({"decryption":decryption,"clients":[{"id":"example","flow":"xtls-rprx-vision"}]})
            ),
            Ok(Inbound::Vless { .. })
        ));
        // Missing decryption and user-level inbound encryption still fail.
        assert!(inbound("vless", &json!({"clients":[{"id":"example"}]})).is_err());
        assert!(
            inbound(
                "vless",
                &json!({"decryption":"none","clients":[{"id":"example","encryption":"none"}]})
            )
            .is_err()
        );
        assert!(
            inbound(
                "vless",
                &json!({"decryption":"none","clients":[{"id":"example"},{"id":"example"}]})
            )
            .is_err()
        );
    }

    #[test]
    fn trojan_and_shadowsocks_udp_flags() {
        assert!(matches!(
            inbound("trojan", &json!({"clients":[{"password":"pw"}]})),
            Ok(Inbound::Trojan { udp: true, .. })
        ));
        // 2022 ciphers opt into UDP via `tcp,udp`; legacy ciphers stay TCP-only.
        let password = STANDARD.encode(vec![7; 32]);
        let settings = json!({"method":"2022-blake3-aes-256-gcm","password":password});
        assert!(matches!(
            inbound("shadowsocks", &settings),
            Ok(Inbound::Shadowsocks2022 { udp: false, .. })
        ));
        let mut udp_settings = settings.clone();
        udp_settings["network"] = json!("tcp,udp");
        assert!(matches!(
            inbound("shadowsocks", &udp_settings),
            Ok(Inbound::Shadowsocks2022 { udp: true, .. })
        ));
        let mut legacy = json!({"method":"aes-128-gcm","password":"pw"});
        assert!(inbound("shadowsocks", &legacy).is_ok());
        legacy["network"] = json!("tcp,udp");
        assert!(matches!(
            inbound("shadowsocks", &legacy).unwrap(),
            Inbound::Shadowsocks { udp: true, .. }
        ));
    }
}
