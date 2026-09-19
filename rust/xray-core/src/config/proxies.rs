use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;

use super::{Account, Inbound, Outbound};
use crate::{
    address::Destination,
    protocol::{trojan, vless},
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
        ensure!(
            self.flow.is_empty() && self.seed.is_empty(),
            "VLESS Vision/seed flow is not migrated yet"
        );
        if outbound {
            ensure!(
                self.encryption == "none",
                "VLESS encryption must be explicitly set to none; encryption is not migrated yet"
            );
        } else {
            ensure!(
                self.encryption.is_empty(),
                "VLESS inbound users cannot specify encryption"
            );
        }
        Ok(vless::Account {
            id: *parse_id(&self.id)?.as_bytes(),
            email: self.email.clone(),
        })
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
            ensure!(
                matches!(settings.network.as_str(), "" | "tcp"),
                "Shadowsocks UDP is not migrated yet"
            );
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
                Ok(Inbound::Shadowsocks2022(user.compile_2022()?))
            } else {
                Ok(Inbound::Shadowsocks(user.compile()?))
            }
        }
        "vless" => {
            let settings: VlessInbound =
                serde_json::from_value(settings.clone()).context("VLESS inbound settings")?;
            ensure!(
                settings.decryption == "none",
                "VLESS decryption must be explicitly set to none; encryption is not migrated yet"
            );
            ensure!(
                settings.flow.is_empty(),
                "VLESS Vision flow is not migrated yet"
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
            Ok(Inbound::Vless(accounts))
        }
        "trojan" => {
            let settings: TrojanInbound =
                serde_json::from_value(settings.clone()).context("Trojan inbound settings")?;
            ensure!(
                settings.fallbacks.is_empty(),
                "Trojan fallbacks are not migrated yet"
            );
            let users = settings.clients.unwrap_or(settings.users);
            Ok(Inbound::Trojan(
                users
                    .iter()
                    .map(TrojanUser::compile)
                    .collect::<Result<_>>()?,
            ))
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
            Ok(Outbound::Vless {
                server: Destination::new(&server.address, server.port)?,
                account: server.users[0].compile(true)?,
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
                Inbound::Shadowsocks2022(account) => assert_eq!(account.email(), "ss2022@test"),
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
                ("method", json!("2022-blake3-chacha20-poly1305")),
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
    fn rejects_unimplemented_flow_and_missing_encryption() {
        assert!(
            outbound(
                "vless",
                &json!({"address":"127.0.0.1","port":443,"id":"example"})
            )
            .is_err()
        );
        assert!(outbound("vless", &json!({"address":"127.0.0.1","port":443,"id":"example","encryption":"none","flow":"xtls-rprx-vision"})).is_err());
        assert!(
            outbound(
                "vless",
                &json!({"address":"127.0.0.1","port":443,"id":"example","encryption":"none"})
            )
            .is_ok()
        );
        assert!(
            inbound(
                "vless",
                &json!({"decryption":"none","clients":[{"id":"example"},{"id":"example"}]})
            )
            .is_err()
        );
    }
}
