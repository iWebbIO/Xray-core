use super::{Inbound, Outbound};
use crate::{
    address::Destination,
    protocol::vmess::{Account, Security, ServerAuthenticator},
};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct User {
    id: String,
    email: String,
    level: u32,
    security: String,
    experiments: String,
    #[serde(rename = "alterId")]
    alter_id: u32,
}
impl User {
    fn compile(&self) -> Result<Account> {
        ensure!(self.level == 0, "VMess policy levels are not migrated yet");
        ensure!(
            self.alter_id == 0,
            "legacy VMess alterId authentication is not supported"
        );
        ensure!(
            self.experiments.is_empty(),
            "VMess experiments are not migrated yet"
        );
        Account::from_user_id(&self.id, self.email.clone())
    }
    fn security(&self) -> Result<Security> {
        match self.security.to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" => Ok(Security::Aes128Gcm),
            "chacha20-poly1305" => Ok(Security::Chacha20Poly1305),
            _ => anyhow::bail!("unsupported VMess security {:?}", self.security),
        }
    }
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct InboundSettings {
    clients: Option<Vec<User>>,
    users: Vec<User>,
    default: Option<Defaults>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Defaults {
    level: u32,
}
pub(super) fn inbound(value: &Value) -> Result<Inbound> {
    let settings: InboundSettings = serde_json::from_value(value.clone())?;
    ensure!(
        settings.default.is_none_or(|d| d.level == 0),
        "VMess default policy levels are not migrated yet"
    );
    let users = settings.clients.unwrap_or(settings.users);
    let accounts = users
        .iter()
        .map(User::compile)
        .collect::<Result<Vec<_>>>()?;
    let authenticator = ServerAuthenticator::new(accounts, 65536)?;
    Ok(Inbound::Vmess(std::sync::Arc::new(std::sync::Mutex::new(
        authenticator,
    ))))
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Server {
    address: String,
    port: u16,
    users: Vec<User>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OutboundSettings {
    address: Option<String>,
    port: u16,
    id: String,
    email: String,
    level: u32,
    security: String,
    experiments: String,
    #[serde(rename = "alterId")]
    alter_id: u32,
    vnext: Vec<Server>,
}
pub(super) fn outbound(value: &Value) -> Result<Outbound> {
    let settings: OutboundSettings = serde_json::from_value(value.clone())?;
    let server = if let Some(address) = settings.address {
        Server {
            address,
            port: settings.port,
            users: vec![User {
                id: settings.id,
                email: settings.email,
                level: settings.level,
                security: settings.security,
                experiments: settings.experiments,
                alter_id: settings.alter_id,
            }],
        }
    } else {
        ensure!(
            settings.vnext.len() == 1,
            "VMess requires exactly one server"
        );
        settings.vnext.into_iter().next().unwrap()
    };
    ensure!(
        server.users.len() == 1,
        "VMess requires exactly one outbound user"
    );
    let user = &server.users[0];
    Ok(Outbound::Vmess {
        server: Destination::new(&server.address, server.port)?,
        account: user.compile()?,
        security: user.security()?,
    })
}
