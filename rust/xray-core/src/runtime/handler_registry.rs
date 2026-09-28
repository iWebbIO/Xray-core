//! Runtime backing for the HandlerService management API.
//!
//! The read path is served from the startup snapshot: inbound/outbound
//! listings carry the handler tags with the receiver (listen/port) settings,
//! and user queries are answered from the raw inbound settings (the compiled
//! accounts keep only key material hashes, which cannot be listed back).
//!
//! Every mutating operation this runtime build cannot perform honestly fails
//! explicitly, never silently: the runtime's outbound set and per-listener
//! account sets are immutable after startup (adding or removing handlers
//! needs the proto-to-config decoder for `InboundHandlerConfig` plus
//! listener ownership handoff from the server task, both not integrated
//! yet), and `alter_inbound` user edits would need mutable per-inbound
//! account sets.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use tokio_util::sync::CancellationToken;
use xray_proto::xray::{
    app::proxyman::{ReceiverConfig, SenderConfig},
    common::{
        net::{IpOrDomain, PortList, PortRange},
        protocol::User,
        serial::TypedMessage,
    },
    core::{InboundHandlerConfig, OutboundHandlerConfig},
};

use super::Dispatcher;
use crate::api::handler::{HandlerStore, HandlerStoreError, InboundOperation};
use crate::config::{Inbound, InboundConfig, OutboundConfig};
use crate::transport::InboundTransport;

/// One startup inbound as the registry sees it: the raw JSON config (the
/// source of the account sets), the compiled protocol inbound and transport.
struct SeededInbound {
    raw: InboundConfig,
    inbound: Inbound,
    #[allow(dead_code)] // pairs with the future dynamic-listener path
    transport: InboundTransport,
}

#[derive(Default)]
struct RegistryState {
    inbounds: Vec<SeededInbound>,
    outbounds: Vec<OutboundConfig>,
}

pub(super) struct RuntimeRegistry {
    state: Arc<Mutex<RegistryState>>,
}

impl RuntimeRegistry {
    pub(super) fn new(_dispatcher: Arc<Dispatcher>, _cancel: CancellationToken) -> Arc<Self> {
        // The dispatcher and server token feed the dynamic-listener path
        // (add/remove through the runtime's own accept loop); the read path
        // needs only the seeded snapshot below.
        let _ = (_dispatcher, _cancel);
        Arc::new(Self {
            state: Arc::default(),
        })
    }

    /// Record one startup inbound for listings and user queries.
    pub(super) fn seed_inbound(
        &self,
        raw: InboundConfig,
        inbound: Inbound,
        transport: InboundTransport,
    ) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .inbounds
            .push(SeededInbound {
                raw,
                inbound,
                transport,
            });
    }

    /// Record the startup outbound list for listings.
    pub(super) fn seed_outbounds(&self, outbounds: Vec<OutboundConfig>) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .outbounds = outbounds;
    }

    /// The store backing HandlerService; it shares the registry's snapshot.
    pub(super) fn store(&self) -> Arc<dyn HandlerStore> {
        Arc::new(StoreHandle {
            state: self.state.clone(),
        })
    }
}

struct StoreHandle {
    state: Arc<Mutex<RegistryState>>,
}

/// Encode one proto message as a TypedMessage, like Go's `serial.ToTypedMessage`.
fn typed<M: prost::Message + prost::Name>(message: &M) -> TypedMessage {
    TypedMessage {
        r#type: M::type_url(),
        value: message.encode_to_vec(),
    }
}

fn ip_or_domain(address: IpAddr) -> IpOrDomain {
    let bytes = match address {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    IpOrDomain {
        address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(
            bytes,
        )),
    }
}

/// The inbound's receiver settings (Go app/proxyman builds these from the
/// detour config): the listen address and the single port it owns.
fn receiver_settings(raw: &InboundConfig) -> ReceiverConfig {
    ReceiverConfig {
        port_list: Some(PortList {
            range: vec![PortRange {
                from: u32::from(raw.port),
                to: u32::from(raw.port),
            }],
        }),
        listen: Some(ip_or_domain(raw.listen)),
        ..Default::default()
    }
}

/// The user records one inbound's raw settings carry, in Go's manager order.
fn inbound_users(raw: &InboundConfig, inbound: &Inbound) -> Vec<User> {
    // Level zero everywhere: the config layer rejects non-zero user levels.
    let settings = &raw.settings;
    let user_list = settings
        .get("clients")
        .or_else(|| settings.get("users"))
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let mut users = Vec::new();
    match inbound {
        Inbound::Vless { .. } => {
            for entry in &user_list {
                if let (Some(email), Some(id)) = (
                    entry.get("email").and_then(|value| value.as_str()),
                    entry.get("id").and_then(|value| value.as_str()),
                ) {
                    let account = xray_proto::xray::proxy::vless::Account {
                        id: id.to_owned(),
                        flow: entry
                            .get("flow")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                        ..Default::default()
                    };
                    users.push(User {
                        level: 0,
                        email: email.to_owned(),
                        account: Some(typed(&account)),
                    });
                }
            }
        }
        Inbound::Trojan { .. } => {
            for entry in &user_list {
                if let (Some(email), Some(password)) = (
                    entry.get("email").and_then(|value| value.as_str()),
                    entry.get("password").and_then(|value| value.as_str()),
                ) {
                    let account = xray_proto::xray::proxy::trojan::Account {
                        password: password.to_owned(),
                    };
                    users.push(User {
                        level: 0,
                        email: email.to_owned(),
                        account: Some(typed(&account)),
                    });
                }
            }
        }
        Inbound::Shadowsocks(_) | Inbound::Shadowsocks2022 { .. } => {
            // The single-account settings carry the email at the top level or
            // inside the one user entry; Go's shadowsocks manager lists that
            // account. The password itself stays out of the listing (Go's
            // shadowsocks Account proto is cipher-specific).
            if let Some(email) = settings
                .get("email")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    user_list
                        .first()
                        .and_then(|entry| entry.get("email"))
                        .and_then(|value| value.as_str())
                })
            {
                users.push(User {
                    level: 0,
                    email: email.to_owned(),
                    account: None,
                });
            }
        }
        _ => {
            // Non-user-managed inbounds have no user records.
        }
    }
    users
}

#[tonic::async_trait]
impl HandlerStore for StoreHandle {
    async fn add_inbound(&self, _config: InboundHandlerConfig) -> Result<(), HandlerStoreError> {
        Err(HandlerStoreError::Message(
            "adding inbounds at runtime requires the InboundHandlerConfig decoder, \
             which is not integrated in this runtime build"
                .into(),
        ))
    }

    async fn remove_inbound(&self, tag: &str) -> Result<(), HandlerStoreError> {
        // The store contract: an unknown or empty tag fails with NoClue.
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if tag.is_empty() || !state.inbounds.iter().any(|seeded| seeded.raw.tag == tag) {
            return Err(HandlerStoreError::NoClue);
        }
        Err(HandlerStoreError::Message(
            "removing inbounds at runtime requires listener ownership handoff, \
             which is not integrated in this runtime build"
                .into(),
        ))
    }

    async fn alter_inbound(
        &self,
        tag: &str,
        _operation: InboundOperation,
    ) -> Result<(), HandlerStoreError> {
        // The store contract: an unknown tag fails with HandlerNotFound.
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.inbounds.iter().any(|seeded| seeded.raw.tag == tag) {
            return Err(HandlerStoreError::HandlerNotFound(tag.to_owned()));
        }
        Err(HandlerStoreError::Message(
            "altering inbound users at runtime requires mutable per-inbound account \
             sets, which are not integrated in this runtime build"
                .into(),
        ))
    }

    async fn list_inbounds(&self) -> Vec<InboundHandlerConfig> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .inbounds
            .iter()
            .map(|seeded| InboundHandlerConfig {
                tag: seeded.raw.tag.clone(),
                receiver_settings: Some(typed(&receiver_settings(&seeded.raw))),
                proxy_settings: None, // per-protocol decoder not integrated yet
            })
            .collect()
    }

    async fn get_inbound_users(
        &self,
        tag: &str,
        email: &str,
    ) -> Result<Vec<User>, HandlerStoreError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(seeded) = state.inbounds.iter().find(|seeded| seeded.raw.tag == tag) else {
            return Err(HandlerStoreError::HandlerNotFound(tag.to_owned()));
        };
        Ok(inbound_users(&seeded.raw, &seeded.inbound)
            .into_iter()
            .filter(|user| user.email == email)
            .collect())
    }

    async fn get_inbound_users_count(&self, tag: &str) -> Result<i64, HandlerStoreError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(seeded) = state.inbounds.iter().find(|seeded| seeded.raw.tag == tag) else {
            return Err(HandlerStoreError::HandlerNotFound(tag.to_owned()));
        };
        Ok(inbound_users(&seeded.raw, &seeded.inbound).len() as i64)
    }

    async fn add_outbound(&self, _config: OutboundHandlerConfig) -> Result<(), HandlerStoreError> {
        Err(HandlerStoreError::Message(
            "adding outbounds at runtime requires the OutboundHandlerConfig decoder, \
             which is not integrated in this runtime build"
                .into(),
        ))
    }

    async fn remove_outbound(&self, _tag: &str) -> Result<(), HandlerStoreError> {
        Err(HandlerStoreError::Message(
            "removing outbounds at runtime requires a mutable dispatcher outbound set, \
             which is not integrated in this runtime build"
                .into(),
        ))
    }

    async fn list_outbounds(&self) -> Vec<OutboundHandlerConfig> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .outbounds
            .iter()
            .map(|raw| OutboundHandlerConfig {
                tag: raw.tag.clone(),
                sender_settings: Some(typed(&SenderConfig::default())),
                proxy_settings: None, // per-protocol decoder not integrated yet
                ..Default::default()
            })
            .collect()
    }
}
