//! Runtime backing for the HandlerService management API.
//!
//! AddInbound decodes the wire config through the startup protobuf
//! conversion (which fails closed on everything it cannot represent),
//! compiles it with the ordinary config validation, and binds a listener
//! through the runtime's own accept loop on a child of the server token;
//! RemoveInbound cancels exactly that tag's listeners (startup and
//! runtime-added alike). Listings and user queries are served from the raw
//! inbound settings (the compiled accounts keep only key material hashes,
//! which cannot be listed back).
//!
//! The remaining mutations fail explicitly, never silently: the runtime's
//! outbound set is immutable after startup (AddOutbound/RemoveOutbound need a
//! mutable dispatcher, not integrated), and `alter_inbound` user edits would
//! need mutable per-listener account sets.

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
use crate::api::routing::{BalancerSnapshot, ProtoRule, RoutingRuleEntry, RoutingStore};
use crate::config::{Inbound, InboundConfig, OutboundConfig};
use crate::router::RouterHandle;
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
    /// One cancellation token per inbound tag: RemoveInbound cancels exactly
    /// this inbound's listeners (startup and runtime-added alike).
    inbound_tokens: std::collections::HashMap<String, CancellationToken>,
}

pub(super) struct RuntimeRegistry {
    state: Arc<Mutex<RegistryState>>,
    routing: Arc<RuntimeRoutingStore>,
    /// The runtime dispatcher spawned listeners dispatch through.
    dispatcher: Arc<Dispatcher>,
    /// The server token; runtime-added inbounds get children of it.
    cancel: CancellationToken,
}

/// The runtime backing for RoutingService: the original routing config plus
/// the compiled outbound-tag registry and the swappable router handle. Rule
/// mutations recompile the whole routing config (validating against the
/// outbound tags exactly like startup) and swap the handle atomically.
pub(super) struct RuntimeRoutingStore {
    config: Mutex<crate::router::RoutingConfig>,
    outbounds: Vec<String>,
    router: std::sync::OnceLock<Arc<RouterHandle>>,
}

impl RuntimeRoutingStore {
    fn new(routing: crate::router::RoutingConfig, outbounds: Vec<String>) -> Self {
        Self {
            config: Mutex::new(routing),
            outbounds,
            router: Default::default(),
        }
    }

    /// The runtime installs the swappable handle after construction.
    fn attach(&self, handle: Arc<RouterHandle>) {
        let _ = self.router.set(handle);
    }

    fn compile_and_swap(&self) -> Result<(), String> {
        let handle = self
            .router
            .get()
            .cloned()
            .ok_or_else(|| "the routing store is not attached to the runtime".to_owned())?;
        let (config, outbounds) = {
            let config = self
                .config
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let outbounds = self
                .outbounds
                .iter()
                .map(|tag| crate::config::OutboundConfig {
                    tag: tag.clone(),
                    protocol: "registry".into(),
                    settings: serde_json::json!({}),
                    stream_settings: Default::default(),
                    mux: None,
                })
                .collect::<Vec<_>>();
            (config, outbounds)
        };
        let router = crate::router::Router::compile(&config, &outbounds)
            .map_err(|error| format!("{error:#}"))?;
        handle.swap(Arc::new(router));
        Ok(())
    }
}

#[tonic::async_trait]
impl RoutingStore for RuntimeRoutingStore {
    async fn list_rules(&self) -> Vec<RoutingRuleEntry> {
        self.config
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .rules
            .iter()
            .map(|rule| RoutingRuleEntry {
                rule_tag: rule.rule_tag.clone(),
                outbound_tag: rule.outbound_tag.clone(),
                balancer_tag: rule.balancer_tag.clone(),
            })
            .collect()
    }

    async fn add_rule(&self, rule: ProtoRule, should_append: bool) -> Result<(), String> {
        let port = rule.port.map(crate::router::PortSpec::List);
        let source_port = rule.source_port.map(crate::router::PortSpec::List);
        let config_rule = crate::router::RuleConfig {
            rule_tag: rule.rule_tag,
            outbound_tag: rule.outbound_tag,
            balancer_tag: rule.balancer_tag,
            domain: rule.domain,
            ip: rule.ip,
            port,
            network: rule.network.join(","),
            inbound_tag: rule.inbound_tag,
            source_ip: rule.source_ip,
            source_port,
            user: rule.user_email,
            protocol: rule.protocol,
            ..Default::default()
        };
        {
            let mut config = self.config.lock().unwrap_or_else(|p| p.into_inner());
            if config.rules.iter().any(|existing| {
                !existing.rule_tag.is_empty() && existing.rule_tag == config_rule.rule_tag
            }) {
                return Err(format!("duplicate rule tag {:?}", config_rule.rule_tag));
            }
            if should_append {
                config.rules.push(config_rule);
            } else {
                config.rules.insert(0, config_rule);
            }
        }
        self.compile_and_swap()
    }

    async fn remove_rule(&self, rule_tag: &str) -> Result<(), String> {
        {
            let mut config = self.config.lock().unwrap_or_else(|p| p.into_inner());
            let before = config.rules.len();
            config.rules.retain(|rule| rule.rule_tag != rule_tag);
            if config.rules.len() == before {
                return Err(format!("rule {rule_tag} not found"));
            }
        }
        self.compile_and_swap()
    }

    async fn balancer_info(&self, balancer_tag: &str) -> Result<BalancerSnapshot, String> {
        let config = self.config.lock().unwrap_or_else(|p| p.into_inner());
        let balancer = config
            .balancers
            .iter()
            .find(|balancer| balancer.tag == balancer_tag)
            .ok_or_else(|| format!("balancer {balancer_tag} not found"))?;
        Ok(BalancerSnapshot {
            // The pinned override lives on the compiled balancer; the config
            // snapshot reports the selector's candidates.
            override_target: None,
            principle_targets: balancer.selectors.clone(),
        })
    }

    async fn override_balancer(&self, balancer_tag: &str, target: &str) -> Result<(), String> {
        let handle = self
            .router
            .get()
            .cloned()
            .ok_or_else(|| "the routing store is not attached to the runtime".to_owned())?;
        // The compiled router owns the live balancer state; the override
        // pins its pick (Go's Balancer override, empty target clears).
        let router = handle.get();
        let balancer = router
            .balancer(balancer_tag)
            .ok_or_else(|| format!("balancer {balancer_tag} not found"))?;
        balancer.set_override(target);
        Ok(())
    }

    async fn test_route(
        &self,
        context: xray_proto::xray::app::router::command::RoutingContext,
    ) -> Result<String, String> {
        let handle = self
            .router
            .get()
            .cloned()
            .ok_or_else(|| "the routing store is not attached to the runtime".to_owned())?;
        let destination = if !context.target_domain.is_empty() {
            crate::address::Destination::new(&context.target_domain, context.target_port as u16)
                .map_err(|error| format!("{error}"))?
        } else {
            crate::address::Destination::from(std::net::SocketAddr::new(
                context
                    .target_i_ps
                    .first()
                    .map(|bytes| ip_from_bytes(bytes))
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                context.target_port as u16,
            ))
        };
        let selected = handle.select(&crate::router::RouteContext {
            destination: &destination,
            source: std::net::SocketAddr::from((
                context
                    .source_i_ps
                    .first()
                    .map(|bytes| ip_from_bytes(bytes))
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                context.source_port as u16,
            )),
            inbound_tag: context.inbound_tag.as_str(),
            user: context.user.as_str(),
            network: if context.network == 2 { "udp" } else { "tcp" },
        });
        self.outbounds
            .get(selected)
            .cloned()
            .ok_or_else(|| "the selected outbound is not registered".to_owned())
    }
}

fn ip_from_bytes(bytes: &[u8]) -> std::net::IpAddr {
    match bytes.len() {
        4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    }
}

impl RuntimeRegistry {
    pub(super) fn new(
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
        routing: crate::router::RoutingConfig,
        outbound_tags: Vec<String>,
    ) -> Arc<Self> {
        // The dispatcher and server token feed the dynamic-listener path:
        // AddInbound binds and spawns through the runtime's own accept loop.
        Arc::new(Self {
            state: Arc::default(),
            routing: Arc::new(RuntimeRoutingStore::new(routing, outbound_tags)),
            dispatcher,
            cancel,
        })
    }

    /// The RoutingService backing; the router handle attaches after the
    /// dispatcher is constructed.
    pub(super) fn routing_store(&self) -> Arc<RuntimeRoutingStore> {
        self.routing.clone()
    }

    pub(super) fn attach_router(&self, handle: Arc<RouterHandle>) {
        self.routing.attach(handle);
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

    /// Record one startup inbound's cancellation token so RemoveInbound can
    /// close exactly that inbound's listeners.
    pub(super) fn attach_inbound_cancel(&self, tag: String, token: CancellationToken) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .inbound_tokens
            .insert(tag, token);
    }

    /// The store backing HandlerService; it shares the registry's snapshot.
    pub(super) fn store(&self) -> Arc<dyn HandlerStore> {
        Arc::new(StoreHandle {
            state: self.state.clone(),
            dispatcher: self.dispatcher.clone(),
            cancel: self.cancel.clone(),
        })
    }
}

struct StoreHandle {
    state: Arc<Mutex<RegistryState>>,
    /// The runtime dispatcher the spawned listeners dispatch through.
    dispatcher: Arc<Dispatcher>,
    /// The server token; every runtime-added inbound gets a child of it.
    cancel: CancellationToken,
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
            range: raw
                .port
                .ports()
                .iter()
                .map(|port| PortRange {
                    from: u32::from(*port),
                    to: u32::from(*port),
                })
                .collect(),
        }),
        listen: Some(ip_or_domain(
            raw.listen
                .ip()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        )),
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
        Inbound::Shadowsocks { .. } | Inbound::Shadowsocks2022 { .. } => {
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
    /// `core.AddInboundHandler` over the runtime's own listener machinery:
    /// decode the wire config through the startup protobuf conversion (which
    /// fails closed on everything it cannot represent), compile it with the
    /// ordinary config validation, bind, spawn the accept loop on a child of
    /// the server token, and register the seed. A bind failure cancels the
    /// inbound's child token and registers nothing.
    async fn add_inbound(&self, config: InboundHandlerConfig) -> Result<(), HandlerStoreError> {
        let error = |error: anyhow::Error| HandlerStoreError::Message(format!("{error:#}"));
        let json = crate::config::protobuf::inbound_handler(config).map_err(error)?;
        let raw: InboundConfig = serde_json::from_value(json).map_err(|e| error(e.into()))?;
        if !raw.tag.is_empty() {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state
                .inbounds
                .iter()
                .any(|existing| existing.raw.tag == raw.tag)
            {
                return Err(HandlerStoreError::ExistingTag(raw.tag));
            }
        }
        let sniff = super::sniffing::SniffingRequest::compile(
            raw.sniffing.as_ref(),
            &crate::geodata::GeoDataStore::from_env().map_err(error)?,
        )
        .map_err(error)?
        .map(Arc::new);
        let (inbound, transport) = crate::config::compile_inbound(&raw).map_err(error)?;
        let cancel = self.cancel.child_token();
        let tag: Arc<str> = Arc::from(raw.tag.as_str());
        // A path listen binds a unix domain socket (dokodemo only).
        if let Some(path) = raw.listen.path() {
            let address =
                crate::transport::unix_listener::UnixListenAddress::parse(path).map_err(error)?;
            let listener = crate::transport::unix_listener::UnixListener::bind(&address)
                .await
                .map_err(error)?;
            tokio::spawn(super::accept_loop(
                crate::transport::InboundListener::Unix(listener),
                inbound.clone(),
                raw.tag.clone(),
                crate::transport::InboundTransport::default(),
                sniff.clone(),
                self.dispatcher.clone(),
                cancel.clone(),
            ));
        }
        // TUN owns a device, not a socket: one serve task, no port loop.
        if let crate::config::Inbound::Tun { entry } = &inbound {
            let serve = super::tun_inbound::serve(
                (**entry).clone(),
                self.dispatcher.clone(),
                tag.clone(),
                sniff.clone(),
                cancel.clone(),
            );
            tokio::spawn(async move {
                if let Err(ended) = serve.await {
                    tracing::warn!(%ended, "tun listener ended");
                }
            });
        }
        // WireGuard owns one UDP endpoint per port.
        if let crate::config::Inbound::Wireguard { entry } = &inbound {
            for port in raw.port.ports() {
                let bound = entry.clone().listen_on(std::net::SocketAddr::new(
                    raw.listen.ip().map_err(error)?,
                    *port,
                ));
                let serve = super::wireguard_inbound::serve(
                    bound,
                    self.dispatcher.clone(),
                    tag.clone(),
                    sniff.clone(),
                    cancel.clone(),
                );
                tokio::spawn(async move {
                    if let Err(ended) = serve.await {
                        tracing::warn!(%ended, "wireguard listener ended");
                    }
                });
            }
        }
        for port in raw.port.ports() {
            let address = std::net::SocketAddr::new(raw.listen.ip().map_err(error)?, *port);
            if let crate::config::Inbound::Hysteria { users } = &inbound {
                let listener =
                    super::hysteria_seam::bind_inbound(&raw, users, *port).map_err(error)?;
                let serve = super::hysteria_seam::serve(
                    listener,
                    inbound.clone(),
                    tag.clone(),
                    sniff.clone(),
                    self.dispatcher.clone(),
                    cancel.clone(),
                );
                tokio::spawn(async move {
                    if let Err(ended) = serve.await {
                        tracing::warn!(%ended, "hysteria listener ended");
                    }
                });
                continue;
            }
            let listener = transport.bind(address).await.map_err(|e| error(e.into()))?;
            tokio::spawn(super::accept_loop(
                listener,
                inbound.clone(),
                raw.tag.clone(),
                transport.clone(),
                sniff.clone(),
                self.dispatcher.clone(),
                cancel.clone(),
            ));
        }
        // The UDP sidecars the seeds loop binds beside their TCP listener.
        match &inbound {
            crate::config::Inbound::Shadowsocks { account, udp: true } => {
                for port in raw.port.ports() {
                    let bound = super::plain_udp::LegacyShadowsocksUdp::bind(
                        std::net::SocketAddr::new(raw.listen.ip().map_err(error)?, *port),
                        account,
                    )
                    .map_err(error)?;
                    let dispatcher = self.dispatcher.clone();
                    let tag = tag.clone();
                    let stop = cancel.clone();
                    tokio::spawn(async move {
                        let _ = bound.run(dispatcher, tag, stop).await;
                    });
                }
            }
            crate::config::Inbound::Dokodemo {
                destination,
                udp: true,
            } => {
                for port in raw.port.ports() {
                    let dispatcher = self.dispatcher.clone();
                    let tag = tag.clone();
                    let destination = destination.clone();
                    let stop = cancel.clone();
                    let address = std::net::SocketAddr::new(raw.listen.ip().map_err(error)?, *port);
                    tokio::spawn(async move {
                        let _ = super::plain_udp::serve_dokodemo_udp(
                            address,
                            destination,
                            dispatcher,
                            tag,
                            stop,
                        )
                        .await;
                    });
                }
            }
            crate::config::Inbound::Shadowsocks2022 { account, udp: true } => {
                for port in raw.port.ports() {
                    let bound = super::ss2022_udp_runtime::Ss2022UdpListener::bind(
                        std::net::SocketAddr::new(raw.listen.ip().map_err(error)?, *port),
                        account,
                    )
                    .map_err(error)?;
                    let dispatcher = self.dispatcher.clone();
                    let stop = cancel.clone();
                    tokio::spawn(async move {
                        let _ = bound.run(dispatcher, stop).await;
                    });
                }
            }
            _ => (),
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Re-check under the lock: a concurrent add of the same tag loses.
        if !raw.tag.is_empty()
            && state
                .inbounds
                .iter()
                .any(|existing| existing.raw.tag == raw.tag)
        {
            drop(state);
            cancel.cancel();
            return Err(HandlerStoreError::ExistingTag(raw.tag));
        }
        state.inbounds.push(SeededInbound {
            raw,
            inbound,
            transport,
        });
        if !tag.is_empty() {
            state.inbound_tokens.insert(tag.to_string(), cancel);
        }
        Ok(())
    }

    /// `inbound.Manager.RemoveHandler`: cancel the tag's listeners and drop
    /// the seed; an empty or unknown tag is `common.ErrNoClue`.
    async fn remove_inbound(&self, tag: &str) -> Result<(), HandlerStoreError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The store contract: an unknown or empty tag fails with NoClue.
        if tag.is_empty() || !state.inbounds.iter().any(|seeded| seeded.raw.tag == tag) {
            return Err(HandlerStoreError::NoClue);
        }
        if let Some(token) = state.inbound_tokens.remove(tag) {
            token.cancel();
        }
        state.inbounds.retain(|seeded| seeded.raw.tag != tag);
        Ok(())
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
