//! Native RoutingService (app/router/command): runtime routing-rule and
//! balancer management over gRPC.
//!
//! The source `RouterService` forwards every RPC to the router's managers.
//! The runtime backing is supplied through [`RoutingStore`]: rule
//! mutations recompile the routing configuration and swap the compiled
//! router through the runtime's swappable handle, so live connections pick
//! up the new rules on their next route. SubscribeRoutingStats requires the
//! dispatcher's statistics channel, which is not integrated in this runtime
//! build — the subscription fails explicitly instead of streaming nothing.

use std::sync::Arc;

use anyhow::Result;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, service::Routes};

use xray_proto::xray::app::router::command::{
    AddRuleRequest, AddRuleResponse, BalancerMsg, GetBalancerInfoRequest, GetBalancerInfoResponse,
    ListRuleItem, ListRuleRequest, ListRuleResponse, OverrideBalancerTargetRequest,
    OverrideBalancerTargetResponse, RemoveRuleRequest, RemoveRuleResponse, RoutingContext,
    SubscribeRoutingStatsRequest, TestRouteRequest,
    routing_service_server::{RoutingService, RoutingServiceServer},
};

/// One entry of the routing configuration the store exposes: a compiled rule
/// with its `ruleTag` and the target (outbound or balancer) it selects.
#[derive(Clone, Debug)]
pub struct RoutingRuleEntry {
    pub rule_tag: String,
    pub outbound_tag: String,
    pub balancer_tag: String,
}

/// The runtime backing for RoutingService. Implementations own the routing
/// configuration and the swappable router handle; `add_rule`/`remove_rule`
/// recompile and swap atomically (an invalid rule fails without touching the
/// live router).
#[tonic::async_trait]
pub trait RoutingStore: Send + Sync + 'static {
    /// The compiled rules in configuration order (Go's manager listing).
    async fn list_rules(&self) -> Vec<RoutingRuleEntry>;

    /// Validate and append (or prepend) one rule; the rule arrives as the
    /// proto `RoutingRule`, decoded by this module before the call.
    async fn add_rule(&self, rule: ProtoRule, should_append: bool) -> Result<(), String>;

    /// Remove the rule with the given tag; unknown tags fail with the
    /// source's error text.
    async fn remove_rule(&self, rule_tag: &str) -> Result<(), String>;

    /// The balancer's override target and its selector tags (Go's
    /// `GetBalancerInfo`); unknown balancers fail.
    async fn balancer_info(&self, balancer_tag: &str) -> Result<BalancerSnapshot, String>;

    /// Pin the balancer to one outbound tag (Go's `OverrideBalancerTarget`).
    async fn override_balancer(&self, balancer_tag: &str, target: &str) -> Result<(), String>;

    /// Route one context through the current rules (Go's `TestRoute`).
    /// Returns the selected outbound tag.
    async fn test_route(&self, context: RoutingContext) -> Result<String, String>;
}

/// A balancer's observable state (Go's `BalancerMsg`).
#[derive(Clone, Debug, Default)]
pub struct BalancerSnapshot {
    /// The pinned override target, when set.
    pub override_target: Option<String>,
    /// The selector's current candidate tags.
    pub principle_targets: Vec<String>,
}

/// The proto `RoutingRule` plus the position it should take — the decoded
/// form the store recompiles from.
pub struct ProtoRule {
    pub rule_tag: String,
    pub outbound_tag: String,
    pub balancer_tag: String,
    pub domain: Vec<String>,
    pub ip: Vec<String>,
    pub port: Option<String>,
    pub network: Vec<String>,
    pub source_ip: Vec<String>,
    pub source_port: Option<String>,
    pub user_email: Vec<String>,
    pub inbound_tag: Vec<String>,
    pub protocol: Vec<String>,
}

pub struct RoutingServiceBackend {
    store: Arc<dyn RoutingStore>,
}

impl RoutingServiceBackend {
    pub fn new(store: Arc<dyn RoutingStore>) -> Self {
        Self { store }
    }

    pub fn into_server(self) -> RoutingServiceServer<Self> {
        RoutingServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl RoutingService for RoutingServiceBackend {
    type SubscribeRoutingStatsStream =
        Box<dyn Stream<Item = Result<RoutingContext, Status>> + Send + Unpin>;

    async fn subscribe_routing_stats(
        &self,
        _request: Request<SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        Err(Status::unimplemented(
            "routing statistics streaming requires the dispatcher's statistics channel, \\
             which is not integrated in this runtime build",
        ))
    }

    async fn test_route(
        &self,
        request: Request<TestRouteRequest>,
    ) -> Result<Response<RoutingContext>, Status> {
        let request = request.into_inner();
        let context = request
            .routing_context
            .ok_or_else(|| Status::invalid_argument("TestRoute requires a routing context"))?;
        let outbound = self
            .store
            .test_route(context.clone())
            .await
            .map_err(Status::failed_precondition)?;
        let mut result = context;
        result.outbound_tag = outbound;
        Ok(Response::new(result))
    }

    async fn get_balancer_info(
        &self,
        request: Request<GetBalancerInfoRequest>,
    ) -> Result<Response<GetBalancerInfoResponse>, Status> {
        let tag = request.into_inner().tag;
        let snapshot = self
            .store
            .balancer_info(&tag)
            .await
            .map_err(Status::failed_precondition)?;
        let mut balancer = BalancerMsg::default();
        if let Some(target) = snapshot.override_target {
            balancer.r#override = Some(OverrideInfo { target });
        }
        if !snapshot.principle_targets.is_empty() {
            balancer.principle_target = Some(PrincipleTargetInfo {
                tag: snapshot.principle_targets,
            });
        }
        Ok(Response::new(GetBalancerInfoResponse {
            balancer: Some(balancer),
        }))
    }

    async fn override_balancer_target(
        &self,
        request: Request<OverrideBalancerTargetRequest>,
    ) -> Result<Response<OverrideBalancerTargetResponse>, Status> {
        let request = request.into_inner();
        self.store
            .override_balancer(&request.balancer_tag, &request.target)
            .await
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(OverrideBalancerTargetResponse {}))
    }

    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<AddRuleResponse>, Status> {
        let request = request.into_inner();
        let config = request
            .config
            .ok_or_else(|| Status::invalid_argument("AddRule requires a rule config"))?;
        // The typed message must be the app.router RoutingRule.
        let type_url = config
            .r#type
            .trim_start_matches('/')
            .trim_start_matches("type.googleapis.com/");
        if type_url != "xray.app.router.RoutingRule" {
            return Err(Status::invalid_argument(format!(
                "AddRule requires xray.app.router.RoutingRule, got {type_url}"
            )));
        }
        let rule: xray_proto::xray::app::router::RoutingRule =
            prost::Message::decode(config.value.as_slice()).map_err(|error| {
                Status::invalid_argument(format!("invalid RoutingRule: {error}"))
            })?;
        let is_balancer = matches!(
            rule.target_tag,
            Some(xray_proto::xray::app::router::routing_rule::TargetTag::BalancingTag(_))
        );
        let outbound_tag = match &rule.target_tag {
            Some(xray_proto::xray::app::router::routing_rule::TargetTag::Tag(tag)) => tag.clone(),
            Some(xray_proto::xray::app::router::routing_rule::TargetTag::BalancingTag(tag)) => {
                tag.clone()
            }
            None => {
                return Err(Status::invalid_argument(
                    "AddRule requires the rule's outbound or balancer tag",
                ));
            }
        };
        let proto_rule = ProtoRule {
            rule_tag: rule.rule_tag.clone(),
            outbound_tag: if is_balancer {
                String::new()
            } else {
                outbound_tag.clone()
            },
            balancer_tag: if is_balancer {
                outbound_tag.clone()
            } else {
                String::new()
            },
            domain: rule.domain.iter().map(domain_rule_text).collect(),
            ip: rule.ip.iter().map(ip_rule_text).collect(),
            port: rule.port_list.as_ref().map(port_list_text),
            network: rule
                .networks
                .iter()
                .map(|network| network_name(*network))
                .collect(),
            source_ip: rule.source_ip.iter().map(ip_rule_text).collect(),
            source_port: rule.source_port_list.as_ref().map(port_list_text),
            user_email: rule.user_email,
            inbound_tag: rule.inbound_tag,
            protocol: rule.protocol,
        };
        self.store
            .add_rule(proto_rule, request.should_append)
            .await
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(AddRuleResponse {}))
    }

    async fn remove_rule(
        &self,
        request: Request<RemoveRuleRequest>,
    ) -> Result<Response<RemoveRuleResponse>, Status> {
        let tag = request.into_inner().rule_tag;
        self.store
            .remove_rule(&tag)
            .await
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(RemoveRuleResponse {}))
    }

    async fn list_rule(
        &self,
        _request: Request<ListRuleRequest>,
    ) -> Result<Response<ListRuleResponse>, Status> {
        let entries = self.store.list_rules().await;
        let rules = entries
            .into_iter()
            .map(|entry| ListRuleItem {
                tag: entry.outbound_tag,
                rule_tag: entry.rule_tag,
            })
            .collect();
        Ok(Response::new(ListRuleResponse { rules }))
    }
}

use xray_proto::xray::app::router::command::{OverrideInfo, PrincipleTargetInfo};

/// One proto DomainRule → the config-layer matcher string: `ext:file:code`
/// for geosite references, `type:value` for plain domains.
fn domain_rule_text(rule: &xray_proto::xray::common::geodata::DomainRule) -> String {
    use xray_proto::xray::common::geodata::domain_rule::Value;
    match &rule.value {
        Some(Value::Geosite(geosite)) => {
            format!("ext:{}:{}", geosite.file, geosite.code)
        }
        Some(Value::Custom(domain)) => format!(
            "{}:{}",
            match domain.r#type {
                0 => "plain",
                1 => "regexp",
                2 => "domain",
                3 => "full",
                _ => "plain",
            },
            domain.value
        ),
        None => String::new(),
    }
}

/// One proto IpRule → the config-layer matcher string: `ext:file:code`
/// for geoip references, `a.b.c.d/prefix` for literal CIDRs.
fn ip_rule_text(rule: &xray_proto::xray::common::geodata::IpRule) -> String {
    use xray_proto::xray::common::geodata::ip_rule::Value;
    match &rule.value {
        Some(Value::Geoip(geoip)) => {
            format!("ext:{}:{}", geoip.file, geoip.code)
        }
        Some(Value::Custom(cidr_rule)) => match &cidr_rule.cidr {
            Some(cidr) => format!("{}/{}", ip_bytes_text(&cidr.ip), cidr.prefix),
            None => String::new(),
        },
        None => String::new(),
    }
}

fn ip_bytes_text(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let octets: Vec<String> = bytes
                .chunks(2)
                .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
                .collect();
            let full: Vec<Option<String>> = octets
                .iter()
                .map(|octet| {
                    u16::from_str_radix(octet, 16)
                        .ok()
                        .filter(|v| *v != 0)
                        .map(|_| octet.clone())
                })
                .collect();
            let _ = full;
            // Collapse the zero runs of the canonical IPv6 form.
            let groups: Vec<u16> = bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            let text: Vec<String> = groups.iter().map(|g| format!("{g:x}")).collect();
            text.join(":")
        }
        _ => String::new(),
    }
}

fn port_list_text(list: &xray_proto::xray::common::net::PortList) -> String {
    list.range
        .iter()
        .map(|range| {
            if range.from == range.to {
                range.from.to_string()
            } else {
                format!("{}-{}", range.from, range.to)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn network_name(network: i32) -> String {
    match network {
        1 => "tcp".to_owned(),
        2 => "udp".to_owned(),
        _ => String::new(),
    }
}

/// Start a router containing both source service-name aliases (the Xray
/// `RoutingService` name).
pub fn routing_routes(service: RoutingServiceBackend) -> Routes {
    let server = service.into_server();
    tonic::service::Routes::default().add_service(server)
}

/// Add the RoutingService to a router that already contains other services.
pub fn add_routing_routes(routes: Routes, service: RoutingServiceBackend) -> Routes {
    let server = service.into_server();
    routes.add_service(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryStore {
        rules: std::sync::Mutex<Vec<RoutingRuleEntry>>,
    }

    #[tonic::async_trait]
    impl RoutingStore for MemoryStore {
        async fn list_rules(&self) -> Vec<RoutingRuleEntry> {
            self.rules.lock().unwrap().clone()
        }

        async fn add_rule(&self, rule: ProtoRule, should_append: bool) -> Result<(), String> {
            let entry = RoutingRuleEntry {
                rule_tag: rule.rule_tag,
                outbound_tag: rule.outbound_tag,
                balancer_tag: rule.balancer_tag,
            };
            let mut rules = self.rules.lock().unwrap();
            if should_append {
                rules.push(entry);
            } else {
                rules.insert(0, entry);
            }
            Ok(())
        }

        async fn remove_rule(&self, rule_tag: &str) -> Result<(), String> {
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|entry| entry.rule_tag != rule_tag);
            if rules.len() == before {
                return Err(format!("rule {rule_tag} not found"));
            }
            Ok(())
        }

        async fn balancer_info(&self, _tag: &str) -> Result<BalancerSnapshot, String> {
            Ok(BalancerSnapshot::default())
        }

        async fn override_balancer(
            &self,
            _balancer_tag: &str,
            _target: &str,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn test_route(&self, _context: RoutingContext) -> Result<String, String> {
            Ok("direct".to_owned())
        }
    }

    fn rule_wire(tag: &str, outbound: &str) -> AddRuleRequest {
        let rule = xray_proto::xray::app::router::RoutingRule {
            rule_tag: tag.to_owned(),
            target_tag: Some(xray_proto::xray::app::router::routing_rule::TargetTag::Tag(
                outbound.to_owned(),
            )),
            ..Default::default()
        };
        AddRuleRequest {
            config: Some(xray_proto::xray::common::serial::TypedMessage {
                r#type: "type.googleapis.com/xray.app.router.RoutingRule".to_owned(),
                value: prost::Message::encode_to_vec(&rule),
            }),
            should_append: true,
        }
    }

    #[tokio::test]
    async fn add_list_and_remove_rules_round_trip() {
        let store = Arc::new(MemoryStore {
            rules: std::sync::Mutex::new(vec![RoutingRuleEntry {
                rule_tag: "seed".to_owned(),
                outbound_tag: "direct".to_owned(),
                balancer_tag: String::new(),
            }]),
        });
        let service = RoutingServiceBackend::new(store.clone());
        service
            .add_rule(Request::new(rule_wire("added", "proxy")))
            .await
            .unwrap();
        let response = service
            .list_rule(Request::new(ListRuleRequest {}))
            .await
            .unwrap();
        let rules = response.into_inner().rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].rule_tag, "added");
        assert_eq!(rules[1].tag, "proxy");
        service
            .remove_rule(Request::new(RemoveRuleRequest {
                rule_tag: "added".to_owned(),
            }))
            .await
            .unwrap();
        let response = service
            .list_rule(Request::new(ListRuleRequest {}))
            .await
            .unwrap();
        assert_eq!(response.into_inner().rules.len(), 1);
        // Unknown tags fail with the store's error.
        let error = service
            .remove_rule(Request::new(RemoveRuleRequest {
                rule_tag: "missing".to_owned(),
            }))
            .await
            .unwrap_err();
        assert!(error.message().contains("not found"));
    }

    #[tokio::test]
    async fn wrong_typed_messages_and_missing_configs_fail() {
        let service = RoutingServiceBackend::new(Arc::new(MemoryStore {
            rules: std::sync::Mutex::new(Vec::new()),
        }));
        let error = service
            .add_rule(Request::new(AddRuleRequest {
                config: Some(xray_proto::xray::common::serial::TypedMessage {
                    r#type: "type.googleapis.com/xray.app.stats.command.GetStats".to_owned(),
                    value: Vec::new(),
                }),
                should_append: true,
            }))
            .await
            .unwrap_err();
        assert!(error.message().contains("RoutingRule"));
        let error = service
            .add_rule(Request::new(AddRuleRequest {
                config: None,
                should_append: true,
            }))
            .await
            .unwrap_err();
        assert!(error.message().contains("requires"));
    }
}
