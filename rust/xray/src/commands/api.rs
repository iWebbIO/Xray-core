//! Native clients for management services implemented by this Rust runtime.
//!
//! Flags and JSON follow `main/commands/all/api` and `common/reflect/marshal.go`.
//! The source prints reflection JSON, not protobuf JSON: integer fields remain
//! numbers, zero scalar fields are omitted, keys are sorted, indentation is
//! four spaces, and successful responses end with two newline characters.

use std::{collections::BTreeMap, future::Future, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Subcommand};
use serde_json::Value;
use tokio::time::{Instant, sleep_until, timeout_at};
use tonic::{
    Request, Response, Status,
    metadata::MetadataMap,
    transport::{Channel, Endpoint},
};

use xray_core::{
    api::wire::{self, stats_service_client::StatsServiceClient},
    proto::xray::app::log::command::{
        RestartLoggerRequest, logger_service_client::LoggerServiceClient,
    },
    proto::xray::app::router::command::{
        AddRuleRequest, ListRuleRequest, RemoveRuleRequest,
        routing_service_client::RoutingServiceClient,
    },
};

#[derive(Clone, Debug, Subcommand)]
pub enum ApiCommand {
    /// Fetch a counter, optionally resetting it after reading.
    Stats(StatArgs),
    /// Query counters using a literal substring pattern.
    #[command(name = "statsquery")]
    StatsQuery(QueryArgs),
    /// Retrieve system statistics.
    #[command(name = "statssys")]
    StatsSys(ConnectionArgs),
    /// Retrieve the online count for a user's email.
    #[command(name = "statsonline")]
    StatsOnline(OnlineArgs),
    /// Retrieve a user's IPs, or all online users and optional traffic.
    #[command(name = "statsonlineiplist")]
    StatsOnlineIpList(OnlineIpArgs),
    /// Retrieve the registered names of all online users.
    #[command(name = "statsgetallonlineusers")]
    StatsGetAllOnlineUsers(ConnectionArgs),
    /// Reopen the running process's logger outputs.
    #[command(name = "restartlogger")]
    RestartLogger(ConnectionArgs),
    /// List the running router's rules.
    #[command(name = "lsrules")]
    ListRules(ConnectionArgs),
    /// Remove a routing rule by its tag.
    #[command(name = "rmrules")]
    RemoveRules(RemoveRulesArgs),
    /// Add routing rules from config files (JSON config format).
    #[command(name = "adrules")]
    AddRules(AddRulesArgs),
    /// Add inbounds from config files (their `inbounds` fields).
    #[command(name = "adi")]
    AddInbounds(AddInboundsArgs),
    /// Remove inbounds by tag, or by the tags a config file carries.
    #[command(name = "rmi")]
    RemoveInbounds(RemoveInboundsArgs),
    /// List the running inbounds.
    #[command(name = "lsi")]
    ListInbounds(ListInboundsArgs),
    /// Retrieve inbound user(s) by tag, optionally by email.
    #[command(name = "inbounduser")]
    InboundUser(InboundUserArgs),
    /// Retrieve the user count of an inbound.
    #[command(name = "inboundusercount")]
    InboundUserCount(InboundUserCountArgs),
    /// Preserve an explicit unsupported-service diagnostic for other commands.
    #[command(external_subcommand)]
    Unsupported(Vec<String>),
}

#[derive(Clone, Debug, Args)]
pub struct AddInboundsArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// Config files whose `inbounds` fields carry the handlers (stdin with `-`).
    #[arg(required = true)]
    pub configs: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub struct RemoveInboundsArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// An inbound tag, or a config file whose inbound tags to remove.
    #[arg(required = true)]
    pub targets: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub struct ListInboundsArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// Print only the inbound tags.
    #[arg(long, default_value_t = false)]
    pub is_only_tags: bool,
}

#[derive(Clone, Debug, Args)]
pub struct InboundUserArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// The inbound tag.
    #[arg(long, default_value = "")]
    pub tag: String,
    /// The user's email; empty retrieves every user of the inbound.
    #[arg(long, default_value = "")]
    pub email: String,
}

#[derive(Clone, Debug, Args)]
pub struct InboundUserCountArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// The inbound tag.
    #[arg(long, default_value = "")]
    pub tag: String,
}

#[derive(Clone, Debug, Args)]
pub struct RemoveRulesArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// The rule tag to remove (repeatable).
    #[arg(required = true)]
    pub rule_tags: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub struct AddRulesArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// Append after the existing rules instead of prepending.
    #[arg(long, default_value_t = false)]
    pub append: bool,
    /// Config files whose `routing` fields carry the rules (stdin with `-`).
    #[arg(required = true)]
    pub configs: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub struct ConnectionArgs {
    #[arg(short = 's', long, default_value = "127.0.0.1:8080")]
    pub server: String,
    /// Total connection and RPC deadline, in seconds.
    #[arg(short = 't', long, default_value_t = 3, allow_hyphen_values = true)]
    pub timeout: i64,
    /// Accepted for source compatibility; these commands always print JSON.
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub json: bool,
}

impl Default for ConnectionArgs {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:8080".into(),
            timeout: 3,
            json: false,
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct StatArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    #[arg(long, default_value = "")]
    pub name: String,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub reset: bool,
}

#[derive(Clone, Debug, Args)]
pub struct QueryArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    #[arg(long, default_value = "")]
    pub pattern: String,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub reset: bool,
}

#[derive(Clone, Debug, Args)]
pub struct OnlineArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    #[arg(long, default_value = "")]
    pub email: String,
}

#[derive(Clone, Debug, Args)]
pub struct OnlineIpArgs {
    #[command(flatten)]
    pub connection: ConnectionArgs,
    #[arg(long, default_value = "")]
    pub email: String,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub all: bool,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub include_traffic: bool,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub reset: bool,
}

impl ApiCommand {
    fn connection(&self) -> Result<&ConnectionArgs> {
        Ok(match self {
            Self::Stats(args) => &args.connection,
            Self::StatsQuery(args) => &args.connection,
            Self::StatsOnline(args) => &args.connection,
            Self::StatsOnlineIpList(args) => &args.connection,
            Self::StatsSys(args)
            | Self::StatsGetAllOnlineUsers(args)
            | Self::RestartLogger(args)
            | Self::ListRules(args) => args,
            Self::RemoveRules(args) => &args.connection,
            Self::AddRules(args) => &args.connection,
            Self::ListInbounds(args) => &args.connection,
            Self::AddInbounds(args) => &args.connection,
            Self::RemoveInbounds(args) => &args.connection,
            Self::InboundUser(args) => &args.connection,
            Self::InboundUserCount(args) => &args.connection,
            Self::Unsupported(args) => {
                let name = args.first().map(String::as_str).unwrap_or("");
                let service = match name {
                    "ado" | "rmo" | "lso" | "adu" | "rmu" => "HandlerService",
                    "bi" | "bo" | "sib" => "RoutingService",
                    "observatory" | "outboundstatus" => {
                        "ObservatoryService with a real observation provider"
                    }
                    _ => bail!("unsupported API command {name:?}"),
                };
                bail!(
                    "API command {name:?} requires {service}; this CLI integration is not implemented"
                );
            }
        })
    }

    fn validate(&self) -> Result<()> {
        self.connection()?;
        if let Self::StatsOnlineIpList(args) = self {
            ensure!(
                !args.all || args.email.is_empty(),
                "-all and -email are mutually exclusive"
            );
            ensure!(
                args.all || !args.email.is_empty(),
                "either -all or -email must be specified"
            );
        }
        Ok(())
    }
}

/// Execute exactly one command. The deadline includes dialing and the RPC,
/// matching the source's one shared timeout context. No Go subprocess is used.
pub async fn execute(command: ApiCommand) -> Result<String> {
    command.validate()?;
    let args = command.connection()?;
    ensure!(
        args.timeout > 0,
        "failed to dial {}: deadline exceeded",
        args.server
    );
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(args.timeout as u64))
        .context("API timeout exceeds the platform's supported range")?;
    execute_at(command, deadline).await
}

/// One config-format routing rule (`routing.rules[i]`) → the proto
/// `RoutingRule` TypedMessage AddRule carries. Domain/ip entries keep the
/// config spelling; the service's matcher parser handles them on arrival.
fn rule_to_typed_message(rule: &Value) -> Result<xray_proto::xray::common::serial::TypedMessage> {
    use xray_proto::xray::app::router::{RoutingRule, routing_rule::TargetTag};
    use xray_proto::xray::common::geodata::{
        Cidr, CidrRule, Domain, DomainRule, IpRule, domain_rule::Value as DomainValue,
        ip_rule::Value as IpValue,
    };

    let strings = |value: &Value| -> Vec<String> {
        match value {
            Value::Array(items) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
            Value::String(text) => vec![text.clone()],
            _ => Vec::new(),
        }
    };
    let domain_entry = |text: &str| -> Option<DomainRule> {
        // The config spellings: plain, regexp:, domain:, full:, subdomain:,
        // and ext:file:code references.
        if let Some(rest) = text.strip_prefix("ext:") {
            let (file, code) = rest.split_once(':')?;
            return Some(DomainRule {
                value: Some(DomainValue::Geosite(
                    xray_proto::xray::common::geodata::GeoSiteRule {
                        file: file.to_owned(),
                        code: code.to_owned(),
                        attrs: String::new(),
                    },
                )),
            });
        }
        let (kind, value) = match text.split_once(':') {
            Some(("plain", value)) => (0, value),
            Some(("regexp", value)) => (1, value),
            Some(("domain", value)) => (2, value),
            Some(("full", value)) => (3, value),
            Some(("subdomain", value)) => (2, value),
            _ => (0, text),
        };
        Some(DomainRule {
            value: Some(DomainValue::Custom(Domain {
                r#type: kind,
                value: value.to_owned(),
                attribute: Vec::new(),
            })),
        })
    };
    let ip_entry = |text: &str| -> Option<IpRule> {
        if let Some(rest) = text.strip_prefix("ext:") {
            let (file, code) = rest.split_once(':')?;
            return Some(IpRule {
                value: Some(IpValue::Geoip(
                    xray_proto::xray::common::geodata::GeoIpRule {
                        file: file.to_owned(),
                        code: code.to_owned(),
                        reverse_match: false,
                    },
                )),
            });
        }
        let (address, prefix) = text.split_once('/').unwrap_or((text, "32"));
        let ip: std::net::IpAddr = address.parse().ok()?;
        let bytes = match ip {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let prefix: u32 = prefix.parse().ok()?;
        Some(IpRule {
            value: Some(IpValue::Custom(CidrRule {
                cidr: Some(Cidr { ip: bytes, prefix }),
                reverse_match: false,
            })),
        })
    };
    let port_list = |spec: &str| -> Option<xray_proto::xray::common::net::PortList> {
        let ranges = spec
            .split(',')
            .map(|part| {
                let (from, to) = match part.split_once('-') {
                    Some((from, to)) => (from.parse::<u32>().ok()?, to.parse::<u32>().ok()?),
                    None => {
                        let port = part.parse::<u32>().ok()?;
                        (port, port)
                    }
                };
                Some(xray_proto::xray::common::net::PortRange { from, to })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(xray_proto::xray::common::net::PortList { range: ranges })
    };

    let outbound_tag = rule.get("outboundTag").and_then(|tag| tag.as_str());
    let balancer_tag = rule.get("balancerTag").and_then(|tag| tag.as_str());
    let target_tag = match (outbound_tag, balancer_tag) {
        (Some(tag), _) => Some(TargetTag::Tag(tag.to_owned())),
        (None, Some(tag)) => Some(TargetTag::BalancingTag(tag.to_owned())),
        (None, None) => bail!("the routing rule sets neither outboundTag nor balancerTag"),
    };
    let networks = strings(rule.get("network").unwrap_or(&Value::Null))
        .iter()
        .flat_map(|text| text.split(','))
        .map(|text| match text.trim() {
            "udp" => 2,
            _ => 1,
        })
        .collect::<Vec<i32>>();
    let mut proto_rule = RoutingRule {
        rule_tag: rule
            .get("ruleTag")
            .and_then(|tag| tag.as_str())
            .unwrap_or_default()
            .to_owned(),
        domain: rule
            .get("domain")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().and_then(domain_entry))
                    .collect()
            })
            .unwrap_or_default(),
        ip: rule
            .get("ip")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().and_then(ip_entry))
                    .collect()
            })
            .unwrap_or_default(),
        port_list: rule
            .get("port")
            .and_then(|value| value.as_str())
            .and_then(port_list),
        networks,
        source_ip: rule
            .get("sourceIP")
            .or_else(|| rule.get("sourceIp"))
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().and_then(ip_entry))
                    .collect()
            })
            .unwrap_or_default(),
        source_port_list: rule
            .get("sourcePort")
            .and_then(|value| value.as_str())
            .and_then(port_list),
        user_email: strings(rule.get("user").unwrap_or(&Value::Null)),
        inbound_tag: strings(rule.get("inboundTag").unwrap_or(&Value::Null)),
        protocol: strings(rule.get("protocol").unwrap_or(&Value::Null)),
        ..Default::default()
    };
    if let Some(tag) = target_tag {
        proto_rule.target_tag = Some(tag);
    }
    Ok(xray_proto::xray::common::serial::TypedMessage {
        r#type: "type.googleapis.com/xray.app.router.RoutingRule".to_owned(),
        value: prost::Message::encode_to_vec(&proto_rule),
    })
}

fn endpoint(server: &str) -> Result<Endpoint> {
    // Plain HTTP is the HTTP/2 transport for source-compatible insecure gRPC.
    // Other gRPC resolver/socket schemes need their own connector, not a
    // misleading transformation into a TCP hostname.
    let server = server.strip_prefix("dns:///").unwrap_or(server);
    let url = if server.starts_with("http://") {
        server.to_owned()
    } else {
        ensure!(
            !server.contains("://"),
            "API server supports plaintext TCP host:port endpoints only"
        );
        format!("http://{server}")
    };
    let endpoint = Endpoint::from_shared(url).context("invalid API server address")?;
    let uri = endpoint.uri();
    ensure!(
        uri.scheme_str() == Some("http") && uri.host().is_some() && uri.port_u16().is_some(),
        "API server requires host:port"
    );
    ensure!(
        uri.path() == "/" && uri.query().is_none(),
        "API server address cannot contain a path or query"
    );
    Ok(endpoint)
}

async fn connect(server: &str, deadline: Instant) -> Result<Channel> {
    let endpoint = endpoint(server)?;
    // Go DialContext(WithBlock) retries an endpoint that is still starting.
    // Keep that useful behavior while retaining one finite absolute deadline.
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .with_context(|| format!("failed to dial {server}: deadline exceeded"))?;
        match timeout_at(
            deadline,
            endpoint.clone().connect_timeout(remaining).connect(),
        )
        .await
        {
            Ok(Ok(channel)) => return Ok(channel),
            Ok(Err(_)) => {
                sleep_until((Instant::now() + Duration::from_millis(50)).min(deadline)).await;
            }
            Err(_) => bail!("failed to dial {server}: deadline exceeded"),
        }
    }
}

fn request<T>(message: T, deadline: Instant) -> Result<Request<T>> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("API deadline exceeded")?;
    let mut request = Request::new(message);
    request.set_timeout(remaining);
    Ok(request)
}

async fn rpc<T>(
    deadline: Instant,
    action: &str,
    call: impl Future<Output = Result<Response<T>, Status>>,
) -> Result<Response<T>> {
    timeout_at(deadline, call)
        .await
        .with_context(|| {
            format!("{action}: rpc error: code = DeadlineExceeded desc = context deadline exceeded")
        })?
        .map_err(|error| {
            anyhow!(
                "{action}: rpc error: code = {:?} desc = {}",
                error.code(),
                error.message()
            )
        })
}

async fn execute_at(command: ApiCommand, deadline: Instant) -> Result<String> {
    command.validate()?;
    let channel = connect(&command.connection()?.server, deadline).await?;
    let mut client = StatsServiceClient::new(channel.clone());
    let value = match command {
        ApiCommand::Stats(args) => {
            let response = rpc(
                deadline,
                "failed to get stats",
                client.get_stats(request(
                    wire::GetStatsRequest {
                        name: args.name,
                        reset: args.reset,
                    },
                    deadline,
                )?),
            )
            .await?;
            stat_response(response.into_inner())
        }
        ApiCommand::StatsQuery(args) => {
            let response = rpc(
                deadline,
                "failed to query stats",
                client.query_stats(request(
                    wire::QueryStatsRequest {
                        pattern: args.pattern,
                        reset: args.reset,
                    },
                    deadline,
                )?),
            )
            .await?;
            query_response(response.into_inner())
        }
        ApiCommand::StatsSys(_) => {
            let response = rpc(
                deadline,
                "failed to get sys stats",
                client.get_sys_stats(request(wire::SysStatsRequest {}, deadline)?),
            )
            .await?;
            system_response(response)
        }
        ApiCommand::StatsOnline(args) => {
            let response = rpc(
                deadline,
                "failed to get stats",
                client.get_stats_online(request(
                    wire::GetStatsRequest {
                        name: online_name(&args.email),
                        reset: false,
                    },
                    deadline,
                )?),
            )
            .await?;
            stat_response(response.into_inner())
        }
        ApiCommand::StatsOnlineIpList(args) if args.all => {
            let response = rpc(
                deadline,
                "failed to get stats",
                client.get_users_stats(request(
                    wire::GetUsersStatsRequest {
                        include_traffic: args.include_traffic,
                        reset: args.reset,
                    },
                    deadline,
                )?),
            )
            .await?;
            users_response(response.into_inner())
        }
        ApiCommand::StatsOnlineIpList(args) => {
            // The source ignores include-traffic/reset in single-user mode.
            let response = rpc(
                deadline,
                "failed to get stats",
                client.get_stats_online_ip_list(request(
                    wire::GetStatsRequest {
                        name: online_name(&args.email),
                        reset: false,
                    },
                    deadline,
                )?),
            )
            .await?;
            online_ips_response(response.into_inner())
        }
        ApiCommand::StatsGetAllOnlineUsers(_) => {
            let response = rpc(
                deadline,
                "failed to get stats",
                client.get_all_online_users(request(wire::GetAllOnlineUsersRequest {}, deadline)?),
            )
            .await?;
            all_users_response(response.into_inner())
        }
        ApiCommand::RestartLogger(_) => {
            let mut client = LoggerServiceClient::new(channel);
            rpc(
                deadline,
                "failed to restart logger",
                client.restart_logger(request(RestartLoggerRequest {}, deadline)?),
            )
            .await?;
            object(BTreeMap::new())
        }
        ApiCommand::ListRules(_) => {
            let mut client = RoutingServiceClient::new(channel);
            let response = rpc(
                deadline,
                "failed to perform ListRule",
                client.list_rule(request(ListRuleRequest {}, deadline)?),
            )
            .await?;
            let rules: Vec<Value> = response
                .into_inner()
                .rules
                .into_iter()
                .map(|rule| {
                    object(BTreeMap::from([
                        ("tag".to_owned(), Value::String(rule.tag)),
                        ("ruleTag".to_owned(), Value::String(rule.rule_tag)),
                    ]))
                })
                .collect();
            Value::Array(rules)
        }
        ApiCommand::RemoveRules(args) => {
            let mut client = RoutingServiceClient::new(channel);
            for rule_tag in args.rule_tags {
                rpc(
                    deadline,
                    "failed to perform RemoveRule",
                    client.remove_rule(request(RemoveRuleRequest { rule_tag }, deadline)?),
                )
                .await?;
            }
            object(BTreeMap::new())
        }
        ApiCommand::AddRules(args) => {
            let mut client = RoutingServiceClient::new(channel);
            let mut added = 0usize;
            for config_path in &args.configs {
                let raw = if config_path == "-" {
                    use std::io::Read;
                    let mut buffer = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buffer)
                        .context("cannot read the rule configuration from stdin")?;
                    buffer
                } else {
                    std::fs::read_to_string(config_path).with_context(|| {
                        format!("cannot read the rule configuration {config_path}")
                    })?
                };
                let document: serde_json::Value = serde_json::from_str(&raw)
                    .with_context(|| format!("invalid rule configuration {config_path}"))?;
                let routing = document
                    .get("routing")
                    .context("failed to add routing rule: config did not have \"routing\" field")?;
                let rules = routing
                    .get("rules")
                    .and_then(|rules| rules.as_array())
                    .context("the routing field carries no rules")?;
                for rule in rules {
                    let typed = rule_to_typed_message(rule)
                        .with_context(|| format!("invalid rule in {config_path}"))?;
                    rpc(
                        deadline,
                        "failed to perform AddRule",
                        client.add_rule(request(
                            AddRuleRequest {
                                config: Some(typed),
                                should_append: args.append,
                            },
                            deadline,
                        )?),
                    )
                    .await?;
                    added += 1;
                }
            }
            let _ = added;
            object(BTreeMap::new())
        }
        ApiCommand::AddInbounds(args) => {
            use xray_proto::xray::app::proxyman::command::{
                AddInboundRequest, handler_service_client::HandlerServiceClient,
            };
            let mut client = HandlerServiceClient::new(channel);
            for config_path in &args.configs {
                let inbounds = read_inbounds(config_path)?;
                for inbound in inbounds {
                    let handler = inbound_to_handler(&inbound)
                        .with_context(|| format!("invalid inbound in {config_path}"))?;
                    rpc(
                        deadline,
                        "failed to perform AddInbound",
                        client.add_inbound(request(
                            AddInboundRequest {
                                inbound: Some(handler),
                            },
                            deadline,
                        )?),
                    )
                    .await?;
                }
            }
            object(BTreeMap::new())
        }
        ApiCommand::RemoveInbounds(args) => {
            use xray_proto::xray::app::proxyman::command::{
                RemoveInboundRequest, handler_service_client::HandlerServiceClient,
            };
            let mut client = HandlerServiceClient::new(channel);
            for target in &args.targets {
                // A readable config file contributes its inbound tags; every
                // other argument is a tag itself, exactly like the source.
                let tags = match std::fs::read_to_string(target) {
                    Ok(raw) => serde_json::from_str::<Value>(&raw)
                        .with_context(|| format!("invalid inbound configuration {target}"))?
                        .get("inbounds")
                        .and_then(|inbounds| inbounds.as_array())
                        .map(|inbounds| {
                            inbounds
                                .iter()
                                .filter_map(|inbound| {
                                    inbound.get("tag").and_then(|tag| tag.as_str())
                                })
                                .map(str::to_owned)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    Err(_) => vec![target.clone()],
                };
                for tag in tags {
                    rpc(
                        deadline,
                        "failed to perform RemoveInbound",
                        client.remove_inbound(request(RemoveInboundRequest { tag }, deadline)?),
                    )
                    .await?;
                }
            }
            object(BTreeMap::new())
        }
        ApiCommand::ListInbounds(args) => {
            use xray_proto::xray::app::proxyman::command::{
                ListInboundsRequest, handler_service_client::HandlerServiceClient,
            };
            let mut client = HandlerServiceClient::new(channel);
            let response = rpc(
                deadline,
                "failed to perform ListInbounds",
                client.list_inbounds(request(
                    ListInboundsRequest {
                        is_only_tags: args.is_only_tags,
                    },
                    deadline,
                )?),
            )
            .await?;
            let inbounds = response
                .into_inner()
                .inbounds
                .into_iter()
                .map(|inbound| {
                    object({
                        let mut fields = Object::new();
                        text(&mut fields, "tag", inbound.tag);
                        fields
                    })
                })
                .collect::<Vec<_>>();
            object({
                let mut fields = Object::new();
                fields.insert("inbounds".into(), Value::Array(inbounds));
                fields
            })
        }
        ApiCommand::InboundUser(args) => {
            use xray_proto::xray::app::proxyman::command::{
                GetInboundUserRequest, handler_service_client::HandlerServiceClient,
            };
            let mut client = HandlerServiceClient::new(channel);
            let response = rpc(
                deadline,
                "failed to get inbound user",
                client.get_inbound_users(request(
                    GetInboundUserRequest {
                        tag: args.tag,
                        email: args.email,
                    },
                    deadline,
                )?),
            )
            .await?;
            // The response prints like Go's showJSONResponse: the user list.
            let users = response
                .into_inner()
                .users
                .into_iter()
                .map(|user| {
                    object({
                        let mut fields = Object::new();
                        text(&mut fields, "email", user.email);
                        number(&mut fields, "level", i64::from(user.level));
                        if let Some(account) = user.account {
                            fields.insert(
                                "account".into(),
                                object({
                                    let mut account_fields = Object::new();
                                    text(&mut account_fields, "type", account.r#type);
                                    account_fields
                                }),
                            );
                        }
                        fields
                    })
                })
                .collect::<Vec<_>>();
            object({
                let mut fields = Object::new();
                fields.insert("users".into(), Value::Array(users));
                fields
            })
        }
        ApiCommand::InboundUserCount(args) => {
            use xray_proto::xray::app::proxyman::command::{
                GetInboundUserRequest, handler_service_client::HandlerServiceClient,
            };
            let mut client = HandlerServiceClient::new(channel);
            let response = rpc(
                deadline,
                "failed to get inbound user count",
                client.get_inbound_users_count(request(
                    GetInboundUserRequest {
                        tag: args.tag,
                        email: String::new(),
                    },
                    deadline,
                )?),
            )
            .await?;
            object({
                let mut fields = Object::new();
                number(&mut fields, "count", response.into_inner().count);
                fields
            })
        }
        ApiCommand::Unsupported(_) => unreachable!("validated before connecting"),
    };
    format_json(value)
}

fn online_name(email: &str) -> String {
    format!("user>>>{email}>>>online")
}

type Object = BTreeMap<String, Value>;

fn object(fields: Object) -> Value {
    Value::Object(fields.into_iter().collect())
}

fn text(fields: &mut Object, name: &str, value: String) {
    if !value.is_empty() {
        fields.insert(name.into(), Value::String(value));
    }
}

fn number(fields: &mut Object, name: &str, value: i64) {
    if value != 0 {
        fields.insert(name.into(), value.into());
    }
}

fn stat(value: wire::Stat) -> Value {
    let mut fields = Object::new();
    text(&mut fields, "name", value.name);
    number(&mut fields, "value", value.value);
    object(fields)
}

fn stat_response(value: wire::GetStatsResponse) -> Value {
    let mut fields = Object::new();
    if let Some(value) = value.stat {
        fields.insert("stat".into(), stat(value));
    }
    object(fields)
}

fn query_response(mut value: wire::QueryStatsResponse) -> Value {
    let mut fields = Object::new();
    if !value.stat.is_empty() {
        // Source counter iteration can be map-ordered. A stable sort does not
        // change the entries and makes native command output reproducible.
        value
            .stat
            .sort_by(|a, b| a.name.cmp(&b.name).then(a.value.cmp(&b.value)));
        fields.insert(
            "stat".into(),
            Value::Array(value.stat.into_iter().map(stat).collect()),
        );
    }
    object(fields)
}

fn online_ips_response(value: wire::GetStatsOnlineIpListResponse) -> Value {
    let mut fields = Object::new();
    text(&mut fields, "name", value.name);
    if !value.ips.is_empty() {
        fields.insert(
            "ips".into(),
            object(
                value
                    .ips
                    .into_iter()
                    .map(|(ip, seen)| (ip, seen.into()))
                    .collect(),
            ),
        );
    }
    object(fields)
}

fn all_users_response(mut value: wire::GetAllOnlineUsersResponse) -> Value {
    let mut fields = Object::new();
    if !value.users.is_empty() {
        value.users.sort();
        fields.insert(
            "users".into(),
            Value::Array(value.users.into_iter().map(Value::String).collect()),
        );
    }
    object(fields)
}

fn users_response(mut value: wire::GetUsersStatsResponse) -> Value {
    let mut fields = Object::new();
    if !value.users.is_empty() {
        value.users.sort_by(|a, b| a.email.cmp(&b.email));
        let users = value
            .users
            .into_iter()
            .map(|mut user| {
                let mut fields = Object::new();
                text(&mut fields, "email", user.email);
                if !user.ips.is_empty() {
                    user.ips
                        .sort_by(|a, b| a.ip.cmp(&b.ip).then(a.last_seen.cmp(&b.last_seen)));
                    let ips = user
                        .ips
                        .into_iter()
                        .map(|ip| {
                            let mut fields = Object::new();
                            text(&mut fields, "ip", ip.ip);
                            number(&mut fields, "lastSeen", ip.last_seen);
                            object(fields)
                        })
                        .collect();
                    fields.insert("ips".into(), Value::Array(ips));
                }
                if let Some(traffic) = user.traffic {
                    let mut values = Object::new();
                    number(&mut values, "uplink", traffic.uplink);
                    number(&mut values, "downlink", traffic.downlink);
                    fields.insert("traffic".into(), object(values));
                }
                object(fields)
            })
            .collect();
        fields.insert("users".into(), Value::Array(users));
    }
    object(fields)
}

fn runtime_metadata(metadata: &MetadataMap) -> Option<Value> {
    let mut fields = Object::new();
    for (header, name) in [
        ("x-xray-system-stats-provider", "provider"),
        ("x-xray-num-goroutine-kind", "numGoroutineKind"),
    ] {
        if let Some(value) = metadata.get(header).and_then(|value| value.to_str().ok()) {
            text(&mut fields, name, value.to_owned());
        }
    }
    if let Some(value) = metadata
        .get("x-xray-unsupported-fields")
        .and_then(|value| value.to_str().ok())
    {
        let mut names: Vec<_> = value
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        names.sort();
        names.dedup();
        fields.insert(
            "unavailableFields".into(),
            Value::Array(names.into_iter().map(Value::String).collect()),
        );
    }
    (!fields.is_empty()).then(|| object(fields))
}

fn system_response(response: Response<wire::SysStatsResponse>) -> Value {
    let mut fields = Object::new();
    if let Some(metadata) = runtime_metadata(response.metadata()) {
        fields.insert("_runtime".into(), metadata);
    }
    let value = response.into_inner();
    for (name, value) in [
        ("NumGoroutine", u64::from(value.num_goroutine)),
        ("NumGC", u64::from(value.num_gc)),
        ("Alloc", value.alloc),
        ("TotalAlloc", value.total_alloc),
        ("Sys", value.sys),
        ("Mallocs", value.mallocs),
        ("Frees", value.frees),
        ("LiveObjects", value.live_objects),
        ("PauseTotalNs", value.pause_total_ns),
        ("Uptime", u64::from(value.uptime)),
    ] {
        if value != 0 {
            fields.insert(name.into(), value.into());
        }
    }
    object(fields)
}

fn format_json(value: Value) -> Result<String> {
    // serde_json's public pretty helper uses two spaces. Doubling only the
    // leading indentation preserves all JSON string escaping and values.
    let pretty = serde_json::to_string_pretty(&value)?;
    let mut output = String::new();
    for line in pretty.lines() {
        let spaces = line.bytes().take_while(|byte| *byte == b' ').count();
        output.extend(std::iter::repeat_n(' ', spaces));
        output.push_str(line);
        output.push('\n');
    }
    output.push('\n');
    // Go's encoding/json escapes these two JavaScript line separators even
    // with SetEscapeHTML(false); '<', '>' and '&' remain literal.
    Ok(output
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

// ---------------------------------------------------------------------------
// The AddInbound encoder: the startup inbound JSON surface back into the
// InboundHandlerConfig wire shape, mirroring the decoder's coverage exactly
// (plain TCP or TLS receivers, and the protocols the decoder carries).
// ---------------------------------------------------------------------------

/// Read one config file (or `-` for stdin) and return its `inbounds` array.
fn read_inbounds(config_path: &str) -> Result<Vec<Value>> {
    let raw = if config_path == "-" {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("cannot read the inbound configuration from stdin")?;
        buffer
    } else {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("cannot read the inbound configuration {config_path}"))?
    };
    let document: Value = serde_json::from_str(&raw)
        .with_context(|| format!("invalid inbound configuration {config_path}"))?;
    document
        .get("inbounds")
        .and_then(|inbounds| inbounds.as_array())
        .cloned()
        .context("the configuration carries no inbounds")
}

/// One PEM block's DER bytes from a list of JSON certificate lines.
fn pem_der(lines: &[String], label: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let text: String = lines.concat();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .with_context(|| format!("no {label} PEM block"))?;
    let body_start = start + begin.len();
    let stop = text[body_start..]
        .find(&end)
        .map(|offset| offset + body_start)
        .with_context(|| format!("unterminated {label} PEM block"))?;
    let body: String = text[body_start..stop]
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    STANDARD
        .decode(body)
        .with_context(|| format!("invalid base64 in the {label} PEM block"))
}

/// Encode one inbound (the startup JSON surface) into the AddInbound wire
/// shape. Everything the decoder cannot carry fails by name here, so the
/// command never silently downgrades a configuration.
fn inbound_to_handler(inbound: &Value) -> Result<xray_proto::xray::core::InboundHandlerConfig> {
    use xray_proto::xray::{
        app::proxyman::ReceiverConfig,
        common::net::{IpOrDomain, PortList, PortRange, ip_or_domain},
        transport::internet::{StreamConfig, TransportConfig, tls},
    };

    let tag = inbound
        .get("tag")
        .and_then(|tag| tag.as_str())
        .unwrap_or_default()
        .to_owned();
    // The receiver: one port, one IP listen address, a plain TCP or TLS
    // stream — the decoder's exact coverage.
    let port = inbound.get("port").and_then(|port| port.as_u64());
    let Some(port) = port else {
        bail!("the adi encoder requires a single numeric \"port\"");
    };
    ensure!(
        (1..=65535).contains(&port),
        "the inbound port {port} is out of range"
    );
    let listen = inbound
        .get("listen")
        .and_then(|listen| listen.as_str())
        .unwrap_or("0.0.0.0");
    let listen_ip: std::net::IpAddr = listen
        .parse()
        .with_context(|| format!("the adi encoder requires an IP \"listen\", got {listen:?}"))?;
    let stream_settings = inbound.get("streamSettings").cloned().unwrap_or_default();
    let network = stream_settings
        .get("network")
        .and_then(|network| network.as_str())
        .unwrap_or("tcp");
    ensure!(
        matches!(network, "" | "tcp" | "raw"),
        "the adi encoder supports the plain TCP transport, got {network:?}"
    );
    let security = stream_settings
        .get("security")
        .and_then(|security| security.as_str())
        .unwrap_or("");
    let mut stream = StreamConfig {
        protocol_name: "tcp".to_owned(),
        transport_settings: vec![TransportConfig {
            protocol_name: "tcp".to_owned(),
            settings: Some(typed_of(
                &xray_proto::xray::transport::internet::tcp::Config::default(),
            )),
        }],
        ..Default::default()
    };
    match security {
        "" | "none" => (),
        "tls" => {
            let tls_settings = stream_settings
                .get("tlsSettings")
                .cloned()
                .unwrap_or_default();
            let mut config = tls::Config::default();
            if let Some(certificates) = tls_settings
                .get("certificates")
                .and_then(|certificates| certificates.as_array())
            {
                for certificate in certificates {
                    let lines = |key: &str| -> Vec<String> {
                        match certificate.get(key) {
                            Some(Value::Array(lines)) => lines
                                .iter()
                                .filter_map(|line| line.as_str().map(str::to_owned))
                                .collect(),
                            Some(Value::String(text)) => text.lines().map(str::to_owned).collect(),
                            _ => Vec::new(),
                        }
                    };
                    config.certificate.push(tls::Certificate {
                        certificate: pem_der(&lines("certificate"), "CERTIFICATE")?,
                        key: pem_der(&lines("key"), "PRIVATE KEY")?,
                        ..Default::default()
                    });
                }
            }
            // The remaining TLS keys the proto carries; anything else on the
            // JSON surface fails by name instead of silently dropping.
            for (json_key, unsupported) in [
                ("serverName", false),
                ("fingerprint", true),
                ("certificateFile", true),
                ("keyFile", true),
                ("ocspStapling", false),
                ("oneTimeLoading", false),
                ("buildChain", false),
                ("pinnedPeerCertSha256", true),
                ("verifyPeerCertByNam", true),
                ("echServerKeys", true),
                ("echConfigList", true),
                ("echSockopt", true),
            ] {
                if unsupported && let Some(value) = tls_settings.get(json_key) {
                    ensure!(
                        value.is_null()
                            || value.as_str().is_some_and(str::is_empty)
                            || value.as_bool() == Some(false)
                            || value.as_array().is_some_and(Vec::is_empty),
                        "the adi encoder does not carry tlsSettings {json_key:?}"
                    );
                }
            }
            let string_list = |key: &str| -> Vec<String> {
                match tls_settings.get(key) {
                    Some(Value::Array(items)) => items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect(),
                    Some(Value::String(text)) => vec![text.clone()],
                    _ => Vec::new(),
                }
            };
            config.server_name = tls_settings
                .get("serverName")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            config.next_protocol = string_list("alpn");
            config.curve_preferences = string_list("curvePreferences");
            config.reject_unknown_sni = tls_settings
                .get("rejectUnknownSni")
                .and_then(|value| value.as_bool())
                .unwrap_or_default();
            config.disable_system_root = tls_settings
                .get("disableSystemRoot")
                .and_then(|value| value.as_bool())
                .unwrap_or_default();
            config.enable_session_resumption = tls_settings
                .get("enableSessionResumption")
                .and_then(|value| value.as_bool())
                .unwrap_or_default();
            config.min_version = tls_settings
                .get("minVersion")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            config.max_version = tls_settings
                .get("maxVersion")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            config.cipher_suites = tls_settings
                .get("cipherSuites")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            config.master_key_log = tls_settings
                .get("masterKeyLog")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            stream.security_type = "xray.transport.internet.tls.Config".to_owned();
            stream.security_settings = vec![typed_of(&config)];
        }
        other => bail!("the adi encoder supports security none/tls, got {other:?}"),
    }
    let receiver = ReceiverConfig {
        port_list: Some(PortList {
            range: vec![PortRange {
                from: port as u32,
                to: port as u32,
            }],
        }),
        listen: Some(IpOrDomain {
            address: Some(ip_or_domain::Address::Ip(match listen_ip {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            })),
        }),
        stream_settings: Some(stream),
        ..Default::default()
    };

    // The proxy settings: the protocols the decoder carries, encoded back
    // from the same JSON keys.
    let settings = inbound.get("settings").cloned().unwrap_or_default();
    let protocol = inbound
        .get("protocol")
        .and_then(|protocol| protocol.as_str())
        .unwrap_or_default();
    let proxy = proxy_settings(protocol, &settings)?;
    Ok(xray_proto::xray::core::InboundHandlerConfig {
        tag,
        receiver_settings: Some(typed_of(&receiver)),
        proxy_settings: Some(proxy),
    })
}

/// One proto message as a TypedMessage (the encoder twin of the decoder's
/// `unpack`).
fn typed_of<M: prost::Message + prost::Name>(
    message: &M,
) -> xray_proto::xray::common::serial::TypedMessage {
    xray_proto::xray::common::serial::TypedMessage {
        // prost's Name::type_url() prefixes a slash; Go's TypedMessage
        // carries the bare type name (the decoder trims the same way).
        r#type: M::type_url().trim_start_matches('/').to_owned(),
        value: message.encode_to_vec(),
    }
}

/// The per-protocol proxy settings encoder: the decoder's supported set,
/// encoded back from the same JSON keys. Anything outside fails by name.
fn proxy_settings(
    protocol: &str,
    settings: &Value,
) -> Result<xray_proto::xray::common::serial::TypedMessage> {
    use xray_proto::xray::common::net::{IpOrDomain, ip_or_domain};
    use xray_proto::xray::common::protocol::User;
    let string = |value: &Value, key: &str| -> String {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let number = |value: &Value, key: &str| -> u64 {
        value.get(key).and_then(|v| v.as_u64()).unwrap_or_default()
    };
    let flag = |value: &Value, key: &str| -> bool {
        value.get(key).and_then(|v| v.as_bool()).unwrap_or_default()
    };
    // The IPOrDomain encoder the address fields share: an IP stays an IP, a
    // non-empty text becomes a domain, and empty stays empty.
    let ip_or_domain_of = |text: &str| -> IpOrDomain {
        IpOrDomain {
            address: Some(match text.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => ip_or_domain::Address::Ip(ip.octets().to_vec()),
                Ok(std::net::IpAddr::V6(ip)) => ip_or_domain::Address::Ip(ip.octets().to_vec()),
                Err(_) if !text.is_empty() => ip_or_domain::Address::Domain(text.to_owned()),
                Err(_) => ip_or_domain::Address::Ip(Vec::new()),
            }),
        }
    };
    let clients = |settings: &Value| -> Vec<Value> {
        settings
            .get("clients")
            .or_else(|| settings.get("users"))
            .and_then(|users| users.as_array())
            .cloned()
            .unwrap_or_default()
    };
    let user = |value: &Value| -> Result<User> {
        Ok(User {
            email: string(value, "email"),
            level: number(value, "level") as u32,
            account: Some(account_settings(protocol, value)?),
        })
    };
    match protocol {
        "socks" => {
            let auth = settings
                .get("auth")
                .and_then(|auth| auth.as_str())
                .unwrap_or("noauth");
            let auth_type = match auth {
                "noauth" => xray_proto::xray::proxy::socks::AuthType::NoAuth as i32,
                "password" => xray_proto::xray::proxy::socks::AuthType::Password as i32,
                other => bail!("the adi encoder cannot carry SOCKS auth {other:?}"),
            };
            let mut accounts = std::collections::HashMap::new();
            for account in settings
                .get("accounts")
                .and_then(|accounts| accounts.as_array())
                .unwrap_or(&Vec::new())
            {
                accounts.insert(string(account, "user"), string(account, "pass"));
            }
            let config = xray_proto::xray::proxy::socks::ServerConfig {
                auth_type,
                accounts,
                udp_enabled: flag(settings, "udp"),
                address: settings
                    .get("ip")
                    .and_then(|ip| ip.as_str())
                    .map(ip_or_domain_of),
                ..Default::default()
            };
            Ok(typed_of(&config))
        }
        "http" => {
            let mut accounts = std::collections::HashMap::new();
            for account in settings
                .get("accounts")
                .and_then(|accounts| accounts.as_array())
                .unwrap_or(&Vec::new())
            {
                accounts.insert(string(account, "user"), string(account, "pass"));
            }
            let config = xray_proto::xray::proxy::http::ServerConfig {
                accounts,
                allow_transparent: flag(settings, "allowTransparent"),
                user_level: number(settings, "userLevel") as u32,
            };
            Ok(typed_of(&config))
        }
        "dokodemo-door" | "tunnel" => {
            let network = settings
                .get("network")
                .or_else(|| settings.get("allowedNetworks"))
                .and_then(|network| network.as_str())
                .unwrap_or("tcp");
            let allowed_networks = match network {
                "tcp" => vec![2],
                "tcp,udp" => vec![2, 3],
                other => bail!("the adi encoder cannot carry dokodemo network {other:?}"),
            };
            let config = xray_proto::xray::proxy::dokodemo::Config {
                rewrite_address: Some(ip_or_domain_of(&string(settings, "address"))),
                rewrite_port: number(settings, "port") as u32,
                follow_redirect: flag(settings, "followRedirect"),
                user_level: number(settings, "userLevel") as u32,
                allowed_networks,
                ..Default::default()
            };
            Ok(typed_of(&config))
        }
        "vless" => {
            let mut users = Vec::new();
            for client in &clients(settings) {
                users.push(user(client)?);
            }
            let decryption = settings
                .get("decryption")
                .and_then(|decryption| decryption.as_str())
                .unwrap_or("none");
            ensure!(
                decryption == "none" || decryption.starts_with("mlkem"),
                "the adi encoder cannot carry VLESS decryption {decryption:?}"
            );
            let config = xray_proto::xray::proxy::vless::inbound::Config {
                users,
                decryption: decryption.to_owned(),
                ..Default::default()
            };
            Ok(typed_of(&config))
        }
        "vmess" => {
            let mut users = Vec::new();
            for client in &clients(settings) {
                ensure!(
                    number(client, "alterId") == 0 && string(client, "experiments").is_empty(),
                    "the adi encoder cannot carry VMess legacy accounts"
                );
                users.push(user(client)?);
            }
            let config = xray_proto::xray::proxy::vmess::inbound::Config {
                user: users,
                default: settings.get("default").map(|default| {
                    xray_proto::xray::proxy::vmess::inbound::DefaultConfig {
                        level: number(default, "level") as u32,
                    }
                }),
            };
            Ok(typed_of(&config))
        }
        "trojan" => {
            let mut users = Vec::new();
            for client in &clients(settings) {
                users.push(user(client)?);
            }
            let config = xray_proto::xray::proxy::trojan::ServerConfig {
                users,
                ..Default::default()
            };
            Ok(typed_of(&config))
        }
        "shadowsocks" => {
            // The 2022 single-key settings travel whole; legacy AEAD carries
            // its one account (the decoder's exact supported shape).
            let method = string(settings, "method");
            if method.starts_with("2022-") {
                let network = settings
                    .get("network")
                    .and_then(|network| network.as_str())
                    .unwrap_or("tcp");
                let networks = match network {
                    "tcp" => vec![2],
                    "tcp,udp" => vec![2, 3],
                    other => bail!("the adi encoder cannot carry network {other:?}"),
                };
                let config = xray_proto::xray::proxy::shadowsocks_2022::ServerConfig {
                    method: method.clone(),
                    key: string(settings, "password"),
                    email: string(settings, "email"),
                    level: number(settings, "level") as i32,
                    network: networks,
                };
                return Ok(typed_of(&config));
            }
            // A single inline account or one clients entry.
            let client = clients(settings)
                .first()
                .cloned()
                .unwrap_or_else(|| settings.clone());
            let cipher = match string(&client, "method").as_str() {
                "aes-128-gcm" => 5,
                "aes-256-gcm" => 6,
                "chacha20-ietf-poly1305" => 7,
                other => bail!("the adi encoder cannot carry cipher {other:?}"),
            };
            let account = xray_proto::xray::proxy::shadowsocks::Account {
                cipher_type: cipher,
                password: string(&client, "password"),
                ..Default::default()
            };
            let config = xray_proto::xray::proxy::shadowsocks::ServerConfig {
                users: vec![User {
                    email: string(&client, "email"),
                    level: number(&client, "level") as u32,
                    account: Some(typed_of(&account)),
                }],
                network: vec![2],
            };
            Ok(typed_of(&config))
        }
        other => bail!("the adi encoder does not carry protocol {other:?}"),
    }
}

/// The per-protocol account TypedMessage inside one user record.
fn account_settings(
    protocol: &str,
    client: &Value,
) -> Result<xray_proto::xray::common::serial::TypedMessage> {
    let string = |key: &str| -> String {
        client
            .get(key)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    match protocol {
        "vless" => Ok(typed_of(&xray_proto::xray::proxy::vless::Account {
            id: string("id"),
            flow: string("flow"),
            ..Default::default()
        })),
        "vmess" => {
            let security = match string("security").to_ascii_lowercase().as_str() {
                "" | "auto" => 2,
                "aes-128-gcm" => 3,
                "chacha20-poly1305" => 4,
                other => bail!("the adi encoder cannot carry VMess security {other:?}"),
            };
            Ok(typed_of(&xray_proto::xray::proxy::vmess::Account {
                id: string("id"),
                security_settings: Some(xray_proto::xray::common::protocol::SecurityConfig {
                    r#type: security,
                }),
                tests_enabled: String::new(),
            }))
        }
        "trojan" => Ok(typed_of(&xray_proto::xray::proxy::trojan::Account {
            password: string("password"),
        })),
        other => bail!("the adi encoder does not carry {other:?} accounts"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context as TaskContext, Poll},
    };

    use clap::Parser;
    use tonic::{
        body::Body,
        codegen::{Service, http},
        server::NamedService,
        service::Routes,
    };
    use xray_core::{
        api::{
            ApiServer, LoggerService, RunningApiServer, StatsService, SystemStatsProvider,
            SystemStatsSnapshot, add_logger_routes, stats_routes,
        },
        features::StatsManager,
        logging::{LogDestination, Logger, LoggerOptions},
    };

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ApiCommand,
    }

    #[test]
    fn clap_preserves_command_names_shared_flags_and_boolean_forms() {
        for name in [
            "stats",
            "statsquery",
            "statssys",
            "statsonline",
            "statsgetallonlineusers",
            "restartlogger",
            "lsi",
            "inbounduser",
            "inboundusercount",
        ] {
            let command = TestCli::try_parse_from(["api", name]).unwrap().command;
            let args = command.connection().unwrap();
            assert_eq!(args.server, "127.0.0.1:8080");
            assert_eq!(args.timeout, 3);
            assert!(!args.json);
        }
        // adi/rmi take required file/tag arguments like the source commands.
        let command = TestCli::try_parse_from(["api", "adi", "inbounds.json"])
            .unwrap()
            .command;
        assert!(matches!(command, ApiCommand::AddInbounds(_)));
        let command = TestCli::try_parse_from(["api", "rmi", "a-tag"])
            .unwrap()
            .command;
        assert!(matches!(command, ApiCommand::RemoveInbounds(_)));
        let cli = TestCli::try_parse_from([
            "api",
            "stats",
            "-s",
            "localhost:9000",
            "-t",
            "7",
            "--name",
            "counter",
            "--reset=true",
            "--json=false",
        ])
        .unwrap();
        let ApiCommand::Stats(args) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.name, "counter");
        assert!(args.reset);
        assert_eq!(args.connection.server, "localhost:9000");
        assert_eq!(args.connection.timeout, 7);
        assert!(!args.connection.json);
        let command = TestCli::try_parse_from([
            "api",
            "statsonlineiplist",
            "--all",
            "--include-traffic",
            "--reset",
        ])
        .unwrap()
        .command;
        assert!(command.validate().is_ok());
        assert!(TestCli::try_parse_from(["api", "stats", "--bogus"]).is_err());
    }

    #[test]
    fn online_modes_and_unimplemented_service_commands_fail_before_dialing() {
        let single = OnlineIpArgs {
            connection: ConnectionArgs::default(),
            email: String::new(),
            all: false,
            include_traffic: false,
            reset: false,
        };
        assert_eq!(
            ApiCommand::StatsOnlineIpList(single.clone())
                .validate()
                .unwrap_err()
                .to_string(),
            "either -all or -email must be specified"
        );
        assert_eq!(
            ApiCommand::StatsOnlineIpList(OnlineIpArgs {
                all: true,
                email: "a".into(),
                ..single
            })
            .validate()
            .unwrap_err()
            .to_string(),
            "-all and -email are mutually exclusive"
        );
        for (name, expected) in [
            ("ado", "HandlerService"),
            ("bi", "RoutingService"),
            ("observatory", "real observation provider"),
        ] {
            let command = TestCli::try_parse_from(["api", name, "--server=not-a-server"])
                .unwrap()
                .command;
            assert!(
                command
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
        }
        assert!(endpoint("https://example.com:443").is_err());
        assert!(endpoint("unix:///tmp/xray.sock").is_err());
        assert!(endpoint("http://example.com:80/path").is_err());
        assert!(endpoint("127.0.0.1:8080").is_ok());
        assert!(endpoint("dns:///localhost:8080").is_ok());
        assert!(endpoint("[::1]:8080").is_ok());
    }

    #[test]
    fn reflection_json_golden_fields_indentation_integers_and_blank_line() {
        let value = stat_response(wire::GetStatsResponse {
            stat: Some(wire::Stat {
                name: "user>>>a&b>>>traffic>>>uplink".into(),
                value: i64::MIN,
            }),
        });
        assert_eq!(
            format_json(value).unwrap(),
            "{\n    \"stat\": {\n        \"name\": \"user>>>a&b>>>traffic>>>uplink\",\n        \"value\": -9223372036854775808\n    }\n}\n\n"
        );
        assert_eq!(
            format_json(stat_response(wire::GetStatsResponse {
                stat: Some(wire::Stat::default())
            }))
            .unwrap(),
            "{\n    \"stat\": {}\n}\n\n"
        );
        assert_eq!(
            format_json(stat_response(wire::GetStatsResponse::default())).unwrap(),
            "{}\n\n"
        );
        assert_eq!(
            format_json(query_response(wire::QueryStatsResponse::default())).unwrap(),
            "{}\n\n"
        );
        let value = stat_response(wire::GetStatsResponse {
            stat: Some(wire::Stat {
                name: "<a>\u{2028}\u{2029}".into(),
                value: 0,
            }),
        });
        let output = format_json(value).unwrap();
        assert!(output.contains("<a>\\u2028\\u2029"));
        assert!(!output.contains("value"));
    }

    #[test]
    fn user_ip_and_system_formatters_preserve_field_case_and_units() {
        let value = users_response(wire::GetUsersStatsResponse {
            users: vec![wire::UserStat {
                email: "test@example.com".into(),
                ips: vec![wire::OnlineIpEntry {
                    ip: "192.0.2.1".into(),
                    last_seen: 1_800_000_001,
                }],
                traffic: Some(wire::TrafficUserStat {
                    uplink: 0,
                    downlink: i64::MAX,
                }),
            }],
        });
        assert_eq!(value["users"][0]["ips"][0]["lastSeen"], 1_800_000_001_i64);
        assert_eq!(value["users"][0]["traffic"]["downlink"], i64::MAX);
        assert!(value["users"][0]["traffic"].get("uplink").is_none());
        let output = format_json(system_response(Response::new(wire::SysStatsResponse {
            alloc: u64::MAX,
            num_goroutine: 7,
            pause_total_ns: 12,
            ..Default::default()
        })))
        .unwrap();
        assert_eq!(
            output,
            "{\n    \"Alloc\": 18446744073709551615,\n    \"NumGoroutine\": 7,\n    \"PauseTotalNs\": 12\n}\n\n"
        );
        let mut response = Response::new(wire::SysStatsResponse::default());
        response.metadata_mut().insert(
            "x-xray-system-stats-provider",
            "rust-tokio".parse().unwrap(),
        );
        response
            .metadata_mut()
            .insert("x-xray-num-goroutine-kind", "tokio-tasks".parse().unwrap());
        response.metadata_mut().insert(
            "x-xray-unsupported-fields",
            "sys,alloc,sys".parse().unwrap(),
        );
        let output = system_response(response);
        assert_eq!(output["_runtime"]["provider"], "rust-tokio");
        assert_eq!(output["_runtime"]["numGoroutineKind"], "tokio-tasks");
        assert_eq!(
            output["_runtime"]["unavailableFields"],
            serde_json::json!(["alloc", "sys"])
        );
    }

    #[test]
    fn output_order_is_deterministic_without_losing_empty_list_entries() {
        let value = query_response(wire::QueryStatsResponse {
            stat: vec![
                wire::Stat {
                    name: "z".into(),
                    value: 2,
                },
                wire::Stat {
                    name: "a".into(),
                    value: 1,
                },
            ],
        });
        assert_eq!(value["stat"][0]["name"], "a");
        assert_eq!(value["stat"][1]["name"], "z");
        let value = all_users_response(wire::GetAllOnlineUsersResponse {
            users: vec!["z".into(), "".into(), "a".into()],
        });
        assert_eq!(value["users"], serde_json::json!(["", "a", "z"]));
        let value = online_ips_response(wire::GetStatsOnlineIpListResponse {
            name: String::new(),
            ips: [("".into(), 0), ("192.0.2.1".into(), -1)].into(),
        });
        assert_eq!(value["ips"][""], 0);
        assert_eq!(value["ips"]["192.0.2.1"], -1);
        assert!(value.get("name").is_none());
    }

    struct MeasuredSystem;

    impl SystemStatsProvider for MeasuredSystem {
        fn snapshot(&self) -> Result<SystemStatsSnapshot, Status> {
            Ok(SystemStatsSnapshot {
                num_goroutine: Some(7),
                num_gc: Some(2),
                alloc: Some(11),
                total_alloc: Some(13),
                sys: Some(17),
                mallocs: Some(19),
                frees: Some(3),
                live_objects: Some(16),
                pause_total_ns: Some(23),
            })
        }
        fn name(&self) -> &'static str {
            "test-measurements"
        }
        fn task_kind(&self) -> &'static str {
            "test-tasks"
        }
    }

    async fn start_server() -> (RunningApiServer, ConnectionArgs, Arc<StatsManager>, Logger) {
        let manager = Arc::new(StatsManager::new());
        let logger = Logger::from_options(LoggerOptions {
            access: LogDestination::None,
            error: LogDestination::None,
            ..Default::default()
        })
        .unwrap();
        let routes = add_logger_routes(
            stats_routes(StatsService::with_system_stats(
                manager.clone(),
                Arc::new(MeasuredSystem),
            )),
            LoggerService::new(logger.clone()),
        );
        let server = ApiServer::from_routes(routes)
            .bind_tcp("127.0.0.1:0")
            .await
            .unwrap();
        let connection = ConnectionArgs {
            server: server.local_addr().unwrap().to_string(),
            ..Default::default()
        };
        (server, connection, manager, logger)
    }

    #[tokio::test]
    async fn real_stats_and_query_rpcs_fetch_reset_and_propagate_missing_counter() {
        let (server, connection, manager, _) = start_server().await;
        let counter = manager.get_or_register_counter("literal[ab].counter");
        counter.set(i64::MAX);
        manager.get_or_register_counter("literalacounter").set(91);
        let output = execute(ApiCommand::Stats(StatArgs {
            connection: connection.clone(),
            name: "literal[ab].counter".into(),
            reset: true,
        }))
        .await
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["stat"]["value"], i64::MAX);
        assert_eq!(counter.value(), 0);
        counter.set(31);
        let output = execute(ApiCommand::StatsQuery(QueryArgs {
            connection: connection.clone(),
            pattern: "[ab]".into(),
            reset: true,
        }))
        .await
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["stat"].as_array().unwrap().len(), 1);
        assert_eq!(value["stat"][0]["value"], 31);
        assert_eq!(counter.value(), 0);
        assert_eq!(manager.get_counter("literalacounter").unwrap().value(), 91);
        let error = execute(ApiCommand::Stats(StatArgs {
            connection,
            name: "missing".into(),
            reset: false,
        }))
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains(
                "failed to get stats: rpc error: code = NotFound desc = missing not found."
            )
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn real_online_and_user_rpcs_preserve_source_names_and_reset_scope() {
        let (server, connection, manager, _) = start_server().await;
        let alice = manager.get_or_register_online_map(online_name("alice@example.test"));
        alice.add_ip_at("192.0.2.2", 1_800_000_001);
        alice.add_ip_at("192.0.2.1", 1_800_000_002);
        let active =
            manager.get_or_register_counter("user>>>alice@example.test>>>traffic>>>uplink");
        active.set(37);
        let offline =
            manager.get_or_register_counter("user>>>offline@example.test>>>traffic>>>uplink");
        offline.set(71);
        let output = execute(ApiCommand::StatsOnline(OnlineArgs {
            connection: connection.clone(),
            email: "alice@example.test".into(),
        }))
        .await
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["stat"]["value"], 2);
        assert_eq!(value["stat"]["name"], online_name("alice@example.test"));
        let output = execute(ApiCommand::StatsOnlineIpList(OnlineIpArgs {
            connection: connection.clone(),
            email: "alice@example.test".into(),
            all: false,
            include_traffic: true,
            reset: true,
        }))
        .await
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["ips"]["192.0.2.1"], 1_800_000_002_i64);
        assert_eq!(active.value(), 37); // ignored for a single user, like Go
        let output = execute(ApiCommand::StatsGetAllOnlineUsers(connection.clone()))
            .await
            .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            value["users"],
            serde_json::json!([online_name("alice@example.test")])
        );
        let output = execute(ApiCommand::StatsOnlineIpList(OnlineIpArgs {
            connection,
            email: String::new(),
            all: true,
            include_traffic: true,
            reset: true,
        }))
        .await
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["users"][0]["email"], "alice@example.test");
        assert_eq!(value["users"][0]["traffic"]["uplink"], 37);
        assert_eq!(value["users"][0]["ips"][0]["lastSeen"], 1_800_000_002_i64);
        assert_eq!(active.value(), 0);
        assert_eq!(offline.value(), 71);
        assert_eq!(alice.count(), 2);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn real_system_and_logger_rpcs_use_the_delivered_services() {
        let (server, connection, _, logger) = start_server().await;
        let output = execute(ApiCommand::StatsSys(connection.clone()))
            .await
            .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["NumGoroutine"], 7);
        assert_eq!(value["TotalAlloc"], 13);
        assert_eq!(value["PauseTotalNs"], 23);
        assert_eq!(value["_runtime"]["provider"], "test-measurements");
        assert!(value["_runtime"].get("unavailableFields").is_none());
        logger.close().unwrap();
        assert!(!logger.is_active());
        assert_eq!(
            execute(ApiCommand::RestartLogger(connection))
                .await
                .unwrap(),
            "{}\n\n"
        );
        assert!(logger.is_active());
        server.shutdown().await.unwrap();
    }

    #[derive(Clone)]
    struct DelayedStats {
        inner: wire::stats_service_server::StatsServiceServer<StatsService>,
        called: Arc<AtomicBool>,
    }

    impl NamedService for DelayedStats {
        const NAME: &'static str = "xray.app.stats.command.StatsService";
    }

    impl Service<http::Request<Body>> for DelayedStats {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, context: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
            <wire::stats_service_server::StatsServiceServer<StatsService> as Service<
                http::Request<Body>,
            >>::poll_ready(&mut self.inner, context)
        }

        fn call(&mut self, request: http::Request<Body>) -> Self::Future {
            self.called.store(true, Ordering::SeqCst);
            let mut inner = self.inner.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                inner.call(request).await
            })
        }
    }

    #[tokio::test]
    async fn rpc_deadline_bounds_a_connected_but_stalled_service() {
        let called = Arc::new(AtomicBool::new(false));
        let service = DelayedStats {
            inner: StatsService::new(Arc::new(StatsManager::new())).into_server(),
            called: called.clone(),
        };
        let server = ApiServer::from_routes(Routes::new(service))
            .bind_tcp("127.0.0.1:0")
            .await
            .unwrap();
        let connection = ConnectionArgs {
            server: server.local_addr().unwrap().to_string(),
            ..Default::default()
        };
        let command = ApiCommand::Stats(StatArgs {
            connection,
            name: "stalled".into(),
            reset: false,
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            execute_at(command, Instant::now() + Duration::from_millis(200)),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(called.load(Ordering::SeqCst));
        let error = format!("{:#}", result.unwrap_err());
        assert!(
            error.contains("DeadlineExceeded")
                || error.contains("Timeout")
                || error.contains("Cancelled"),
            "{error}"
        );
        drop(server);
    }

    #[tokio::test]
    async fn connection_deadline_and_zero_timeout_are_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let connection = ConnectionArgs {
            server: address.to_string(),
            ..Default::default()
        };
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            execute_at(
                ApiCommand::StatsSys(connection.clone()),
                Instant::now() + Duration::from_millis(80),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("failed to dial"));
        let error = execute(ApiCommand::StatsSys(ConnectionArgs {
            timeout: 0,
            ..connection
        }))
        .await
        .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[test]
    fn adi_encoder_carries_the_supported_inbound_shapes() {
        use xray_proto::xray::{
            app::proxyman::ReceiverConfig,
            proxy::socks::{AuthType, ServerConfig as SocksConfig},
        };

        let inbound = serde_json::json!({
            "tag": "added", "listen": "127.0.0.1", "port": 1080, "protocol": "socks",
            "settings": {"auth": "password", "accounts": [{"user": "u", "pass": "p"}], "udp": true}
        });
        let handler = inbound_to_handler(&inbound).unwrap();
        assert_eq!(handler.tag, "added");
        let receiver: ReceiverConfig = handler.receiver_settings.unwrap().unpack().unwrap();
        let ports = receiver.port_list.unwrap().range;
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].from, 1080);
        let listen = receiver.listen.unwrap();
        assert!(matches!(
            listen.address,
            Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(bytes))
                if bytes == [127, 0, 0, 1]
        ));
        assert_eq!(receiver.stream_settings.unwrap().protocol_name, "tcp");
        let proxy: SocksConfig = handler.proxy_settings.unwrap().unpack().unwrap();
        assert_eq!(proxy.auth_type, AuthType::Password as i32);
        assert_eq!(proxy.accounts.get("u").map(String::as_str), Some("p"));
        assert!(proxy.udp_enabled);

        // VLESS accounts travel as typed users; trojan passwords likewise.
        let vless = serde_json::json!({
            "tag": "v", "port": 443, "protocol": "vless",
            "settings": {"decryption": "none", "clients": [
                {"id": "mux-user", "email": "e", "level": 0, "flow": ""}
            ]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {}}
        });
        let handler = inbound_to_handler(&vless).unwrap();
        let stream = handler
            .receiver_settings
            .unwrap()
            .unpack::<ReceiverConfig>()
            .unwrap()
            .stream_settings
            .unwrap();
        assert_eq!(stream.security_type, "xray.transport.internet.tls.Config");
        let config: xray_proto::xray::proxy::vless::inbound::Config =
            handler.proxy_settings.unwrap().unpack().unwrap();
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.decryption, "none");
        let account: xray_proto::xray::proxy::vless::Account =
            config.users[0].account.clone().unwrap().unpack().unwrap();
        assert_eq!(account.id, "mux-user");

        // Shadowsocks 2022 travels whole.
        let ss2022 = serde_json::json!({
            "tag": "s", "port": 8388, "protocol": "shadowsocks",
            "settings": {"method": "2022-blake3-aes-128-gcm", "password": "k==", "email": "e", "network": "tcp,udp"}
        });
        let handler = inbound_to_handler(&ss2022).unwrap();
        let config: xray_proto::xray::proxy::shadowsocks_2022::ServerConfig =
            handler.proxy_settings.unwrap().unpack().unwrap();
        assert_eq!(config.method, "2022-blake3-aes-128-gcm");
        assert_eq!(config.key, "k==");
        assert_eq!(config.network, vec![2, 3]);
    }

    #[test]
    fn adi_encoder_names_its_rejections() {
        let reject =
            |inbound: serde_json::Value| inbound_to_handler(&inbound).unwrap_err().to_string();
        let base = serde_json::json!({"port": 1080, "protocol": "socks", "settings": {}});
        let mut ws = base.clone();
        ws["streamSettings"] = serde_json::json!({"network": "ws"});
        assert!(reject(ws).contains("plain TCP transport"));
        let mut domain = base.clone();
        domain["listen"] = serde_json::json!("proxy.example.com");
        assert!(reject(domain).contains("IP \"listen\""));
        let mut range = base.clone();
        range["port"] = serde_json::json!("3000-4000");
        assert!(reject(range).contains("single numeric"));
        let mut mux = base.clone();
        mux["protocol"] = serde_json::json!("mux");
        assert!(reject(mux).contains("does not carry protocol"));
        let mut fingerprint = base.clone();
        fingerprint["streamSettings"] = serde_json::json!({
            "network": "tcp", "security": "tls",
            "tlsSettings": {"fingerprint": "chrome"}
        });
        assert!(reject(fingerprint).contains("does not carry tlsSettings"));
    }
}
