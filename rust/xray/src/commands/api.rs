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
    /// Preserve an explicit unsupported-service diagnostic for other commands.
    #[command(external_subcommand)]
    Unsupported(Vec<String>),
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
            | Self::RestartLogger(args) => args,
            Self::Unsupported(args) => {
                let name = args.first().map(String::as_str).unwrap_or("");
                let service = match name {
                    "adi" | "ado" | "rmi" | "rmo" | "lsi" | "lso" | "adu" | "rmu"
                    | "inbounduser" | "inboundusercount" => "HandlerService",
                    "bi" | "bo" | "adrules" | "rmrules" | "lsrules" | "sib" => "RoutingService",
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
        ] {
            let command = TestCli::try_parse_from(["api", name]).unwrap().command;
            let args = command.connection().unwrap();
            assert_eq!(args.server, "127.0.0.1:8080");
            assert_eq!(args.timeout, 3);
            assert!(!args.json);
        }
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
            ("adi", "HandlerService"),
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
}
