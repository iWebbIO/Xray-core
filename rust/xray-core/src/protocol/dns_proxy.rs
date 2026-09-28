// P02 dns proxy: the DNS inbound/outbound, ported from Go proxy/dns
// (dns.go) with infra/conf/dns_proxy.go's settings. The handler answers
// wire-format DNS queries arriving on proxied connections through the
// configured DNS client; rules (or the legacy nonIPQuery/blockTypes keys)
// drop, reject, hijack or forward each query. `nonDNSQuery` is this port's
// simplified spelling of the legacy `nonIPQuery: "skip"` profile.
#![allow(dead_code)]

use std::{future::Future, io, net::IpAddr, pin::Pin, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::{
    address::Destination,
    dns::{RecordType, wire},
    transport::BoxStream,
};

/// Go's common/buf `Size`: the largest TCP-framed DNS message the proxy
/// reads (Go's dns_proto TCPReader rejects bigger frames).
const MAX_FRAME: usize = 8192;
/// Go's features/dns `DefaultTTL`: the seam returns no per-record TTL, so
/// hijacked answers carry the port's default.
const ANSWER_TTL: u32 = crate::dns::DEFAULT_TTL;

// ---------------------------------------------------------------------------
// Seams the integrator implements over the runtime
// ---------------------------------------------------------------------------

/// One A/AAAA lookup through the configured DNS app (Go's `dns.Client
/// LookupIP` with FakeEnable). `ipv4`/`ipv6` select the family exactly like
/// Go's IPOption; an empty `Ok` is Go's `ErrEmptyResponse`, answered as an
/// empty NOERROR message.
pub type DnsLookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;

/// The DNS client seam. The integrator implements it over
/// `dns::app::DnsApp::lookup_ip` (which already narrows families per the
/// configured queryStrategy); it must never fall back to the system
/// resolver behind a configured app.
pub trait DnsQuery: Send + Sync {
    fn lookup(&self, domain: &str, ipv4: bool, ipv6: bool) -> DnsLookupFuture;
}

/// One dialed stream toward the forward (rewrite) server — Go's
/// `internet.Dialer.Dial` destination. The integrator dials through the
/// outbound's transport for TCP targets and a connected-datagram adapter
/// for UDP targets.
pub type DnsDialFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;

pub trait DnsForwardDial: Send + Sync {
    fn dial_forward(&self, destination: &Destination) -> DnsDialFuture;
}

// ---------------------------------------------------------------------------
// Settings (infra/conf/dns_proxy.go DNSOutboundConfig)
// ---------------------------------------------------------------------------

/// Go's `DNSOutboundConfig` keys, exactly: the legacy `network`/`address`/
/// `port` fold into the rewrite (forward) server, `rules` is the modern
/// policy, and `nonIPQuery`/`blockTypes` are the legacy policy. Go has no
/// `dns` inbound, so the same settings serve both Rust arms; `nonDNSQuery`
/// is this port's simplified spelling of `nonIPQuery: "skip"`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsProxySettings {
    /// Legacy rewrite network: "tcp" or "udp".
    pub network: Option<String>,
    /// Legacy rewrite address (IP or domain).
    pub address: Option<String>,
    /// Legacy rewrite port.
    pub port: u16,
    /// `rewriteNetwork`: the forward server's network.
    pub rewrite_network: Option<String>,
    /// `rewriteAddress`: the forward server's address.
    pub rewrite_address: Option<String>,
    /// `rewritePort`: the forward server's port.
    pub rewrite_port: u16,
    /// Go's `userLevel`; policy levels are not migrated yet.
    pub user_level: u32,
    /// `rules`: the per-query policy, in order.
    pub rules: Vec<DnsRuleSettings>,
    /// Legacy `nonIPQuery` mode: "", "reject", "drop" or "skip".
    #[serde(rename = "nonIPQuery")]
    pub non_ip_query: Option<String>,
    /// Legacy `blockTypes`: query types to block before the hijack rule.
    pub block_types: Option<Vec<i32>>,
    /// This port's simplified spelling of legacy `nonIPQuery: "skip"`:
    /// A/AAAA queries are still answered locally; every other query — and,
    /// on the inbound, a stream whose first message is not DNS at all —
    /// relays raw to the configured address:port.
    #[serde(rename = "nonDNSQuery")]
    pub non_dns_query: bool,
}

impl DnsProxySettings {
    /// The single entry point the config layer calls.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid dns proxy settings")
    }
}

/// Go's `DNSOutboundRuleConfig` keys: `action`, `qType`, `domain`, `rCode`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsRuleSettings {
    /// One of "direct", "drop", "return" or "hijack" (case-insensitive).
    pub action: String,
    /// Go's PortList: a number or a `"a-b"`/`"a,b-c"` string — never an
    /// array. An empty list matches every query type.
    #[serde(deserialize_with = "q_type_list")]
    pub q_type: Vec<u16>,
    /// Go's StringList matched as substring rules (Domain_Substr).
    #[serde(deserialize_with = "string_list")]
    pub domain: Vec<String>,
    /// The RCode of `return` answers (0..=65535, like Go's check).
    pub r_code: u32,
}

/// Go's StringList: a single string or an array of strings.
fn string_list<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Values {
        Single(String),
        Multiple(Vec<String>),
    }
    Ok(match Values::deserialize(d)? {
        Values::Single(value) => vec![value],
        Values::Multiple(values) => values,
    })
}

/// Go's PortList JSON shape for `qType`: a number, or a string of
/// comma-separated ports and `a-b` ranges. Arrays are rejected exactly
/// like Go's PortList.UnmarshalJSON; a literal number 0 leaves the list
/// empty (matching every type), mirroring Go's `number != 0` guard.
fn q_type_list<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u16>, D::Error> {
    use serde::de::Error as _;
    let value = serde_json::Value::deserialize(d)?;
    let expand = |text: &str| -> std::result::Result<Vec<u16>, D::Error> {
        let mut types = Vec::new();
        for segment in text.split(',') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let (from, to) = match segment.split_once('-') {
                Some((from, to)) => (from, to),
                None => (segment, segment),
            };
            let from: u16 = from
                .trim()
                .parse()
                .map_err(|_| D::Error::custom(format!("invalid port: {segment}")))?;
            let to: u16 = to
                .trim()
                .parse()
                .map_err(|_| D::Error::custom(format!("invalid port: {segment}")))?;
            if from == 0 || to == 0 || from > to {
                return Err(D::Error::custom(format!("invalid port range: {segment}")));
            }
            types.extend(from..=to);
        }
        Ok(types)
    };
    match value {
        serde_json::Value::Number(number) => {
            let Some(port) = number.as_u64().filter(|port| *port <= u16::MAX as u64) else {
                return Err(D::Error::custom(format!("invalid port: {number}")));
            };
            Ok(if port == 0 {
                Vec::new()
            } else {
                vec![port as u16]
            })
        }
        serde_json::Value::String(text) => expand(&text),
        other => Err(D::Error::custom(format!("invalid port: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// The compiled proxy
// ---------------------------------------------------------------------------

/// Go's RuleAction enum values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleAction {
    Direct,
    Drop,
    Return,
    Hijack,
}

/// Message framing: TCP DNS carries every message behind a two-byte length
/// prefix (Go's dns_proto TCP reader/writer); raw framing is one
/// datagram-sized chunk per message (Go's UDP reader/writer).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    Tcp,
    Raw,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    action: RuleAction,
    q_types: Vec<u16>,
    domains: Option<crate::geodata::DomainMatcher>,
    r_code: u16,
}

impl CompiledRule {
    /// Go's `DNSRule.Apply`: an empty qType list matches every type; the
    /// domain matcher (when configured) matches the lowercased query name
    /// with its trailing dot trimmed.
    fn matches(&self, q_type: u16, domain: &str) -> bool {
        if !(self.q_types.is_empty() || self.q_types.contains(&q_type)) {
            return false;
        }
        match &self.domains {
            None => true,
            Some(matcher) => {
                let name = domain.to_ascii_lowercase();
                let name = name.strip_suffix('.').unwrap_or(&name);
                matcher.match_host(name)
            }
        }
    }
}

/// The forward (rewrite) server: only the fields the user set, patched
/// onto the original target like Go's `Handler.Process`.
#[derive(Clone, Debug, Default)]
struct ForwardServer {
    network: Option<Framing>,
    address: Option<String>,
    port: u16,
}

/// Go's proxy/dns `Handler` over the runtime's seams. `compile` runs every
/// config-level check (user levels, legacy/rule mixing, actions, qType
/// ranges, rCode bounds, domain matchers) so invalid settings fail before
/// any listener opens.
pub struct DnsProxy {
    rules: Vec<CompiledRule>,
    forward: ForwardServer,
    non_dns_query: bool,
}

impl DnsProxy {
    pub fn compile(settings: &DnsProxySettings) -> Result<Self> {
        ensure!(
            settings.user_level == 0,
            "user policy levels are not migrated yet"
        );
        let legacy = settings.non_ip_query.is_some()
            || settings.block_types.is_some()
            || settings.non_dns_query;
        ensure!(
            !legacy || settings.rules.is_empty(),
            "legacy nonIPQuery and blockTypes cannot be mixed with rules"
        );
        let rules = if legacy {
            Self::compile_legacy(settings)?
        } else {
            Self::compile_rules(&settings.rules)?
        };
        let network = parse_network(
            settings
                .rewrite_network
                .as_deref()
                .or(settings.network.as_deref()),
        )?;
        Ok(Self {
            rules,
            forward: ForwardServer {
                network,
                address: settings
                    .rewrite_address
                    .clone()
                    .or_else(|| settings.address.clone()),
                port: if settings.rewrite_port != 0 {
                    settings.rewrite_port
                } else {
                    settings.port
                },
            },
            non_dns_query: settings.non_dns_query,
        })
    }

    /// Go's `buildLegacyDNSPolicy`: the nonIPQuery/blockTypes profile.
    fn compile_legacy(settings: &DnsProxySettings) -> Result<Vec<CompiledRule>> {
        let mode = if settings.non_dns_query {
            "skip"
        } else {
            settings.non_ip_query.as_deref().unwrap_or("reject")
        };
        ensure!(
            matches!(mode, "" | "reject" | "drop" | "skip"),
            "unknown nonIPQuery: {mode}"
        );
        let mut rules = Vec::new();
        if let Some(blocked) = settings.block_types.as_deref()
            && !blocked.is_empty()
        {
            let (action, r_code) = if mode == "reject" {
                (RuleAction::Return, 5)
            } else {
                (RuleAction::Drop, 0)
            };
            let mut q_types = Vec::new();
            for q_type in blocked {
                ensure!(
                    (0..=65535).contains(q_type),
                    "legacy blockTypes qType out of range: {q_type}"
                );
                q_types.push(*q_type as u16);
            }
            rules.push(CompiledRule {
                action,
                q_types,
                domains: None,
                r_code,
            });
        }
        rules.push(CompiledRule {
            action: RuleAction::Hijack,
            q_types: vec![RecordType::A.0, RecordType::AAAA.0],
            domains: None,
            r_code: 0,
        });
        let (action, r_code) = match mode {
            "reject" => (RuleAction::Return, 5),
            "drop" => (RuleAction::Drop, 0),
            "skip" => (RuleAction::Direct, 0),
            // An explicit empty mode keeps Go's initialized Return rule
            // with RCode Success.
            _ => (RuleAction::Return, 0),
        };
        rules.push(CompiledRule {
            action,
            q_types: Vec::new(),
            domains: None,
            r_code,
        });
        Ok(rules)
    }

    /// Go's `DNSOutboundRuleConfig.Build` per configured rule.
    fn compile_rules(rules: &[DnsRuleSettings]) -> Result<Vec<CompiledRule>> {
        let mut store = None;
        let mut compiled = Vec::new();
        for rule in rules {
            let action = match rule.action.to_ascii_lowercase().as_str() {
                "direct" => RuleAction::Direct,
                "drop" => RuleAction::Drop,
                "return" => RuleAction::Return,
                "hijack" => RuleAction::Hijack,
                other => bail!("unknown action: {other}"),
            };
            ensure!(
                rule.r_code <= u16::MAX as u32,
                "rCode out of range: {}",
                rule.r_code
            );
            let domains = if rule.domain.is_empty() {
                None
            } else {
                if store.is_none() {
                    store = Some(crate::geodata::GeoDataStore::from_env()?);
                }
                let store = store.as_ref().expect("built above");
                let parsed =
                    store.parse_domain_rules(&rule.domain, crate::geodata::domain::Type::Substr)?;
                Some(store.build_domain_matcher(&parsed)?)
            };
            compiled.push(CompiledRule {
                action,
                q_types: rule.q_type.clone(),
                domains,
                r_code: rule.r_code as u16,
            });
        }
        Ok(compiled)
    }

    /// The inbound: every accepted connection is a DNS query stream (TCP
    /// framing, because the listener is TCP) answered through `resolver`
    /// (Go's hijack) or forwarded to the configured address:port per the
    /// compiled rules. With `nonDNSQuery`, a stream whose first message is
    /// not DNS at all relays raw to the forward server instead.
    pub async fn serve_inbound(
        &self,
        client: BoxStream,
        resolver: Option<&dyn DnsQuery>,
        dial: &dyn DnsForwardDial,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.serve(
            client,
            Framing::Tcp,
            None,
            self.non_dns_query,
            resolver,
            dial,
            cancel,
        )
        .await
    }

    /// Go's `Handler.Process` — the outbound: hijacked DNS traffic on an
    /// established proxied connection. `target` is the hijacked destination
    /// and `src_framing` its network (TCP framing for stream sessions, raw
    /// datagram chunks for UDP-originated ones); the rewrite server patches
    /// its network/address/port for forwarded queries.
    pub async fn serve_outbound(
        &self,
        client: BoxStream,
        target: &Destination,
        src_framing: Framing,
        resolver: Option<&dyn DnsQuery>,
        dial: &dyn DnsForwardDial,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.serve(
            client,
            src_framing,
            Some(target),
            false,
            resolver,
            dial,
            cancel,
        )
        .await
    }

    /// Go's `applyRules`: the first matching rule wins; without rules A/AAAA
    /// hijack and every other type returns an empty NOERROR answer.
    fn apply_rules(&self, q_type: u16, domain: &str) -> (RuleAction, u16) {
        for rule in &self.rules {
            if rule.matches(q_type, domain) {
                return (rule.action, rule.r_code);
            }
        }
        if q_type == RecordType::A.0 || q_type == RecordType::AAAA.0 {
            (RuleAction::Hijack, 0)
        } else {
            (RuleAction::Return, 0)
        }
    }

    /// The forward server destination, patching only the configured fields
    /// onto the base target (Go's Process). The inbound has no base target,
    /// so an incomplete forward server fails explicitly, naming the
    /// missing field.
    fn forward_destination(&self, base: Option<&Destination>) -> Result<Destination> {
        let address = match &self.forward.address {
            Some(address) => address.clone(),
            None => match base {
                Some(target) => target.address.to_string(),
                None => bail!("dns proxy forwarding requires a configured address"),
            },
        };
        let port = if self.forward.port != 0 {
            self.forward.port
        } else {
            match base {
                Some(target) => target.port,
                None => bail!("dns proxy forwarding requires a configured port"),
            }
        };
        Destination::new(&address, port).context("dns proxy forward server")
    }

    /// The forward server's framing: the configured network, else the
    /// client's (the hijacked target's own network in Go).
    fn upstream_framing(&self, client_framing: Framing) -> Framing {
        self.forward.network.unwrap_or(client_framing)
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve(
        &self,
        client: BoxStream,
        client_framing: Framing,
        base: Option<&Destination>,
        raw_fallback: bool,
        resolver: Option<&dyn DnsQuery>,
        dial: &dyn DnsForwardDial,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let (mut reader, writer) = tokio::io::split(client);
        let first = read_first(&mut reader, client_framing).await?;
        let payload = match first {
            FirstRead::Eof => return Ok(()),
            FirstRead::Malformed { raw, error } => {
                if raw_fallback {
                    return self
                        .raw_relay(reader, writer, raw, base, dial, cancel)
                        .await;
                }
                return Err(error).context("dns proxy read the first message");
            }
            FirstRead::Message { payload, .. } => payload,
        };
        let (upstream_tx, upstream_rx) = tokio::sync::oneshot::channel();
        // Both loops write to the client (answers here, relayed answers in
        // the response loop), exactly like Go's concurrent writers.
        let client = Arc::new(tokio::sync::Mutex::new(writer));
        let stop = cancel.child_token();
        let request = {
            let client = Arc::clone(&client);
            let stop = stop.clone();
            async move {
                let result = self
                    .request_loop(
                        payload,
                        reader,
                        client_framing,
                        client,
                        resolver,
                        dial,
                        base,
                        upstream_tx,
                        &stop,
                    )
                    .await;
                if result.is_err() {
                    stop.cancel();
                }
                result
            }
        };
        let response = {
            let client = Arc::clone(&client);
            async move {
                let result = self
                    .response_loop(upstream_rx, client, client_framing, &stop)
                    .await;
                if result.is_err() {
                    stop.cancel();
                }
                result
            }
        };
        // Go's task.Run: both loops run concurrently, the first error wins.
        let (request, response) = tokio::join!(request, response);
        request.or(response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_loop(
        &self,
        first: Vec<u8>,
        reader: tokio::io::ReadHalf<BoxStream>,
        client_framing: Framing,
        client: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxStream>>>,
        resolver: Option<&dyn DnsQuery>,
        dial: &dyn DnsForwardDial,
        base: Option<&Destination>,
        upstream_sender: tokio::sync::oneshot::Sender<tokio::io::ReadHalf<BoxStream>>,
        token: &CancellationToken,
    ) -> Result<()> {
        let mut upstream: Option<(tokio::io::WriteHalf<BoxStream>, Framing)> = None;
        let result = self
            .request_messages(
                &mut upstream,
                first,
                reader,
                client_framing,
                client,
                resolver,
                dial,
                base,
                upstream_sender,
                token,
            )
            .await;
        // The client ended its side: half-close the forward connection so
        // the response loop drains until the forward server closes (Go's
        // teardown closes the outbound conn with the session).
        if let Some((mut writer, _)) = upstream.take() {
            let _ = writer.shutdown().await;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_messages(
        &self,
        upstream: &mut Option<(tokio::io::WriteHalf<BoxStream>, Framing)>,
        first: Vec<u8>,
        mut reader: tokio::io::ReadHalf<BoxStream>,
        client_framing: Framing,
        client: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxStream>>>,
        resolver: Option<&dyn DnsQuery>,
        dial: &dyn DnsForwardDial,
        base: Option<&Destination>,
        upstream_sender: tokio::sync::oneshot::Sender<tokio::io::ReadHalf<BoxStream>>,
        token: &CancellationToken,
    ) -> Result<()> {
        let mut sender = Some(upstream_sender);
        let mut pending = Some(first);
        loop {
            let payload = match pending.take() {
                Some(payload) => payload,
                None => {
                    let read = tokio::select! {
                        biased;
                        _ = token.cancelled() => return Ok(()),
                        read = read_message(&mut reader, client_framing) => read,
                    };
                    match read.context("dns proxy read a query")? {
                        Some(payload) => payload,
                        None => return Ok(()),
                    }
                }
            };
            let Some((id, q_type, name, question)) = parse_query(&payload) else {
                // Go drops unparseable messages silently.
                tracing::debug!("dns proxy dropped an unparseable message");
                continue;
            };
            let (action, r_code) = self.apply_rules(q_type, &name);
            match action {
                RuleAction::Drop => {
                    tracing::debug!(q_type, %name, "dns proxy blocked a query");
                }
                RuleAction::Return => {
                    tracing::debug!(q_type, %name, "dns proxy rejected a query");
                    reject(id, &question, r_code, client_framing, &client).await?;
                }
                RuleAction::Hijack => {
                    if q_type != RecordType::A.0 && q_type != RecordType::AAAA.0 {
                        tracing::warn!("can only hijack A/AAAA records");
                        reject(id, &question, r_code, client_framing, &client).await?;
                    } else {
                        // Go runs each lookup as its own goroutine; this
                        // port answers queries in order over the same
                        // connection (see the module docs).
                        answer(id, &question, resolver, client_framing, &client).await?;
                    }
                }
                RuleAction::Direct => {
                    if upstream.is_none() {
                        let destination = self.forward_destination(base)?;
                        let stream = dial.dial_forward(&destination).await.with_context(|| {
                            format!("dns proxy dial forward server {destination}")
                        })?;
                        let framing = self.upstream_framing(client_framing);
                        let (read, write) = tokio::io::split(stream);
                        // A dropped receiver means the response loop already
                        // ended (Go's buffered connReady behaves the same).
                        if let Some(sender) = sender.take() {
                            let _ = sender.send(read);
                        }
                        *upstream = Some((write, framing));
                    }
                    let (writer, framing) = upstream.as_mut().expect("dialed above");
                    write_frame(writer, *framing, &payload)
                        .await
                        .context("dns proxy forwarded a query")?;
                }
            }
        }
    }

    async fn response_loop(
        &self,
        upstream: tokio::sync::oneshot::Receiver<tokio::io::ReadHalf<BoxStream>>,
        client: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxStream>>>,
        client_framing: Framing,
        token: &CancellationToken,
    ) -> Result<()> {
        // The request loop dials the forward server lazily (Go's
        // outboundConn); if it finishes without ever forwarding, this side
        // simply ends.
        let mut upstream = tokio::select! {
            biased;
            _ = token.cancelled() => return Ok(()),
            upstream = upstream => match upstream {
                Ok(upstream) => upstream,
                Err(_) => return Ok(()),
            },
        };
        let upstream_framing = self.upstream_framing(client_framing);
        loop {
            let read = tokio::select! {
                biased;
                _ = token.cancelled() => return Ok(()),
                read = read_message(&mut upstream, upstream_framing) => read,
            };
            let payload = match read.context("dns proxy read a forwarded answer")? {
                Some(payload) => payload,
                None => return Ok(()),
            };
            let mut writer = client.lock().await;
            write_frame(&mut *writer, client_framing, &payload)
                .await
                .context("dns proxy relayed an answer")?;
        }
    }

    /// The `nonDNSQuery` inbound fallback: a stream whose first message is
    /// not DNS at all relays raw to the forward server — the consumed
    /// prefix bytes are replayed — until either side closes.
    async fn raw_relay(
        &self,
        mut reader: tokio::io::ReadHalf<BoxStream>,
        mut writer: tokio::io::WriteHalf<BoxStream>,
        raw: Vec<u8>,
        base: Option<&Destination>,
        dial: &dyn DnsForwardDial,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let destination = self.forward_destination(base)?;
        let mut upstream = dial
            .dial_forward(&destination)
            .await
            .with_context(|| format!("dns proxy dial forward server {destination}"))?;
        upstream
            .write_all(&raw)
            .await
            .context("dns proxy relayed the first message")?;
        upstream.flush().await?;
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
        let client_to_upstream = tokio::io::copy(&mut reader, &mut upstream_write);
        let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut writer);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = client_to_upstream => result.context("dns proxy relayed a query").map(|_| ()),
            result = upstream_to_client => result.context("dns proxy relayed an answer").map(|_| ()),
        }
    }
}

/// Go's `parseQuery`: the header id and the FIRST question's type and name.
/// The port's decoder is stricter than dnsmessage (it validates every
/// section); a message dnsmessage would half-parse is dropped instead.
fn parse_query(payload: &[u8]) -> Option<(u16, u16, String, wire::Question)> {
    let message = wire::decode(payload).ok()?;
    let question = message.questions.first()?.clone();
    Some((
        message.header.id,
        question.record_type.0,
        question.name.clone(),
        question,
    ))
}

/// Go's `rejectNonIPQuery`: echo the question with the rule's RCode and no
/// answers. Go's dnsmessage builder keeps only the header's four RCode
/// bits, so extended codes are truncated here too.
async fn reject(
    id: u16,
    question: &wire::Question,
    r_code: u16,
    framing: Framing,
    client: &tokio::sync::Mutex<tokio::io::WriteHalf<BoxStream>>,
) -> Result<()> {
    let message = wire::encode_response(
        id,
        question,
        &[],
        0,
        r_code & 0xF,
        None,
        wire::MAX_MESSAGE_SIZE,
    )
    .map_err(|error| anyhow::Error::new(error).context("dns proxy pack reject message"))?;
    let mut writer = client.lock().await;
    write_frame(&mut *writer, framing, &message)
        .await
        .context("dns proxy wrote the reject answer")
}

/// Go's `handleIPQuery`: lookup through the seam, then the AA/RA/RD
/// answer. A lookup error leaves the query unanswered (Go's non-RCode
/// errors), an empty lookup answers NOERROR with no records, and a write
/// failure only ends this answer (Go logs it and keeps the connection).
async fn answer(
    id: u16,
    question: &wire::Question,
    resolver: Option<&dyn DnsQuery>,
    framing: Framing,
    client: &tokio::sync::Mutex<tokio::io::WriteHalf<BoxStream>>,
) -> Result<()> {
    let Some(resolver) = resolver else {
        // Go fails handler creation without a DNS client; this port fails
        // the connection explicitly instead of silently degrading.
        bail!("dns proxy hijack requires a configured DNS app");
    };
    let ipv4 = question.record_type == RecordType::A;
    let ips = match resolver.lookup(&question.name, ipv4, !ipv4).await {
        Ok(ips) => ips,
        Err(error) => {
            tracing::warn!(%error, name = %question.name, "dns proxy ip query failed");
            return Ok(());
        }
    };
    let message = match wire::encode_response(
        id,
        question,
        &ips,
        ANSWER_TTL,
        0,
        None,
        wire::MAX_MESSAGE_SIZE,
    ) {
        Ok(message) => message,
        Err(error) => {
            tracing::warn!(%error, name = %question.name, "dns proxy pack message");
            return Ok(());
        }
    };
    let mut writer = client.lock().await;
    if let Err(error) = write_frame(&mut *writer, framing, &message).await {
        tracing::warn!(%error, "dns proxy write IP answer");
    }
    Ok(())
}

/// Go's `Network.Build`: "" keeps the field unset, tcp/udp select the
/// framing, unix fails explicitly (not migrated), and any other value stays
/// unset exactly like Go's Network_Unknown.
fn parse_network(network: Option<&str>) -> Result<Option<Framing>> {
    match network.map(str::to_ascii_lowercase).as_deref() {
        Some("unix") => bail!("unix forward network is not migrated yet"),
        Some("tcp") => Ok(Some(Framing::Tcp)),
        Some("udp") => Ok(Some(Framing::Raw)),
        _ => Ok(None),
    }
}

/// Write one message with the side's framing: TCP prefixes the two-byte
/// length (Go's TCPWriter skips empty messages), raw writes the bytes as
/// one datagram-sized chunk.
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    framing: Framing,
    payload: &[u8],
) -> io::Result<()> {
    match framing {
        Framing::Tcp => {
            if payload.is_empty() {
                return Ok(());
            }
            writer
                .write_all(&(payload.len() as u16).to_be_bytes())
                .await?;
            writer.write_all(payload).await
        }
        Framing::Raw => writer.write_all(payload).await,
    }
}

/// Read one message. `None` is a clean end of the stream; a truncated frame
/// is `UnexpectedEof`, like Go's serial.ReadUint16.
async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    framing: Framing,
) -> io::Result<Option<Vec<u8>>> {
    match framing {
        Framing::Tcp => {
            let mut prefix = [0u8; 2];
            if reader.read(&mut prefix[..1]).await? == 0 {
                return Ok(None);
            }
            reader.read_exact(&mut prefix[1..]).await?;
            let length = u16::from_be_bytes(prefix) as usize;
            if length > MAX_FRAME {
                return Err(io::Error::other(format!(
                    "message size too large: {length}"
                )));
            }
            let mut payload = vec![0u8; length];
            reader.read_exact(&mut payload).await?;
            Ok(Some(payload))
        }
        Framing::Raw => {
            let mut buffer = vec![0u8; MAX_FRAME];
            let count = reader.read(&mut buffer).await?;
            buffer.truncate(count);
            if count == 0 {
                Ok(None)
            } else {
                Ok(Some(buffer))
            }
        }
    }
}

/// The first message of a connection, with the consumed raw bytes kept so
/// the `nonDNSQuery` inbound can replay them into a raw relay.
enum FirstRead {
    Eof,
    Message { raw: Vec<u8>, payload: Vec<u8> },
    Malformed { raw: Vec<u8>, error: io::Error },
}

/// Fill `buffer`, recording every byte consumed so far; `false` marks a
/// clean EOF before the buffer filled.
async fn read_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    consumed: &mut Vec<u8>,
) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        let slice = &mut buffer[filled..];
        let count = reader.read(slice).await?;
        consumed.extend_from_slice(&slice[..count]);
        if count == 0 {
            return Ok(false);
        }
        filled += count;
    }
    Ok(true)
}

async fn read_first<R: AsyncRead + Unpin>(
    reader: &mut R,
    framing: Framing,
) -> io::Result<FirstRead> {
    match framing {
        Framing::Tcp => {
            let mut consumed = Vec::new();
            let mut prefix = [0u8; 1];
            if reader.read(&mut prefix).await? == 0 {
                return Ok(FirstRead::Eof);
            }
            consumed.extend_from_slice(&prefix);
            let mut second = [0u8; 1];
            if !read_into(reader, &mut second, &mut consumed).await? {
                return Ok(FirstRead::Malformed {
                    raw: consumed,
                    error: io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated DNS frame prefix",
                    ),
                });
            }
            let length = usize::from(u16::from_be_bytes([prefix[0], second[0]]));
            if length > MAX_FRAME {
                return Ok(FirstRead::Malformed {
                    raw: consumed,
                    error: io::Error::other(format!("message size too large: {length}")),
                });
            }
            let mut payload = vec![0u8; length];
            if !read_into(reader, &mut payload, &mut consumed).await? {
                return Ok(FirstRead::Malformed {
                    raw: consumed,
                    error: io::Error::new(io::ErrorKind::UnexpectedEof, "truncated DNS frame"),
                });
            }
            Ok(FirstRead::Message {
                raw: consumed,
                payload,
            })
        }
        Framing::Raw => {
            let mut buffer = vec![0u8; MAX_FRAME];
            let count = reader.read(&mut buffer).await?;
            buffer.truncate(count);
            if count == 0 {
                return Ok(FirstRead::Eof);
            }
            Ok(FirstRead::Message {
                raw: buffer.clone(),
                payload: buffer,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn settings_parse_go_keys_and_defaults() {
        let settings = DnsProxySettings::from_value(&json!({
            "network": "udp",
            "address": "8.8.8.8",
            "port": 53,
            "userLevel": 0,
            "rules": [
                {"action": "Drop", "qType": "33-35", "domain": "ads.example"},
                {"action": "Hijack", "qType": 1, "rCode": 0}
            ]
        }))
        .unwrap();
        assert_eq!(settings.address.as_deref(), Some("8.8.8.8"));
        assert_eq!(settings.port, 53);
        assert_eq!(settings.rules.len(), 2);
        assert_eq!(settings.rules[0].q_type, vec![33, 34, 35]);
        // Go's PortList rejects arrays; so does the port.
        assert!(
            DnsProxySettings::from_value(&json!({
                "rules": [{"action": "Hijack", "qType": [1, 28]}]
            }))
            .is_err()
        );
        // Every default matches Go's zero config.
        let empty = DnsProxySettings::from_value(&json!({})).unwrap();
        assert_eq!(empty, DnsProxySettings::default());
        // Unknown keys fail explicitly.
        assert!(DnsProxySettings::from_value(&json!({"dnsServer": "1.1.1.1"})).is_err());
        // A literal qType 0 leaves the list empty, like Go's PortList.
        let zero = DnsProxySettings::from_value(&json!({
            "rules": [{"action": "Drop", "qType": 0}]
        }))
        .unwrap();
        assert!(zero.rules[0].q_type.is_empty());
    }

    #[test]
    fn settings_reject_unsupported_values() {
        // userLevel is parsed and rejected, never silently ignored.
        assert!(
            DnsProxy::compile(&DnsProxySettings::from_value(&json!({"userLevel": 3})).unwrap())
                .is_err()
        );
        // Legacy policy and rules cannot be mixed, exactly like Go.
        assert!(
            DnsProxy::compile(
                &DnsProxySettings::from_value(&json!({
                    "nonIPQuery": "skip",
                    "rules": [{"action": "Hijack"}]
                }))
                .unwrap()
            )
            .is_err()
        );
        // Unknown actions, modes, ranges and rcodes carry Go's messages.
        assert!(
            DnsProxy::compile(
                &DnsProxySettings::from_value(&json!({"rules": [{"action": "bounce"}]})).unwrap()
            )
            .is_err()
        );
        assert!(
            DnsProxy::compile(
                &DnsProxySettings::from_value(&json!({"nonIPQuery": "leak"})).unwrap()
            )
            .is_err()
        );
        assert!(
            DnsProxy::compile(
                &DnsProxySettings::from_value(&json!({
                    "blockTypes": [70000],
                    "nonIPQuery": "drop"
                }))
                .unwrap()
            )
            .is_err()
        );
        assert!(
            DnsProxy::compile(
                &DnsProxySettings::from_value(&json!({
                    "rules": [{"action": "Return", "rCode": 65536}]
                }))
                .unwrap()
            )
            .is_err()
        );
        // The unix forward network fails explicitly.
        assert!(
            DnsProxy::compile(&DnsProxySettings::from_value(&json!({"network": "unix"})).unwrap())
                .is_err()
        );
    }

    #[test]
    fn legacy_profiles_match_go_build_legacy_dns_policy() {
        // Default (no keys): hijack A/AAAA, return empty NOERROR otherwise.
        let proxy = DnsProxy::compile(&DnsProxySettings::default()).unwrap();
        assert_eq!(
            proxy.apply_rules(1, "example.com."),
            (RuleAction::Hijack, 0)
        );
        assert_eq!(
            proxy.apply_rules(28, "example.com."),
            (RuleAction::Hijack, 0)
        );
        assert_eq!(
            proxy.apply_rules(16, "example.com."),
            (RuleAction::Return, 0)
        );
        // reject: non-IP queries return REFUSED (rcode 5).
        let reject = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({"nonIPQuery": "reject"})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reject.apply_rules(16, "example.com."),
            (RuleAction::Return, 5)
        );
        // drop: non-IP queries are dropped.
        let drop_ = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({"nonIPQuery": "drop"})).unwrap(),
        )
        .unwrap();
        assert_eq!(drop_.apply_rules(16, "example.com."), (RuleAction::Drop, 0));
        // skip (and its nonDNSQuery spelling): non-IP queries forward.
        let skip = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({"nonIPQuery": "skip"})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            skip.apply_rules(16, "example.com."),
            (RuleAction::Direct, 0)
        );
        let simplified = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({"nonDNSQuery": true})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            simplified.apply_rules(16, "example.com."),
            (RuleAction::Direct, 0)
        );
        assert_eq!(
            simplified.apply_rules(1, "example.com."),
            (RuleAction::Hijack, 0)
        );
        // blockTypes 43 with reject returns REFUSED for blocked types,
        // and A/AAAA still hijack under every legacy profile.
        let blocked = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({
                "blockTypes": [43],
                "nonIPQuery": "reject"
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            blocked.apply_rules(43, "whois.example."),
            (RuleAction::Return, 5)
        );
        assert_eq!(
            blocked.apply_rules(16, "whois.example."),
            (RuleAction::Return, 5)
        );
        assert_eq!(
            blocked.apply_rules(1, "whois.example."),
            (RuleAction::Hijack, 0)
        );
    }

    #[test]
    fn rules_match_qtypes_and_domains() {
        let proxy = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({
                "rules": [
                    {"action": "Drop", "qType": 33, "domain": "ads.example"},
                    {"action": "Return", "qType": 16, "rCode": 5},
                    {"action": "Hijack"}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        // Substr domain matching on the lowercased, dot-trimmed name.
        assert_eq!(
            proxy.apply_rules(33, "Tracker.ADS.example."),
            (RuleAction::Drop, 0)
        );
        assert_eq!(
            proxy.apply_rules(33, "clean.example."),
            (RuleAction::Hijack, 0)
        );
        // No domain restriction falls through to qType matching.
        assert_eq!(
            proxy.apply_rules(16, "any.example."),
            (RuleAction::Return, 5)
        );
    }

    #[test]
    fn forward_destination_patches_the_base_target() {
        // Only the configured fields patch the hijacked target, like Go.
        let proxy =
            DnsProxy::compile(&DnsProxySettings::from_value(&json!({"port": 5353})).unwrap())
                .unwrap();
        let base = Destination::new("8.8.8.8", 53).unwrap();
        assert_eq!(
            proxy.forward_destination(Some(&base)).unwrap(),
            Destination::new("8.8.8.8", 5353).unwrap()
        );
        // The rewrite keys take precedence over the legacy spellings.
        let rewrite = DnsProxy::compile(
            &DnsProxySettings::from_value(&json!({
                "address": "1.1.1.1",
                "port": 53,
                "rewriteAddress": "9.9.9.9",
                "rewritePort": 5353,
                "rewriteNetwork": "udp"
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            rewrite.forward_destination(None).unwrap(),
            Destination::new("9.9.9.9", 5353).unwrap()
        );
        assert_eq!(rewrite.upstream_framing(Framing::Tcp), Framing::Raw);
        // The inbound needs a complete forward server when forwarding.
        assert!(proxy.forward_destination(None).is_err());
    }
}
