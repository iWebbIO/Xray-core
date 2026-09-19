//! Pure routing-balancer decisions derived from app/router and infra/conf.
//!
//! The caller supplies an immutable observatory snapshot, registered outbound
//! tags and a uniform bounded-index sampler. This module never probes, opens a
//! socket, resolves DNS, or assumes that an unobserved node failed.

use std::{collections::HashMap, fmt, sync::Mutex};

use regex::Regex;
use serde_json::{Map, Value};

pub use xray_proto::xray::app::router::{
    StrategyLeastLoadConfig as LeastLoadConfig, StrategyWeight as Weight,
};
pub use xray_proto::xray::core::app::observatory::{
    HealthPingMeasurementResult, ObservationResult, OutboundStatus,
};

const MILLIS: i64 = 1_000_000;
const LEAST_PING_SENTINEL: i64 = 99_999_999;

#[derive(Clone, Debug, PartialEq)]
pub enum Strategy {
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad(LeastLoadConfig),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BalancerConfig {
    pub tag: String,
    pub selectors: Vec<String>,
    pub fallback_tag: String,
    pub strategy: Strategy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration(String),
    Selection(String),
    EmptyChoice,
    InvalidSample { index: usize, length: usize },
    CostOutOfRange(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(f, "balancer configuration: {message}"),
            Self::Selection(message) => write!(f, "unable to select outbounds: {message}"),
            Self::EmptyChoice => f.write_str("balancing strategy returns empty tag"),
            Self::InvalidSample { index, length } => {
                write!(f, "sampler returned index {index} for {length} candidates")
            }
            Self::CostOutOfRange(tag) => {
                write!(f, "least-load weighted duration out of range for {tag:?}")
            }
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn configuration(message: impl Into<String>) -> Error {
    Error::Configuration(message.into())
}

impl BalancerConfig {
    /// Convert one JSON `routing.balancers` element, following the source loader.
    /// Unrecognized fields are ignored as in Go's ordinary JSON decoder.
    pub fn from_json(value: &Value) -> Result<Self> {
        let empty = Map::new();
        let object = object_or_null(value, &empty, "balancer")?;
        let tag = string_field(object, "tag")?;
        let selectors = match field(object, "selector") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(value)) => value.split(',').map(str::to_owned).collect(),
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| {
                    // encoding/json treats null string-array entries as empty strings.
                    if value.is_null() {
                        Ok(String::new())
                    } else {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| configuration("selector must contain strings"))
                    }
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(configuration("selector must be a string or string array")),
        };
        let strategy_value = field(object, "strategy").unwrap_or(&Value::Null);
        let strategy_object = object_or_null(strategy_value, &empty, "strategy")?;
        let strategy_type = string_field(strategy_object, "type")?.to_lowercase();
        let settings = field(strategy_object, "settings").unwrap_or(&Value::Null);
        let settings = object_or_null(settings, &empty, "strategy settings")?;
        let strategy = match strategy_type.as_str() {
            "" | "random" => Strategy::Random,
            "roundrobin" => Strategy::RoundRobin,
            "leastping" => Strategy::LeastPing,
            "leastload" => Strategy::LeastLoad(parse_least_load(settings)?),
            _ => {
                return Err(configuration(format!(
                    "unknown balancing strategy: {strategy_type}"
                )));
            }
        };
        let config = Self {
            tag,
            selectors,
            fallback_tag: string_field(object, "fallbackTag")?,
            strategy,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.tag.is_empty() {
            return Err(configuration("empty balancer tag"));
        }
        if self.selectors.is_empty() {
            return Err(configuration("empty selector list"));
        }
        if let Strategy::LeastLoad(settings) = &self.strategy
            && (!settings.tolerance.is_finite()
                || settings.costs.iter().any(|cost| !cost.value.is_finite()))
        {
            return Err(configuration("non-finite typed least-load settings"));
        }
        Ok(())
    }

    /// Parent construction should require an observatory feature in these cases,
    /// just as the Go strategies' InjectContext does. Missing *reports* still use
    /// each strategy's documented fallback/fail-open behavior at decision time.
    pub fn requires_observatory(&self) -> bool {
        !self.fallback_tag.is_empty()
            || matches!(self.strategy, Strategy::LeastPing | Strategy::LeastLoad(_))
    }
}

fn object_or_null<'a>(
    value: &'a Value,
    empty: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>> {
    if value.is_null() {
        Ok(empty)
    } else {
        value
            .as_object()
            .ok_or_else(|| configuration(format!("{name} must be an object")))
    }
}

// Go matches JSON field names without regard to ASCII case. A serde_json::Value
// has already discarded duplicate keys; conflicting duplicate-case keys are not
// a supported source-order preservation API (see the integration note).
fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object.get(name).or_else(|| {
        object
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    })
}

fn string_field(object: &Map<String, Value>, name: &str) -> Result<String> {
    match field(object, name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(configuration(format!("{name} must be a string"))),
    }
}

fn parse_least_load(object: &Map<String, Value>) -> Result<LeastLoadConfig> {
    let mut settings = LeastLoadConfig::default();
    if let Some(value) = field(object, "expected").filter(|v| !v.is_null()) {
        settings.expected = value
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .ok_or_else(|| configuration("expected must be an int32"))?
            .max(0);
    }
    if let Some(value) = field(object, "tolerance").filter(|v| !v.is_null()) {
        let value = value
            .as_f64()
            .ok_or_else(|| configuration("tolerance must be a number"))?;
        settings.tolerance = (value as f32).clamp(0.0, 1.0);
    }
    if let Some(value) = field(object, "maxRTT") {
        settings.max_rtt = duration_value(value)?.max(0);
    }
    if let Some(value) = field(object, "baselines").filter(|v| !v.is_null()) {
        for value in value
            .as_array()
            .ok_or_else(|| configuration("baselines must be an array"))?
        {
            let duration = duration_value(value)?;
            if duration > 0 {
                // Source preserves order; sorting changes which baseline wins.
                settings.baselines.push(duration);
            }
        }
    }
    if let Some(value) = field(object, "costs").filter(|v| !v.is_null()) {
        for value in value
            .as_array()
            .ok_or_else(|| configuration("costs must be an array"))?
        {
            let cost = value
                .as_object()
                .ok_or_else(|| configuration("costs must contain objects, not null"))?;
            let regexp = match field(cost, "regexp") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(value)) => *value,
                _ => return Err(configuration("cost regexp must be boolean")),
            };
            let weight = match field(cost, "value").filter(|v| !v.is_null()) {
                None => 0.0,
                Some(value) => value
                    .as_f64()
                    .ok_or_else(|| configuration("cost value must be a number"))?
                    as f32,
            };
            if !weight.is_finite() {
                return Err(configuration("cost value exceeds float32 range"));
            }
            settings.costs.push(Weight {
                regexp,
                r#match: string_field(cost, "match")?,
                value: weight,
            });
        }
    }
    Ok(settings)
}

fn duration_value(value: &Value) -> Result<i64> {
    parse_duration(
        value
            .as_str()
            .ok_or_else(|| configuration("duration must be a Go duration string"))?,
    )
}

/// Parse signed Go-style h/m/s/ms/us/µs/μs/ns duration components. Integer
/// durations without a unit are rejected, except for the special literal zero.
/// Fractions truncate at nanosecond precision and totals use signed int64 bounds.
pub fn parse_duration(input: &str) -> Result<i64> {
    let invalid = || configuration(format!("invalid duration {input:?}"));
    let (negative, mut rest) = match input.as_bytes().first() {
        Some(b'-') => (true, &input[1..]),
        Some(b'+') => (false, &input[1..]),
        _ => (false, input),
    };
    if rest == "0" {
        return Ok(0);
    }
    if rest.is_empty() {
        return Err(invalid());
    }
    let limit = 1u64 << 63;
    let mut total = 0u64;
    while !rest.is_empty() {
        let digit_count = rest.bytes().take_while(u8::is_ascii_digit).count();
        let mut integer = if digit_count == 0 {
            0
        } else {
            rest[..digit_count].parse::<u64>().map_err(|_| invalid())?
        };
        rest = &rest[digit_count..];
        let mut fraction = 0u64;
        let mut scale = 1.0f64;
        let mut fraction_count = 0;
        if let Some(after_dot) = rest.strip_prefix('.') {
            rest = after_dot;
            fraction_count = rest.bytes().take_while(u8::is_ascii_digit).count();
            let mut overflow = false;
            for byte in rest[..fraction_count].bytes() {
                if !overflow {
                    if let Some(next) = fraction
                        .checked_mul(10)
                        .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                        .filter(|n| *n <= limit)
                    {
                        fraction = next;
                        scale *= 10.0;
                    } else {
                        overflow = true;
                    }
                }
            }
            rest = &rest[fraction_count..];
        }
        if digit_count == 0 && fraction_count == 0 {
            return Err(invalid());
        }
        let unit_end = rest
            .bytes()
            .position(|b| b.is_ascii_digit() || b == b'.')
            .unwrap_or(rest.len());
        let unit = match &rest[..unit_end] {
            "ns" => 1u64,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(invalid()),
        };
        rest = &rest[unit_end..];
        if integer > limit / unit {
            return Err(invalid());
        }
        integer *= unit;
        if fraction > 0 {
            let nanos = (fraction as f64 * (unit as f64 / scale)) as u64;
            integer = integer
                .checked_add(nanos)
                .filter(|n| *n <= limit)
                .ok_or_else(&invalid)?;
        }
        total = total
            .checked_add(integer)
            .filter(|n| *n <= limit)
            .ok_or_else(&invalid)?;
    }
    if negative {
        Ok((total as i64).wrapping_neg())
    } else {
        i64::try_from(total).map_err(|_| invalid())
    }
}

/// Native counterpart of outbound.Manager.Select: literal prefixes, no trimming,
/// one entry per registered nonempty tag, then lexicographic order.
pub fn select_outbounds(registered_tags: &[String], selectors: &[String]) -> Vec<String> {
    let mut selected: Vec<_> = registered_tags
        .iter()
        .filter(|tag| !tag.is_empty() && selectors.iter().any(|prefix| tag.starts_with(prefix)))
        .cloned()
        .collect();
    selected.sort();
    selected.dedup();
    selected
}

/// Report failures and wrong report types are distinct inputs for caller
/// diagnostics, but have the same decision effect. The source least-load type
/// assertion can panic; the native engine treats an invalid report as unavailable.
#[derive(Clone, Copy, Debug)]
pub enum Observation<'a> {
    Missing,
    Failed,
    InvalidType,
    Ready(&'a [OutboundStatus]),
}

impl<'a> From<&'a ObservationResult> for Observation<'a> {
    fn from(value: &'a ObservationResult) -> Self {
        Self::Ready(&value.status)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionSource {
    Strategy,
    Override,
    Fallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub tag: String,
    pub source: DecisionSource,
}

#[derive(Debug)]
enum Matcher {
    Literal(String),
    Regex(Regex),
    Invalid,
}

#[derive(Debug)]
struct CompiledWeight {
    matcher: Matcher,
    value: f32,
}

/// Weight rules are evaluated in declaration order. Nonpositive values request
/// automatic extraction of the first ASCII decimal number in the matched text.
/// Malformed regular expressions are skipped, as in the source WeightManager.
#[derive(Debug)]
pub struct WeightManager {
    rules: Vec<CompiledWeight>,
    invalid_patterns: Vec<String>,
    number: Regex,
}

impl WeightManager {
    pub fn new(weights: &[Weight]) -> Self {
        let mut invalid_patterns = Vec::new();
        let rules = weights
            .iter()
            .map(|weight| {
                let matcher = if weight.regexp {
                    match Regex::new(&weight.r#match) {
                        Ok(regex) => Matcher::Regex(regex),
                        Err(_) => {
                            invalid_patterns.push(weight.r#match.clone());
                            Matcher::Invalid
                        }
                    }
                } else {
                    Matcher::Literal(weight.r#match.clone())
                };
                CompiledWeight {
                    matcher,
                    value: weight.value,
                }
            })
            .collect();
        Self {
            rules,
            invalid_patterns,
            number: Regex::new(r"[0-9]+(\.[0-9]+)?").expect("fixed number regex"),
        }
    }

    pub fn invalid_patterns(&self) -> &[String] {
        &self.invalid_patterns
    }

    pub fn get(&self, tag: &str) -> f64 {
        for rule in &self.rules {
            let matched = match &rule.matcher {
                Matcher::Literal(pattern) if tag.contains(pattern) => pattern.as_str(),
                Matcher::Regex(regex) => regex.find(tag).map_or("", |found| found.as_str()),
                _ => "",
            };
            if matched.is_empty() {
                continue;
            }
            if rule.value > 0.0 {
                return f64::from(rule.value);
            }
            return self
                .number
                .find(matched)
                .and_then(|value| value.as_str().parse::<f64>().ok())
                .filter(|value| value.is_finite())
                .unwrap_or(1.0);
        }
        1.0
    }

    /// The least-load scaling function is deviation * sqrt(cost), not weighted
    /// random selection and not average RTT * cost.
    pub fn weighted_deviation(&self, tag: &str, deviation_ns: i64) -> Result<i64> {
        let scaled = deviation_ns as f64 * self.get(tag).sqrt();
        // Go float-to-duration overflow is implementation-dependent. Avoid Rust
        // saturation (a different silent decision) by reporting the unsupported
        // numerical range. Normal observatory durations are far below it.
        if !scaled.is_finite() || !(-((1u64 << 63) as f64)..(1u64 << 63) as f64).contains(&scaled) {
            return Err(Error::CostOutOfRange(tag.to_owned()));
        }
        Ok(scaled as i64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadNode {
    pub tag: String,
    pub count_all: i64,
    pub count_fail: i64,
    pub average_ns: i64,
    pub deviation_ns: i64,
    pub deviation_cost_ns: i64,
}

#[derive(Debug, Default)]
struct State {
    index: usize,
    override_target: String,
}

#[derive(Debug)]
pub struct Balancer {
    config: BalancerConfig,
    weights: WeightManager,
    state: Mutex<State>,
}

impl Balancer {
    pub fn new(config: BalancerConfig) -> Result<Self> {
        config.validate()?;
        let weights = WeightManager::new(match &config.strategy {
            Strategy::LeastLoad(settings) => &settings.costs,
            _ => &[],
        });
        Ok(Self {
            config,
            weights,
            state: Mutex::new(State::default()),
        })
    }

    pub fn config(&self) -> &BalancerConfig {
        &self.config
    }
    pub fn invalid_weight_patterns(&self) -> &[String] {
        self.weights.invalid_patterns()
    }

    /// Empty clears the override. Source allows tags outside selectors and does
    /// not validate whether the tag exists; final outbound dispatch owns that.
    pub fn set_override(&self, target: impl Into<String>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .override_target = target.into();
    }

    pub fn override_target(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .override_target
            .clone()
    }

    /// `draw(n)` must return a uniform integer in 0..n; inject a scripted sampler
    /// in tests. It is never called for zero/one candidate or deterministic modes.
    /// Registry selection applies source prefix matching, sorting and deduplication.
    pub fn pick(
        &self,
        registered: &[String],
        observation: Observation<'_>,
        draw: impl FnMut(usize) -> usize,
    ) -> Result<Decision> {
        let selected = select_outbounds(registered, &self.config.selectors);
        self.pick_selected(Ok(&selected), observation, draw)
    }

    /// Already-selected candidates permit custom HandlerSelector integration.
    /// Selection failure is processed BEFORE override, matching Balancer.PickOutbound.
    pub fn pick_selected(
        &self,
        selected: std::result::Result<&[String], &str>,
        observation: Observation<'_>,
        mut draw: impl FnMut(usize) -> usize,
    ) -> Result<Decision> {
        let candidates = match selected {
            Ok(tags) => tags,
            Err(message) => return self.fallback(Error::Selection(message.to_owned())),
        };
        let override_target = self.override_target();
        if !override_target.is_empty() {
            return Ok(Decision {
                tag: override_target,
                source: DecisionSource::Override,
            });
        }
        let tag = match &self.config.strategy {
            Strategy::LeastPing => least_ping(candidates, observation),
            Strategy::LeastLoad(settings) => {
                let nodes = self.load_nodes(candidates, observation)?;
                let count = least_load_count(&nodes, settings);
                sample(count, &mut draw)?
                    .map(|index| nodes[index].tag.clone())
                    .unwrap_or_default()
            }
            Strategy::Random | Strategy::RoundRobin => {
                let eligible = self.random_eligible(candidates, observation);
                let index = if eligible.is_empty() {
                    None
                } else if matches!(self.config.strategy, Strategy::Random) {
                    sample(eligible.len(), &mut draw)?
                } else {
                    let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    let index = state.index % eligible.len();
                    state.index = (state.index + 1) % eligible.len();
                    Some(index)
                };
                index
                    .map(|index| eligible[index].clone())
                    .unwrap_or_default()
            }
        };
        if tag.is_empty() {
            self.fallback(Error::EmptyChoice)
        } else {
            Ok(Decision {
                tag,
                source: DecisionSource::Strategy,
            })
        }
    }

    fn fallback(&self, error: Error) -> Result<Decision> {
        if self.config.fallback_tag.is_empty() {
            Err(error)
        } else {
            Ok(Decision {
                tag: self.config.fallback_tag.clone(),
                source: DecisionSource::Fallback,
            })
        }
    }

    fn random_eligible<'a>(
        &self,
        candidates: &'a [String],
        observation: Observation<'_>,
    ) -> Vec<&'a String> {
        if self.config.fallback_tag.is_empty() {
            return candidates.iter().collect();
        }
        let Observation::Ready(status) = observation else {
            return candidates.iter().collect();
        };
        // Last duplicate observation wins only for random/round-robin, as in the
        // source map assignment. Unknown candidates are considered alive.
        let health: HashMap<_, _> = status
            .iter()
            .map(|v| (v.outbound_tag.as_str(), v.alive))
            .collect();
        candidates
            .iter()
            .filter(|tag| health.get(tag.as_str()).copied().unwrap_or(true))
            .collect()
    }

    /// Source GetPrincipleTarget is not a preview of the next random/round-robin
    /// pick: those modes return all selected tags, without filtering health.
    /// Least-ping returns one empty string when no observation can win.
    pub fn principle_targets(
        &self,
        registered: &[String],
        observation: Observation<'_>,
    ) -> Result<Vec<String>> {
        let selected = select_outbounds(registered, &self.config.selectors);
        self.principle_targets_selected(&selected, observation)
    }

    pub fn principle_targets_selected(
        &self,
        candidates: &[String],
        observation: Observation<'_>,
    ) -> Result<Vec<String>> {
        Ok(match &self.config.strategy {
            Strategy::Random | Strategy::RoundRobin => candidates.to_vec(),
            Strategy::LeastPing => vec![least_ping(candidates, observation)],
            Strategy::LeastLoad(settings) => {
                let mut nodes = self.load_nodes(candidates, observation)?;
                nodes.truncate(least_load_count(&nodes, settings));
                nodes.into_iter().map(|node| node.tag).collect()
            }
        })
    }

    /// Qualified, fully sorted least-load nodes before baseline/expected limits.
    /// Delay is milliseconds; burst average/deviation and costs are nanoseconds.
    pub fn load_nodes(
        &self,
        candidates: &[String],
        observation: Observation<'_>,
    ) -> Result<Vec<LoadNode>> {
        let Strategy::LeastLoad(settings) = &self.config.strategy else {
            return Ok(Vec::new());
        };
        let Observation::Ready(status) = observation else {
            return Ok(Vec::new());
        };
        let mut nodes = Vec::new();
        for value in status {
            if !value.alive
                || !candidates.contains(&value.outbound_tag)
                || (settings.max_rtt != 0 && value.delay >= settings.max_rtt / MILLIS)
                || value.health_ping.as_ref().is_some_and(|health| {
                    health.all > 0
                        && settings.tolerance > 0.0
                        && health.fail as f64 / health.all as f64 > f64::from(settings.tolerance)
                })
            {
                continue;
            }
            let mut node = LoadNode {
                tag: value.outbound_tag.clone(),
                count_all: 1,
                count_fail: 1,
                average_ns: value.delay.wrapping_mul(MILLIS),
                deviation_ns: value.delay.wrapping_mul(MILLIS),
                deviation_cost_ns: 0,
            };
            if let Some(health) = &value.health_ping {
                node.count_all = health.all;
                node.count_fail = health.fail;
                node.average_ns = health.average;
                node.deviation_ns = health.deviation;
            }
            node.deviation_cost_ns = self
                .weights
                .weighted_deviation(&node.tag, node.deviation_ns)?;
            nodes.push(node);
        }
        nodes.sort_by(|left, right| {
            left.deviation_cost_ns
                .cmp(&right.deviation_cost_ns)
                .then_with(|| left.average_ns.cmp(&right.average_ns))
                .then_with(|| left.count_fail.cmp(&right.count_fail))
                .then_with(|| right.count_all.cmp(&left.count_all))
                .then_with(|| left.tag.cmp(&right.tag))
        });
        Ok(nodes)
    }
}

fn sample(length: usize, draw: &mut impl FnMut(usize) -> usize) -> Result<Option<usize>> {
    match length {
        0 => Ok(None),
        1 => Ok(Some(0)),
        _ => {
            let index = draw(length);
            if index < length {
                Ok(Some(index))
            } else {
                Err(Error::InvalidSample { index, length })
            }
        }
    }
}

fn least_ping(candidates: &[String], observation: Observation<'_>) -> String {
    let Observation::Ready(status) = observation else {
        return String::new();
    };
    let mut least = LEAST_PING_SENTINEL;
    let mut selected = String::new();
    // Observation order, not candidate order, decides equal-delay ties.
    for value in status {
        if value.alive && value.delay < least && candidates.contains(&value.outbound_tag) {
            least = value.delay;
            selected.clone_from(&value.outbound_tag);
        }
    }
    selected
}

fn least_load_count(nodes: &[LoadNode], settings: &LeastLoadConfig) -> usize {
    if nodes.is_empty() {
        return 0;
    }
    if settings.expected > 0 && settings.expected as usize > nodes.len() {
        return nodes.len();
    }
    let expected = settings.expected.max(1) as usize;
    if settings.baselines.is_empty() {
        return expected;
    }
    let mut count = 0;
    for baseline in &settings.baselines {
        while count < nodes.len() && nodes[count].deviation_cost_ns < *baseline {
            count += 1;
        }
        if count >= expected {
            break;
        }
    }
    if settings.expected > 0 {
        count.max(expected)
    } else {
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tags(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }
    fn config(strategy: Strategy, fallback: &str) -> BalancerConfig {
        BalancerConfig {
            tag: "balance".into(),
            selectors: vec![String::new()],
            fallback_tag: fallback.into(),
            strategy,
        }
    }
    fn status(tag: &str, alive: bool, delay: i64) -> OutboundStatus {
        OutboundStatus {
            outbound_tag: tag.into(),
            alive,
            delay,
            ..Default::default()
        }
    }
    fn burst(
        tag: &str,
        delay: i64,
        average: i64,
        deviation: i64,
        all: i64,
        fail: i64,
    ) -> OutboundStatus {
        OutboundStatus {
            health_ping: Some(HealthPingMeasurementResult {
                average,
                deviation,
                all,
                fail,
                ..Default::default()
            }),
            ..status(tag, true, delay)
        }
    }
    fn no_random(_: usize) -> usize {
        panic!("deterministic choice must not request randomness")
    }

    #[test]
    fn selector_prefixes_sort_deduplicate_and_do_not_trim() {
        let registered = tags(&["node-b", "other", "node-a", "node-a", "", " node-c"]);
        assert_eq!(
            select_outbounds(&registered, &tags(&["node-", "node-a"])),
            tags(&["node-a", "node-b"])
        );
        assert_eq!(
            select_outbounds(&registered, &tags(&[""])),
            tags(&[" node-c", "node-a", "node-b", "other"])
        );
        assert!(select_outbounds(&registered, &[]).is_empty());
    }

    #[test]
    fn loader_defaults_clamps_and_preserves_baseline_order() {
        let parsed = BalancerConfig::from_json(&json!({"tag":"pool","selector":"node, other","strategy":{"type":"LEASTLOAD","settings":{"expected":-4,"tolerance":2,"maxRTT":"-3s","baselines":["400ms","0","-1s","200ms"],"costs":[{"match":"x8"}]}}})).unwrap();
        assert_eq!(parsed.selectors, tags(&["node", " other"]));
        let Strategy::LeastLoad(settings) = parsed.strategy else {
            panic!("wrong strategy")
        };
        assert_eq!(settings.expected, 0);
        assert_eq!(settings.tolerance, 1.0);
        assert_eq!(settings.max_rtt, 0);
        assert_eq!(settings.baselines, [400_000_000, 200_000_000]);
        assert_eq!(settings.costs[0].value, 0.0);
        assert_eq!(
            BalancerConfig::from_json(&json!({"tag":"p","selector":""}))
                .unwrap()
                .strategy,
            Strategy::Random
        );
        assert_eq!(
            BalancerConfig::from_json(&json!({"TAG":"p","SELECTOR":[null]}))
                .unwrap()
                .selectors,
            tags(&[""])
        );
    }

    #[test]
    fn loader_rejects_missing_fields_types_and_invalid_durations() {
        for value in [
            json!({}),
            json!({"tag":"p","selector":[]}),
            json!({"tag":"p","selector":"a","strategy":{"type":" random"}}),
            json!({"tag":"p","selector":9}),
        ] {
            assert!(BalancerConfig::from_json(&value).is_err(), "{value}");
        }
        for settings in [
            json!({"expected":1.5}),
            json!({"maxRTT":100}),
            json!({"maxRTT":null}),
            json!({"baselines":[null]}),
            json!({"costs":[null]}),
            json!({"costs":[{"value":1e99}]}),
        ] {
            assert!(BalancerConfig::from_json(&json!({"tag":"p","selector":"a","strategy":{"type":"leastload","settings":settings}})).is_err());
        }
    }

    #[test]
    fn go_duration_bounds_fractional_units_and_micro_aliases() {
        for (input, expected) in [
            ("0", 0),
            ("-0", 0),
            ("+0", 0),
            ("1h2m3.4s", 3_723_400_000_000),
            (".5ms", 500_000),
            ("1.s", 1_000_000_000),
            ("1us2µs3μs", 6_000),
            ("1.9ns", 1),
            ("-1.9ns", -1),
            ("9223372036854775807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
        ] {
            assert_eq!(parse_duration(input).unwrap(), expected, "{input}");
        }
        for input in [
            "",
            "+",
            "1",
            " 1s",
            "1d",
            "1s-2s",
            ".s",
            "9223372036854775808ns",
            "-9223372036854775809ns",
            "2562048h",
        ] {
            assert!(parse_duration(input).is_err(), "{input}");
        }
    }

    #[test]
    fn source_weight_test_fixture_and_first_match_semantics() {
        // Literal expectations copied from app/router/weight_test.go:TestWeight.
        let manager = WeightManager::new(&[
            Weight {
                r#match: "x5".into(),
                value: 100.0,
                ..Default::default()
            },
            Weight {
                r#match: "x8".into(),
                ..Default::default()
            },
            Weight {
                r#match: r"\bx0+(\.\d+)?\b".into(),
                regexp: true,
                value: 1.0,
            },
            Weight {
                r#match: r"\bx\d+(\.\d+)?\b".into(),
                regexp: true,
                ..Default::default()
            },
        ]);
        for (tag, weight) in [
            ("node name, x5, and more", 100.0),
            ("node name, x8", 8.0),
            ("node name, x15", 15.0),
            ("node name, x0100, and more", 100.0),
            ("node name, x10.1", 10.1),
            ("node name, x00.1, and more", 1.0),
        ] {
            assert_eq!(manager.get(tag), weight, "{tag}");
        }
        let manager = WeightManager::new(&[
            Weight {
                r#match: "[".into(),
                regexp: true,
                value: 5.0,
            },
            Weight {
                r#match: String::new(),
                value: 8.0,
                ..Default::default()
            },
            Weight {
                r#match: "zero0".into(),
                value: -2.0,
                ..Default::default()
            },
            Weight {
                r#match: "word".into(),
                ..Default::default()
            },
            Weight {
                r#match: "word".into(),
                value: 100.0,
                ..Default::default()
            },
        ]);
        assert_eq!(manager.invalid_patterns(), &["["]);
        assert_eq!(manager.get("zero0"), 0.0);
        assert_eq!(manager.get("word"), 1.0);
        assert_eq!(manager.get("anything"), 1.0);
        assert_eq!(manager.weighted_deviation("zero0", 123).unwrap(), 0);
    }

    #[test]
    fn random_health_filter_is_enabled_only_with_fallback_and_last_duplicate_wins() {
        let candidates = tags(&["a", "b", "c"]);
        let reports = [
            status("a", false, 1),
            status("b", false, 2),
            status("b", true, 3),
        ];
        let plain = Balancer::new(config(Strategy::Random, "")).unwrap();
        assert_eq!(
            plain
                .pick(&candidates, Observation::Ready(&reports), |n| {
                    assert_eq!(n, 3);
                    0
                })
                .unwrap()
                .tag,
            "a"
        );
        let health = Balancer::new(config(Strategy::Random, "fallback")).unwrap();
        assert_eq!(
            health
                .pick(&candidates, Observation::Ready(&reports), |n| {
                    assert_eq!(n, 2);
                    1
                })
                .unwrap()
                .tag,
            "c"
        );
        for observation in [
            Observation::Missing,
            Observation::Failed,
            Observation::InvalidType,
        ] {
            assert_eq!(
                health
                    .pick(&candidates, observation, |n| {
                        assert_eq!(n, 3);
                        0
                    })
                    .unwrap()
                    .tag,
                "a"
            );
        }
        assert_eq!(
            health
                .principle_targets(&candidates, Observation::Ready(&reports))
                .unwrap(),
            candidates
        );
    }

    #[test]
    fn random_singleton_does_not_consume_sampler_and_invalid_sample_is_an_error() {
        let balancer = Balancer::new(config(Strategy::Random, "fallback")).unwrap();
        assert_eq!(
            balancer
                .pick(&tags(&["a"]), Observation::Missing, no_random)
                .unwrap()
                .tag,
            "a"
        );
        assert!(matches!(
            balancer.pick(&tags(&["a", "b"]), Observation::Missing, |n| n),
            Err(Error::InvalidSample { .. })
        ));
    }

    #[test]
    fn all_dead_falls_back_but_empty_report_leaves_unknown_candidates_alive() {
        for strategy in [Strategy::Random, Strategy::RoundRobin] {
            assert!(!config(strategy.clone(), "").requires_observatory());
            let settings = config(strategy, "fallback");
            assert!(settings.requires_observatory());
            let balancer = Balancer::new(settings).unwrap();
            let candidates = tags(&["a"]);
            assert_eq!(
                balancer
                    .pick(&candidates, Observation::Ready(&[]), no_random)
                    .unwrap()
                    .tag,
                "a"
            );
            assert_eq!(
                balancer
                    .pick(
                        &candidates,
                        Observation::Ready(&[status("a", false, 1)]),
                        no_random
                    )
                    .unwrap()
                    .source,
                DecisionSource::Fallback
            );
        }
        assert!(config(Strategy::LeastPing, "").requires_observatory());
        assert!(config(Strategy::LeastLoad(LeastLoadConfig::default()), "").requires_observatory());
    }

    #[test]
    fn fallback_override_and_selection_error_order_match_source() {
        let balancer = Balancer::new(config(Strategy::Random, "fallback")).unwrap();
        balancer.set_override("not-in-selectors");
        assert_eq!(
            balancer
                .pick_selected(Err("manager unavailable"), Observation::Missing, no_random)
                .unwrap()
                .source,
            DecisionSource::Fallback
        );
        assert_eq!(
            balancer
                .pick(&[], Observation::Missing, no_random)
                .unwrap()
                .tag,
            "not-in-selectors"
        );
        balancer.set_override("");
        assert_eq!(
            balancer
                .pick(&[], Observation::Missing, no_random)
                .unwrap()
                .tag,
            "fallback"
        );
        let plain = Balancer::new(config(Strategy::Random, "")).unwrap();
        assert_eq!(
            plain
                .pick(&[], Observation::Missing, no_random)
                .unwrap_err(),
            Error::EmptyChoice
        );
        plain.set_override("forced");
        assert_eq!(
            plain
                .pick_selected(Err("failure"), Observation::Missing, no_random)
                .unwrap_err(),
            Error::Selection("failure".into())
        );
    }

    #[test]
    fn round_robin_index_survives_candidate_count_changes_and_overrides() {
        let balancer = Balancer::new(config(Strategy::RoundRobin, "fallback")).unwrap();
        let all = tags(&["c", "a", "b"]);
        assert_eq!(
            balancer
                .pick(&all, Observation::Missing, no_random)
                .unwrap()
                .tag,
            "a"
        );
        balancer.set_override("forced");
        assert_eq!(
            balancer
                .pick(&all, Observation::Missing, no_random)
                .unwrap()
                .tag,
            "forced"
        );
        balancer.set_override("");
        assert_eq!(
            balancer
                .pick(
                    &all,
                    Observation::Ready(&[status("b", false, 1)]),
                    no_random
                )
                .unwrap()
                .tag,
            "c"
        );
        assert_eq!(
            balancer
                .pick(&all, Observation::Missing, no_random)
                .unwrap()
                .tag,
            "a"
        );
        assert_eq!(
            balancer
                .pick(&all, Observation::Missing, no_random)
                .unwrap()
                .tag,
            "b"
        );
    }

    #[test]
    fn least_ping_uses_report_order_strict_sentinel_and_alive_only() {
        let balancer = Balancer::new(config(Strategy::LeastPing, "fallback")).unwrap();
        let candidates = tags(&["a", "b", "c"]);
        let reports = [
            status("a", false, 0),
            status("b", true, 5),
            status("c", true, 5),
            status("unselected", true, 1),
        ];
        assert_eq!(
            balancer
                .pick(&candidates, Observation::Ready(&reports), no_random)
                .unwrap()
                .tag,
            "b"
        );
        assert_eq!(
            balancer
                .pick(
                    &candidates,
                    Observation::Ready(&[status("a", true, LEAST_PING_SENTINEL)]),
                    no_random
                )
                .unwrap()
                .tag,
            "fallback"
        );
        assert_eq!(
            balancer
                .pick(
                    &candidates,
                    Observation::Ready(&[status("a", true, -1)]),
                    no_random
                )
                .unwrap()
                .tag,
            "a"
        );
        assert_eq!(
            balancer
                .principle_targets(&candidates, Observation::Failed)
                .unwrap(),
            tags(&[""])
        );
    }

    #[test]
    fn source_leastload_baseline_expected_fixtures() {
        // Literal inputs/answers from strategy_leastload_test.go, not derived
        // by running this selector to generate expected values.
        for (costs, baselines, expected, count) in [
            (vec![100, 200, 300, 350], vec![], 3, 3),
            (vec![100, 200], vec![], 3, 2),
            (vec![100, 200, 250, 300, 310], vec![200, 300, 400], 3, 3),
            (vec![500, 600, 700, 800, 900], vec![200, 300, 400], 3, 3),
            (vec![100, 200, 300], vec![200, 400, 600], 0, 1),
            (vec![800, 1000], vec![200, 400, 600], 0, 0),
        ] {
            let nodes: Vec<_> = costs
                .into_iter()
                .map(|cost| LoadNode {
                    tag: String::new(),
                    count_all: 1,
                    count_fail: 1,
                    average_ns: cost,
                    deviation_ns: cost,
                    deviation_cost_ns: cost,
                })
                .collect();
            assert_eq!(
                least_load_count(
                    &nodes,
                    &LeastLoadConfig {
                        baselines,
                        expected,
                        ..Default::default()
                    }
                ),
                count
            );
        }
    }

    #[test]
    fn leastload_baselines_can_expand_pool_and_are_not_sorted() {
        let reports = [
            burst("a", 1, 100, 100, 3, 0),
            burst("b", 1, 200, 200, 3, 0),
            burst("c", 1, 300, 300, 3, 0),
        ];
        let candidates = tags(&["a", "b", "c"]);
        let balancer = Balancer::new(config(
            Strategy::LeastLoad(LeastLoadConfig {
                expected: 1,
                baselines: vec![301, 101],
                ..Default::default()
            }),
            "",
        ))
        .unwrap();
        assert_eq!(
            balancer
                .principle_targets(&candidates, Observation::Ready(&reports))
                .unwrap(),
            candidates
        );
        assert_eq!(
            balancer
                .pick(&candidates, Observation::Ready(&reports), |n| {
                    assert_eq!(n, 3);
                    2
                })
                .unwrap()
                .tag,
            "c"
        );
    }

    #[test]
    fn leastload_qualification_uses_delay_for_max_rtt_and_float32_tolerance() {
        let settings = LeastLoadConfig {
            max_rtt: 100_999_999,
            tolerance: 0.1,
            ..Default::default()
        };
        let balancer = Balancer::new(config(Strategy::LeastLoad(settings), "fallback")).unwrap();
        let reports = [
            burst("equal", 100, 1, 1, 10, 0),
            burst("kept", 99, 999_000_000, 5, 10, 1),
            burst("failed", 1, 1, 1, 10, 2),
            burst("zero", 1, 1, 6, 0, 100),
        ];
        let candidates = tags(&["equal", "kept", "failed", "zero"]);
        let nodes = balancer
            .load_nodes(&candidates, Observation::Ready(&reports))
            .unwrap();
        assert_eq!(
            nodes.iter().map(|n| n.tag.as_str()).collect::<Vec<_>>(),
            ["kept", "zero"]
        );
        assert_eq!(nodes[0].average_ns, 999_000_000);
        assert_eq!(
            balancer
                .pick(&candidates, Observation::Failed, no_random)
                .unwrap()
                .tag,
            "fallback"
        );
    }

    #[test]
    fn leastload_cost_sqrt_and_complete_sort_tiebreaks() {
        let balancer = Balancer::new(config(
            Strategy::LeastLoad(LeastLoadConfig {
                expected: 20,
                costs: vec![Weight {
                    r#match: "cost9".into(),
                    value: 9.0,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            "",
        ))
        .unwrap();
        let reports = [
            burst("cost9", 1, 1, 40, 10, 0),
            burst("average", 1, 90, 60, 10, 0),
            burst("fail", 1, 100, 60, 10, 2),
            burst("count", 1, 100, 60, 20, 1),
            burst("z", 1, 100, 60, 10, 1),
            burst("a", 1, 100, 60, 10, 1),
        ];
        let candidates = tags(&["cost9", "average", "fail", "count", "z", "a"]);
        let nodes = balancer
            .load_nodes(&candidates, Observation::Ready(&reports))
            .unwrap();
        assert_eq!(
            nodes.iter().map(|n| n.tag.as_str()).collect::<Vec<_>>(),
            ["average", "count", "a", "z", "fail", "cost9"]
        );
        assert_eq!(nodes.last().unwrap().deviation_cost_ns, 120);
    }

    #[test]
    fn leastload_classic_reports_use_ms_as_ns_and_one_failure_count() {
        let balancer =
            Balancer::new(config(Strategy::LeastLoad(LeastLoadConfig::default()), "")).unwrap();
        let nodes = balancer
            .load_nodes(&tags(&["a"]), Observation::Ready(&[status("a", true, 17)]))
            .unwrap();
        assert_eq!(
            nodes[0],
            LoadNode {
                tag: "a".into(),
                count_all: 1,
                count_fail: 1,
                average_ns: 17_000_000,
                deviation_ns: 17_000_000,
                deviation_cost_ns: 17_000_000
            }
        );
        let manager = WeightManager::new(&[Weight {
            r#match: "a".into(),
            value: f32::MAX,
            ..Default::default()
        }]);
        assert!(matches!(
            manager.weighted_deviation("a", i64::MAX),
            Err(Error::CostOutOfRange(_))
        ));
    }

    #[test]
    fn round_robin_is_serialized_across_concurrent_picks() {
        let balancer =
            std::sync::Arc::new(Balancer::new(config(Strategy::RoundRobin, "")).unwrap());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let balancer = std::sync::Arc::clone(&balancer);
                std::thread::spawn(move || {
                    (0..30)
                        .map(|_| {
                            balancer
                                .pick(&tags(&["a", "b", "c"]), Observation::Missing, no_random)
                                .unwrap()
                                .tag
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut counts = HashMap::new();
        for task in threads {
            for tag in task.join().unwrap() {
                *counts.entry(tag).or_insert(0) += 1;
            }
        }
        assert_eq!(counts.get("a"), Some(&80));
        assert_eq!(counts.get("b"), Some(&80));
        assert_eq!(counts.get("c"), Some(&80));
    }
}
