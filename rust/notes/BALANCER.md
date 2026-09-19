# Native routing-balancer decision engine

`rust/xray-core/src/router/balancer.rs` implements pure native selection for
`random`, `roundrobin`, `leastping`, and `leastload`. It opens no sockets and does
not probe destinations or run an observatory scheduler. The caller supplies an
immutable report snapshot and the current outbound registry. This is a component
for the parent router, not a claim that JSON `balancerTag` is already integrated.

## Integration API

The parent has declared `pub mod balancer;` in `router.rs`. Dependencies are already
present: `std`, `regex`, `serde_json`, and `xray-proto`; no manifest edit is needed.

```rust,ignore
use xray_core::router::balancer::{Balancer, BalancerConfig, Observation};
use rand::Rng;

let balancer = Balancer::new(BalancerConfig::from_json(&balancer_json)?)?;
// Validate that an observatory feature exists if this returns true.
let needs_observatory = balancer.config().requires_observatory();
let decision = balancer.pick(
    &registered_outbound_tags,
    Observation::from(&report),
    |n| rand::thread_rng().gen_range(0..n),
)?;
// Resolve decision.tag through the parent outbound registry.
```

| API | Purpose |
| --- | --- |
| `BalancerConfig::from_json(&Value)` | Convert one `routing.balancers` item with source defaults/normalization. |
| `Balancer::new(config)` | Compile weight matchers; own round-robin/override state. Typed protobuf least-load settings may be supplied directly through `Strategy::LeastLoad`. |
| `pick(&[String], Observation, draw)` | Apply normal outbound-manager prefix selection, then strategy/override/fallback. |
| `pick_selected(Result<&[String], &str>, Observation, draw)` | Integrate a custom selector or represent a manager selection error. Preserves already-selected ordering/duplicates. |
| `principle_targets` / `principle_targets_selected` | Source `GetPrincipleTarget` semantics, including its spelling and unusual empty least-ping result. Does not advance round-robin state. |
| `set_override` / `override_target` | Thread-safe management override; empty string clears it. |
| `load_nodes` | Qualified and sorted least-load records before baseline/expected limits, for inspection. |
| `select_outbounds` | Literal-prefix selector, sorted and deduplicated over registered nonempty tags. |
| `WeightManager` | First matching cost rule, automatic decimal extraction, weighted deviation and invalid-regex diagnostics. |
| `parse_duration` | Signed Go-style duration strings with h/m/s/ms/us/µs/μs/ns components and int64 bounds. |

`Decision` includes a tag and `DecisionSource::{Strategy, Override, Fallback}`.
`Error::EmptyChoice` corresponds to the source empty-strategy error; the parent
router decides whether that means use its default handler. The engine does not
invent an outbound for that error. Invalid sampler indices and unsupported
numeric-cost ranges are explicit errors, not hidden fallbacks.

The caller's `draw(n)` must be uniform in `0..n`. Scripted indices make tests
deterministic without depending on Go/Rust PRNG implementation. No sampler is
called for zero/one candidate or for least-ping/round-robin. Random and least-load
selection is uniform over eligible entries, not weighted random sampling.

The module reexports the original generated `LeastLoadConfig`, `Weight`,
`ObservationResult`, `OutboundStatus`, and `HealthPingMeasurementResult` types.
The observatory package is `xray_proto::xray::core::app::observatory`; the router
settings package is `xray_proto::xray::app::router`. `OutboundStatus.delay` is in
milliseconds. Burst `average`/`deviation` and baseline/maxRTT settings are signed
nanoseconds. No unit conversion is needed when passing generated reports.

## Preserved source behavior

Source references:

- `infra/conf/router.go:BalancingRule.Build`
- `infra/conf/router_strategy.go:strategyLeastLoadConfig.Build`
- `infra/conf/common.go:StringList.UnmarshalJSON`
- `infra/conf/cfgcommon/duration/duration.go`
- `app/proxyman/outbound/outbound.go:Manager.Select`
- `app/router/{balancing,balancing_override,strategy_random,strategy_leastping,strategy_leastload,weight}.go`
- `app/observatory/config.proto` and `app/observatory/burst/burstobserver.go:createResult`

Configuration requires a nonempty balancer tag and nonempty selector list. An
empty selector *element* is allowed and matches every registered tag. A string
selector is split on commas without trimming; overlapping selectors do not
duplicate an outbound. The source manager sorts its result, so normal selection
does too. Strategy names are case-insensitive, empty means random, and whitespace
is not stripped. Random/round-robin/least-ping ignore object fields inside their
otherwise-empty strategy settings, as their source builders do.

The JSON least-load builder clamps expected count below zero to zero, negative
maxRTT to zero, tolerance to `[0, 1]` after conversion to float32, and removes
nonpositive baselines. Baseline order is preserved, **not sorted**. Cost values
retain protobuf float32 precision. Typed settings supplied directly to `new`
preserve their values instead of running this JSON normalization again.

Selection errors happen before checking override. A configured fallback wins
over a selection failure even if an override exists. On successful selection,
a nonempty override bypasses strategy/health and can name a tag outside the
selectors or registry. Neither fallback nor override is recursively balanced or
validated here. Parent dispatch owns tag lookup.

Random and round-robin subscribe to health **only when fallbackTag is nonempty**.
They retain unobserved candidates, remove known dead ones, and keep all candidates
if report retrieval fails or returns an unknown report type. Last duplicate
status wins when building their health map. An empty successful report therefore
does not mean every node is dead. `requires_observatory()` reports the source
feature-construction dependency separately from these report-time behaviors.

Round-robin selects `index % current_count` and updates
`index = (index + 1) % current_count`, including after membership changes. Empty
selection and overrides do not advance the index. A mutex serializes this state
across concurrent callers.

Least-ping scans the original report order, requires an alive selected outbound,
and replaces the winner only for a strictly smaller delay. Equal delays retain
the first report entry, not the first sorted candidate. The source initial limit
is **99,999,999 milliseconds**, not int64 maximum; entries at/above that value do
not win. It does not consult burst deviation/failure ratio or add an age cutoff.
Its principle-target API returns `[""]` when no node wins, as the source does.

Least-load eligibility checks alive status, candidate membership, and
`delay < maxRTT.Milliseconds()` when maxRTT is nonzero. This uses the report's
classic delay even if burst average differs. A positive sub-millisecond maxRTT
becomes zero milliseconds. A burst failure ratio is rejected only when `all > 0`,
tolerance is positive, and `fail / all > float64(float32(tolerance))`; equality is
accepted and zero tolerance disables that filter.

Classic reports become nodes with average/deviation `delay * 1,000,000` and
counts `all = fail = 1`. Burst statistics replace those values. Costs apply as
`deviation * sqrt(cost)`, truncated to nanoseconds. Nodes sort by:

1. weighted deviation ascending;
2. average ascending;
3. failure count ascending;
4. total count descending;
5. outbound tag ascending.

Cost rules use first nonempty matching substring/regexp match. A positive value
is explicit; zero/negative values extract the first ASCII decimal number from
the matched text, defaulting to one if absent or unparseable. Automatic zero is
valid. Invalid regex rules are ignored, and `invalid_weight_patterns()` lets the
parent log them. The engine compiles regexes once rather than recompiling and
caching a value for every tag; this changes cost, not matching precedence.

With no baselines, least-load picks the first `max(expected, 1)` qualified nodes,
limited by availability. With baselines it includes nodes whose weighted
deviation is **strictly below** each baseline, stopping at the first baseline
that includes the expected minimum. That may yield more nodes than expected.
Positive expected count supplies a minimum if no baseline reaches it; zero
expected count supplies no such guarantee and can return an empty pool. If
expected exceeds all available nodes, the source returns them immediately,
without considering baselines. These boundary cases are preserved.

## Explicit limits and remaining integration

- No probing, HTTP health requests, timeout scheduling, burst RTT collection,
  cache expiry, report publication, outbound add/remove notification, webhook,
  management RPC wiring or router `balancerTag` dispatch is added here. Parent
  configuration/feature wiring must enforce required observer availability.
- Supply a consistent snapshot; this engine does not mutate source observation
  data or apply freshness checks absent from the source strategy. Report timestamps,
  diagnostic strings, and burst min/max are preserved in generated types but are
  not used by these selection rules.
- Rust `regex` and Go regexp do not have identical syntax/Unicode classes or
  word-boundary semantics. The source ASCII weight fixtures are covered; arbitrary
  Go-regex parity is not claimed. Unsupported expressions may be reported as
  invalid patterns. Exact RE2-compatible regex behavior remains integration work.
- Float-to-int64 conversion for out-of-range weighted durations is
  implementation-dependent in Go. This engine returns `CostOutOfRange` instead
  of silently saturating or claiming a platform-dependent match. Ordinary bounded
  probe durations are supported; nonfinite typed settings are rejected.
- A wrong observatory result type yields an unavailable report instead of the
  source least-load unchecked type assertion panic. JSON null cost entries are
  rejected instead of allowing a later nil-pointer panic. These are explicit
  failure-handling differences.
- JSON is consumed as `serde_json::Value`. Ordinary ASCII case-insensitive field
  matching is supported, but repeated/conflicting field-case keys cannot retain
  all source JSON decoding order after parsing into that map. Pass normalized,
  unambiguous configuration. Unknown fields are ignored like the ordinary Go
  loader; this component does not silently implement them.
- No equivalence between the Go and Rust PRNG sequences is claimed. The caller
  controls entropy quality and seeding; the engine enforces bounded sampler output.

## Verification

The module has 17 standalone tests. They include the literal answers from
`app/router/weight_test.go:TestWeight` and all six active baseline/expected-count
fixtures in `app/router/strategy_leastload_test.go`, plus source-derived eligibility,
float32 tolerance, ordering, health/fallback/override, duration bounds, selector
and concurrent round-robin cases. Expected fixture values were copied from source
tests or derived directly from source branch conditions, not generated by the
new implementation.

All **17 tests passed** with `rustc --test` linked to existing workspace regex/serde_json/
xray-proto artifacts, in a unique owned temporary directory. The parent retains
Cargo/workspace build ownership. Individual rustfmt and standalone clippy with
`-W clippy::all -D warnings` also passed. No network/privileged tests are
necessary for this pure decision component.

On September 19, 2026, the parent additionally reported an integrated core run
with this module exported: 405 passed and one reference-only test ignored, plus
16 passing runtime tests. These parent results do not claim that balancer
configuration, routing dispatch, or observatory scheduling is wired; they confirm
that the exported decision component coexists with the current crate.
