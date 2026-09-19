# Rust logging implementation

`xray-core/src/logging.rs` ports record presentation and configuration from
`infra/conf/log.go`, `app/log/log.go`, `common/log/{access,dns,log,logger}.go`,
and dispatcher detour formatting in `app/dispatcher/default.go`.

## Integration

The parent migration owns module exports, Cargo dependencies, config, runtime,
and management-service integration. This module needs `chrono` 0.4 with its
`clock` feature and `tracing-subscriber` 0.3; `serde`, `regex`, and `tracing`
are already core dependencies.

- Use `Logger::from_optional_config(config.log.as_ref())` when the surrounding
  configuration represents the presence of a log object with `Option`.
  `LoggerOptions::default()` has no access writer and a warning-level stdout
  error writer, matching an omitted log object. `LogConfig::default().build()`
  enables access stdout as well, matching a present, empty log object.
- `LogConfig` consumes the Xray JSON fields `access`, `error`, `loglevel`,
  `dnsLog`, and `maskAddress`; null scalar fields preserve their zero defaults
  as in Go. Unknown fields are ignored as they are by Go's JSON unmarshaler.
- Both JSON console destinations use stdout. Only empty strings and the exact
  string `none` have destination special meanings; `stdout` or `stderr` in JSON
  remain literal file paths. Code can select `LogDestination::Stderr` explicitly.
- `loglevel: "none"` disables both writers, including access and DNS records.
  Other level names are case-insensitive; unknown names default to warning.
- Cloning `Logger` shares its writers, configuration, and lifecycle. Pass it
  explicitly to runtimes/services. The module never installs a global logger.
- `write_general(Severity, content)`, `write_access(&AccessRecord)`, and
  `write_dns(&DnsRecord)` return I/O errors to callers. Matching `*_at` methods
  take a `Timestamp` (`chrono::DateTime<FixedOffset>`) for deterministic records.
- The timestamp prefix is local `YYYY/MM/DD HH:MM:SS.ffffff`, with nanoseconds
  truncated to microseconds. Record terminators match Go's host platform
  (`\r\n` on Windows; `\n` elsewhere). Embedded message newlines are retained.
- Access records preserve source/target text, accepted/rejected status, detour,
  reason, and email in Go's order. `format_detour` reproduces default `>>`,
  forced `==>`, and routed `->` forms; the caller supplies dispatch semantics.
- DNS records go to the access writer only when `dnsLog` is true. Status strings
  preserve the source's `got answer:`, `cache HIT:`, and `cache OPTIMISTE:` forms.
  IP lists, errors, and positive Go-style duration strings are supported.
- `start`, `close`, `flush`, `restart`, and `reopen` support service management.
  Successful `restart`/`reopen` also activate a closed logger. `reopen` is
  transactional: failed opens leave the previous writers usable. New Unix log
  files use mode 0600, and existing files are appended without truncation.
- Attach `logger.tracing_layer()` to the caller's chosen subscriber. It bridges
  existing tracing events without globally filtering other layers, includes
  inherited span fields, and formats numeric `session_id` as `[id]`. Targets can
  be omitted with `.with_target(false)`. Since tracing callbacks cannot return
  errors, `take_tracing_error()` retrieves the latest bridge I/O error.

## Source compatibility and remaining boundaries

Address masking deliberately preserves the source's regex behavior rather than
silently replacing it with address-token parsing. This includes matching
IPv4-shaped strings without validating octet ranges, processing IPv4 before
IPv6, ignoring mask components after the first two, and accepting out-of-range
IPv6 prefix values (which render parsed candidates as `<nil>/N`). Masking is
applied to record bodies before timestamps are prefixed. The `half`, `quarter`,
`full`, and explicit prefix formats are implemented.

The Go general logger uses a bounded 128-message asynchronous queue, silently
drops messages when full, ignores write errors, and closes idle writers after
one or two minute ticks. This Rust object instead writes synchronously under a
shared mutex, returns write failures, and retains writers until close/reopen or
last-clone drop. Consequently automatic idle reopen and the precise queue-drop
behavior are not reproduced. These lifecycle/performance differences remain a
parity decision for the root migration; output formatting and explicit file
rotation are implemented.

The bridge preserves Rust tracing targets and fields. It cannot automatically
derive the original Go package/caller names or error-chain structure from
arbitrary Rust events; direct `write_general` calls can pass the exact content.
Go's process-global handler/handler-creator registration is represented by
explicit logger objects and the typed output destinations instead of mutable
global registration. Arbitrary third-party handler factories are not exposed.

Runtime access/DNS emission, absent-log-block preservation in the surrounding
config, subscriber installation, and `RestartLogger` RPC wiring are owned by
the parent task. This isolated module does not by itself complete those paths.

## Verification

The module includes tests for configuration presence/defaults, record ordering,
DNS statuses and durations, source mask fixtures and quirks, deterministic time
and platform line endings, filtering and DNS gating, append semantics, shared
close/start lifecycle, successful and failed reopening, concurrent record
integrity, tracing span/event fields, and Unix file modes. `rustfmt` was run by
the implementation worker. Cargo checks and tests are delegated to the parent
task to avoid competing shared-workspace builds.
