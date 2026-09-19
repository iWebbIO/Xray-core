# Native management API CLI

`commands/api.rs` implements the client side of the management services already
delivered in the native core. `commands::Command::Api` exposes the nested Clap
commands, and `commands::api::execute(ApiCommand)` performs the asynchronous
request and returns its complete stdout text. `commands::execute_to` builds a
Tokio runtime and writes that text for the executable.

Supported source command names:

| Command | Additional flags | RPC |
| --- | --- | --- |
| `stats` | `-name`, `-reset` | `GetStats` |
| `statsquery` | `-pattern`, `-reset` | `QueryStats` |
| `statssys` | none | `GetSysStats` |
| `statsonline` | `-email` | `GetStatsOnline` |
| `statsonlineiplist` | `-email` or `-all`, `-include-traffic`, `-reset` | `GetStatsOnlineIpList` or `GetUsersStats` |
| `statsgetallonlineusers` | none | `GetAllOnlineUsers` |
| `restartlogger` | none | `RestartLogger` |

Every command accepts `-s` / `--server` (default `127.0.0.1:8080`), `-t` /
`--timeout` (integer seconds, default `3`), and `--json`. The source accepts
`--json` but these commands emit JSON regardless of its value, so the native
CLI does the same. Boolean flags accept `--flag`, `--flag=true` and
`--flag=false`. The parent executable owns normalization of source-style
single-dash long flags; its list must include `-server`, `-timeout`, `-name`,
`-reset`, `-pattern`, `-email`, `-all`, `-include-traffic` and `-json`.

The IP-list command requires exactly the source's selection rule: `-all` and
a nonempty `-email` are mutually exclusive, and one must be selected.
`include-traffic` and `reset` are ignored in single-user mode, as in Go.
All-user reset behavior belongs to the server and affects the requested
online users' traffic counters, leaving online presence and unrelated
counters intact. `statsgetallonlineusers` preserves full registered names
such as `user>>>alice@example.test>>>online`.

Connections use native tonic HTTP/2 with insecure/plaintext transport, matching
the source API client's credentials. Plain `host:port`, IPv6 `[host]:port`,
`http://host:port`, and `dns:///host:port` are accepted. Other resolver schemes,
Unix socket connectors and API TLS are rejected explicitly. Dial retries are
bounded by one absolute deadline shared with the RPC; RPC requests also send
`grpc-timeout`. Zero or negative timeout fails before connection. Errors keep
the source command's action prefix and gRPC code/description, while executable
error prefixes and usage formatting remain parent-owned.

Output follows `common/reflect/marshal.go`, not protobuf JSON:

- Four-space indentation, sorted object keys and two trailing newlines.
- Signed/unsigned 64-bit counters remain JSON numbers without conversion to
  floating point or quoted protobuf-JSON strings.
- Zero scalar fields, empty strings, empty repeated fields/maps and absent
  message fields are omitted; present empty messages remain `{}`.
- `last_seen` becomes `lastSeen`; system field names preserve `NumGoroutine`,
  `TotalAlloc`, `PauseTotalNs`, etc.
- HTML punctuation stays literal; U+2028/U+2029 remain escaped as in Go.
- Counter/user/IP arrays are sorted for deterministic native output. Go's
  underlying map iteration can give these arrays an unspecified order.

When a native server supplies the `x-xray-system-stats-provider`,
`x-xray-num-goroutine-kind`, or `x-xray-unsupported-fields` headers, `statssys`
also includes an additive `_runtime` object. It records `provider`,
`numGoroutineKind` and sorted `unavailableFields`. This retains the distinction
between Tokio tasks and Go goroutines, and between unavailable allocator
measurements and measured zero. Go servers without these headers retain the
ordinary source JSON shape.

Handler, routing/balancer and observatory commands are not silently accepted
as functional clients. Recognized source commands requiring those services
fail before dialing with an explicit service-specific diagnostic. The
observatory service interface alone does not establish real probe state.

Ten module tests cover Clap names/flags, unsupported commands, endpoint and
selection validation, JSON fixtures/ordering, actual loopback HTTP/2 RPCs for
all supported commands, reset scope, shared logger lifecycle, system metadata,
unavailable-counter errors and stalled connection/RPC deadlines.

Independent source check: a temporary instance of the repository's existing
Go 26.9.9 reference executable was started with StatsService and LoggerService.
Its `restartlogger`, empty `statsquery`, `statsgetallonlineusers`, and
`statsonlineiplist -all` commands each returned exactly `{}\n\n` with exit
status zero. Its `statssys` output confirmed numeric values, four-space
indentation and two final newlines. The temporary reference process was
terminated after these checks. No command implementation invokes Go, and no
shared build or manifest was changed by this work package.
