# Policy and statistics integration

The owning crate must declare `pub mod features;`. This module uses only the
existing `serde` dependency and the standard library; tests also use the existing
`serde_json` dependency. It does not alter configuration parsing or the runtime.

## Policy

Deserialize the top-level `policy` value as `policy::PolicyConfig`, then create
`PolicyManager::new(&config)`. If the policy feature is entirely absent, use
`PolicyManager::default()` to retain the source default manager's special
600-second level-1 idle timeout. A configured manager uses 300 seconds for an
unconfigured level, including level 1.

`for_level(level)` returns a copyable `SessionPolicy` containing `timeouts`,
`stats`, and `buffer`. `for_system()` returns `SystemPolicy`. Timeout fields are
`Duration`s; omitted JSON fields inherit defaults while explicit zero survives.
JSON buffer values are KiB, environment values are MiB, and raw byte limits
retain the source signed-int32 wraparound behavior. Negative JSON buffer values
become -1. Environment resolution accepts both `xray.ray.buffer.size` and its
uppercase underscore alias, with the primary name taking precedence.

Default environment values are captured when constructing a manager. Reconstruct
the manager to apply an environment reload. The process-wide Go environment
reload registry and Go context buffer overrides have no Rust adapter here.

## Statistics

Share `Arc<stats::StatsManager>` between the runtime and management API.

- `register_counter` rejects duplicates; `get_or_register_counter` atomically
  reuses a handle. `Counter::add` returns the new value, `set` returns the old
  value, and `value` reads the value. Arithmetic wraps as signed Go int64.
- `stat(name, reset)` returns `Option<Stat>`. `query_stats(pattern, reset)` uses
  a literal substring and returns `Vec<Stat>` in lexical name order. A reset
  atomically swaps each matched counter to zero; it is not a transaction across
  all counters.
- `get_online_map(name)` returns `Option<Arc<OnlineMap>>`; `count()` gives the
  number of distinct exact IP strings. `snapshot()` and manager
  `online_ips(name)` return `OnlineIpEntry { ip, last_seen }`, with Unix seconds.
- Each `OnlineMap::add_ip` adds a connection reference and refreshes last-seen;
  `remove_ip` removes one reference. Only the exact source strings `127.0.0.1`
  and `[::1]` are excluded. `track(ip)` provides a non-cloneable `OnlineSession`
  guard that releases one reference on drop or explicit `close`.
- `get_all_online_users()` returns active registered map names, as Go does.
  `users_stats(include_traffic, reset)` returns `UserStat { email, ips, traffic }`.
  Only online users' counters reset, and only when traffic is requested. It
  matches the source's second-delimiter-component email extraction for arbitrary
  map names and embedded delimiters. Duplicate emails coalesce with a stable
  lexical winner; Go's winner depends on map iteration order. Invalid counter
  string slices are safely skipped instead of panicking.
- `user_session(email, source_ip, UserStatsPolicy)` returns the selected traffic
  handles plus an optional online guard. Keep the guard alive for the connection
  lifetime; call `traffic.add_uplink/downlink(actual_bytes)` after successful I/O.
  `inbound_counters(tag, SystemStatsPolicy)` and `outbound_counters` select system
  traffic handles. Empty identities and disabled flags create no handles.
- `visit_counters`, `visit_online_maps`, and `OnlineMap::for_each` snapshot before
  invoking callbacks, allowing reentry. This deliberately avoids the source's
  restriction against modifying the registry from a visitor.
- `clear()` removes the manager's handles; existing connection handles remain
  valid, matching source registry removal semantics.

## Scope and verification

Source references: `infra/conf/policy.go`, `features/policy/{policy,default}.go`,
`app/policy/{config,manager}.go`, `app/stats/{counter,online_map,stats}.go`,
`app/stats/command/command.go`, and statistics setup in the dispatcher/proxyman.
The policy fixture combines cases from those loaders; baseline handshake and
buffer tests carry the expectations from the corresponding Go tests.

All 19 module tests passed using an isolated `rustc --test` harness linked against
existing workspace serde artifacts. Tests include concurrent get-or-register and
reset accounting, concurrent online session references, exact loopback rules,
policy defaults/null/zero/ranges, and source query delimiter behavior. Individual
file rustfmt passed. The lead owns Cargo/workspace integration validation.

This is policy data and counter/online-map functionality, not complete parity for
all features. It does not implement statistics event channels/subscriptions,
gRPC serving, Go-runtime memory/GC metrics, policy protobuf adapters, timeout
timers, per-session context override propagation, or automatic traffic counting
inside socket I/O. Runtime and management owners must integrate the provided
models and handles.
