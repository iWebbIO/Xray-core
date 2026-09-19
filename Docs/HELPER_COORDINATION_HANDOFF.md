# Helper coordination handoff

**Paused at the user's request on September 19, 2026, around 21:34 BST.**

This document records the work owned or reviewed by the helper coordination task. The migration lead's [repository handoff](RUST_MIGRATION_HANDOFF.md) and separate validation/remaining-work pages cover the wider project. **Full Go/Rust feature parity has not been achieved.** Source presence, standalone tests, native integration tests, and actual Go/Rust interoperability are separate evidence.

## Pause state and ownership

- Main migration task: `01a0bad7-07ec-7ab3-b62c-a66f92e3cb66`.
- This helper task: `01a0baee-790c-76f3-9586-037a38d97c79`.
- Other cooperating helpers: `01a0baed-94c1-7b90-aa4c-2ae56c41595d` and `01a0baee-8536-77c1-8c82-116eeedb5750`.
- Five distinct worker identities were used over the task's history. The final three slots reused `geodata`, `parity_interop`, and `wireguard`; no new workers were created for the final assignments.
- All three local workers are stopped. `geodata` and `wireguard` had completed; `parity_interop` was interrupted during the audit-note refresh.
- This helper has no active goal (`get_goal` returned null), shell session, tool cell, or helper-owned build process. The main task reported no Cargo, rustc, Go, or linker processes at 21:34:47 BST.
- Implementation, testing, new assignments, and cleanup are paused. Only this handoff documentation was authorized after the pause.
- Shared Cargo manifests, lockfile, top-level runtime/configuration, integration builds, and wider migration documents belong to the main task. Narrow DNS export/visibility leases are described below.

Resume implementation only after a new user instruction. Preserve existing source and the interrupted audit draft.

## Final assignment A: configured DNS network adapter

Files:

- [DNS configuration and selection](../rust/xray-core/src/config/dns.rs).
- [Network adapter](../rust/xray-core/src/dns/network.rs).
- [Connector and checked routes](../rust/xray-core/src/dns/network/connector.rs).
- [Network tests](../rust/xray-core/src/dns/network/tests.rs).
- [Exact runtime wiring recipe](../rust/xray-core/src/dns/network/WIRING.md).

The adapter is implemented and formatted. `NetworkDns::new` takes an `Arc<CompiledDns>`, an injected `Arc<dyn Connector>`, bindings indexed by DNS server, and resource limits. `ServerBinding` contains numeric bootstrap addresses and optional TLS settings. The adapter implements `ServerQuery` and exposes `lookup`, `clear_cache`, `cache_len`, and asynchronous `shutdown`.

Implemented behavior includes classic UDP/TCP and encrypted DoH/DoT exchanges, per-server caches, bounded coalescing of identical queries, bounded stale-refresh tasks, explicit numeric/static-host bootstrap, family/error merging, checked numeric connection plans, and cancellation. The existing compiled policy continues to own hosts, selection, filters, family restrictions, and serial fallback. There is no implicit system-resolver fallback.

The granted shared-file changes were limited to `pub mod network` in `dns.rs` and making `resolver.rs::{answer_from_message, validate_response}` visible to sibling modules with `pub(super)`. Keep the single pre-existing `dns::encrypted` declaration; the main task removed its accidentally duplicated export.

Review fixes already applied:

1. Encrypted-client timeout is `max(server.timeout, eight seconds)`. The enclosing foreground or refresh timeout supplies the appropriate limit, so a configured foreground timeout above eight seconds is preserved.
2. Family replies retain completion times. Their TTLs age while waiting for the other family; remaining TTL rounds up and an expired completed reply yields TTL one, following the source merge behavior.
3. A refresh-registration guard is captured before spawning, so a task dropped before its first poll still removes its registration.

**Validation:** 19 new tests are present: 17 asynchronous and two ordinary unit tests. They cover local UDP/TCP/DoT/DoH, cache and family semantics, negative replies, bootstrap, immutable targets, local/routed separation, Freedom checks, cancellation, query coalescing, stale refresh/shutdown, aged TTLs, and a simulated nine-second encrypted request with a twelve-second configured timeout. No completed centralized result for these 19 tests had been reported to this helper when paused. Individual rustfmt and whitespace checks passed. The earlier configuration adapter's 13 standalone tests passed before this network work.

**Current integration boundary:** the observed root `Config` still has no top-level DNS field. This adapter is a library ready for integration, not a completed configured DNS runtime. The complete recipe is in `dns/network/WIRING.md`.

Mandatory integration details:

- Store the compiled policy and one shared adapter on the runtime. Initialize it before accepting traffic or starting probes.
- Avoid a reference cycle: the adapter owns `Arc<Connector>`, so a connector pointing back to a dispatcher that stores the adapter must use `Weak<Dispatcher>` or separately shared routing state. The documented pattern uses an initially empty resolver slot, then installs it before startup.
- Keep DNS target pins separate from outer proxy-hop pins. `runtime::establish` applies its `resolved` argument to the outer remote endpoint. For a proxy, the tunneled `target` must be the chosen numeric DNS destination, while `resolved` must contain independently pinned proxy-server addresses.
- Named outer proxy endpoints need explicit numeric/static bootstrap or a clear error. Do not recursively bootstrap through the same DNS adapter or silently invoke system DNS.
- Reject redirected Freedom outbounds in this connector until a separate admitted redirect plan exists. The current checked route authorizes the original immutable DNS targets.
- Go's internal DNS client replaces the inbound context with `Inbound{Tag: c.tag}`. Its inbound protocol name is empty. Do not inherit an end-user VLESS/VMess private-target default; explicit final rules still apply. DNS/HTTPS content-protocol labels are separate from the inbound protocol.
- Explicit local endpoints use `LocalConnector`; routed endpoints must use the runtime bridge. UDP connectors must restrict replies to the admitted peer. Unsupported proxy/transport capabilities must fail.
- On shutdown, cancel consumers and await adapter shutdown to join refresh tasks.

DoT is a native extension. System DNS, system-host integration, FakeDNS, parallel-query policies, and unsupported schemes remain explicitly rejected or outside this configuration path. The native response parser intentionally validates identities, owners/classes, and CNAME chains more strictly than the Go parser.

## Final assignment B: SOCKS5 UDP routing and accounting

Files:

- [SOCKS handshake](../rust/xray-core/src/protocol/socks.rs).
- [UDP association runtime](../rust/xray-core/src/runtime/udp.rs).
- [UDP routing adapter](../rust/xray-core/src/runtime/udp_routing.rs).

`handshake_with_udp` preserves the original TCP handshake API while distinguishing CONNECT and authenticated ASSOCIATE requests. An association binds its socket before success is returned, owns the control connection, and limits destinations, queued work, responses, idle time, and operations. Cancellation and control EOF stop and join its work.

The routing API consists of `RouteOutbound::from_config`, `RoutingDispatcher::new`, optional `RoutingDispatcher::with_stats`, an injected `UdpResolver`, and `Association::with_stats(UserSessionStats)`. Route entries must remain in the exact Router order, including synthetic API slots marked unsupported.

Each datagram routes using its original destination, actual pinned source, inbound tag, user, and network `udp`. Freedom redirects apply after selection. DNS resolves once; every returned numeric answer is checked with UDP final rules, and the exact selected numeric endpoint is passed to the socket. Unsupported proxy/security/transport choices fail without falling back to direct traffic. Current direct support is bare Freedom; blackhole drops. `SystemResolver` is an explicit choice only when configured DNS is absent.

The peer key contains both endpoint and route identity. Different outbounds targeting the same address therefore do not share a socket or traffic attribution. Generation checks reject responses from retired sockets.

Accounting boundaries were checked against the source:

- User payload counters follow the dispatcher pre-write boundary.
- Outbound counters increment around actual UDP socket I/O, inside the worker futures, so draining or aborting completion reports cannot erase successful I/O accounting.
- The user-online guard lasts through association cleanup.
- Dynamic SOCKS UDP wire bytes are not added to system inbound counters: Go opens this socket through `TempUDPConn`, outside the inbound counter wrapper. The TCP control connection retains its normal runtime counting.

Review fixes already applied:

1. Shutdown folds successful completion reports into the returned `Outcome`; biased cancellation/EOF no longer discards already completed byte totals. Intentional cancellation is not counted as an I/O error. Live API counters were already correct.
2. The public capability guard also rejects `kcp_settings`. Root configuration validation already rejected incompatible KCP settings, so this was constructor hardening rather than a demonstrated production bypass.

**Validation:** the original source harness passed 30 tests: 14 new handshake/relay tests plus 16 existing address/codec tests. Original standalone Clippy and formatting passed. The later routing/accounting batch added eight adapter tests, two real-socket accounting/route-isolation tests, and one shutdown regression. The shutdown regression passed independently in a small source-extracted rustc harness. Current owned counts are 13 association tests, eight routing tests, and four SOCKS handshake tests. Their final combined execution after root integration was pending at pause. Formatting and whitespace checks passed.

Root source now contains the UDP routing export and `handshake_with_udp` path. This is an observed implementation change, not proof that final executable integration passed. The main runtime owner was adding the associated configuration/startup tests.

Three intentional restrictions tighten the Go source behavior: a concrete requested source IP must match the TCP peer; a requested nonzero UDP port remains enforced even with a wildcard address; and malformed/fragmented/oversized packets cannot pin a learned port. Plaintext SOCKS UDP provides no cryptographic replay protection. The association uses connected upstream sockets for peer filtering.

## Final assignment C: ordinary observatory configuration and construction

Files:

- [Configuration compiler](../rust/xray-core/src/config/observatory.rs).
- [Probe engine and provider](../rust/xray-core/src/features/observatory.rs).
- [Runtime construction](../rust/xray-core/src/features/observatory/runtime.rs).
- [Exact wiring recipe](../rust/xray-core/src/features/observatory/WIRING.md).

The compiler accepts the four ordinary-observatory fields: `subjectSelector`, `probeURL`, string `probeInterval`, and `enableConcurrency`. It uses the existing Go-duration parser and shared URL/TLS validation. Zero interval defaults to ten seconds; negative/overflow/type/unknown/burst settings are rejected explicitly.

`ObservatoryRuntime::new` takes the compiled config, outbound tags, and an injected `RoutedProbeDialer`. It exposes the observer, provider, enabled state, one-round check, and cancellation-owned scheduler. Selection uses literal Go prefix matching and sorted unique named tags. The connector requires the exact selected outbound and has no direct fallback.

The root dialer must use normal final admission, redirect handling, checked addresses, and protocol establishment. It returns a raw stream; the observer adds origin HTTPS. The current root `establish` function also takes traffic counters. Register the actual provider with ObservatoryService and spawn the scheduler only if `is_enabled`: a disabled scheduler returns immediately and must not terminate a server JoinSet. Cancel and join the scheduler during shutdown.

The underlying ordinary observer treats any valid final HTTP status, including redirects and 503, as alive; it reads headers without consuming the body. It publishes measured delay and timestamps, preserves last-seen time on failure, and uses the source failure sentinel. Initial state is empty, not synthetic health. Burst sampling/statistics and balancer feedback are separate remaining work.

**Validation:** the original probe engine passed 13 standalone local HTTP/TLS and lifecycle tests. The final compiler/runtime package adds eight tests, three configuration and five runtime. The standalone attempt for these additions could not run after the shared core artifact was removed during disk recovery. Formatting passed. Root configuration fields/exports and integration hooks are now visible, but the final central integration result remained pending at pause.

## Earlier completed packages

| Package | Work and checkpoint | Remaining boundary |
| --- | --- | --- |
| `rust/xray/src/config_loader.rs` | JSON/JSONC, local YAML/TOML, input ordering, source discovery, and tag-aware merging | YAML 1.1 differences, remote/protobuf loading, and environment application documented; no new aggregate test claim here |
| `geodata.rs` and subtree | Protobuf datasets, matchers, caching, reload registry; 17 tests passed | Download/update scheduling and full consumer integration are separate |
| `features/{policy,stats}.rs` | Policy models, counters, online tracking and statistics components; 19 tests passed | Complete source policy/statistics coverage is not established |
| `features/session.rs` | Policy-aware bounded relay, half-close, partial-write accounting, inactivity/cancellation, owned online guard; nine integrated tests passed | Whole-runtime behavior needs the central integration suite |
| `protocol/wireguard.rs` and subtree | Native boringtun packet engine, keys/config/routes; 16 tests passed | UDP socket ownership, timers, userspace TCP/IP or TUN bridge, and runtime integration remain |
| `dns/encrypted.rs` | Native HTTP/2 DoH and DoT; 11 focused real TLS/h2 tests passed | Runtime selection/cache wiring was subsequently implemented by assignment A; DoT is an extension |
| `router/balancer.rs` | Source decision engine for random, round-robin, least-ping and least-load; 17 tests and standalone Clippy passed | Runtime observation feedback and complete configuration integration remain |
| `config/dns.rs` | Server/hosts configuration, geodata matching, filters, source selection and serial fallback; 13 standalone tests passed | Top-level executable DNS integration remains |
| `rust/xray/tests/interop.rs` | Expanded both-direction VMess AES-GCM/ChaCha tests and narrow, symmetric echo-target rules | New protocol/transport combinations need actual executable interoperability runs |

An early review found that Go Freedom blocks private targets by default for several encrypted inbound types while the original Rust runtime allowed them. The migration lead implemented native final rules and checked-address dialing. The interoperability harness permits only its owned loopback echo target on both implementations; broad allow-all rules must not replace that setup.

## Independent reviews and integration constraints

- **PROXY protocol:** read-only comparison with the pinned `pires/go-proxyproto` v0.15.0 and source listener. No confirmed defect in trust gating, fragmented/coalesced payload preservation, LOCAL/UNKNOWN behavior, TLV/SSL structure or CRC validation. Documented intentional differences remain. No new tests were executed by the reviewer.
- **Native VLESS 1-RTT encryption:** checked authentication/transcript order, directional AEAD state, continuous counters, bounded records, low-order X25519 rejection, partial I/O and cancellation. No remaining blocking finding in that reviewed scope. A concurrently fixed backpressure issue was not reported as outstanding.
- **VLESS replay capacity:** the default fail-closed library cache retains 4,096 fresh handshakes for 180 seconds. A completed hello consumes capacity before inner VLESS user authentication and remains retained on subsequent failure. Treat this as an integration capacity/admission requirement, not a demonstrated current JSON-exposed vulnerability. Configure a suitable capacity and admission budget without evicting still-live entries and weakening replay rejection.
- **New UDP review:** the shutdown-report and KCP capability fixes above are applied. Other checked routing, pinning, counter, peer-generation and guard-lifetime behavior had no confirmed defect.
- **New DNS connector review:** no further blocking adapter defect was found. The proxy-hop/DNS-target pin distinction, redirect rejection, weak ownership and internal inbound context are mandatory integration details, not optional recommendations.

## Validation ledger at pause

The following central results were reported by the migration lead and were not rerun by this helper:

| Checkpoint | Reported result | Scope limitation |
| --- | --- | --- |
| Combined core snapshot | 679 total: 672 passed, three failed, four ignored | Not green. One KCP cancellation and two XDRIVE failures were assigned elsewhere. Later changes require a new run. |
| Compiled gRPC integration binary | Eight passed | Native tests; no new Go gRPC result claimed |
| Compiled KCP integration binary | Five passed | Predates tightened startup rollback changes |
| Compiled runtime-accounting binary | Six passed | Scoped accounting evidence |
| Compiled proxy integration binary | 18 passed, including native SS2022 TCP with both AES ciphers | No actual Go SS2022 result claimed |
| Historical actual Go/Rust executable target | 30 passed, no skips, in 20.42 seconds | Valid for that earlier checkpoint and its tested modes, not later source mutations |

The pinned Go reference checkpoint was commit `dcdfc57ccdad496e192344788a7d14a8d4c88573`, Xray 26.9.9. Its executable was `target/reference-xray.exe`; the Rust executable was `target/debug/xray.exe`. Set `XRAY_GO_BINARY` for real interop execution. A test run that prints `SKIPPED` when the reference executable is absent is not interoperability evidence.

An earlier, separate checkpoint reported 406 core tests: 405 passed and one reference test ignored; 16 runtime tests passed. Preserve that as historical evidence, not the current totals.

The main task planned a workspace `--all-targets` run with the Go executable environment after the final mutation freeze. No completed result from that planned run was reported to this helper before the pause. New Go SS2022, KCP, gRPC and XHTTP-mode runs were still pending in the known ledger. Consult the main task's validation document for anything it completed before stopping its processes.

## Interrupted parity audit and repository state

[rust/notes/PARITY_AUDIT.md](../rust/notes/PARITY_AUDIT.md) is a saved **draft**. The final worker was updating stale claims about API, logging, policy, CLI commands, geodata, observatory and UDP against current source when interrupted. Its saved content already contains the current central-results table and several updated integration boundaries. Its full final review was not completed.

At the pause check, `git diff --cached --name-only` returned empty: the draft was **not staged**. No commit was created by this helper. The Rust tree and new Cargo/workflow files were largely untracked, while existing README, `.gitignore` and workflow configuration had modifications. Do not reset, overwrite, stage unrelated paths or infer ownership from Git tracking alone.

The main task owns README, migration/agent ledgers and the repository-wide Docs pages. This helper owns only this documentation file during the pause.

## Cleanup restriction

The ignored directory `rust/xray-core/src/geodata/validation-41b0aeb1317a4f1fae67274ba19d34aa` remains, containing a temporary harness and roughly 11 MB of executable/PDB artifacts. Earlier recursive and exact-file removal attempts were automatically rejected with **“blocked by policy.”** Do not retry deletion through another route. The lead added an exact `.gitignore` entry and the restriction was already disclosed.

Later, unrelated unique temporary harnesses were successfully cleaned. That does not authorize retrying the blocked directory. No cleanup was attempted for this pause.

## Resume checklist

Only after the user resumes:

1. Read the main Docs checkpoint, check current source and active ownership, and reconcile any central test result that arrived after this helper's snapshot.
2. Finish reviewing the saved parity-audit draft; preserve separate historical and current evidence.
3. Run the agreed centralized validation after all source owners report stable. Address actual diagnostics in owned files; do not treat unrun tests as passing.
4. Confirm executable SOCKS UDP and observatory configuration/startup/service/cancellation tests after their root wiring.
5. Integrate top-level DNS using its wiring recipe and the pinning, bootstrap, ownership, source-context and shutdown constraints above. Add executable DNS tests rather than relying only on library fixtures.
6. Execute the pending Go/Rust protocol/transport combinations with a real reference binary and explicit narrowly scoped destination policies.
7. Continue the wider parity inventory without inferring completion from file or test counts. Known categories still include complete DNS modes, burst/feedback integration, wider protocol UDP support, mux/XUDP/reverse, remaining transports/platform networking, CLI/API permutations and lifecycle behavior.

This checklist records future work; it does not schedule or authorize automatic resumption.
