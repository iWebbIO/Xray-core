# Source-to-Rust parity audit

Audit snapshot: **September 19, 2026**, refreshed **September 27, 2026** after the
upstream merge `71e232c1`. Go reference rebuilt from the merged source (Xray
26.9.9 plus MASQUE, FakeDNS pool, geodata regex prefilter and WireGuard updates).
The Rust tree is an actively changing migration. Dated test checkpoints
describe their tested snapshots; subsequent code is not covered automatically.

**Full feature parity has not been achieved.** Native TCP proxy paths and the
reported cross-language exchanges below work within their tested scope.
Generated schemas, standalone libraries and newly connected runtime hooks are
not substitutes for complete configuration integration or interoperability.

## Current validation boundary — September 27, 2026 (merged tree)

Executed by the migration lead on Windows x86-64 against the merged Go source
(`71e232c1`) with the Go reference and all four Go test fixtures rebuilt from
that source:

| Executed target / checkpoint | Reported result | Limit of the evidence |
| --- | --- | --- |
| `cargo fmt` / `cargo clippy -D warnings` / `cargo test --workspace --locked --no-fail-fast` | **fmt clean, clippy clean, 885 passed / 0 failed / 5 ignored** | The five ignored are the env-gated Go-fixture tests, executed separately below. A green workspace is not feature parity; see inventory rows. |
| `interop` with rebuilt `XRAY_GO_BINARY` | **34 passed, 0 skipped** | Real-process bidirectional coverage for SOCKS/HTTP/VLESS/Trojan/legacy-SS/VMess/TLS/XHTTP modes; unchanged scope caveats below still apply. |
| `transport_interop` with rebuilt reference | **6 passed** | KCP and gRPC-tun Rust→Go exchanges now execute after granting the Go server the same scoped echo-port `finalRules` allow `interop.rs` uses; Go→Rust uses the in-test native server, not the Rust binary. |
| `xhttp_modes` with rebuilt reference | **8 passed** | XHTTP mode matrix including H1 streaming/stream-one over TLS and non-TLS against the Go reference. |
| SS2022 / XDRIVE / REALITY Go-fixture tests (`--ignored`, env-gated) | **5 passed** | REALITY native server accepts the pinned Go uTLS client in both plain and target-mirroring modes after two repairs: the server no longer requires Ed25519 (0x0807) in the client signature list (the pinned Go fork forces Ed25519 for its synthetic certificate and never consults that list), and the Go target fixture serves ECDSA P-256 because browser fingerprints do not advertise Ed25519 and Go's standard server rejects that pairing pre-flight. |

Two earlier assigned workspace failures are fixed deterministically: the KCP
linger test now proves the held port with a wildcard re-bind (Winsock permits a
specific-address bind over another socket's wildcard bind), and the DNS dual
protocol fixture picks its port through the UDP allocator (Windows TCP-selected
ephemeral ports can fall wholly inside UDP-excluded ranges). CI gained an
`interop` job (Go reference built in-job, all three interop targets serially);
a declared job is not a completed run until it executes on GitHub.

The upstream merge added the Go MASQUE family (`proxy/masque`,
`transport/internet/masque`, ~6.6k lines, RFC 9484 CONNECT-IP with HTTP/2 and
HTTP/3 modes). `xray-proto` regenerates bindings for the new protos
automatically. **Native MASQUE components now exist** (capsule codec with
Go/IANA type numbers, HTTP/2 extended-CONNECT transport, proxy session over a
`ConnectIpSession` trait; 24 transport + 14 codec + 10 proxy tests) — as
components with integration contracts, not yet wired into root config. The
MASQUE HTTP/3 branch is explicitly rejected with a named error.

### Parallel batch — September 27, 2026 (commit 421a7630)

Fifteen subsystem packages ported by a 15-agent batch with strict file
ownership: MASQUE (proxy/transport/capsules), VLESS encryption session, XTLS
Vision adapter, Trojan UDP, SS2022 multi-user UDP, WireGuard userspace
netstack (smoltcp), Mux.Cool session scheduling, reverse bridge/portal, burst
observatory, DNS app composition, HandlerService management API, YAML-1.1
scalar/env compat. All are components awaiting root config/runtime wiring;
until then the corresponding selectors remain rejected by the strict config
layer. Workspace evidence: **fmt/clippy clean, 1020 passed / 0 failed / 5
ignored** (+135 tests), Go-reference interop unchanged (34/6/8). Inventory
rows below still describe their pre-batch boundaries where the runtime layer
is concerned; the component columns for MASQUE, `loopback`-style detours,
Vision/encryption, UDP families, mux scheduling, reverse, burst observatory
and DNS app composition now have native tested implementations.

## Prior validation boundary — September 19, 2026

The migration lead supplied these executed results for this refresh. This
documentation worker did not run builds or integration tests:

| Executed target / checkpoint | Reported result | Limit of the evidence |
| --- | --- | --- |
| Combined core snapshot | **679 tests: 672 passed, 3 failed, 4 ignored** | A non-green snapshot. Three KCP/XDRIVE failures have fixes assigned; those fixes and subsequent mutations need another central run. |
| Compiled gRPC integration binary | **8 passed** | Native integration coverage; no new Go gRPC exchange is claimed. |
| Compiled KCP integration binary | **5 passed** | Precedes tightened startup rollback changes and does not validate those later changes. |
| Compiled runtime-accounting integration binary | **6 passed** | Scoped runtime accounting coverage, not complete source policy/statistics parity. |
| Compiled proxy integration binary | **18 passed** | Includes native SS2022 TCP for both AES ciphers; no Go SS2022 exchange is claimed. |
| Historical actual Go/Rust executable checkpoint | **30 passed, no skips** | The earlier real-process checkpoint below remains valid for its tested modes and binaries. New Go SS2022, KCP, gRPC and XHTTP-mode runs are pending. |

These are separate targets and snapshots, not counts to add into one workspace
pass. DNS network work is awaiting stable central validation. SOCKS UDP and
ordinary-observatory root configuration/runtime hooks are now present, but their
integration remains under active validation; the above passes do not establish
a pass for those later hooks.

## Component handoffs — September 19, 2026

These **standalone component results** remain distinct from the lead's
integration runs. Current wiring is listed explicitly; a source file or runtime
hook alone is not evidence of an executed integration pass.

| Delivered package | Native behavior and standalone evidence | Current integration boundary |
| --- | --- | --- |
| DNS configuration adapter, `rust/xray-core/src/config/dns.rs` | Source-derived server selection, hosts and response filtering. **13 standalone tests passed**, including local UDP NXDOMAIN fallback/cache behavior and trailing-dot aliases. | New `dns/network.rs` connector/cache work awaits central validation. Root `Config` still has no DNS field; policy-aware routed connectors and executable DNS startup remain separate work. |
| Ordinary observatory, `rust/xray-core/src/features/observatory.rs` | Measured ordinary-observatory provider. **13 standalone tests passed**, including local HTTP/TLS probes and lifecycle behavior. | Config, root scheduling, exact-outbound dialing and ObservatoryService hooks now exist and await integrated validation. Burst observatory and routing-balancer feedback remain gaps. |
| SOCKS5 UDP, `runtime/udp.rs`, `runtime/udp_routing.rs` and `protocol/socks.rs` | Original parser/relay handoff: **30 standalone tests passed: 14 new plus 16 existing address/codec tests**, with standalone Clippy/rustfmt. One later deterministic shutdown-report test passed independently after completed-send byte totals were preserved during cancellation. | Root ASSOCIATE handling, per-datagram routing, UDP final rules, resolver injection, route-isolated sockets and user/outbound counters now exist. Eight adapter tests and two added accounting tests await integrated execution; the original 30-test result does not cover these additions or root wiring. |

The SOCKS UDP package intentionally tightens three source behaviors: a concrete
requested source IP must match the canonical TCP peer IP; a requested nonzero
UDP source port remains enforced with wildcard/domain source addresses; and only
a validated, unfragmented packet may pin the learned source port. Malformed
packets cannot claim an association. These are documented differences from the
Go helper. SOCKS UDP has **no cryptographic replay protection**; duplicate valid
datagrams remain valid. Connected upstream sockets and generation checks filter
unrelated and retired-socket replies.

UDP capability currently permits bare freedom and explicit blackhole only.
Unsupported proxies or layered transports fail without direct-dial fallback.
Root wiring explicitly selects system DNS while top-level configured DNS remains
rejected. Final admission checks every answer and passes a checked numeric
endpoint to the relay. Like the source's dynamic TempUDPConn, the relay does not
add SOCKS UDP framing to system inbound counters. TCP control accounting,
dispatcher payload/user counters and outbound socket counters have separate
boundaries.

## Highest-priority concrete finding

### Freedom private-target defaults: repair implemented and focused checks passed

Follow-up on September 19, 2026: the migration lead implemented native
`protocol/freedom.rs`, configuration/runtime wiring, the source default ranges,
and checked-address dialing to avoid a DNS check/dial race. The lead reports that
the integrated freedom/core tests passed and the actual 30-case Go/Rust test
target passed with scoped allows on both sides. The finding below describes the
earlier executable snapshot; these focused checks do not establish complete
freedom feature parity.

The Go reference's `proxy/freedom/freedom.go:getDefaultFinalRule` selects a
private-address blocking rule for VLESS, VMess, Trojan, Hysteria, WireGuard, and
Shadowsocks inbound names, and an all-target blocking rule for `vless-reverse`.
`matchFinalRule` checks configured `finalRules` before that default. SOCKS and HTTP
do not get that default. Source configuration is
`infra/conf/freedom.go:FreedomConfig` / `FreedomFinalRuleConfig`.

At the audited executable snapshot (historical hashes below), Rust `config.rs:FreedomSettings` had only domain strategy,
redirect, and user level, and `runtime.rs:establish` dialed the destination without
the source default restriction. This was an **access-control mismatch**: a
Go-to-Rust VLESS/Trojan/Shadowsocks connection reached a loopback target that the
equivalent Go server blocked. Explicit `finalRules` were also rejected by Rust's
configuration model rather than enforced.

Observed during independent process probes:

- Rust-to-Go SOCKS/HTTP connections succeeded with the default freedom settings.
- Rust-to-Go VLESS, Trojan, three legacy Shadowsocks ciphers, VLESS TLS, and VLESS
  XHTTP reached the correct decoded destination, but the Go server logged
  `proxy/freedom: blocked target: tcp:127.0.0.1:<port>, blackholing connection`.
- Go-to-Rust equivalents reached the echo service with no explicit allow rule.
- All affected Rust-to-Go exchanges succeeded after a Go-only allow rule for
  **the owned `127.0.0.1/32` TCP echo port**. This establishes a policy discrepancy,
  not a wire-codec failure.

The required repair identified was to carry inbound protocol identity to final outbound policy,
preserve source private ranges and precedence, validate/apply `finalRules`,
implement block-delay/cancellation semantics, and add default-denial as well as
explicit-allow tests. A generic allow-all rule would conceal this defect.

The interoperability harness now grants the same narrow allow to both Rust and
Go servers. It measures wire interoperability, **not equal access policy**.
Separate core default-denial assertions cover the policy repair. Historical probe
results below still refer to the original binaries and Go-only allow; the
updated committed harness has now passed the integrated run described next.

## Historical executed interoperability evidence — September 19, 2026

**Integrated run, September 19, 2026:** the migration lead ran the actual
`rust/xray/tests/interop.rs` target with `XRAY_GO_BINARY` pointing to the Go
reference executable. **All 30 tests passed in 20.42 seconds, with no skips.**
This includes VMess AES-128-GCM and ChaCha20-Poly1305 in both directions and the
same echo-only `finalRules` allow on both server implementations. This report is
distinct from the earlier independent Python probes and their historical hashes.
An earlier follow-up checkpoint on the same date reported 406 core tests: 405 passed and
one reference test was ignored. The balancer module was included. All 16 runtime
tests passed, including level-zero handshake timeout, live user/system traffic
counters, online-guard cleanup, masked access-file logging, and the freedom
default avoiding a loopback dial. Encrypted DNS was exported for the next full
run after its 11 focused TLS/HTTP2 tests passed. API Stats/Logger configuration
integration was written but still awaited its new tests at that checkpoint.
It is now wired in the inspected source; see the current inventory and newer
scoped results above. No complete workspace pass is asserted by this ledger.

The executed interoperability checkpoint covered 30 real-process cases: 15 configurations in
each direction. The four VMess AES-128-GCM and ChaCha20-Poly1305 cases use a
standard UUID. The front process accepts local SOCKS5; its outbound connects to
the other implementation's server; the server uses freedom to reach an owned
loopback echo service. The echo service XORs every byte with `0xa5`, so local
reflection cannot satisfy the expected reply. Two exchanges on the same stream
carry **98,321 + 3,097 = 101,418 bytes** in each direction, crossing legacy AEAD
record and configured XHTTP upload-packet boundaries.

| Configuration | Rust client → Go server | Go client → Rust server |
| --- | --- | --- |
| SOCKS5, no authentication | Successful process probe | Successful process probe |
| SOCKS5, username/password | Successful process probe | Successful process probe |
| HTTP CONNECT, no authentication | Successful process probe | Successful process probe |
| HTTP CONNECT, Basic authentication | Successful process probe | Successful process probe |
| Base VLESS, TCP | Successful with scoped Go allow | Successful process probe |
| Base Trojan, TCP | Successful with scoped Go allow | Successful process probe |
| Shadowsocks `aes-128-gcm` | Successful with scoped Go allow | Successful process probe |
| Shadowsocks `aes-256-gcm` | Successful with scoped Go allow | Successful process probe |
| Shadowsocks `chacha20-ietf-poly1305` | Successful with scoped Go allow | Successful process probe |
| VLESS, TLS 1.2 only | Successful with scoped Go allow | Successful process probe |
| VLESS, TLS 1.3 only | Successful with scoped Go allow | Successful process probe |
| VLESS, XHTTP HTTP/1.1 `packet-up` | Successful with scoped Go allow | Successful process probe |
| VLESS, XHTTP HTTP/1.1 `packet-up` over TLS | Successful with scoped Go allow | Successful process probe |
| VMess, AES-128-GCM | Passed actual integrated test | Passed actual integrated test |
| VMess, ChaCha20-Poly1305 | Passed actual integrated test | Passed actual integrated test |

These were independent Python socket/process probes of the already-built native
executables, using the same configuration and payloads as the committed Rust
harness. No Go or Cargo build was run by this audit worker. The first pass had
17 successes and nine policy-induced timeouts; a second pass of those nine with
the scoped Go rule succeeded. Failed probes are not counted as successes before
the explicit configuration change.

Binary identities used for these probes (Windows x86-64):

- `target/debug/xray.exe`, last-write time September 19, 2026 19:50:52 Europe/London;
  SHA-256 `1E988C9B2F7241FDFB8A74D6D99F338FC81D6769F5DB99C3C4606FD4DFE1E1C9`.
- `target/reference-xray.exe`, last-write time September 19, 2026 19:49:50
  Europe/London; SHA-256
  `8AEB5D56DBC9F09BB5C21AE47C7B972D88D70C4C4910A72CC616DBD71A94D5FA`.

The Rust integration target was subsequently compiled and executed by the
migration lead: all 30 actual tests passed as recorded above. The binary hashes
in this historical probe section identify the earlier executables, not the
subsequently rebuilt Rust binary. A skipped target still provides no evidence.

Reproduce after the lead builds both executables:

```powershell
$env:XRAY_GO_BINARY = (Resolve-Path target/reference-xray.exe).Path
cargo test -p xray --test interop -- --nocapture --test-threads=1
```

The test uses `env!("CARGO_BIN_EXE_xray")` for the Rust executable. An absent
`XRAY_GO_BINARY` prints `SKIPPED ... no cross-language exchange ran` for each
case and returns; Rust's test runner will label that return `ok`, which is **not
interop evidence**. An explicitly configured missing binary fails. CI needs to
supply a real reference binary and retain the `INTEROP PASSED`/`SKIPPED` output.

Harness properties: unique owned temporary directories, ephemeral port
reservations, child stdout/stderr captured in files, direct child kill/wait and
file cleanup on unwind, a 20-second case deadline, bounded socket operations,
and a cancellable echo thread. No public endpoint, privileged interface, external
DNS, shell-launched proxy, or production credential is used. TLS uses an embedded
public **test-only** CA/key, a leaf SAN `interop.xray.test`, explicit trust, and
disabled system roots; `allowInsecure` is not used. The fixture expires in 2045.

### What these checks do not establish

They do not cover domain destinations, IPv6 targets, UDP, failure/authentication
rejection equivalence, replay behavior, half-close semantics, certificate-name
or untrusted-chain rejection, every proxy/transport pairing, user hot reload,
long-running resource limits, concurrent fairness, cancellation under stalled
peers, fuzzing, or Linux/macOS behavior. Unit/self-loop tests elsewhere may cover
some of those independently; they are not cross-implementation evidence here.

## How to read the inventory

- **Integrated / probed:** selectable through CLI configuration and runtime,
  with executed peer coverage only where the ledger explicitly reports it.
- **Integrated subset:** selectable code exists; full source equivalence or
  reference interoperability has not been established.
- **Integration in progress:** root hooks exist but their current combined
  configuration/lifecycle behavior still awaits central validation.
- **Component:** native implementation exists without a complete executable
  selection/dispatch path. An exported module alone does not change this status.
- **Absent:** no native integrated implementation was found at this boundary.

The inspected boundaries are `rust/xray/src/{main,commands,config_loader}.rs`,
`rust/xray-core/src/config.rs`, `config/proxies.rs`, `runtime.rs` and its modules,
`router.rs` and `transport.rs`. Runtime wiring now includes TCP proxies and SS2022,
several native stream transports, policy/statistics/logging, management services,
and in-progress ordinary-observatory/SOCKS UDP integration. Unsupported top-level
fields and settings continue to fail validation; strict rejection still marks a
parity gap rather than an implementation of the rejected feature.

## Proxy inventory — every `proxy/` family

| Go family | Native Rust evidence | Executable status / remaining work |
| --- | --- | --- |
| `blackhole` | `config.rs`, `runtime.rs`, `runtime/udp_routing.rs` | Integrated TCP close/HTTP response/custom bytes; UDP drop selection is part of the new SOCKS UDP integration. Complete response/network equivalence is unproven. |
| `dns` | `dns/{wire,resolver,service,cache,encrypted,network}.rs`, `config/dns.rs` | Native resolver/service and configuration components. No configured DNS proxy outbound or root DNS field; network connector/cache work awaits validation. |
| `dokodemo` | `config.rs`, `runtime.rs` | Integrated fixed TCP forwarding; UDP, transparent/original-destination interception and followRedirect remain rejected. |
| `freedom` | `runtime.rs`, `runtime/admission.rs`, `protocol/freedom.rs`, `runtime/udp_routing.rs` | Integrated TCP direct/redirect with private defaults, ordered final rules and checked-address dialing; scoped allows passed historical Go interop. UDP final admission is now connected through SOCKS and awaits integrated validation. Broader freedom DNS strategies, fragmentation/noise and socket options remain gaps. |
| `http` | `protocol/{http,outbound}.rs` | CONNECT + Basic auth probed both ways; simple absolute-URI forwarding exists. No full per-request keepalive routing, transparent HTTP or complete HTTP connection behavior claim. |
| `hysteria` | `protocol/hysteria.rs`, `transport/hysteria.rs` | Native Hysteria2/UDP-fragment/HTTP3/Quinn components. Not selectable as a root proxy or transport. |
| `loopback` | No corresponding runtime variant | Absent configured loopback dispatch. |
| `shadowsocks` | `protocol/{shadowsocks,shadowsocks_session,shadowsocks_udp}.rs`, `config/proxies.rs` | Three legacy AEAD TCP ciphers passed historical Go probes. UDP components do not enable root Shadowsocks UDP; multi-user and remaining legacy cipher behavior are not claimed. |
| `shadowsocks_2022` | `protocol/shadowsocks2022.rs`, `config/proxies.rs`, `runtime.rs` | Native TCP inbound/outbound selection for `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`; both covered by the reported 18-case native proxy integration run. Go exchanges, UDP, identity chains and other SS2022 modes remain unproven or unsupported. |
| `socks` | `protocol/{socks,outbound,udp}.rs`, `runtime/{udp,udp_routing,udp_integration}.rs` | SOCKS4/4a/5 TCP inbound and SOCKS5 outbound; password/noauth TCP probed. SOCKS5 ASSOCIATE now has root bind/serve/routing hooks, pending integrated validation. UDP supports only admitted bare freedom/blackhole, with the documented source restrictions above. |
| `trojan` | `protocol/trojan.rs`, `config/proxies.rs` | Base authenticated TCP probed; fallbacks/flow rejected. UDP frame components do not enable Trojan UDP runtime. |
| `tun` | `protocol/tun.rs`, `protocol/tun/` | Portable packet/session/route components and an optional Linux native adapter separate from root dispatcher policy/routing. Privileged device, OS-route and supported-platform behavior are unproven. |
| `vless` | `protocol/vless.rs`, `protocol/vless_security.rs`, `config/proxies.rs` | Base UUID TCP with encryption/decryption explicitly `none` probed, including TLS/XHTTP. Vision/XTLS flows, encryption/seeds, reverse and mux/XUDP remain unsupported by root runtime; crypto/CLI helpers do not enable them. |
| `vmess` | `protocol/vmess.rs`, `protocol/vmess/{crypto,encoding,stream}.rs` | Native authentication/KDF/header/body/replay/stream and TCP integration. Four actual AES-GCM/ChaCha20 Go cases passed with a standard UUID. Broader modes/transports and ID parsing differences still require coverage. |
| `wireguard` | `protocol/wireguard.rs`, `protocol/wireguard/{config,routes,engine}.rs` | Native config, cryptokey routing and userspace packet engine. Caller-owned UDP sockets, DNS, timer polling and TCP/IP or TUN integration remain outside this component; no root Xray stream-proxy integration. |

## Transport inventory — every `transport/internet/` family

| Go family | Native Rust evidence | Executable status / remaining work |
| --- | --- | --- |
| `tcp` | `transport.rs` | Integrated ordinary TCP/raw. Header camouflage and all socket semantics are not implied. |
| `tls` | `transport/tls.rs` | Integrated rustls TLS and explicit trust; TLS1.2/1.3 VLESS probed. Certificate reload/selection helpers exist. Browser/uTLS impersonation, transport ECH, source MITM and pinned-peer modes remain rejected or absent. TLS CLI certificate utilities are a separate feature. |
| `splithttp` | `transport/xhttp.rs`, `transport/xhttp/http2.rs` | HTTP/1.1 packet-up integrated/probed with and without TLS. HTTP/1.1 stream-up/stream-one are now selectable, with new Go-mode runs pending. HTTP/2 stream-one is a component; runtime HTTP/2 selection, HTTP/3, Xmux, downloadSettings and tokenish padding remain gaps. |
| `websocket` | `transport/websocket.rs`, `config.rs`, `transport.rs` | Upgrade/framing/early data selectable by StreamSettings on inbound/outbound paths. No Go WebSocket result is included in the historical 30-case ledger; broader combination coverage remains required. |
| `httpupgrade` | `transport/httpupgrade.rs`, `config.rs`, `transport.rs` | Native client/server upgrade and validation are selectable. Full source/refusal and cross-language equivalence are not established here. |
| `reality` | `transport/reality.rs`, `transport/reality/handshake.rs`, `config/reality.rs` | Native outbound handshake is wired for explicit `fingerprint="native"`. Inbound REALITY remains rejected; browser fingerprint emulation/spider behavior and reference interoperability are not established. |
| `hysteria` | `transport/hysteria.rs` | HTTP/3/Quinn components without root selection. Quinn congestion algorithms do not establish source Brutal/BBR parity. |
| `finalmask` | `transport/finalmask.rs`, `finalmask/{fragment,noise,custom,salamander}.rs` | Native mask components; complete configured mask-chain/socket integration remains absent. |
| `grpc` | `transport/grpc.rs`, `config.rs`, `transport.rs`, `runtime.rs` | Native HTTP/2 proxy transport selectable; reported integration binary **8 passed**. This is separate from management tonic gRPC. Go reference exchanges remain pending. |
| `kcp` | `transport/kcp.rs` and submodules, `config.rs`, `runtime.rs` | Native reliable-UDP byte stream is selectable as kcp/mkcp. Reported integration binary **5 passed before tightened startup rollback changes**; combined core snapshot had assigned KCP failures. Latest rollback/fixes and Go exchanges need central validation; all legacy headers/masks/socket options are not claimed. |
| `xdrive` | `transport/xdrive.rs` and submodules | Native local-storage/explicit-HTTP-template object-stream components; no StreamSettings/root dispatcher selection. Google Drive is unsupported. Combined core snapshot had assigned XDRIVE failures; fixes need revalidation. |
| `udp` | `protocol/udp.rs`, `runtime/udp.rs` | Bounded SOCKS UDP relay and routing hooks exist, pending integrated validation. No general UDP proxy/transport dispatcher or all-protocol UDP support. |
| `browser_dialer` | No runtime adapter | Absent browser-mediated dialer. |
| `headers` | No complete configured header framework | Absent complete source camouflage-header family. |
| `stat` | `features/stats.rs`, `runtime/accounting.rs`, `features/session.rs` | Policy-enabled user/system counters are connected to stream I/O; reported accounting integration **6 passed**. UDP follows the separate boundaries above. Full per-protocol wire/payload parity is not inferred. |
| `tagged` | No general dialer-proxy/tagged transport adapter | Absent configured transport redirection/chaining. API tag dispatch and observatory's exact-outbound selection do not implement this general feature. |

Tokio byte streams and bounded buffers approximate source pipe/link behavior.
MultiBuffer ownership, general packet links, splice/zero-copy paths and complete
socket/platform behavior require separate validation. A native PROXY-protocol
codec exists in `transport/proxy_protocol.rs`, but that does not enable configured
PROXY protocol, transparent sockets or the full `sockopt` surface.

## Application inventory — every `app/` family

| Go family | Native Rust evidence | Executable status / remaining work |
| --- | --- | --- |
| `commander` | `api.rs`, `api/server.rs`, `config.rs`, `runtime.rs` | API config now starts selected StatsService/LoggerService routes through an optional TCP listener and routed API tag. Ordinary ObservatoryService has new provider wiring awaiting integration validation. HandlerService, RoutingService and other mutation surfaces remain unsupported. |
| `dispatcher` | `runtime.rs` and modules | TCP routing, policy, stats and logging are connected. SOCKS UDP per-datagram routing is being integrated. General packet dispatch, sniffing/content override, mux, dynamic handlers and outbound chaining remain gaps. |
| `dns` | `dns/`, `config/dns.rs` | Classic UDP/TCP, encrypted-query, hosts/cache/stale/ECS and geodata server-selection components exist. New NetworkDns connector/cache composition awaits central validation; root DNS config/outbound/routed connector integration and FakeDNS remain incomplete. |
| `geodata` | `geodata.rs`, `geodata/`, `router.rs`, `protocol/freedom.rs` | Native on-disk geoip/geosite/external matchers now compile into immutable router and final-rule matchers, including supported attributes/inverse groups. Router recompilation is needed for changed assets; downloader/update scheduling and dynamic route reload are absent. |
| `log` | `logging.rs`, `runtime.rs`, `api/logger.rs`, CLI tracing setup | Log config, file outputs/masking, TCP access records and tracing are wired; LoggerService reopens outputs. Earlier runtime checkpoint covered masked access-file logging. Full DNS/UDP access-record production and every source logging behavior are not established. |
| `metrics` | No configured metrics service | Absent source HTTP/metrics runtime. |
| `observatory` | `features/observatory.rs`, `config/observatory.rs`, `runtime/observatory.rs`, `api/observatory.rs` | Ordinary measured probes, selected-outbound dialing, startup/cancellation and API provider hooks now exist; current root integration awaits validation. Burst scheduling and routing-balancer feedback remain unsupported. |
| `policy` | `features/{policy,session}.rs`, `config.rs`, `runtime.rs` | Level-zero handshake/idle/drain policy, buffering and user/system stat flags are wired. Nonzero user levels remain rejected; full source policy/dial/timeout equivalence is not claimed. |
| `proxyman` | `runtime.rs` listeners, `config.rs` enums | Static inbound/outbound ownership, transports and cancellation are integrated; SOCKS UDP hooks are new. Handler/user mutation RPCs, detours and complete per-handler options remain absent. |
| `reverse` | `mux/wire.rs` and reverse-related components | No integrated bridges/portals/reverse dispatch. Frame codecs are not a reverse service. |
| `router` | `router.rs`, `router/balancer.rs` | Ordered domain/IP/port/network/inbound/source/user routing, outbound tags and native geodata matching are wired. Only AsIs DNS strategy is accepted. Balancer algorithms are a standalone component; balancer config, observatory feedback, content rules and management mutation are not integrated. |
| `stats` | `features/stats.rs`, `api/stats.rs`, `runtime/accounting.rs` | Live counters, online-user guards and StatsService share the runtime manager when stats/policy are enabled. Reported accounting integration **6 passed**. Enabling the API alone does not enable traffic collection. |
| `version` | CLI source-target version output | No full source configuration version-feature equivalence established. |

StatsService and LoggerService implement service methods rather than only
generated messages. Native system snapshots cannot reproduce Go goroutine/GC
metrics; unsupported-field metadata remains explicit. A generated client or
service descriptor does not provide the absent handler/routing mutation APIs.

## Infrastructure, CLI, core/features, and common behavior

| Source area | Rust evidence / status | Remaining boundary |
| --- | --- | --- |
| `infra/conf/{json,serial}`, `main/run.go` | CLI loader supports local JSON/JSONC/YAML/TOML, stdin, repeated config files, sorted confdir/environment locations, tag-aware merging and single-file protobuf via `config/protobuf.rs`. | YAML 1.2 scalar resolution differs from Go YAML 1.1. Remote HTTP/Unix loading, process `env` application and unsupported protobuf/config fields remain gaps; strict protobuf subset decoding is not full conversion parity. |
| `infra/conf/xray.go` full construction | Strict native config now includes logging, policy, stats, API, ordinary observatory, geodata routing, SS2022 and several stream transports; SOCKS UDP root hooks are present. | Top-level configured DNS, reverse, metrics, burst observatory, sniffing, mux, sendThrough, socket options and numerous protocol settings remain rejected/unwired. Rich source defaults/null/legacy forms still need differential checks. |
| `main` run/test/dump/version | Native execution, config validation/dump, legacy flags and exit handling are wired. | Complete source help/error/flag/version-check equivalence remains unproven. |
| `main/commands/all/{uuid,x25519,wg}` | Native UUID/X25519/WG commands are dispatched by main. | Full CLI error/output/default parity requires coverage; key generation does not imply WireGuard runtime. |
| `main/commands/all/{mlkem768,mldsa65,vlessenc}` | Native helpers in `xray/src/commands.rs` are now dispatched through the CLI. | Helper availability does not enable VLESS encryption or REALITY inbound runtime; no new executable-reference test result is inferred by this refresh. |
| `main/commands/all/tls` | Native `cert`, `hash`, `ping` and `ech` utilities are dispatched by the CLI. | CLI ECH/certificate generation does not enable transport ECH or source certificate-issuing runtime modes. Full command differential/platform coverage is unproven. |
| `main/commands/all/convert` | Native strict protobuf input adapter exists. | No general JSON/protobuf conversion CLI; accepting supported protobuf input is a narrower feature. |
| `main/commands/all/api` | Native stats/query/system/online-user commands and `restartlogger` are dispatched through `commands/api.rs`. | Handler/user/inbound/outbound/rule/balancer/source-IP-block mutation and observatory CLI commands remain explicit unsupported diagnostics. |
| `core` feature registry/lifecycle | Native Server construction/cancellation, management services and source schemas. | Dynamic feature dependency registry, complete Go API/library surface and all lifecycle interactions remain unported. |
| `features/{inbound,outbound,routing,dns,policy,stats,extension}` | Typed config/dispatcher, integrated policy/stats and native DNS components. | No complete equivalent service/extension registry; protobuf types do not implement those contracts. |
| `common/{protocol,net,uuid}` | Native addresses, users and per-protocol serializers. | Broad differential coverage of coercion, mapped IPs, invalid names and all family paths remains needed. |
| `common/{crypto,antireplay}` | Legacy AEAD, SS2022, VMess, REALITY and encryption helpers. | Protocol-specific replay, nonce, time and key lifecycle checks remain distinct; no blanket cryptographic parity claim. |
| `common/{mux,xudp}` and reverse links | `mux/wire.rs` and UDP components. | No complete root Mux.Cool/XUDP scheduling/reuse/retry or reverse multiplexing. |
| `common/{platform,net}` OS integration | Standard/Tokio sockets and optional TUN components. | Transparent proxy, original cross-platform socket options, Android/service integration and full OS matrix remain unproven. |
| `common/{buf,bytespool,cache,ctx,session,signal,task,retry,drain}` | Owned buffers, Arc/cancellation, caches and per-feature helpers. | Externally visible bounds, deadlines, anti-probing/drain, retry and cleanup still need feature-specific validation. |
| `common/{geodata,log,ocsp,peer,singbridge,serial,utils}` | Integrated geodata/logging, TypedMessage and limited TLS support. | OCSP, external stack bridges and remaining peer/context/helper semantics depend on incomplete features. |
| `common/{bitmask,cmdarg,dice,errors,reflect,units}` | Rust standard types, clap, rand, anyhow and local parsers. | Source flag/range/randomness/error and reflection-JSON behavior still need scoped differential checks. |
| `testing/` and Go fuzz/test fixtures | Native unit/integration/CLI tests plus actual Go-peer harness. | Original test corpus, fuzzers and all permutations are not migrated or executed. No completion percentage follows from file/test counts. |

All **80 original `.proto` files** feed `rust/xray-proto/build.rs` message/service
bindings and a descriptor set. TypedMessage pack/unpack checks preserve schema
identity. These bindings do not implement every corresponding proxy, app,
configuration builder, service or lifecycle.

## Build, release, and platform inventory

The Cargo workspace and `rust.yml` declare fmt/clippy/test jobs for Ubuntu,
Windows and macOS. A declared matrix is not a completed CI run. Native
`.github/workflows/rust-release.yml` and `rust/packaging/Dockerfile` now exist,
while the original `release.yml` and Win7 workflow still include Go builds.
Packaging definitions alone do not establish produced/released Rust artifacts.

No full cross-target smoke result, Linux capability/TUN permission coverage,
Windows service/Wintun behavior, macOS networking equivalence or original
Android/MIPS/ARM/BSD support follows from the Windows loopback evidence here.
The reported non-green core snapshot and pending integrations preclude a
complete current workspace/release validation claim.

The Rust runtime is native. Interop tests spawn a **test reference peer**, not a
Go backend used by the Rust executable. Test-only Go execution is not a shipped
runtime dependency.

## Completion gates suggested by the evidence

1. Retain the repaired freedom final rules/default restrictions and their denial
   tests. Extend differential policy coverage beyond the scoped-allow wire tests
   before declaring the integrated subset safe to replace source configurations.
2. Wire delivered components through strict configuration, dispatch, cancellation,
   policy, accounting and logging. Test each externally selectable feature with
   real peer traffic, including failure and authentication cases.
3. Add reference coverage for IPv6/domain destinations, UDP, half-close, timeouts,
   malformed frames, replay, large/concurrent loads and every supported security
   and transport combination. Explicitly record intentionally unsupported modes.
4. Integrate the absent protocol families, source config/CLI services, routing/
   DNS/app behavior and OS networking; inspect every inventory row again after
   the active workstreams land.
5. Run the full locked workspace checks and real-reference harness with output
   retained, then platform/release verification. Do not retire Go source or
   claim full parity until the inventory and validation evidence justify it.

## September 28, 2026 — root config/runtime wiring complete (11284fa8)

The 15 delivered components are wired into the root config and runtime
(Phase-0 skeleton 77a47812 + integration 11284fa8): VLESS Vision flows and
mlkem768x25519plus sessions live on both sides; REALITY inbound accepts
through the batch parser; Trojan UDP and SS2022 `tcp,udp` listeners serve
through the UDP dispatcher; the WireGuard outbound engine pool dials real
targets (the transport send is now async — the sync try_send_to surfaced
tokio's readiness gate as an engine-killing WouldBlock); freedom
domainStrategy resolves through the configured DNS app; the reverse app
compiles portal tags as routing outbounds, attaches bridge-domain carriers
before routing and relays end to end (two-server test); burstObservatory
mirrors the ordinary observer with Go's Manager.Select prefix selection;
HandlerService serves listings and user queries from runtime state with
every unimplemented mutation failing explicitly; the MASQUE outbound shares
one h2 client per outbound and opens one extended-CONNECT per connection;
the generic masque transport arm relays through the Hub; the CLI loader
applies the Go-verified YAML 1.1/env compat.

Gates: fmt/clippy -D warnings clean, workspace tests **1062/0/5**, Go
interop **34/6/8** (XRAY_GO_BINARY as an absolute path), all five
env-gated Go fixtures pass. Explicitly rejected (fail with named gaps,
never silently): HandlerService mutations, reverse XUDP, 2022-chacha20
UDP, MASQUE HTTP/3, legacy SS UDP, dokodemo UDP, port ranges, user levels.

## September 29, 2026 — routing API, reflection, convert, hysteria wired (this batch)

- **RoutingService** (xray.app.router.RoutingService): TestRoute,
  GetBalancerInfo/OverrideBalancerTarget (through the compiled
  `Balancer::set_override`), AddRule/RemoveRule/ListRule with the
  `RuntimeRoutingStore` hot-recompiling the router and swapping it inside
  `RouterHandle` (balancer observations re-attach across swaps);
  SubscribeRoutingStats is a named unimplemented (the statistics channel
  does not exist in the port). The CLI gained `lsrules`, `rmrules`,
  `adrules` with the Go config-JSON spellings for rules.
- **gRPC server reflection** over the full descriptor set
  (tonic-reflection), registered as `ReflectionService`.
- **`xray convert json`**: TypedMessage files decode through
  prost-reflect into JSON (the `_TypedMessage_` annotation optional);
  `convert pb` remains a named rejection (the config-to-protobuf encoder
  is not integrated).
- **Hysteria end to end**: the `hysteria` inbound/outbound config arms
  (version-2 users, `hysteriaSettings`, `finalmask.quicParams` with Go's
  StreamConfig.Build validation and Bandwidth parsing), one QUIC listener
  per inbound port, the dispatch seam (TCP streams run the shared
  post-handshake dispatch — routing, sniffing, stats; UDP sessions
  dispatch each datagram through the UDP routing dispatcher with relay
  peers and XUDP pumps), and the outbound pool keeping one shared
  authenticated QUIC session per outbound. Two full-runtime tests relay
  both directions (client dialer → inbound seam → freedom, and SOCKS →
  hysteria outbound → second runtime → freedom).
- Named rejections added: the pinned Hysteria **BBR profiles** (quinn's
  experimental BBR is a different controller — the config default
  therefore requires `congestion: "reno"`) and **Brutal**; quicParams
  `debug`/`disableGSO`/`disableStatelessReset`; `finalmask` tcp/udp mask
  chains (the mask codecs exist, the socket chain install is not wired);
  quinn has no stateless resets at all and never parrots Chrome's QUIC
  fingerprint (Go's defaults differ — documented, not fixable).
- Gates: fmt/clippy -D warnings clean; workspace tests **1175/0/5**;
  Go interop **34/34, 6/6, 8/8**; all five env-gated Go fixtures green.

## September 29, 2026 — handler mutations live, five modules wired (last two batches)

- **HandlerService AddInbound/RemoveInbound** now work: the wire config
  decodes through the startup protobuf converter (receiver sniffing added;
  `receiveOriginalDestination` named-rejected), recompiles with the ordinary
  validation, and binds through the runtime's accept loop on a per-tag child
  token; every inbound family the runtime serves is covered (TCP listeners,
  hysteria QUIC, TUN devices, WireGuard endpoints, unix sockets, and the
  SS/dokodemo/SS2022 UDP sidecars). RemoveInbound cancels exactly that tag's
  listeners. E2E: a SOCKS password relay through an AddInbound'd listener,
  close-on-remove, Go's existing-tag and ErrNoClue contracts. Deviation:
  GetInboundUser on non-user-managed inbounds answers empty where Go errors.
- **CLI**: `api adi` (the InboundHandlerConfig encoder over the decoder's
  exact coverage — socks/http/dokodemo/vless/vmess/trojan/shadowsocks
  including 2022, plain-TCP or TLS receivers, PEM certificate parsing),
  `api rmi` (tag or config-file targets), `api lsi` (isOnlyTags honored).
- **TUN inbound** wired: config arm → runtime entry, one serve task per
  inbound (no port key needed — InboundConfig.port now defaults to Go's
  zero), full-cone UDP through the dispatcher. Named rejections: desc, dns
  install, autoSystemRoutingTable, autoOutboundsInterface (OS plumbing);
  mtu < 1280 (netstack floor).
- **WireGuard inbound** wired: one UDP endpoint per port, server-role engine
  with catch-all listener bootstrap (SYN-peek on decrypted packets),
  loopback engine e2e both TCP and UDP.
- **tcpSettings.header** wired end-to-end: StreamSettings decodes
  rawSettings (header object; null fails like Go's loader), the codec wraps
  the accept (after TLS) and the dial (before the first proxy write); the
  e2e test runs SOCKS→SOCKS over two runtimes with HTTP camouflage on the
  wire between them.
- **Unix domain sockets** wired: `ListenAddress` (IP or path) on the inbound
  config; dokodemo network lists parse Go-style (tcp/udp/unix entries); a
  path listen binds the unix listener (abstract `@`/`@@` and `,perm`
  parsing, lockfile exclusivity; Windows fails with the named platform
  rejection, never a TCP fallback).
- **Browser dialer** wired: armed at Server::start (Go's ReloadEnvSettings
  path), the websocket outbound dials through it when
  XRAY_BROWSER_DIALER carries an address; early data is not carried through
  the browser path (documented deviation).
- Gates both batches: fmt; clippy -D warnings clean; workspace tests
  **1248/0/5**; Go interop **34/34 + 6/6 + 8/8**; all five env-gated Go
  fixtures green.

## September 29, 2026 — xdrive transport live; API user queries in the CLI

- **XDRIVE stream transport** end to end: the engine-backed adapter
  (XdriveSettings over Go's XDriveConfig keys, local + HTTP-template object
  stores, per-stream sessions over the WAL) wired as `network: "xdrive"` —
  inbound listeners accept from the store, outbound dials write to it, the
  proxy handshake rides the object-store stream. Two-runtime e2e: SOCKS→SOCKS
  with every byte of the second hop in shared storage. Named rejections:
  unknown services (Google Drive parses but the native backend is not
  implemented), malformed templates, security non-none.
- **CLI**: `api inbounduser` / `api inboundusercount` (GetInboundUsers /
  GetInboundUsersCount). The remaining api commands stay named rejections:
  ado/rmo/lso (the runtime's outbound set is immutable after startup),
  adu/rmu (alter_inbound needs mutable per-listener account sets).
- Gates: fmt; clippy -D warnings clean; workspace tests **1256/0/5**.
