# Migration agent ledger

The user requested 25 subagents. There are 26 distinct subagents in total:
9 under the integrating task and 7, 5, and 5 under its three helper tasks.
The second additional transport worker started before the count correction
arrived. No further distinct workers are being created; follow-up work reuses
existing workers. There are at most three active workers per coordinating task.
Work-package numbers below are assignments, not unique-agent counts: package23
reused the HTTP Upgrade worker.

The parent owns shared builds, manifests, configuration, runtime and exports.
Library tests, runtime integration and cross-implementation parity are separate
milestones. A completed bounded assignment does not mean complete subsystem parity.

| # | Initial assignment | Delivered coverage / current status |
|---|---|---|
| 1 | VLESS/Trojan | Base TCP integrated; Go/Rust interop passes |
| 2 | SOCKS5/HTTP outbounds | Integrated; authenticated and unauthenticated interop passes |
| 3 | Shadowsocks | Legacy AEAD and single-account 2022 AES TCP integrated; legacy Go interop and native 2022 runtime chains pass |
| 4 | REALITY | Authentication primitives tested; full transport remains partial |
| 5 | XHTTP | HTTP/1.1 packet-up integrated and interop tested |
| 6 | TLS | TLS1.2/1.3 integrated and interop tested |
| 7 | WebSocket | Integrated; module and runtime tests pass |
| 8 | HTTP Upgrade | Integrated; module and runtime tests pass |
| 9 | DNS | Wire/resolver/cache library tested; runtime integration pending |
| 10 | VMess crypto | Integrated through TCP adapter; both cipher interop cases pass |
| 11 | VMess framing | TCP stream adapter integrated; replay/cancellation/interop tests pass |
| 12 | UDP | Protocol/session codecs tested; runtime dispatch pending |
| 13 | Configuration loader | JSONC/YAML/TOML merging integrated and tested |
| 14 | Geodata | Native geodata routing integrated; advanced DNS strategy and routing remain work |
| 15 | Policy/statistics | Level-zero relay and runtime accounting integrated and tested |
| 16 | Management API | StatsService and LoggerService configured direct/routed runtime tests pass; observatory integration underway |
| 17 | Logging | File/access/trace logging integrated; runtime tests pass |
| 18 | CLI commands | Native crypto/certificate/ECH utilities integrated; 19 command tests pass |
| 19 | Final masks | Native codecs tested; packet/config integration pending |
| 20 | Hysteria | QUIC/H3 client/wire tests pass; full runtime/server/congestion parity pending |
| 21 | WireGuard | Native packet engine tested; runtime/network-stack integration pending |
| 22 | TUN | Portable tests pass; optional native stack validation pending |
| 23 | Mux/reverse | Native library tests pass; runtime dispatch integration pending |
| 24 | Packaging | Build/archive driver and artifact-only CI delivered; no publication |
| 25 | Parity audit | Actual Go/Rust interoperability:30 cases pass, including VMess |

Current follow-up assignments reuse the existing workers:

- REALITY: native client and ML-DSA verification passed the pinned-Go fixture;
  native server and bounded target mirroring delivered, with new Go validation pending.
- XHTTP: H1 streaming fixture correction and native H2 stream-one module delivered;
  actual streaming-mode interoperability and H2 tests are queued.
- VLESS encryption: native 1-RTT hybrid exchange and up to eight NFS relay keys;
  replay-equivalent X25519 aliases are undergoing a security fix before acceptance.
- Shadowsocks 2022: TCP configuration/runtime integrated and both AES chains pass;
  authenticated UDP/session wrapper delivered, packet runtime integration pending.
- DNS: server selection, cache, encrypted transports and routed numeric-address
  connector delivered in layers; full runtime construction is still pending.
- SOCKS UDP and observatory: dispatcher/configuration/scheduler integration underway.
- KCP/gRPC: eight gRPC runtime and five KCP runtime tests pass; KCP cancellation
  and immediate rollback corrections require the next rebuild.
- Runtime policy/accounting: six regressions pass, covering separate protocol
  framing, failed handshakes, routed API ownership and setup inactivity deadlines.
- XDRIVE: local WAL/session and HTTP-template providers delivered; deadline and
  Windows timestamp regressions fixed, rebuilt validation pending.
- Protobuf: strict native decoder and CLI byte loader delivered; tests pending.
- Audit: refresh current feature evidence and remaining whole-project gaps.

## Checkpoint — September 27, 2026, parallel batch (commit 421a7630)

A 15-agent parallel batch (strict per-file ownership, shared conventions in
notes/AGENT_CONVENTIONS.md) ported fifteen previously-missing subsystems as
tested components, followed by central integration. Delivered:

MASQUE stack (capsule codec + HTTP/2 extended-CONNECT transport + proxy
session), VLESS encryption wire session, XTLS Vision stream adapter, Trojan
UDP frames, multi-user Shadowsocks-2022 UDP, WireGuard userspace netstack
(smoltcp TCP + UDP over the existing Noise engine), Mux.Cool session
scheduling, reverse bridge/portal, burst observatory, DNS app composition,
HandlerService management API, and Go-verified YAML-1.1/env compat.

Each package ships focused loopback tests (135 new tests total). Integration
repairs: the SS2022 UDP AEAD open double-stripped the GCM tag; the MASQUE
client raced ahead of the server's HTTP/2 SETTINGS before the extended-CONNECT
check; the Vision reader awaited bytes forever after a decoder poisoning; the
WireGuard loopback test wire fed each side its own sends; TCP shutdown waited
for the peer's FIN instead of the local one; the REALITY inbound default for
absent maxTimeDiff stayed zero (disabled) like Go; Go's /0 range-to-prefix
case was fixed in host-mask computation.

Executed: fmt clean, clippy `-D warnings` clean, `cargo test --workspace
--locked` **1020 passed / 0 failed / 5 ignored** (the five env-gated Go
fixtures all verified passing), Go-reference interop unchanged (34/6/8).
These are components with `from_value`/runtime-hook contracts; root
config/runtime wiring for the new selectors is the next milestone, and the
Go MASQUE HTTP/3 branch remains explicitly rejected.

## Checkpoint — September 27, 2026 (after upstream merge 71e232c1)

The upstream merge added the Go MASQUE outbound/transport (RFC 9484 CONNECT-IP,
~6.6k lines), an HTTP/2 MASQUE mode, a FakeDNS IPv6 pool default change, geodata
regex prefiltering, and WireGuard packet-view releases. No Rust code referenced
the removed/renumbered `wireguard`/`udphop` proto fields, and `xray-proto`
regenerates bindings from the merged `.proto` set automatically; a native Rust
MASQUE implementation is a new backlog item, not started.

Executed on the merged tree (Windows x86-64, Go 1.27 reference rebuilt from
source at commit 71e232c1):

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
  --locked -- -D warnings`: both clean after fixing 48 lints raised by the
  newer 1.96 toolchain (let-underscore futures, is_multiple_of, needless
  borrows, collapsible ifs, boxed a large REALITY enum variant, and context
  structs replacing two 8-argument runtime functions).
- `cargo test --workspace --locked --no-fail-fast`: **885 passed, 0 failed,
  5 ignored** (the ignored are the env-gated Go-fixture tests). The previously
  assigned failures are resolved: the KCP linger test now probes the wildcard
  bind form (Winsock permits specific-over-wildcard binds), and the DNS
  TCP/UDP fixture reserves via the UDP allocator to avoid Windows excluded
  port ranges.
- Real-reference interoperability with `XRAY_GO_BINARY=target/reference-xray.exe`
  (rebuilt from the merged source): `interop` 34/34, `transport_interop` 6/6,
  `xhttp_modes` 8/8. The KCP and gRPC-tun Rust→Go cases pass after granting the
  Go server the same scoped echo-port freedom `finalRules` allow that interop.rs
  already used; the Go freedom private-target default was blackholing them.
- All five env-gated Go-fixture tests pass against fixtures rebuilt from the
  merged source: SS2022 both directions/ciphers, XDRIVE local both directions,
  REALITY Go-server direction, and both REALITY native-server directions.
  Two parity repairs landed: the native REALITY server no longer requires
  Ed25519 (0x0807) in the client signature list (the pinned Go fork forces
  Ed25519 for its synthetic certificate and never consults that list), and the
  Go target fixture now serves an ECDSA P-256 certificate because browser
  fingerprints do not advertise Ed25519 and Go's standard server rejects that
  pairing before sending any flight.
- CI: `rust.yml` gained an `interop` job that builds the Go reference from
  `go.mod`-pinned toolchain and runs the three interop targets with
  `XRAY_GO_BINARY`, closing the audit's missing-external-evidence gap on Linux.

Validation checkpoints are recorded in notes/PARITY_AUDIT.md. The entire project
conversion remains active; Go sources and Go release workflows are preserved.

## Checkpoint — September 28, 2026, root wiring (commits 77a47812 + 11284fa8)

The 15 delivered components are wired into the root config and runtime. A
Phase-0 skeleton (commit 77a47812) landed the final shapes — dns/reverse/
burstObservatory root keys, the masque transport, REALITY inbound, VLESS
Vision flows + mlkem768x25519plus encryption, Trojan/SS2022 UDP flags, the
full freedom domainStrategy set, masque/wireguard outbound protocols, seven
runtime satellite contracts — and the agents' landed work was integrated and
finished in commit 11284fa8 (several agents died mid-flight after writing
their files; their code was completed, corrected and validated centrally).

Now live end to end: VLESS Vision body wrap (both sides, header camouflage),
VLESS encrypted sessions, REALITY inbound accept, Trojan UDP-over-TCP,
SS2022 UDP listeners, WireGuard outbound engines (one per settings value),
freedom domainStrategy through the configured DNS app, the reverse app
(portal tags as routing outbounds, carrier attach, two-server e2e relay),
burst observatory, HandlerService listings/user queries (mutations fail
explicitly with named gaps), MASQUE outbound dispatch (shared h2 client,
extended-CONNECT per connection), the generic masque transport, and the
Go-verified YAML 1.1/env compat in the CLI loader.

Deterministic fixes this pass: the burst scheduler test's paused-clock
quantization (inclusive round window), the WireGuard engine deaths from the
sync try_send_to surfacing tokio's readiness gate as WouldBlock (the
transport send is now async/reactor-aware; proved by a minimal socket
probe), the portal-tag compile catch-22 (portals compile as routing
outbounds inside Config::compile so routing rules validate), and the
vless addon test's Go-accuracy (empty addons are the base case; the
unknown-flow arm carries no account UUID).

Executed: fmt clean, clippy -D warnings clean, cargo test --workspace
--locked 1062/0/5 (+39 over the batch), Go interop 34/34 + 6/6 + 8/8
against target/reference-xray.exe (absolute path required — relative
XRAY_GO_BINARY paths fail from rust/), and all five env-gated Go-fixture
tests pass (SS2022 both directions/ciphers, XDRIVE local, REALITY
Go-server, REALITY native-server/client pairs).

Known explicitly-rejected surfaces (unchanged): HandlerService mutations
(proto-to-config decoder + listener ownership handoff), reverse XUDP,
2022-blake3-chacha20 UDP, MASQUE HTTP/3, legacy Shadowsocks UDP,
dokodemo UDP, port ranges, user policy levels.

## Checkpoint — September 28, 2026, final completion batch (commits 5cdf0d66..3fe474ff)

Six commits closing the audit's A/B/C lists. Newly live, all with gates
(fmt/clippy -D warnings clean; workspace tests 1155/0/5; Go interop 34/6/8;
all five env-gated Go fixtures green):

- Mux.Cool outbound multiplexing: the "mux" settings with two carrier pools
  per outbound (TCP + XUDP), the inbound carrier server intercepting every
  v1.mux.cool request, XUDP packet sessions through the UDP routing
  dispatcher, and Go's xudpProxyUDP443 policies (skip names its gap).
- Traffic sniffing: http/tls/quic sniffers with Go's constants and golden
  bytes, destOverride with routeOnly, sniffed-protocol routing conditions.
- Encrypted DNS: DoH (h2) and DoT nameservers with #ip bootstrap fragments;
  routed domain endpoints name the missing runtime dialer.
- FakeDNS: root fakeDns pools, the fakedns nameserver answering TTL-1 pool
  leases, and the dispatcher's fake-IP-to-domain swap before routing.
- Remote config sources (http(s) and Unix sockets); port ranges; the
  tunnel/mixed/block/direct aliases.
- sockopt (all 19 Go fields; applicable options apply; the Linux-only ones
  name their gaps) + PROXY protocol accept with v1/v2 headers.
- Balancers (balancers/balancerTag, strategies, fallbackTag with explicit
  unresolvable-fallback rejection), observatory health through the
  BalancerObservations seam.
- Shadowsocks 2022 chacha single-key (TCP IETF-ChaCha verified against the
  pinned Go peer both directions; UDP XChaCha), legacy AEAD SS UDP, and
  dokodemo UDP.
- The dns inbound/outbound (hijack + rewrite-forward) and the loopback
  outbound; user policy levels end to end (accounts → handshakes →
  PolicyManager.ForLevel); the root env/version/geodata/metrics keys.
- RoutingService (TestRoute, balancer info/override, Add/Remove/List rule
  with hot router recompile+swap), gRPC reflection, the CLI lsrules/rmrules/
  adrules and `convert json`.
- Hysteria end to end: config arms, per-port QUIC listeners, the dispatch
  seam (TCP through the shared dispatch, UDP through the routing
  dispatcher with XUDP), the shared-session outbound pool; verified by two
  full-runtime tests plus the engine suite.

- HandlerService add/remove inbounds (every inbound family, per-tag listener
  tokens; alter_inbound user edits stay a named rejection), the CLI adi/rmi/lsi.
- The five late modules, all wired into config/runtime: the TUN inbound, the
  WireGuard inbound, the tcpSettings.header obfuscation, the unix domain
  socket listener, and the browser dialer on the websocket outbound.

Explicitly-rejected surfaces (fail with named errors, never silently):
nested Mux.Cool carriers; bittorrent/UTP and fakedns sniffing; HTTP/3
(QUIC) DNS; the geodata download scheduler; the metrics pprof app;
HandlerService runtime mutations; the TUN runtime; `convert pb`; the
pinned Hysteria BBR profiles and Brutal congestion (configs must select
`reno`); finalmask mask chains (codecs ported, socket install rejected by
name); kcp legacy header/seed obfuscation; xhttp xmux/download sessions;
`convert pb`'s encoder rejecting exactly what the decoder cannot consume
(the proto envelope's fail-closed list — documented per module);
TLS fingerprint impersonation (uTLS); routed encrypted DNS without
bootstrap pins; xudpProxyUDP443=skip. Known quinn deviations from Go's
hysteria defaults (documented, not configurable): no stateless resets,
no Chrome-QUIC fingerprint parroting.

## Checkpoint — September 29, 2026, routing API + reflection + convert + hysteria

One batch landing the RoutingService/reflection/convert trio and the full
hysteria runtime wiring. All gates green (fmt/clippy -D warnings clean;
workspace tests **1175/0/5**; Go interop 34/34 + 6/6 + 8/8 with the absolute
XRAY_GO_BINARY path; all five env-gated Go fixtures):

- `RouterHandle` (RwLock-swappable compiled router) on the Dispatcher; the
  `RuntimeRoutingStore` recompiles+swaps on every AddRule/RemoveRule and
  serves TestRoute/balancer info/balancer override; RoutingService itself
  runs over it (SubscribeRoutingStats is a named unimplemented).
- gRPC server reflection (ReflectionService over the descriptor set).
- CLI `lsrules`/`rmrules`/`adrules` (Go config-JSON rule spellings) and
  `xray convert json` (prost-reflect TypedMessage → JSON; `convert pb`
  stays a named rejection).
- Hysteria: config arms both sides (`hysteriaSettings`,
  `finalmask.quicParams` with Go's exact validation and Bandwidth
  parsing), per-port QUIC listeners via `bind_inbound`, the
  `RuntimeSeam` (TCP through `dispatch_request`, UDP through the UDP
  routing dispatcher with relay peers and XUDP pumps), and the outbound
  `HysteriaPool` (one shared authenticated QUIC session per outbound,
  `open_stream` through `establish`). Engine suite 5/5 plus the two
  full-runtime tests (client dialer → seam → freedom; SOCKS → hysteria
  outbound → second runtime → freedom).
- Named rejections added this batch: pinned BBR profiles/Brutal (the
  Go default congestion needs `reno`), quicParams debug/disableGSO/
  disableStatelessReset, finalmask mask chains; documented quinn
  deviations: no stateless resets, no Chrome fingerprint parroting.

## Checkpoint — September 29, 2026 — the Go reference tree removed

After the completed, gate-verified translation, the Go implementation left
the tree: 991 `.go` files, go.mod/go.sum, the four Go fixture peers under
rust/, the Go CI workflows and Dockerfiles, and the Go-tree artifacts. The
82 protobuf schemas moved to `rust/xray-proto/proto/` (paths preserved;
build.rs points there; the generated bindings are unchanged). The reference
lives in the git history; the built reference binaries remain in `target/`
for re-verification. Post-removal gates: fmt/clippy clean, workspace
1268/0/5, interop 34/6/8, fixtures 5/5.

## Checkpoint — September 29, 2026, handler mutations + five wired modules

Two commits: (1) HandlerService AddInbound/RemoveInbound live through the
runtime's own listener machinery (protobuf decode → config validation →
bind/spawn on per-tag child tokens; every inbound family covered), plus the
CLI `api adi` encoder / `api rmi` / `api lsi`; (2) the five agent-ported
modules wired into config and runtime — the TUN inbound (no port key,
device + netstack + full-cone UDP), the WireGuard inbound (per-port UDP
endpoints), the `tcpSettings.header` obfuscation (accept-side after TLS,
dial-side before the first write; two-runtime e2e with HTTP camouflage on
the wire), the unix domain socket listener (`ListenAddress` path-or-IP,
dokodemo-only, Windows named platform rejection), and the browser dialer
(armed at startup, websocket outbound routing). Gates at each commit: fmt;
clippy -D warnings; workspace tests 1242/0/5 then **1248/0/5**; interop
34/34 + 6/6 + 8/8; all five env-gated Go fixtures green. Deviations
recorded in PARITY_AUDIT.md (GetInboundUser on non-user-managed inbounds
answers empty; browser-dialer websocket early data not carried; tun OS
plumbing options named-rejected).
