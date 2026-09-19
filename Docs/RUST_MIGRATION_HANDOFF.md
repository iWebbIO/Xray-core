# Rust migration handoff

## Objective and pause

The user requested conversion of the entire Xray-core project to native Rust
with full feature parity, requested 25 subagents (especially REALITY/XHTTP),
then explicitly requested **pause and document all work in /Docs**.
This is the repository's Docs folder.

Implementation is paused. There is no completion claim. No migration commits,
pull requests, merges, release publication, deployment, or retirement of Go
sources was performed. No tests/builds were launched after the pause.

The goal API returned no active goal at pause. An attempted paused-status update
therefore could not change a goal record; no replacement goal was created.
Implementation agents were stopped. Coordinator work afterward is documentation
only.

## Workspace

- Workspace: C:/Users/W/Documents/iwebbio/Xray-core.
- Branch: main; HEAD: dcdfc57c.
- Source target: Xray 26.9.9.
- Original inventory: 948 Go files, approximately 137,610 nonblank lines,
  80 protobuf schemas.
- Host: Windows/PowerShell. Rust 1.96 and Go 1.27 were available during work.
- Changes are uncommitted. Cargo files, Rust tree and new workflows are untracked.
  Tracked changes include README, .gitignore and Dependabot.
- Go remains the reference until native parity is demonstrated.

## Native architecture

| Crate | Responsibility |
|---|---|
| rust/xray-proto | Original schema messages, tonic services, descriptors, TypedMessage helpers |
| rust/xray-core | Protocols, transports, runtime, routing, policy, statistics, logging, DNS and API |
| rust/xray | Executable, configuration loading/merging, CLI and process tests |

Runtime owns listeners, connection tasks, gRPC logical streams, cancellation
and shutdown draining. Unsupported security/routing/configuration options must
fail explicitly. Native execution has no Go fallback.

Shared integration files are config.rs, config/proxies.rs, config/reality.rs,
runtime.rs, transport.rs and transport/tls.rs. Runtime support now includes
runtime/{accounting,admission,observatory,udp_integration,udp,udp_routing}.rs.
Root owns manifests, shared exports and central Cargo/Go validation. Library
delivery, runtime integration, unit testing and external interoperability are
different milestones.

## Functionality present at pause

“Integrated” means a configuration/runtime path exists, not that the latest
edits have passed all tests.

| Area | Present implementation | Evidence / remaining boundary |
|---|---|---|
| Base proxies | SOCKS4/4a/5, HTTP CONNECT/basic forwarding, dokodemo, base VLESS, Trojan | TCP/runtime and historical Go interoperability |
| VMess | AEAD TCP, AES-GCM/ChaCha outbound choice, shared replay authenticator | Historical native and both-cipher Go tests |
| Legacy Shadowsocks | Three AEAD TCP ciphers and shared session state | Historical three-cipher Go tests |
| Shadowsocks 2022 | Single-account AES128/AES256 TCP config/runtime | Native large/half-close chains pass; four new executable Go cases unrun |
| SOCKS UDP | Association, per-datagram routing/admission, limits, stats and shutdown | Final wiring and three new runtime tests unrun; bare freedom/blackhole only |
| Outbounds | Freedom, blackhole, SOCKS, HTTP, VLESS, VMess, Trojan, legacy/2022 SS, internal API | Full chaining/options/platform parity incomplete |
| TCP/TLS | Stream composition, validation/reload, actual ALPN checks | Historical TLS1.2/1.3 Go tests; browser fingerprints/other options remain gaps |
| WS/HTTP Upgrade | Native framing, metadata and stream composition | Component/runtime evidence; full option parity unproven |
| XHTTP H1 | packet-up, stream-up, stream-one | Packet-up Go pass; corrected Windows streaming fixture awaits rerun |
| XHTTP H2 | Exported standalone stream-one module, 20 authored tests | Runtime selection/ALPN integration absent; tests unrun |
| gRPC | Tun/TunMulti H2, multiple logical streams, bounded ownership, actual h2 ALPN | Eight runtime tests pass; external Go cases pending |
| KCP | Native UDP, strict config, listener adapter, optional TLS | Five runtime tests pass before latest cancellation/drop/rollback changes |
| REALITY client | Explicit native fingerprint, TLS1.3/authentication, ML-DSA verification | Earlier pinned-Go server fixture passed; browser emulation rejected |
| REALITY server | Native handshake, bounded target hello/record-size mirror and rejected-peer forwarding | Library only; updated Go fixture built, new validation pending |
| VLESS encryption | Native 1-RTT hybrid exchange, records, up to eight NFS relay keys | Library only; final semantic replay identity correction untested |
| Freedom/routing | Protocol-dependent private/reserved blocking, finalRules, checked/pinned addresses, geodata | AsIs subset; DNS strategies, full balancers and advanced matching incomplete |
| Policy/stats | Level-zero deadlines, setup budget, half-close, user guards, distinct framed counters | Six regressions and 18 proxy cases passed at recorded snapshot |
| Logging | File/access/tracing, masks, omitted-vs-empty config, restart | Runtime tests passed; complete equivalence still needs audit |
| Management | Configured direct/routed StatsService/LoggerService; native API CLI | Runtime tests pass; new API CLI tests lack separately confirmed pass |
| Observatory | Ordinary config, real selected-outbound probes, provider/API/scheduler | Final wiring plus six runtime tests unrun; burst/feedback incomplete |
| DNS | Classic/encrypted transports, cache, hosts/server config and checked connector library | Top-level configured DNS still rejected |
| XDRIVE | Local WAL/session streams and template HTTP provider | Libraries; final fixes/template tests unrun; Drive/fronting unsupported |
| Config/CLI | JSONC/YAML/TOML merging, binary protobuf decoder/loader, key/cert/ECH/management commands | Protobuf compilation and TLS certificate-location defect unresolved |
| Other components | UDP codecs, final masks, Hysteria, WireGuard, TUN, mux/reverse, balancers, PROXY | Substantial libraries; runtime parity varies |
| Packaging/CI | Rust workflow and artifact-only package workflow/driver | No publication; Go release remains |

## Accounting and policy changes

The earlier runtime used application payload totals for both system directions,
omitted framed bytes/failed handshakes, handed API connections away from policy
ownership, and started inactivity enforcement after outbound setup.

The correction wraps decoded transport streams before proxy framing, registers
configured counters at startup, creates user guards after authentication,
carries the original idle deadline through DNS/dialing, and feeds initial
payload through the timed relay. Routed API sessions use an owned bounded
duplex bridge. Six regression tests passed.

For VLESS IPv4, inbound counts are payload+26 uplink and payload+2 downlink;
freedom outbound remains application bytes. Later observatory/UDP changes reuse
this integration but need new tests. Dynamic SOCKS UDP wire bytes intentionally
do not enter system-inbound connection counters, matching the reference
TempUDPConn boundary.

## Exact stopping state

1. Latest broad library run: **679 total, 672 passed, three failed, four ignored**.
   Failures were KCP cancellation classification and two XDRIVE
   deadline/timestamp cases. Corrections are on disk and untested.
2. Existing compiled integration binaries passed **8 gRPC, 5 KCP, 6 accounting,
   18 proxy** cases. They predate the final source wave.
3. Last whole-workspace check failed E0433 because httpupgrade::Config did not
   exist. The owner changed both relevant sites to HttpUpgradeConfig. No
   subsequent successful check ran.
4. Final protobuf TLS conversion preserves embedded PEM for one-time,
   verification, or incomplete path-pair cases. For reloadable encipherment
   pairs it compares current files with embedded snapshots, then keeps paths
   and removes inline fields. This patch is formatted but uncompiled/untested.
5. That patch reads paths directly with std::fs::read. It does not resolve
   xray.location.cert / XRAY_LOCATION_CERT and executable-directory fallback.
   Real file-backed TLS protobuf regression fixtures were not added.
6. Final VLESS replay history hashes authenticated semantics rather than
   malleable NFS prefixes. Equivalent canonical X25519 reciprocal points were
   independently demonstrated. Corrected Rust tests have not run.
7. XHTTP H1 intermittent process failure was traced to accepted Windows echo
   sockets inheriting nonblocking mode. The fixture now resets blocking mode
   and reports worker errors. Full/repeated reruns remain pending.
8. Observatory, SOCKS UDP, DNS network, H2, protobuf and template storage final
   changes await combined validation.
9. Repository fmt/Clippy are not known green. A fmt dry run listed seven files;
   scoped formatting followed and further edits arrived. target/fmt-check.log
   is historical evidence, not a current result.
10. rust/notes/PARITY_AUDIT.md refresh was interrupted. Saved changes are a
    draft, not a completed final audit or staged/committed result.

## Agent coordination

The requested 25 distinct agents became **26** because queued transport workers
launched before a counting correction. This was disclosed. All later work
reused existing workers; no further distinct agents were created.

| Task/agent | Ownership history / final assignment |
|---|---|
| Parent 01a0bad7-07ec-7ab3-b62c-a66f92e3cb66 | Manifests, integration, exports, central validation and fixtures |
| crypto_cli | Native utilities/API/geodata; accounting/policy, KCP/SS2022 dispatch, observatory/UDP wiring |
| logging | Logging, XHTTP H1, protobuf decoder and CLI loading |
| management_api | REALITY client, XDRIVE/template, protobuf read-only review |
| Helper A 01a0baee-8536-77c1-8c82-116eeedb5750 | Transport/platform/packaging, latest KCP/gRPC/PROXY/H2 |
| Helper B 01a0baed-94c1-7b90-aa4c-2ae56c41595d | Protocol/security, latest REALITY server, SS2022 UDP, VLESS |
| Helper C 01a0baee-790c-76f3-9586-037a38d97c79 | DNS/UDP/observatory, geodata/parity and independent reviews |

Editing leases cease with the pause. Coordinator documents preserve the module
ownership context for a future authorized resume.

## Preservation and disk history

Disk exhaustion previously truncated VLESS handshake tests and GRPC.md. Both
were restored and verified; the restored library suite passed before later
changes. The user subsequently freed disk space. The pause process check found
no cargo, rustc, go or link process; approximately 3.77 GB was free.

Reference binaries/diagnostics remain in ignored target. Scoped cargo clean
operations ran earlier. Automatic approval review rejected an attempted
recursive target/debug deletion; it was not retried.

Preserve the protected ignored directory
rust/xray-core/src/geodata/validation-41b0aeb1317a4f1fae67274ba19d34aa/
and its exact .gitignore entry. Earlier deletion attempts were also rejected.
Do not bypass either rejection with alternative deletion commands.

No original Go code was removed. No migration cleanup, feature development,
testing or build activity is authorized by this pause documentation.

