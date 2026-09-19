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

The latest broad library checkpoint ran 679 tests: 672 passed, three failed and
four external-reference tests were ignored. The three failures were assigned to
the KCP/XDRIVE owners and are not waived. Compiled runtime test suites separately
passed 8 gRPC, 5 KCP, 6 accounting and 18 proxy cases. Subsequent source changes
still require rebuilding; these counts are not a claim that the current tree is
fully validated.

Validation checkpoints are recorded in notes/PARITY_AUDIT.md. The entire project
conversion remains active; Go sources and Go release workflows are preserved.
