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
