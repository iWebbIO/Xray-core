# Rust migration

The goal is to replace the complete Go implementation with native Rust while
preserving configuration, protocol, CLI, and platform behavior. The Go sources
remain a reference until the Rust implementation passes the corresponding
compatibility checks. A buildable Rust workspace is not evidence of feature parity.

Baseline: commit `dcdfc57c`, 948 Go files, 137,610 nonblank lines counted by
PowerShell `Measure-Object -Line`. Source version: 26.9.9.

## Completion requirements

- All protocol and transport combinations supported by the reference work in Rust.
- JSON, JSONC, YAML, TOML, protobuf, config merging, and environment behavior match.
- DNS, routing, geodata, policy, stats, API, observatory, reverse, and lifecycle match.
- CLI commands and deployment artifacts use the native Rust executable.
- Windows, Linux, macOS, Android, and other supported platform paths have coverage.
- Compatibility fixtures and interoperability checks cover the migrated behavior.
- CI builds and tests Rust, and Go-only sources/dependencies can then be retired.

## Work queue

1. Shared protobuf bindings, address codecs, configuration, routing, lifecycle,
   CLI, and TCP SOCKS/HTTP/dokodemo to freedom/blackhole.
2. Proxy outbounds and UDP; VLESS, Trojan, Shadowsocks and VMess wire behavior.
3. TCP/TLS, WebSocket, HTTP upgrade, gRPC, XHTTP, REALITY, KCP, QUIC/Hysteria,
   XDRIVE, final masks, mux and XTLS/Vision.
4. DNS and geodata; complete routing, policy, logging, stats and management APIs.
5. WireGuard, TUN, platform integration, reverse, observation and complete CLI.
6. Cross-implementation testing, release migration and retirement of Go.

Unsupported options must fail explicitly; never silently downgrade security,
ignore routing conditions, or claim compatibility based only on parsing a field.

## Validation

Use `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
and `cargo test --workspace`. Live protocol tests use loopback sockets and bounded
timeouts. Preserve original protobuf files and golden wire bytes for compatibility.

Go 1.27 is available for reference tests. The reference executable is built from
the unchanged Go source; it is never called by the Rust implementation.

The opt-in integration harness uses `XRAY_GO_BINARY` and explicitly reports a
skip when it is absent. Thirty bidirectional Go/Rust proxy cases have passed,
including VMess AES-GCM/ChaCha, legacy Shadowsocks AEAD, SOCKS, HTTP, VLESS,
Trojan, TLS 1.2/1.3, and HTTP/1.1 XHTTP packet-up. See `notes/PARITY_AUDIT.md`.
The separate REALITY client fixture also passed against the pinned Go server;
that does not establish full transport, fingerprint, or server parity.
