# Native Rust migration

This workspace is an active port of Xray-core, targeting full feature parity.
It is **not yet a complete replacement** for the Go executable. See
[MIGRATION.md](MIGRATION.md) for the work queue and completion requirements.
Unsupported configuration currently fails explicitly.

Build and run from the repository root:

```sh
cargo build --release --locked
cargo run -- run -c rust/examples/socks-direct.json -test
cargo run -- run -c rust/examples/socks-direct.json
cargo run -- uuid -i example
cargo run -- x25519
```

The executable is `target/release/xray` (`xray.exe` on Windows). No Go runtime,
Go subprocess, or Go FFI is used by the Rust implementation.

Integrated TCP proxy paths include SOCKS4/4a/5, HTTP CONNECT and basic forwarding,
dokodemo, base VLESS, VMess AEAD, Trojan and legacy Shadowsocks AEAD, with direct,
blackhole and proxy outbounds. TCP, TLS, WebSocket, HTTP Upgrade and HTTP/1.1
XHTTP are composed through stream settings. Freedom applies source-compatible
default private-address blocking and ordered `finalRules`, including checks on
resolved domain addresses. Owned loopback interoperability fixtures explicitly
allow only their test destination.

JSONC/YAML/TOML loading, source-derived merging, key/certificate/ECH CLI utilities,
level-zero policy timeouts, user/system traffic counters, online-user lifecycle,
and file/access logging are implemented. Management StatsService/LoggerService
configuration and geodata routing are being integrated. All 80 original protobuf
schemas generate Rust messages and service bindings; bindings alone do not
implement the corresponding service behavior.

Tested library components additionally cover DNS, encrypted DNS, geodata, routing
balancers, UDP codecs, final masks, WireGuard packet processing, TUN primitives,
mux/reverse, Hysteria, and REALITY authentication and a strict native client.
Their runtime/configuration coverage varies; consult `notes/` and
[AGENT_WORK.md](AGENT_WORK.md). Full REALITY server/fingerprint behavior, VLESS
encryption/Vision sessions, UDP dispatch, DNS routing, advanced XHTTP, complete
HTTP proxy behavior and platform support remain migration work.

Run validation:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The tests include known protocol bytes, malformed input, authenticated local proxy
chains, large payloads, half-closed connections, cancellation and listener rollback.
Cross-implementation and cross-platform coverage must expand before retiring Go.

Run the actual Go/Rust interoperability suite with `XRAY_GO_BINARY` pointing to
a reference binary built from this checkout. Without that variable the opt-in
tests print an explicit skip; a normal workspace test run does not demonstrate
cross-implementation interoperability.
