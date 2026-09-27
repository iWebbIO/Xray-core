# Parallel-batch agent conventions (45-agent porting batch)

Repo root: `C:\Users\W\Documents\iwebbio\Xray-core`. The Rust workspace lives in
`rust/` (crates `xray-core`, `xray`, `xray-proto`). The Go sources in the repo
root (`app/`, `proxy/`, `transport/`, `infra/`, `common/`, `features/`) are the
reference; port their behavior. Go is never called by the Rust code.

## 1. File ownership — absolute rule

You own EXACTLY the files listed in your prompt (they already exist as stubs).
You may READ any file in the repo. You must NOT edit, create, delete, rename, or
format any other file — this includes `Cargo.toml` (all needed dependencies are
already present), `lib.rs`, every `mod.rs`/parent module file, and files owned by
other agents. 44 other agents work concurrently; touching their files poisons
their work and yours.

## 2. Allowed commands

Never run git commands. Never run workspace-wide `cargo fmt`, `cargo clippy`, or
`cargo test`. Allowed, with Bash `timeout: 600000`, at most 3 invocations each,
only when you believe your code is complete or nearly so:

- `cargo check -p xray-core --lib`
- `cargo check -p xray --lib`
- `cargo test -p xray-core --lib <your::module::path::filter>` (targeted filter)

CONCURRENCY: other agents are editing other files of the same crate while you
compile. If compilation fails with errors ONLY in files you do not own, do not
fix them, do not touch those files — wait 60–120 seconds and retry once; if the
tree still fails on others' files, finish your work and set `"blocked_checks":
true` in your report. Do not spend your attempts on other people's errors.

## 3. Code style

- Edition 2024, `unsafe` is forbidden (workspace lint).
- Match the idioms of neighboring modules: protocol/transport code uses
  `io::Result`/`io::Error` with `io::Error::other`/`invalid`-style messages;
  runtime glue uses `anyhow`. Read one neighboring file before writing yours.
- JSON config structs: `#[derive(Deserialize)] #[serde(default,
  rename_all = "camelCase", deny_unknown_fields)]` unless the Go parser is
  intentionally lenient; expose `pub fn from_value(value: &serde_json::Value)
  -> anyhow::Result<Self>` as the single entry point the integrator will call.
- Keep `#![allow(dead_code)]` at the very top of your file (after the one-line
  `// P{NN}` comment) until integration wires you in; it must stay or the
  clippy `-D warnings` gate fails on unwired code.
- No `println!` outside tests; use `tracing::debug!`/`tracing::warn!` like the
  neighbors.

## 4. Strict porting

Behavior must match the cited Go reference. Options the Go code supports that
you did not implement must be explicitly rejected with a clear error (never
silently ignored, never partially emulated). Unsupported does not mean absent:
the module still parses and identifies the option, then fails with a message
naming it. Do not claim parity for anything without a passing test.

## 5. Tests

Every package ships focused tests inside its owned files (`#[cfg(test)] mod
tests` / `#[path]` submodule only if inside your owned files). Rules:

- Loopback sockets only (`127.0.0.1:0` ephemeral binds); no external network,
  no system DNS, no spawned processes, no privileged operations.
- Every wait is bounded (`tokio::time::timeout`, <= 5 s) and every listener or
  task is cleaned up on drop/unwind.
- Cover the happy path AND at least one malformed/rejection case; reuse the Go
  source's golden bytes, fixture values, and defaults (port exact defaults and
  assert them).
- Deterministic: no real-wall-clock assertions without tolerance, no fixed
  ports, no cross-test shared state.

## 6. Shared contracts (cross-agent APIs)

Where your package consumes another agent's module, write against these exact
names; they will exist at integration time even if the file does not compile
during your window (another agent owns it). If your final targeted check fails
only in that file, trust the contract and report `"blocked_checks": true` for
the affected test.

CONTRACT-CAPSULE — owner P17, `rust/xray-core/src/transport/masque_connectip.rs`:

```rust
pub mod capsule {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Capsule {
        Close,
        AddressAssigned { ipv4: Vec<(ipnet::Ipv4Net, u8)>, ipv6: Vec<(ipnet::Ipv6Net, u8)> },
        RouteAdvertisement { ipv4: Vec<(ipnet::Ipv4Net, u8)>, ipv6: Vec<(ipnet::Ipv6Net, u8)> },
        Datagram { context_id: u32, payload: Vec<u8> },
        Unknown { kind: u64, payload: Vec<u8> },
    }
    pub fn encode(capsule: &Capsule, out: &mut Vec<u8>);
    pub fn decode(input: &[u8]) -> io::Result<(Capsule, usize)>; // (capsule, bytes consumed)
}
```
(RFC 9484 capsule framing: varint capsule type, varint length, value; datagram
capsule type 0x40 with varint quarter-stream-id/context id. P17 owns the exact
bytes; consumers use only the API above.)

CONTRACT-WGNETSTACK — owner P12, `rust/xray-core/src/protocol/wireguard_netstack.rs`:
a userspace TCP/IP termination over the existing WireGuard engine, built on the
`netstack-smoltcp` crate (dependency present, feature `native-tun` is default):

```rust
pub struct Netstack;
impl Netstack {
    pub fn new(mtu: usize) -> io::Result<Self>;
    pub fn write_ip(&self, packet: &[u8]) -> io::Result<()>;         // IP packets in
    pub async fn read_ip(&self, out: &mut [u8]) -> io::Result<usize>; // IP packets out
    pub async fn dial_tcp(&self, bind: SocketAddr, remote: SocketAddr) -> io::Result<NetTcpStream>;
    pub async fn listen_tcp(&self, bind: SocketAddr) -> io::Result<NetTcpListener>;
}
```
`NetTcpStream` implements tokio AsyncRead+AsyncWrite; `NetTcpListener::accept()
-> io::Result<(NetTcpStream, SocketAddr)>`. Exact internal types are P12's
choice; consumers reference only these signatures.

CONTRACT-REALITY-INBOUND — owner P25, `rust/xray-core/src/transport/reality_inbound.rs`:
reuses `crate::transport::reality::handshake::server::{ServerConfig, accept,
accept_with_target}` (already merged). Public API:

```rust
pub struct InboundConfig;  // from_value parses the Go REALITY streamSettings JSON
impl InboundConfig {
    pub fn from_value(value: &serde_json::Value) -> anyhow::Result<Self>;
    pub fn server_config(&self) -> io::Result<ServerConfig>;
}
pub async fn accept_stream(config: &InboundConfig, stream: BoxStream)
    -> io::Result<(BoxStream, Option<crate::transport::reality::handshake::server::ServerConnectionInfo>)>;
```
Inbound streamSettings that select REALITY currently fail config validation with
"REALITY inbound is not supported" — P25 provides the module; the integrator
removes the rejection.

## 7. Required final message

Your FINAL message must be exactly one JSON object (no prose around it):

```json
{
  "package": "P{NN}",
  "status": "implemented | partial | blocked",
  "owned_files": ["..."],
  "public_api": ["the exact signatures the integrator calls"],
  "integration": {"config_json": "example JSON the config layer must accept",
                   "runtime_hook": "where/how the runtime should dispatch to you"},
  "tests": "N tests written; executed: yes/partial/no (why)",
  "blocked_checks": false,
  "notes": ["unported options with reasons", "assumptions", "follow-ups"]
}
```

## 8. Time discipline

Aim to finish within roughly 20–25 minutes of tool work. Prioritize a correct,
tested core that compiles over exhaustively porting every option. List anything
unported in `notes`. Do not start follow-on work outside your owned files.

---

## Wiring batch annex (September 28, 2026)

The wiring batch integrates the 15 delivered components into the root
config/runtime. Phase 0 (commit 77a47812) landed the skeleton: final enum
shapes, root config keys, masque/REALITY stream settings, and seven runtime
satellite stubs whose doc comments are binding contracts. Every unwired path
currently fails explicitly; your job is to replace exactly one stub region
with the real implementation and keep all gates green.

### Ownership (strict, one agent per file set)

| Agent | Files |
|---|---|
| A-VLESS | protocol/vless.rs, protocol/vless_encryption.rs, protocol/vless_vision.rs |
| A-UDP | protocol/trojan.rs, protocol/trojan_udp.rs, protocol/ss2022_udp.rs, runtime/trojan_udp_runtime.rs, runtime/ss2022_udp_runtime.rs |
| A-WG | runtime/wireguard_runtime.rs (+ protocol/wireguard_netstack.rs additions only if a real-socket transport is missing) |
| A-REV | runtime/reverse_runtime.rs, reverse.rs, reverse/bridge.rs, reverse/control.rs, tests/runtime_reverse.rs (new) |
| A-DNS | runtime/dns_runtime.rs, runtime/admission.rs, runtime/udp_integration.rs (internals), protocol/freedom.rs, dns/app.rs (additions only if needed) |
| A-HANDLER | runtime/handler_registry.rs, api/handler.rs, api/proxyman.rs |
| A-YAML | xray/src/config_loader.rs |
| R-RUNTIME | runtime.rs, runtime/burst_observatory.rs |
| R-TRANSPORT | transport.rs |

Nobody edits another agent's files. config.rs, config/proxies.rs and the
other Phase-0 regions are frozen; if a contract there is wrong, report it in
your JSON instead of editing.

### Cross-agent contracts (in addition to the stub doc comments)

1. `admission::admit` final signature (A-DNS owns the file, R-RUNTIME owns
   the runtime.rs call site):
   `pub(super) async fn admit(outbound: &Outbound, origin: &str, target: &Destination, dns: Option<&std::sync::Arc<crate::dns::app::DnsApp>>) -> Result<Admission>`.
   R-RUNTIME passes `dispatcher.dns.as_ref()` and removes the temporary
   `strategy != AsIs` bail in `establish`, routing resolution through
   admission (Go: UseIP falls back to domain dial, ForceIP errors, the
   ip46 pairs try both families in order — mirror proxy/freedom/freedom.go).
2. `establish` gains the WireGuard pool (R-RUNTIME owns the signature):
   `establish(outbound, transport, target, resolved, counters, wireguard: &wireguard_runtime::WireguardPool)`
   with the dispatcher passing `&dispatcher.wireguard`; the Wireguard bail
   is replaced by `wireguard.connect(dispatcher, settings, target).await`.
   A-WG keeps `WireguardPool::connect` compatible with this call.
3. `dispatch_request` (R-RUNTIME extracts from handle_stream's post-handshake
   half, A-REV consumes via `super::`):
   a child-visible async fn taking the established inbound request (stream,
   `protocol::Request`, source, inbound tag, dispatcher, cancel) performing
   route → establish → relay with the runtime's accounting/logging. The
   reverse bridge pumps portal-requested sessions through it.
4. Portal dispatch (A-REV exposes the stub API; R-RUNTIME wires the sites):
   portal tags are registered as routing outbounds (Router::compile outbound
   list and `dispatcher.outbound_tags`) and dispatching to them opens a
   portal session; inbound requests whose destination is a bridge domain are
   handed to `attach_carrier`. A-REV verifies against Go whether this is
   built-in or routing-rule driven and reports the finding.
5. UDP dispatch: `dispatcher.udp` is installed for any SOCKS/Trojan/SS2022
   inbound with UDP enabled (done in Phase 0); the trojan and SS2022 runtimes
   reuse `udp::UdpDispatcher` exactly like `runtime/udp_integration.rs` does.
6. The MASQUE proxy outbound bypasses `establish` (its `process_tcp` owns the
   relay) and dials through `transport::masque::MasqueClient` per its module
   docs; the generic masque *transport* (other proxies over masque) is
   R-TRANSPORT's `connect_resolved` arm.

### Same rules as the package batch

Commands: `cargo check -p xray-core --lib` (or `cargo test -p xray-core
--lib <filter>`), at most 3 invocations per run, rerun once if a sibling's
file broke your check. Final self-check: `cargo fmt --all` on your files,
`cargo clippy -p xray-core --all-targets -- -D warnings`, `cargo test -p
xray-core --lib` plus any integration test you added. Never run git. Report
as a JSON object: `{"files": [...], "status": "done"|"blocked", "tests":
{"added": N, "passing": true|false}, "notes": "...", "blocked_checks": "..."}`.
