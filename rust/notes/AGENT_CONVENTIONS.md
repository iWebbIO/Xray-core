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
