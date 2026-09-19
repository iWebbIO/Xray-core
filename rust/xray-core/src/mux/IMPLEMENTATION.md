# Mux.Cool, XUDP, and reverse integration

Owned implementation files are `mux.rs`, this `mux/` subtree, `reverse.rs`, and
`reverse/control.rs`. Existing shared modules/manifests were not edited.

## Required integration

Export `pub mod mux;` and `pub mod reverse;` in the crate root. The lead owns the
`blake3.workspace = true` dependency addition. Remaining dependencies already
exist: Tokio, tokio-util, rand, and standard library.

Authenticate/connect the enclosing proxy before constructing a Mux carrier.
Ordinary Mux clients use the enclosing proxy destination `v1.mux.cool:9527`.
Call `Connection::client(BoxStream, Options)` for initiating sessions, or
`Connection::server(BoxStream, Options)` to receive `(Connection,
mpsc::Receiver<Session>)`. A server dispatcher must service that receiver;
otherwise bounded backpressure intentionally stops new sessions.

`Connection::open(Target, OpenOptions)` returns a session. Sessions support
`send(&[u8], Option<Target>)`, `recv() -> io::Result<Option<Packet>>`,
`close(error)`, and `split()` into a clonable sender and cancellation-safe
receiver. Per-packet targets are only valid on UDP sessions. `Session::into_stream`
adapts TCP sessions to `BoxStream`, preserves terminal I/O/protocol errors, and
aborts its pump on drop. Mux End closes both directions; it has no TCP half-close
wire representation.

`Target` uses explicit `Network::{Tcp,Udp}` and `Host::{Ip,Domain}`. It allows
port zero for reverse control/carrier destinations. `from_destination` and
`destination` bridge the existing crate address types without imposing their
nonzero-port constructor restriction.

The default carrier closes after source-style idle checks (16-second client /
60-second server intervals), never wraps locally allocated session IDs, and
uses bounded frame/session queues. Concurrency and connection budgets can be
configured. Carrier reader/writer ownership is separate from cancellation-safe
session receive operations, so cancelling an individual read cannot desynchronize
the carrier. Dropping a receiver uses a separate lifecycle channel to request
End even when the data command queue is full.

## Wire behavior

`wire::Frame::{encode,new,control}` and `wire::decode` implement the two-byte
metadata length, two-byte session ID, New/Keep/End/KeepAlive status, data/error
options, optional target/source/local/GlobalID metadata, and a two-byte data
length when OptionData is set. Metadata is bounded to 512 bytes. Addresses are
port-first, with tags IPv4=1/domain=2/IPv6=3; they are not SOCKS tags.

Ordinary and reverse metadata modes are explicit. Keep metadata contains a
target only if its first extension byte is UDP tag 2. New GlobalID is read only
for UDP plus OptionData in ordinary mode. Reverse mode instead reads source and
local endpoints, stopping at a zero padding byte. All-zero global IDs are not
resumable associations. Unknown session Keep data is consumed and answered with
End; unsolicited New frames on a client are consumed/ignored like Go.

`read_frame`/`write_frame` provide direct Tokio wire access. Direct frame reads
must not be cancelled and then reused on the same stream: cancellation closes
that carrier. `Connection` already enforces this through its reader task.

## XUDP ownership contract

`xudp::PacketEncoder` emits source-compatible session-zero New/Keep frames,
initial target/global ID, and later optional per-packet UDP destinations.
`read_xudp_packet` reads Keep packets, ignores KeepAlive, and handles End.
Payload bounds match the source buffer sizes: 7,526 bytes for the dedicated
XUDP writer and 8,192 bytes for received UDP packets. Empty/oversize dedicated
XUDP writes return explicit errors instead of Go's silent drop.

`xudp_global_id(base_key, cone, inbound_name, source)` implements keyed BLAKE3
over the exact Go `udp:host:port` source string, including IPv6 brackets. It
returns zero unless cone UDP and inbound name is dokodemo-door, socks,
shadowsocks, or tun. The runtime owns the random 32-byte base key and its
environment/config reload policy.

`xudp::AssociationRegistry<T>` stores `Arc<T>` resources across carriers. An
acquisition reuses an existing active/unexpired resource, returns a generation
lease and previous generation to detach, and can call a creation callback for
a new association. Detaching keeps the resource for one minute. A stale prior
carrier cannot expire a replacement generation. The runtime must periodically
call `expire` and implement resource cancellation/response routing inside `T`.

Global-ID sessions are rejected by default with `Unsupported`. Set
`GlobalIdPolicy::Dispatch` only for a dispatcher that uses this registry and
rebinds actual UDP response ownership when the carrier changes. The library
does not silently create independent UDP sockets for a supposedly resumed ID.
The registry operations are synchronous; the owner must serialize them with
its registry lock and avoid blocking an async runtime in the creation callback.

## Reverse components

`reverse::Portal::new(Config { tag, domain }, PortalOptions)` creates the native
portal pool. Route matching bridge-domain carriers into `attach(BoxStream)`;
route ordinary portal outbounds into `open(Target, OpenOptions)`. A bridge
carrier is a Mux **client** at the portal and a Mux **server** at the bridge.
Portal workers open an internal UDP `reverse:0` session, send source-compatible
protobuf Control messages, and select the least loaded non-draining available
carrier, with Go's draining fallback when necessary.

Default heartbeat ticks are two seconds; Active messages are sent immediately
then every fifth tick. Once a carrier's total sessions exceed 256, the portal
sends Drain, closes control, and allows existing sessions to finish. The leak
timeout after drain is 24 hours. Browser/process clocks are not involved.

`BridgeWorker::attach(stream, inbound_tag, Dispatcher, BridgeOptions)` consumes
internal control sessions and dispatches ordinary sessions through an injected
async callback. Callbacks own the entire session lifetime; errors emit End with
OptionError. Source/local metadata and XUDP policy are supplied through its
Mux options. A missing/stale control channel expires the worker after 60
seconds; closing control changes its inactivity deadline to 24 hours. Malformed
protobuf closes the worker with an explicit error.

`run_bridge(config, Connector, Dispatcher, options, CancellationToken)` maintains
at least one active carrier and adds another when the integer mean active
session count per active carrier exceeds 16. The injected connector receives
the configured domain with TCP/port zero and the inbound tag. Connector failures
are returned to the runtime for its retry/logging policy rather than swallowed.
Cancellation closes both active and draining workers.

The protobuf codec matches state field 1 and random field 99. Padding length is
uniformly 1..64 cryptographically random bytes. Unknown ordinary fields are
skipped; unknown enum states and legacy protobuf groups return explicit errors.

## Remaining runtime integration and deliberate differences

- Root routing/outbound registration, TLS/proxy authentication, socket setup,
  access logs, policy/statistics, inbound metadata propagation and cancellation
  policy remain with the main runtime.
- Live XUDP resource reuse is an explicit dispatcher responsibility through the
  provided registry; default rejection prevents a false unsupported success.
- Endpoint overrides for reverse UDP original-destination restoration are not
  implemented here. A runtime that changes routed UDP addresses must apply its
  original-target mapping around session packet I/O.
- Dynamic ordinary Mux carrier selection/creation is external. Reverse portal
  selection and bridge scaling are implemented. `run_bridge` connector errors
  use explicit return/retry supervision rather than Go's internal log-and-retry.
- ID exhaustion never overwrites a live session; duplicate active incoming IDs
  fail the carrier rather than reproducing Go's map overwrite behavior.
- Exact errors remain available on session packet I/O and the TCP adapter;
  normal End remains EOF. OptionError becomes ConnectionReset.
- XUDP environment parsing/reload and the global key's lifetime are external.
  Registry cleanup cadence is external; the one-minute expiry rule is native.

## Validation actually performed

The implementation agent uses only independent standard-library harnesses and
rustfmt, per the lead's no-shared-Cargo-build instruction:

```
rustc --edition 2024 --test rust/xray-core/src/mux/standalone_tests.rs -o <temp executable>
rustc --edition 2024 --test rust/xray-core/src/reverse/control.rs -o <temp executable>
```

These exercise wire golden fixtures, partial-frame boundaries, IPv4/domain/IPv6,
reverse source/local/zero padding, GlobalID mode separation, XUDP packets,
stale-generation handling and one-minute expiry, plus protobuf control fixtures.
The current final results are recorded in the handoff message.

Additional Tokio tests in `mux.rs` and `reverse.rs` cover concurrent sessions,
UDP boundaries/overrides, raw TCP adapters, clean/error End, invalid carriers,
drop cancellation, unknown sessions, session-ID budgets, native portal/bridge
forwarding, draining/picker behavior, and malformed/stale control. Their Cargo
execution belongs to the integration owner and is not claimed here.
