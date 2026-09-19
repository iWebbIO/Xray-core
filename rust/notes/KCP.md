# Native Xray KCP transport

Implementation is in `xray-core/src/transport/kcp.rs`, `kcp/wire.rs`, and
`kcp/session.rs`. It derives from the repository's Go
`transport/internet/kcp/{segment,config,sending,receiving,connection,dialer,listener}.go`.
It does not use stock ikcp, Go FFI, or a Go subprocess.

## Integration API

The shared transport module exports `kcp`. JSON `network: "kcp"` and
`network: "mkcp"` are wired through configuration, transport, and runtime for UDP
listeners and outbound dials, with optional TLS layered over the KCP byte stream.
No dependency changes are required: the adapter uses the existing Tokio,
tokio-util, and rand dependencies.

- `connect(remote: SocketAddr, Config, StreamOptions) -> io::Result<KcpStream>`
  opens a UDP client conversation. Name resolution is the caller's responsibility.
- `KcpListener::bind(local, Config, StreamOptions)` binds one UDP socket.
  `accept(&mut self)` returns `(KcpStream, SocketAddr)`. `local_addr()` reports the
  socket address; consuming `close().await` cancels sessions and joins their tasks.
- `KcpStream` implements `AsyncRead + AsyncWrite + Unpin + Send` and can be boxed
  directly as `crate::transport::BoxStream`. It exposes local/peer addresses,
  conversation ID, and immediate `cancel()`.
- `Config` exposes Go's MTU, TTI (as `tti_ms`), uplink/downlink capacities,
  `cwnd_multiplier`, and `max_sending_window`, plus explicit queue/session,
  retransmission, and lifecycle limits. Default capacity arithmetic matches Go:
  194 sending segments per interval, 776 receiving segments, 1332-byte MSS.
- `Config::from_json(&Value)` is the strict runtime parser. It accepts the current
  Go names `mtu`, `tti`, `uplinkCapacity`, `downlinkCapacity`, `cwndMultiplier`,
  and `maxSendingWindow` (bytes), with defaults 1350/50/5/20/1/2097152.
  An optional `header:{"type":"none"}` is permitted. Any `seed` (even empty),
  other headers/fields, and the obsolete `congestion`, `readBufferSize`, and
  `writeBufferSize` settings fail explicitly. JSON TTI is constrained to Go's
  10..1000 ms range; the lower-level deterministic engine accepts 1 ms for tests.
  The current Go config has no boolean congestion switch; `cwndMultiplier`
  multiplies the calculated sending budget directly.
- `connect_destination(&Destination, Option<&[SocketAddr]>, Config)` returns a
  boxed stream and actual local UDP bound address. It preserves supplied resolver
  results, rejects empty explicit lists instead of consulting DNS, and bounds
  lists to 64 addresses. UDP setup success is not a reachability handshake;
  fallback advances only after a socket error. The runtime applies its dial
  deadline and optional outer TLS separately. Integration recognizes `kcp` and
  `mkcp`, rejects REALITY+KCP, and keeps TCP/gRPC transport branches separate.
- `Session` is a synchronous deterministic engine, driven by a wrapping `u32`
  millisecond clock: `queue`, `input_datagram`/`input`, `pop_received`, `poll`,
  `close`, state and acknowledgement counters. `poll` returns UDP datagrams.
  `wire` exports `Segment`, command enums, encode/decode, and framing constants.

`connect` does not prove reachability, matching Go's UDP dialer behavior. `flush`
waits for ACKs covering every accepted write; idle/retransmission/socket failures
are returned from the byte adapter. Bytes already delivered to the application
pipe are drained before reporting a read error. An EOF/publication interlock
prevents the worker's pipe teardown from hiding its error as clean EOF.

`shutdown` flushes and requests full-conversation close. Xray KCP has no TCP-style
half-close. Public `KcpStream` drop attempts to queue and drain already accepted
writes within the configured close bounds. `connect_destination` instead returns
an internal forwarding wrapper whose drop cancels the UDP tasks, so runtime
teardown bypasses the default eight-second graceful termination linger. Ordinary
read/write/flush/shutdown behavior is unchanged. Cancellation is asynchronous:
the Tokio runtime must schedule the cancelled tasks before their socket is freed.

## Wire and reliability behavior

The wire uses big-endian `u16` conversation IDs. Commands are ACK 0, DATA 1,
TERMINATE 2, and PING 3; the close option is bit 0. DATA has an 18-byte header,
ACK has a 17-byte header plus `u32` numbers, and commands have 16-byte headers.
Nonempty DATA, zero-count ACK, concatenated segments, and Go's byte-sized ACK
list parser are supported. Sender ACK batches cap at 128 and the MTU.

The engine implements ordered byte delivery, duplicate suppression, cumulative
and selective ACKs, repeated ACKs until SendingNext advances, fast ACK timeout
reduction, RTO retransmission, source-derived RTT smoothing, advertised receive
windows, capacity pacing, congestion-window adjustment, periodic pings, and the
six Go connection lifecycle states. Serial-number comparisons and timestamps
wrap without relying on numeric map ordering. The adapter demultiplexes by
remote address plus conversation and bounds session/backlog/datagram queues.
Generation tags prevent old task completion from deleting a replacement session.

## Explicit limits and deliberate differences

- Bare UDP is implemented. `StreamOptions` explicitly rejects requested UDP
  masks, custom socket settings, security wrappers, and legacy header/seed
  obfuscation. A caller may deliberately layer supported TLS around the returned
  byte stream. These options must not be silently stripped by runtime integration.
- MTU range is 64..65507, TTI 1..1000 ms; per-direction configured payload buffers
  are capped at 16 MiB. Queue/session and retransmission limits are validated
  before opening sockets. Congestion multiplier is bounded to 1..16.
- Malformed suffixes and mixed-conversation datagrams are rejected atomically;
  Go's reader accepts a valid prefix. Unknown option bits are rejected.
- Cumulative/number ACKs cannot acknowledge unsent segments. Wrap comparisons,
  zero/oversized peer RTO clamping, ACK-state bounds, and future-window handling
  harden cases that use plain integer comparisons or unchecked values in Go.
- ACK scheduling/coalescing, congestion bookkeeping, and ping scheduling are
  semantically compatible, not exact reproduction of Go goroutine timings.
  The adapter may flush immediately after input. Pings occur at 3 seconds;
  Go's separate updater can defer an otherwise idle ping until its 5-second tick.
- Local idle/retransmission exhaustion returns an explicit timeout. Listener
  close cancels accepted sessions; Go's listener comment promises to preserve
  accepted connections. Consumers must use this module's documented lifetime.
- UDP queue overflow drops the datagram for retransmission, rather than growing
  a queue. This transport provides no authentication, anti-spoofing handshake,
  path migration, or amplification protection beyond bounded state.
- JSON KCP/mKCP listener and dialer wiring is present in the shared transport and
  runtime. TLS is an outer stream wrapper; REALITY, UDP masks, custom socket
  settings, and obsolete KCP settings remain explicitly rejected. The ten new
  adapter/runtime tests below still await the lead's validation.

## Validation status

Actually executed without Cargo: 18 tests in the standalone std-only harness,
all passing on September 19, 2026. Run:

```powershell
rustc --edition=2021 --test rust/xray-core/src/transport/kcp/portable_tests.rs -o "$env:TEMP/xray-kcp-portable-tests.exe"
& "$env:TEMP/xray-kcp-portable-tests.exe"
```

These cover Go-derived DATA/ACK/PING fixtures, an independently supplied
non-symmetric endian fixture, all DATA truncations, ACK count/MTU limits,
malformed suffixes, loss/reordering/duplicates, repeated/lost ACKs, fast retry,
receive/send bounds, duplicate/stale/forged ACKs, sequence and clock wrap,
timeout/close lifecycle, invalid configuration, and bidirectional delivery of
91,000 bytes with deterministic 20% packet loss, jitter, and duplication.

Eight additional adapter tests were written for the lead's Cargo integration run:
200 KB local UDP stream round trip and flush, unreachable-peer timeout propagation,
client/listener cancellation, malformed/unsolicited-terminate filtering, explicit
unsupported-wrapper rejection, drop draining, expired-session slot reuse, and
deterministic EOF-before-error-publication behavior. At authorship these adapter
tests had not been executed by this worker. The lead subsequently reported all
KCP and gRPC module tests passing in its combined Cargo suite. Rustfmt was run on
all owned source files.

The later runtime adapter adds five module tests for strict Go settings/defaults,
legacy rejection, explicit resolver use/local address reporting, and empty or
oversized resolver lists, plus runtime stream drop followed by UDP port reuse
within 800 ms despite the default eight-second termination linger. Five new tests
in `rust/xray-core/tests/kcp_runtime.rs`
cover configured plain and TLS chains with concurrent conversations, UDP-only
binding, incomplete-handshake shutdown, bind rollback, and unsupported settings.
The bind rollback test requires immediate port reuse after failed startup,
without a retry loop or scheduler yield. These ten additions await lead-owned
Cargo validation at authoring time:

```text
cargo test -p xray-core transport::kcp::adapter -- --nocapture
cargo test -p xray-core --test kcp_runtime -- --nocapture
```

Actual Go/Rust process fixtures are separately available in
`rust/xray/tests/transport_interop.rs`; they require `XRAY_GO_BINARY` and print
SKIPPED without it. That harness bypasses Rust JSON/runtime transport wiring
and therefore cannot substitute for `kcp_runtime` validation.
