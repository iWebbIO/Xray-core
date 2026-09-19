# Transport and platform migration handoff

Checkpoint: **September 19, 2026. Implementation is paused at the user's request.**

This is the handoff for the transport/platform coordination task
`01a0baee-8536-77c1-8c82-116eeedb5750`, working with migration lead
`01a0bad7-07ec-7ab3-b62c-a66f92e3cb66`. It covers this coordinator's delivered
WebSocket, HTTP Upgrade, DNS, TUN, Mux/reverse, packaging, KCP, gRPC, PROXY
protocol, interoperability fixtures, and standalone XHTTP HTTP/2 work.

All paths below are relative to the repository root. The Cargo workspace
manifest and lockfile are the root `Cargo.toml` and `Cargo.lock`.

## Pause and ownership state

- Implementation, assignments, builds, and tests have stopped. Only this
  documentation was authorized after the pause.
- This coordinator has no goal object to pause (`get_goal` returned null).
- The latest worker inventory has `grpc` and `kcp` completed and `httpupgrade`
  interrupted. There are no active child workers or child assignments here.
  Earlier WebSocket, DNS, TUN, and packaging workers had already completed.
- There are no helper-owned active shell, test, or build processes to stop.
  The lead owns the central Cargo/Go processes and their shutdown.
- No implementation write is pending. The latest owned source changes are
  formatted and held stable. “Ready” means ready for the lead's next compiler
  pass, not that unexecuted tests passed.
- All shared-file leases were returned. In particular, `transport.rs`,
  `config.rs`, `runtime.rs`, and `transport/tls.rs` have subsequent work owned
  by the lead or its runtime workers. Do not restore an earlier copy of these
  files from this handoff.
- The lead owns manifests, dependency integration, all shared Cargo/Go builds,
  and the main `/Docs` index/status/validation handoff. This helper owns only
  this documentation file during the pause.
- No commits, publication, worktrees, privileged device tests, host route/DNS
  changes, or release uploads were performed by this coordination task.

## Validation ledger: executed versus authored

Reports from the lead are identified as such. Unit-test counts are counts at
the delivered checkpoint; later shared-source additions may change totals.
Do not add overlapping suite totals together.

| Area | Evidence retained at pause | Remaining validation |
| --- | --- | --- |
| Earlier combined native TUN run | Lead reported `cargo test -p xray-core --features native-tun`: 508 core tests passed, one opt-in REALITY fixture ignored, and 17 runtime tests passed. This included KCP, gRPC, WebSocket, HTTP Upgrade, Mux/reverse and native TUN packet-channel coverage. | This predates later runtime integration and cleanup edits. |
| Later central core batch | Lead reported 679 tests: 672 passed, 3 failed, 4 ignored. One failure was the KCP cancellation race; two XDRIVE failures were assigned to its owner. | The repaired KCP source and subsequent central mutation wave require a new run. This is not a clean-suite result. |
| gRPC transport | 23 transport tests reported passing by the lead in the earlier combined suite. | Real Go interoperability remains separate. |
| gRPC runtime | Lead subsequently ran the existing integration executable and reported **8/8 passed**: plain/TLS, multiple logical streams, both modes, ALPN rejection, connection loss and shutdown. | Regressions after later shared runtime changes still belong in the next central batch. |
| KCP runtime | Lead reported **5/5 passed** from the pre-cleanup executable. That executable used the older retry-based startup-rollback assertion. | The runtime Drop wrapper, immediate rollback assertion, and latest cancellation regression need rebuilt execution. |
| Latest KCP source | 32 module tests plus 5 runtime tests authored. Formatting passed. The older executable reproduced the cancellation failure on attempt 2. | Do not claim the source fix passed by rerunning that old executable. |
| XHTTP HTTP/2 | 20 tests authored; individual rustfmt checks and two independent static reviews completed. | No compiler/test execution was reported to this helper after export. |
| PROXY protocol | 24 tests authored; formatting and an independent Python CRC32C fixture check passed; an independent read-only audit found no concrete issue in its requested scope. | No separate 24-test execution result was conveyed to this helper. Do not infer an isolated result from a suite count. |
| DNS | 25 original tests authored; 10 wire/cache tests passed in a standalone harness importing production files. | No isolated final 25-test execution transcript is retained here. Later DNS work belongs to other owners. |
| TUN | Portable standard-library harness reported passing. Lead later confirmed native packet-channel tests in its passing combined run. | No privileged live-device test or operating-system parity claim. |
| Mux/reverse | Worker reported standalone wire/control harness validation; lead later included Mux/reverse in the passing combined suite. | No isolated numeric final test result is retained here; runtime registration and live XUDP reuse are separate work. |
| Packaging | Eight Python packaging tests passed. | Native release builds, five-runner CI, real Docker builds/execution, signing and publishing were not validated here. |
| Go transport fixtures | Six opt-in Go/Rust cases authored in `rust/xray/tests/transport_interop.rs`. | Actual execution was still queued in the latest lead report. An unset `XRAY_GO_BINARY` prints SKIPPED and is not interoperability success. |

The last compiler update received before the pause said the next source freeze
included root startup rollback, SOCKS UDP, observatory and an alias fix. A Cargo
check had stopped at a protobuf `E0433` reference to the nonexistent
`httpupgrade::Config`; the logging owner was assigned that fix. The lead also
reported that H2 was exported and the KCP cancellation fix would be included in
the next pass. Its main validation document may have newer results.

Some earlier module notes still say that runtime tests or wiring are pending.
Where this ledger records a later explicit result, it supersedes that older
note. It does not supersede the lead's newer main validation ledger.

## WebSocket

Files:

- `rust/xray-core/src/transport/websocket.rs`
- `rust/notes/WEBSOCKET.md`
- Shared browser-header helper in
  `rust/xray-core/src/transport/httpupgrade.rs`

APIs include `Config::from_json`, `client`, `server`, and
`server_with_metadata`. They wrap an existing `BoxStream`; the metadata API
exposes request information for caller policy without establishing trust.

Delivered native HTTP upgrade, masking/framing, fragmentation, early data,
heartbeat and ping/pong handling, bounded incoming/outgoing queues, flush
barriers, and cancellation-aware worker ownership. Deferred handshakes preserve
their failure state and buffered bytes. Header and queue bounds are explicit.
TLS, browser impersonation, PROXY processing, and trusted forwarding policy are
outer layers. The module does not provide browser TLS fingerprint identity.

Important lifecycle fix: a Close already queued for writing is allowed to
complete using its write acknowledgement even if the reader observes a racing
raw EOF. Successful shutdown/flush remain idempotent. An unexpected raw EOF on
the read side still reports an error; the fix did not globally convert failures
to successful EOF. The existing masking/shutdown test was extended, and the
lead confirmed subsequent combined runs passed.

The original delivery had 22 tests, with closure/error-persistence coverage
subsequently expanded. Independent Python checks covered the RFC accept hash,
masked-Hello bytes and the early-data Base64 fixture. Cargo validation came
from the lead, not a helper-owned build.

## HTTP Upgrade

Files:

- `rust/xray-core/src/transport/httpupgrade.rs`
- `rust/notes/HTTPUPGRADE.md`

The configuration type is **`HttpUpgradeConfig`**, not `Config`.
Entry points are `client_upgrade`, `server_upgrade`, and
`server_upgrade_with_metadata`. `RequestMetadata` provides ordered raw headers,
`header`, and `trusted_forwarded_ip` for an explicitly supplied header policy.

This is an HTTP handshake followed by raw byte-stream transport, without
WebSocket frame encoding. Nonzero early-data settings defer response validation
until the first nonempty read; they are not a numeric write-size cap. Deferred
response failures remain persistent errors. Coalesced HTTP/tunnel bytes and
partially read response headers survive buffering and cancellation.

Go-compatible path/query conversion, Host behavior, browser aliases, upgrade
header checks, bounded request/response parsing, and stream half-close were
implemented. The server has a bounded request deadline. TLS must be supplied as
an outer HTTP/1.1 stream. `acceptProxyProtocol: true` remains explicitly
unsupported in this transport parser until an outer listener consumes it.

`pub(crate) apply_browser_headers(&mut BTreeMap<String, String>)` is shared
with WebSocket and gRPC. Three later Clippy cleanups collapsed nested conditions
without changing evaluation order or errors.

Sixteen original tests cover settings/wire fixtures, deferred/cancelled reads,
header bounds, buffered payloads, failure persistence and a native loopback
round trip. They were included in the lead's reported passing combined work.
The helper did not run a separate Cargo build.

## Original DNS resolver and service

Owned original delivery:

- `rust/xray-core/src/dns.rs`
- `rust/xray-core/src/dns/wire.rs`
- `rust/xray-core/src/dns/cache.rs`
- `rust/xray-core/src/dns/resolver.rs`
- `rust/xray-core/src/dns/service.rs`
- `rust/xray-core/src/dns/tests.rs`
- `rust/notes/DNS.md`

Important APIs are `Resolver::new`, `lookup_ip`, `query`, `clear_cache`,
`cache_len`, `QueryOptions`, `ResolverConfig`, and `Upstream::{udp,tcp,parse}`.
`DnsService::{new,handle_query,handle_udp_query,serve_udp,serve_tcp,serve_connection}`
provides the bounded query service. `read_tcp_message` and `write_tcp_message`
implement DNS-over-TCP framing.

Delivered strict DNS wire parsing, A/AAAA queries, matching transaction/question
validation, compressed-name handling, EDNS, UDP/TCP upstreams, TTL/stale and
negative cache behavior, aliases/hosts, family selection and UDP/TCP service
loops. Responses do not promote unrelated answer names into resolved IPs.
UDP truncation uses complete records and TC; unsupported service-query types
follow the documented source behavior instead of inventing forwarding success.

The Go EDNS fixture intentionally preserves the unusual OPT TTL `0xe0008000`
produced by the pinned source's `SetEDNS0(1350, 0xfe00, true)`. Do not replace
this fixture merely because a conventional flag encoding looks different.

The original typed resolver did not include encrypted DNS, FakeDNS, arbitrary
record forwarding, general DNSSEC/IDNA, full routing policy, or hostname
bootstrap. **These are scope limits of this delivery, not a claim about the
entire current tree.** Other owners subsequently added files such as
`dns/encrypted.rs`, `dns/network.rs`, `dns/network/`, `config/dns.rs`, and
`rust/notes/DNS_ENCRYPTED.md`; preserve and consult their handoffs.

Twenty-five original tests were authored. Ten actual wire/cache tests passed
in an isolated standard-library harness; async execution belonged to the
lead's central build lane.

## TUN packet handling and optional userspace stack

Files:

- `rust/xray-core/src/protocol/tun.rs`
- `rust/xray-core/src/protocol/tun/packet.rs`
- `rust/xray-core/src/protocol/tun/packet_tests.rs`
- `rust/xray-core/src/protocol/tun/route.rs`
- `rust/xray-core/src/protocol/tun/session.rs`
- `rust/xray-core/src/protocol/tun/native.rs`
- `rust/xray-core/src/protocol/tun/native_tests.rs`
- `rust/notes/TUN.md`

Portable APIs include `TunConfig::{validate,validate_native}`,
`packet::{parse_ip,parse_udp,validate_tcp,parse_echo_request,build_echo_reply,build_udp,build_ip,checksum}`,
`route::{IpPrefix,plan_routes,select_outbound_interface}`, and
`session::UdpSessions`. `RouteTransaction` takes an explicit `RouteBackend`;
route planning itself changes no host state. Failed removals remain retryable,
and rollback does not delete routes whose add operation failed.

The optional `native-tun` feature uses the dependency choices recorded at
implementation: `tun-rs` 2.8.9 with async Tokio, `netstack-smoltcp` 0.2.4 and
`futures-util` sink support. The lead added the dependency declarations.

`native::channels` supplies an endpoint/dispatcher pair.
`native::run_packets` runs the actual userspace TCP stack and UDP/ICMP handlers
over packet channels without opening a device. `native::run_native` is the
live-device entry point. `TunEvent::Tcp` yields a Tokio-compatible stream plus
source/original destination. UDP events and reply handles use generation-tagged
sessions so stale replies cannot revive a reused source port. Event consumption
and reply processing must run concurrently.

Live native device startup is Linux-only in this delivery. Automatic OS route
installation, DNS modification, interface-selection backends and broader OS
support are not established by dependency portability. Existing-device and
unsupported configuration paths fail explicitly. Fragment reassembly, IPv6
extension processing and gVisor-equivalent TCP behavior are not claimed.

Portable fixtures/harnesses passed, and the lead reported native stack
packet-channel tests passing in its combined native-TUN run. There was **no
privileged device test, route change, DNS change, or live Windows TUN test**.
Runtime registration/accounting/policy integration is separate from proving
the packet-channel stack works.

## Mux.Cool, XUDP and reverse

Files:

- `rust/xray-core/src/mux.rs`
- `rust/xray-core/src/mux/wire.rs`
- `rust/xray-core/src/mux/xudp.rs`
- `rust/xray-core/src/mux/standalone_tests.rs`
- `rust/xray-core/src/mux/IMPLEMENTATION.md`
- `rust/xray-core/src/reverse.rs`
- `rust/xray-core/src/reverse/control.rs`

Mux entry points are `Connection::{client,server,open,close,closed}`. The server
constructor supplies an incoming-session receiver that a dispatcher must
service. Sessions expose packet `send`/`recv`, `split`, `close(error)`, and
`into_stream` for TCP. Direct wire APIs include `read_frame`, `write_frame`,
`read_xudp_packet`, and the codec helpers in `wire`/`xudp`.

Authenticate the enclosing proxy before constructing the carrier. Ordinary Mux
uses enclosing destination `v1.mux.cool:9527`. Source/local metadata, UDP targets
and global-ID handling are explicit modes. Frame/session queues are bounded,
session ID exhaustion never overwrites a live session, and receiver-drop
cleanup has a lifecycle channel independent of a full data queue.

Important fixes preserve terminal carrier/protocol errors through
`Session::into_stream` instead of returning successful EOF, and abort its pump
on drop. Normal End is EOF; OptionError is a failure. Mux End closes both
directions: it is not a TCP half-close representation.

`xudp_global_id` uses keyed BLAKE3 with the source Go address string. The lead
added the dependency. `xudp::AssociationRegistry<T>` provides generation leases
and detached one-minute retention. **Global-ID dispatch is rejected by default.**
Enabling `GlobalIdPolicy::Dispatch` requires a real runtime registry and response
ownership transfer; independent sockets are not a valid substitute for resumed
associations. The runtime owns the global key, registry locking/expiry and
resource cancellation.

Reverse APIs include `Portal::{new,accepts,attach,open,workers,close}`,
`BridgeWorker::attach` and `run_bridge`, with injected `Connector`/`Dispatcher`
callbacks. Portal carrier selection, bridge scaling, heartbeat/drain control,
protobuf control messages, stale-control expiry and cancellation are native.
Portal and bridge use opposite Mux roles. Outer routing registration,
authentication, policy/statistics and original UDP destination restoration
remain runtime responsibilities.

Standalone wire/control harnesses were reported run, and the lead later
reported Mux/reverse passing in its combined suite. The retained handoff does
not contain a separate numerical final count; do not invent one.

## Packaging and release scaffolding

Files:

- `rust/packaging/package.py`
- `rust/packaging/test_package.py`
- `rust/packaging/targets.json`
- `rust/packaging/Dockerfile`
- `rust/packaging/Dockerfile.dockerignore`
- `.github/workflows/rust-release.yml`
- `rust/notes/PACKAGING.md`

The script exposes `matrix`, native `build`, and a side-effect-free build
`--dry-run`. Native host/target validation, locked release builds, executable
version/config smoke checks, artifact manifests, SHA-256 sidecars and bounded
archive creation are implemented. Existing archives are not silently replaced.
`SOURCE_DATE_EPOCH` controls archive timestamps; deterministic archives are not
a claim that arbitrary Cargo builds are reproducible.

Five native CI target configurations were prepared: Linux x86_64/aarch64,
Windows x86_64 MSVC, and macOS x86_64/aarch64. The target inventory records all
32 variants in the existing Go release inventory, including pending platforms;
it does not claim they all build or match Go ABI/platform support.

The workflow is artifact-only, with partial-migration labeling. It does not
publish releases or images or replace the Go release workflow. Packaging does
not enable `native-tun` by default. The Dockerfile has native build and offline
smoke stages and an unprivileged runtime, but a real Docker build/run was not
performed here. Cross-builds, other operating-system baselines, signing,
notarization, service installation, geodata distribution and full parity remain
unvalidated.

Eight Python packaging tests passed. They validate packaging behavior with
fixtures, not release compilation or protocol interoperability.

## KCP transport and runtime integration

Files:

- `rust/xray-core/src/transport/kcp.rs`
- `rust/xray-core/src/transport/kcp/wire.rs`
- `rust/xray-core/src/transport/kcp/session.rs`
- `rust/xray-core/src/transport/kcp/portable_tests.rs`
- `rust/xray-core/src/transport/kcp/adapter.rs` (new runtime adapter)
- `rust/xray-core/tests/kcp_runtime.rs` (new runtime tests)
- `rust/notes/KCP.md`
- Shared integration touches in `transport.rs`, `config.rs` and `runtime.rs`,
  now returned to their owners.

This is Xray's bespoke KCP protocol, not stock ikcp. `Config`, `Session`, `State`
and `wire` implement the bounded reliability engine. `connect` returns a
`KcpStream`; `KcpListener::{bind,accept,local_addr,close}` owns inbound UDP
conversations. `KcpStream::{local_addr,peer_addr,conversation,cancel}` exposes
the socket/session metadata and immediate cancellation request. Flush confirms
acknowledgement of prior writes. Shutdown is full-conversation close, not TCP
half-close.

The runtime adapter adds `Config::from_json(&Value)` and
`connect_destination(&Destination, Option<&[SocketAddr]>, Config)`, returning
`(BoxStream, local_udp_bound)`. Explicit empty resolution is an error; it never
falls back to system DNS. Address lists are bounded. UDP connect proves local
socket setup, not peer reachability or application success.

Supported Go-shaped settings are `mtu`, `tti`, `uplinkCapacity`,
`downlinkCapacity`, `cwndMultiplier`, `maxSendingWindow` in bytes and
`header: {type: "none"}`. Defaults are 1350, 50, 5, 20, 1 and 2097152
respectively. JSON TTI is 10..1000 ms; the lower-level engine permits 1..1000.
Existing finite engine memory/capacity limits still apply. Unknown settings,
legacy seed, non-none headers, congestion/readBufferSize/writeBufferSize,
unsupported masks and socket options are rejected rather than discarded.

Configuration supports both `kcp` and `mkcp`, permits an explicit TLS stream
wrapper, and rejects REALITY+KCP. `InboundTransport::bind` returns an
`InboundListener::{Tcp,Kcp}`. Its `accept` returns
`(BoxStream, source, bound)` and TCP alone applies nodelay. `close(self)` returns
`io::Result<()>`, joining the KCP listener driver. Runtime shutdown records its
close result, drains owned connection tasks, then returns the combined result.

Lifecycle fixes and remaining verification:

1. An earlier EOF-before-error-publication race was fixed with completion state
   and an EOF waker. A closing application pipe cannot prematurely turn an
   eventual timeout/cancellation into successful EOF.
2. Drop draining, listener generation reuse and full-size UDP receive buffers
   were addressed. Oversized Windows datagrams cannot trigger a truncated
   receive-buffer failure that kills the listener.
3. The runtime-only `RuntimeStream` forwards all normal read/write, vectored,
   flush and shutdown calls; its Drop requests `KcpStream::cancel()`.
   Public native KCP graceful Drop semantics remain unchanged. Socket release
   still requires cancelled Tokio tasks to be scheduled. A new test waits for
   an initial ping, then requires local UDP port reuse within 800 ms instead
   of the default 8000 ms termination linger.
4. Failed startup previously only dropped earlier UDP listeners. The runtime
   owner added explicit close/join rollback. The latest integration test
   requires immediate UDP rebind after startup failure, with no retry loop.
5. The central batch exposed local cancellation racing with a closed receive
   channel. The old executable reproduced `ConnectionAborted` where the test
   required `Interrupted`. The latest fix checks cancellation when the channel
   is closed, preserving `ConnectionAborted` for unexpected uncancelled loss.
   The main select stays fair; only the two-way UDP-send select prioritizes
   cancellation. The original assertion remains. A new actual-actor regression
   exercises 32 cancellation races plus an uncancelled control under a deadline.

The latest written total is **32 module tests plus 5 runtime tests**. The
original 18 portable wire/engine tests passed independently; earlier async KCP
tests were included in the lead's passing combined suite. The lead also
reported the older five runtime tests passed. The latest cleanup/cancellation
source still needs rebuilt execution. The old executable is at
`target/debug/deps/xray_core-cb51c88d9cf6c234.exe`; its results cannot validate
source changes made after it was built.

## gRPC transport, TLS checks and runtime integration

Files:

- `rust/xray-core/src/transport/grpc.rs`
- `rust/notes/GRPC.md`
- `rust/xray-core/tests/grpc_runtime.rs`
- Shared integration in `transport.rs`, `config.rs`, `runtime.rs` and
  `transport/tls.rs`, now returned to their owners.

APIs are `Client::handshake(BoxStream, Config, fallback_authority)`,
`Client::{open,open_mode}`, `Server::{handshake,accept}`, `Tunnel::boxed`,
`Tunnel::finish(Status)`, and `Config::authority_for`. The client handle may be
cloned for low-level HTTP/2 reuse. Tun and TunMulti framing, protobuf bounds,
flow control, status trailers, response failures and stream cancellation are
handled by the native adapter. The driver remains alive while a client/server
or emitted tunnel owns it.

Runtime inbound connections use `AcceptedTransport::{Single,Grpc}` and dispatch
up to 64 logical stream tasks per physical connection through an owned JoinSet.
Cancellation closes/drains those tasks. The shared dispatcher is held by Arc;
the existing routing, policy, logging, API and accounting paths were preserved.
Runtime outbound dialing currently creates a fresh gRPC client for each dial;
the returned tunnel keeps its driver alive. This is not a destination-wide pool.

`TlsClient::connect_with_alpn` and `TlsServer::accept_with_alpn` require actual
negotiated ALPN before returning the boxed stream. Original `connect`/`accept`
signatures remain wrappers for other callers. gRPC TLS configuration is h2-only;
missing ALPN is rejected as well as a disjoint protocol. Native REALITY client
configuration selects h2 and validates `ConnectionInfo.alpn` after handshake.
This helper did not add REALITY inbound integration; other owners' later
REALITY work must be checked separately.

Positive keepalive settings, unsupported compression, destination pooling,
retry/backoff and adaptive BDP behavior are not silently implemented. Forwarded
headers remain untrusted metadata. The runtime-only `pub mod udp;` addition was
an export requested by the lead, not UDP behavior implemented in this gRPC task.

The lead reported **23 transport tests passed** and subsequently **8 runtime
tests passed**. The eight include plain/TLS pooled logical streams, both modes,
configured outbound chains, half-close, cancellation, physical connection loss
with live upstreams, shutdown during unfinished handshakes and ALPN rejection.
Real Go interoperability still requires the separate fixture run.

During a disk-full incident an attempted note rewrite left `GRPC.md` empty.
The worker restored the complete updated note and verified 9119 bytes. Source
and test files remained intact. The restored note's “runtime tests pending”
sentence predates the lead's later 8/8 result recorded here.

## PROXY protocol

Files:

- `rust/xray-core/src/transport/proxy_protocol.rs`
- `rust/notes/PROXY_PROTOCOL.md`

`accept(BoxStream, &Config, PeerTrust)` returns `Accepted { stream, header }`.
The caller must derive `PeerTrust` from the actual peer before any header is
read. Both Required and Optional reject Untrusted before reading. Defaults are
Required, a ten-second deadline and a 4096-byte v2 payload cap.

The pure `decode` returns Incomplete, Absent or Complete with consumed length.
`Decode::Complete.header` is now a **`Box<Header>`** after the large-enum cleanup;
the stream adapter still exposes `Accepted.header: Option<Header>`.

Fragmented v1/v2 headers, optional passthrough and coalesced application/TLS bytes
are preserved. LOCAL/UNKNOWN never replace actual endpoints. IPv4/IPv6/Unix
metadata, bounded TLVs/SSL vectors and CRC32C validation are implemented.
SSL/CRC metadata does not authenticate a client. The stream adapter rejects
PROXY+DGRAM. It owns the input stream, so timeout/cancellation does not leave a
detached reader. Required policy and fixture details follow the pinned
`github.com/pires/go-proxyproto@v0.15.0` source.

Twenty-four tests were authored. A Python calculation independently verified
the AWS NLB fixture CRC32C (`0xe8d6892d` for the 100-byte header). The lead fixed
an E0716 temporary `Config::default()` borrow in a test; this coordinator boxed
the Decode header. An independent helper audited trust, incremental/prefix
handling, LOCAL/UNKNOWN, lengths, TLVs and CRC without finding a concrete bug.
That audit was read-only and did not execute tests.

There is no isolated final 24-test result in this helper's records. Listener
configuration, actual-peer allowlists and effective endpoint propagation remain
runtime work unless a later owner integrated them. Do not enable
`acceptProxyProtocol` merely because the parser module exists.

## XHTTP HTTP/2 stream-one child module

File: `rust/xray-core/src/transport/xhttp/http2.rs`.

The existing H1 owner approved the child-module design; this worker did not
edit `xhttp.rs` or its existing children. The lead later reported adding
`pub mod http2;`. The default runtime XHTTP path was not switched to H2 here.

APIs:

- `Client::handshake(BoxStream, xhttp::Config)` and cloneable `Client::open()`.
- `connect(config, Connector) -> BoxStream` for a fresh connection convenience
  path whose emitted tunnel retains the driver.
- `Server::{handshake,accept}` yielding multiple logical `Tunnel`s.
- `Tunnel::boxed()` for normal stream composition.

**H2 DATA carries raw bytes.** The `application/grpc` value is camouflage;
there are no gRPC message envelopes or required grpc-status trailers. Request
and response half-close independently.

The child reuses parent request/response/metadata/padding/CORS helpers, converts
their header templates to HTTP/2, and strips standard and Connection-nominated
hop-by-hop headers. It has header limits, a 64-stream accept bound, a 1 MiB
connection receive window, one retained receive DATA frame in the adapter,
bounded writes, receive-capacity release as application bytes are consumed,
per-stream resets and Arc-owned connection drivers. An incoming queue does not
hold a driver-reference cycle or stall the H2 connection loop.

Twenty tests cover raw wire bytes, delayed response headers, large full-duplex
transfers, small-window cancellation, header conversion, padding/CORS, response
status/compression errors, trailers, half-close, driver ownership and connection
reuse. Formatting passed; coordinator and worker static reviews found no
additional concrete issue. **Execution is unverified at pause.**

The client requires explicit stream-one. The server accepts the source's
stream-one-compatible auto/stream-up settings while rejecting split sessions.
Auto client selection, split-mode H2, Xmux policy, HTTP/3 and runtime routing to
this module remain outside the delivery. Supplied TLS/REALITY streams must
already have negotiated h2; a boxed stream cannot expose erased TLS metadata.
Do not just allow h2 in the H1 runtime and send HTTP/1 bytes over it.

## Real Go transport fixtures

File: `rust/xray/tests/transport_interop.rs`.

Six opt-in tests cover KCP, gRPC Tun and gRPC TunMulti in both Rust-to-Go and
Go-to-Rust directions. They use native Rust transport/VLESS APIs, an owned Go
process, a loopback payload transformer, 270338 bytes in each direction,
bounded process/socket cleanup and a 30-second deadline.

`XRAY_GO_BINARY` must name a real executable. Absence prints SKIPPED; an invalid
configured path fails. These fixtures bypass Rust JSON/runtime transport
wiring, so they cannot replace `grpc_runtime` or `kcp_runtime` validation.
Formatting passed. The latest lead report still queued actual execution after
the workspace pass. No Go interoperability success is claimed here.

## Shared integration changes outside module ownership

At the lead's explicit request this coordinator also added the `xdrive` module
export to `transport.rs` and `Inbound::Shadowsocks2022(Account)` /
`Outbound::Shadowsocks2022 { server, account }` variants to `config.rs`.
The lead owned `config/proxies.rs`, the runtime owner added the match arms, and
the original protocol/XDRIVE implementations belong to other workers. Do not
attribute their completeness or validation to this transport handoff.

## Resume only after explicit user instruction

The following are recorded commands and priorities, **not authorization to run
them during the pause**. Coordinate one central build lane with the lead and
consult its newer validation/ownership documents first.

1. Preserve all shared changes. Confirm the protobuf alias fix, startup rollback
   fix, H2 export and runtime mutation wave are in the intended source snapshot.
   Resolve compiler failures before interpreting test counts.
2. Rebuild the latest KCP tests, keeping the original cancellation assertion:

   ```text
   cargo test -p xray-core transport::kcp --lib
   cargo test -p xray-core --test kcp_runtime -- --nocapture
   ```

   Specifically cover `receive_loop_shutdown_preserves_explicit_cancellation`,
   runtime cancel-on-drop port release and immediate startup rollback rebind.
3. Compile and execute the new H2 module, then PROXY and gRPC regressions:

   ```text
   cargo test -p xray-core transport::xhttp::http2 --lib
   cargo test -p xray-core transport::proxy_protocol --lib
   cargo test -p xray-core --test grpc_runtime
   ```

4. Let the lead run its full workspace/native-TUN regression selection after
   related owner fixes. Old binaries are useful only for the snapshots they
   were built from.
5. Run real Go fixtures with a deliberately configured `XRAY_GO_BINARY`:

   ```text
   cargo test -p xray --test transport_interop -- --nocapture --test-threads=1
   ```

6. Release/Docker/platform validation remains separate. Passing local transport
   tests does not establish full Go parity, a production release, privileged
   device behavior or supported cross-platform artifacts.

No further packages or worker assignments were requested before the pause.
