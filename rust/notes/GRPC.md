# Native gRPC transport and runtime integration

Implementation: `rust/xray-core/src/transport/grpc.rs`.
Runtime integration: `config.rs`, `transport.rs`, `runtime.rs`, and the additional
ALPN-checking methods in `transport/tls.rs`.

## Source contract

Wire behavior follows `transport/internet/grpc/config.go`, `config_test.go`,
`dial.go`, `hub.go`, `encoding/stream.proto`, `encoding/customSeviceName.go`,
`encoding/hunkconn.go`, and `encoding/multiconn.go`. Config JSON names follow
`infra/conf/transport_method.go`.

Each HTTP/2 POST carries an independent bidirectional stream of uncompressed
gRPC messages. The five-byte envelope contains a zero compression byte and a
big-endian protobuf message length. Tun uses `Hunk { bytes data = 1; }`;
TunMulti uses `MultiHunk { repeated bytes data = 1; }`. Received MultiHunk pieces
are flattened in order. Vectored writes preserve multiple pieces in MultiHunk,
while Tun concatenates them into one field. Prost supplies singular-field
replacement and unknown-field handling.

Regular service names are escaped as one Go `url.PathEscape` segment and use
Tun/TunMulti. A leading slash enables Xray's custom convention: intermediate
segments are escaped individually, and the last segment is `tun|multi` (or the
same custom method for either client mode). Empty service names retain `//Tun`;
paths are not cleaned or slash-normalized. The server accepts both methods
independently of outbound `multiMode`.

HTTP/2 authority precedence is explicit authority, TLS server name, destination
domain when REALITY is absent, then the target endpoint including its port.
`Config::authority_for` implements this selection. The client pseudo-header
scheme is http, matching Go's insecure grpc-go credentials over externally
wrapped TLS/REALITY. This does not disable outer encryption.

## Runtime configuration and ownership

The runtime recognizes `network: "grpc"` and `grpcSettings` on inbounds and
outbounds. Misplaced settings, unknown options, and unsupported keepalive fail
configuration validation. TLS ALPN defaults to h2 only; explicit mixed or
non-h2 lists are rejected.

Actual TLS negotiation is checked by `TlsClient::connect_with_alpn` and
`TlsServer::accept_with_alpn`. Omitted ALPN is rejected as well as a different
protocol. Existing TLS method signatures remain wrappers with their previous
behavior. Native REALITY clients offer only h2 for gRPC and check the returned
negotiated protocol. The explicit native fingerprint restriction remains in
place; REALITY inbound remains unsupported.

Inbound transport acceptance returns either a single optional byte stream or
a driven gRPC Server. Every accepted logical stream runs through the existing
proxy handshake, routing, policy, logger, stats, finalRules, and API dispatch
paths. Each physical gRPC connection owns a JoinSet capped at 64 active logical
tasks. Runtime shutdown cancels and drains these tasks before the listener
finishes; physical HTTP/2 connection loss ends its live logical sessions.

Configured runtime outbounds currently create a fresh HTTP/2 Client per outbound
dial. The returned Tunnel retains its driver when that Client handle goes out of
scope. Destination-wide outbound pooling/retry is not implemented or implied by
the lower-level cloneable Client API.

PROXY protocol is not wired by this integration. The unrelated `runtime::udp`
module is exported for its owner's tests, without enabling UDP config or session
wiring. Existing TLS, native REALITY, WS, HTTP Upgrade, XHTTP, API, logging, stats,
policy, and routing paths are retained.

## Lower-level APIs

Only existing crates are used: h2, http, bytes, prost, serde, tokio, and tracing.
User-agent expansion reuses the existing crate-local
`transport::httpupgrade::apply_browser_headers`; only its User-Agent result is
sent. Empty/chrome, firefox, and edge follow Go's alias behavior; golang omits
the header; other values remain literal. The shared Rust browser profile uses
an OS-seeded cached generator rather than Go's CPU-derived seed.

The module is exported from `transport.rs`.

```rust,ignore
let authority = config.authority_for(&destination, tls_server_name, using_reality);
// io is the TCP stream after any TLS/REALITY and socket wrapping.
let client = grpc::Client::handshake(io, config, &authority).await?;
let stream: BoxStream = client.open().await?.boxed();
```

Retain or clone Client to reuse one physical connection in lower-level callers.
`open_mode(Mode)` can override outbound mode. `open` returns before response
headers, supporting peers that await initial DATA before returning HEADERS.
The connection driver stays alive while any Client or emitted Tunnel exists.

```rust,ignore
let mut server = grpc::Server::handshake(io, config).await?;
while let Some(accepted) = server.accept().await? {
    // Dispatch every independent logical stream with bounded owned tasks.
    let stream: BoxStream = accepted.stream.boxed();
    // accepted.authority and accepted.metadata remain available to caller policy.
}
```

The dedicated HTTP/2 driver continues independently of application reads and
the accept loop. Its bounded accept queue rejects excess streams instead of
blocking established tunnels. Dropping Server initiates graceful HTTP/2 shutdown
while handed-out tunnels retain the driver. Dropping the final owning handle
stops its task.

Tunnel implements AsyncRead/AsyncWrite directly, preserving HTTP/2 errors.
Client shutdown ends only the request body; response data remains readable.
Server shutdown drains pending data and sends successful grpc-status trailers.
`Tunnel::finish(Status::new(code, message)?)` sends an explicit server status.
Dropping an unfinished tunnel resets only that HTTP/2 stream. A nonzero response
status becomes an I/O error after preceding payload; missing/malformed status,
HTTP failure, truncated framing, and compression never become clean EOF.

## Bounds and explicit limitations

Received protobuf messages are capped at grpc-go's default 4 MiB. Advertised
length is checked immediately after the five-byte header. Writes accept at most
16 KiB of application bytes and retain at most one encoded pending message.
HTTP/2 send capacity is reserved, and receive capacity is released as bytes enter
the bounded decoder, allowing messages larger than an HTTP/2 window. Flush or
continue polling I/O when delivery is required under peer flow control.

Positive initial_windows_size values at least 65,535 configure the client's
receive stream window; smaller values retain the grpc-go default minimum.
The server does not apply this client-only option, matching hub.go. Negative
configuration integers retain their source disabled/default meaning.

- Positive idle_timeout, positive health_check_timeout, or permit_without_stream
  true are rejected as Unsupported. HTTP/2 PING keepalive scheduling and grpc-go
  server enforcement policy are not implemented.
- Gzip and other message compression are rejected. Xray's tunnel sender does
  not choose a compressor.
- Automatic destination-wide pooling, retry/backoff, connection idle retirement,
  and grpc-go adaptive BDP window probing remain unimplemented. A low-level
  Client does support concurrent HTTP/2 stream reuse.
- TCP socket options, PROXY handling, and trust policy remain outer runtime work.
  Forwarded addresses are request metadata and are not automatically trusted.
- HTTP/2 SETTINGS and frame scheduling need not fingerprint identically to
  grpc-go; protocol interoperability is the target.
- No Go process, Go FFI, host network changes, or privileged setup is required.

## Validation

The transport has 23 source-derived and local HTTP/2 tests: service paths,
authority, JSON, User-Agent, protobuf/gRPC envelopes, duplicate/unknown fields,
fragmentation, message limits, compression, statuses, both modes, vectored writes,
half-close, 512 KiB transfers, per-stream cancellation, delayed HEADERS, canceled
partial reads, canceled writes under a 64-byte HTTP/2 window, missing/truncated
trailers, response/connection failure, driver ownership, and custom services.

The migration lead reported these 23 transport tests passing in the combined
native-tun-enabled run (508 core tests and 17 runtime tests passed overall).
That run preceded the subsequent runtime integration.

Eight new bounded tests in `rust/xray-core/tests/grpc_runtime.rs` cover pooled
concurrent logical sessions over TCP and TLS; Tun/TunMulti; configured outbound
chains; half-close and stream cancellation; runtime shutdown with unfinished
handshakes; physical connection loss with live upstreams; config/native REALITY
profile validation; and missing/disjoint negotiated TLS ALPN.

Run `cargo test -p xray-core --test grpc_runtime` for those eight integration
tests, plus the existing regression suite. At this handoff those new tests are
authored and await the lead's execution. The worker ran rustfmt check mode on
the owned module, leased integration files, and new tests, without starting a
shared Cargo build. Local Rust HTTP/2 tests do not establish real Rust-to-Go
interoperability; that remains separately unverified.
