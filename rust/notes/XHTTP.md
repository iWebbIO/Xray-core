# Native Rust XHTTP status

The implementation is `rust/xray-core/src/transport/xhttp.rs`. Its reference is
the checked-in `transport/internet/splithttp` Go source, especially `client.go`,
`config.go`, `hub.go`, `upload_queue.go`, `xpadding.go`, and the JSON normalizer
in `infra/conf/transport_method.go`. It does not invoke Go, link Go, or translate
XHTTP into HTTP CONNECT.

## Implemented

- HTTP/1.1 **packet-up** client and server: one persistent GET downlink plus
  independent numbered upload requests. The resulting tunnel implements
  `AsyncRead + AsyncWrite` through the existing `BoxStream` abstraction.
- HTTP/1.1 **stream-up** client and server: a GET downlink plus one chunked
  request-body upload and a single reader claim per session. The upload response
  carries only repeat-X keepalive padding. `scStreamUpServerSecs` defaults to
  20–80 seconds, accepts signed/reversed ranges, and supports negative values to
  disable padding. Upload EOF does not discard the remaining download response.
- HTTP/1.1 **stream-one** client and server: one chunked request carries upload
  bytes while its response carries download bytes. The client exposes the
  logical stream before waiting for response headers so peers can wait for
  initial upload data. Both streaming clients terminate request bodies with a
  final chunk without shutting down the underlying transport write half.
- Streaming upload `Content-Type: application/grpc`, with `noGRPCHeader` support.
  Stream-up responses omit SSE headers; downloads honor `noSSEHeader`.
- Explicit inbound mode enforcement. `auto` accepts all three implemented
  modes; `stream-up` also accepts stream-one, matching the pinned Go listener.
  HTTP/1.1 `auto` clients continue to select packet-up.
- Shared server sessions, a 30-second TTL before the downlink connects, session
  cleanup on dropped connections/tasks, bounded upload queues, out-of-order
  packet reassembly, and retry deduplication.
- Streaming data crosses bounded 64-KiB pipes instead of buffering whole
  requests. Packet uploads reserve queue capacity before reading bodies.
  Cancellation/errors reach the shared downlink; duplicate streaming readers
  and subsequent packet uploads are rejected. Header reads use the Go
  listener's four-second timeout.
- Successful logical write shutdown waits for the final request/response chunk
  to be written; upload shutdown leaves response reads active. Buffered bytes
  arriving with request headers and trailers are retained. Informational HTTP
  responses are handled before the final response, and upload requests with
  `Expect: 100-continue` receive an interim response.
- Persistent upload HTTP/1.1 connections, as needed by the Go client's raw
  upload connection pool. The Rust client currently opens a fresh connection
  per upload request.
- Session/sequence metadata in paths, query parameters, headers, or cookies;
  default and custom metadata keys; UUID session generation.
- Raw body uploads and base64url header/cookie uploads, numbered payload chunks,
  configurable chunk sizes, and server `auto` payload concatenation in the Go
  order (header, cookie, body).
- Mandatory repeat-x padding: legacy Referer query padding, legacy request URL
  fallback, and obfuscated query/header/cookie/query-in-header placement.
  Referer padding replaces its URL query before session/sequence metadata is
  added, matching the Go reference. Padding validation checks byte length.
- Path normalization, query preservation, custom request headers and upload
  method, `extra` replacement rules, post size and interval ranges, queue/header
  limits, CORS preflights, response padding, SSE anti-buffering headers, and
  `noSSEHeader`.
- HTTP body decoding for content length, chunked transfer (including trailers),
  and close-delimited responses; limits and rejection of ambiguous body
  framing and header injection.
- Existing dependencies only: tokio, tokio-util, serde_json, httparse, uuid,
  rand, and base64.

## Explicitly pending

- HTTP/2, HTTP/3, QUIC, browser dialer, and their native connection management.
- Xmux connection selection/reuse policies and separate `downloadSettings`.
- Tokenish padding and its HPACK Huffman size validation.
- Custom session ID alphabets/lengths.
- Go-client/Rust-server and Rust-client/Go-server process interoperability runs.
  The local tests include reference-derived byte fixtures and a native Rust
  client/server TCP roundtrip, which are not proof of cross-language parity.

TLS is supplied by the caller's connector and accepted-stream wrapper. This
module does not create a TLS or REALITY handshake. A wrapping TLS connection
must select `http/1.1` ALPN; passing a stream negotiated as h2/h3 is not supported.
REALITY's Go auto-mode selection is stream-one, so REALITY auto mode must not be
silently routed through HTTP/1.1's packet-up default; the parent transport
composition must select the effective mode when adding REALITY integration.

Streaming client requests use `Connection: close`. This matters to Go's
HTTP/1.1 server: its automatic unread-body drain before response headers is
skipped when `closeAfterReply` is set. The Rust listener independently supports
simultaneous request reads and response writes. A middlebox that removes this
request header or buffers request bodies can still prevent streaming; HTTP/2
support remains separate work.

Cancelling a session interrupts blocked I/O. If cancellation interrupts a
partial response chunk, the socket closes instead of appending an invalid
chunk terminator. Otherwise stream-up response closure emits its terminating
chunk with a bounded wait.

The client currently serializes upload requests and uses a bounded 64-KiB
packet buffer, respecting any smaller configured post maximum. This differs
from Go's performance and pooling policies. Packet-up has no separate upload
EOF frame, matching the reference's stream lifetime model.

For runtime integration, create one `Server` per inbound and clone it for each
accepted HTTP socket. `Server::accept` handles uploads and OPTIONS internally;
only `Some(BoxStream)` is a logical proxy connection. For clients, use
`Config::from_json(...).with_authority(destination_or_server_name, secure)` and
pass an `Arc` connector to `connect`. Explicit `host` overrides the fallback.

## Validation inventory

The module has reference-derived tests for normalized defaults/extra behavior,
legacy Referer request framing, cookie/header payloads and metadata, unsupported
feature rejection, header injection, chunked body/trailer decoding, ambiguous
or truncated framing, sequence reassembly, and a 150-KiB bidirectional TCP echo.
The `xhttp/streaming_tests.rs` suite additionally covers streaming request wire
fields, coalesced chunked bodies/trailers, delayed response headers, upload EOF
followed by a response, Go-style stream-up keepalive responses, wrong-mode and
duplicate-upload rejection, 200-KiB native TCP round trips in both streaming
modes, bounded backpressure/cancellation, and propagation of protocol failures.
The writing agent ran rustfmt only; the parent agent owns workspace compilation
and test execution to avoid competing builds and disk exhaustion.
