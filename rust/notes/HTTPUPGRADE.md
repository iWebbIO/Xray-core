# Native HTTP Upgrade transport

Implementation: `rust/xray-core/src/transport/httpupgrade.rs`.

Source references:

- `transport/internet/httpupgrade/{dialer,hub,config,connection}.go`
- `infra/conf/transport_method.go`, `HttpUpgradeConfig.Build`
- `transport/internet/internet.go`, `IsValidHTTPHost`
- `common/utils/browser.go`, `TryDefaultHeadersWith(..., "ws")`
- `common/protocol/http/headers.go`, `ApplyTrustedXForwardedFor`
- Go standard-library `net/http/{request,response,transfer}.go`, `net/url`

## Integration

The transport module owner must export `pub mod httpupgrade;` from
`rust/xray-core/src/transport.rs`. This implementation uses existing `tokio`,
`serde_json`, and `rand` dependencies and does not require a manifest change.

Public API:

```rust
pub struct HttpUpgradeConfig {
    pub host: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub early_data: u32,
}
impl HttpUpgradeConfig {
    pub fn from_json(value: &serde_json::Value) -> io::Result<Self>;
    pub fn normalized_path(&self) -> String;
}
pub async fn client_upgrade(
    stream: BoxStream,
    config: &HttpUpgradeConfig,
    fallback_host: &str,
) -> io::Result<BoxStream>;
pub async fn server_upgrade(
    stream: BoxStream,
    config: &HttpUpgradeConfig,
) -> io::Result<BoxStream>;
pub async fn server_upgrade_with_metadata(
    stream: BoxStream,
    config: &HttpUpgradeConfig,
) -> io::Result<(BoxStream, RequestMetadata)>;
```

`RequestMetadata` contains `method`, `host`, decoded `path`, and ordered raw
header values. `header(name)` returns the first case-insensitive match.
`trusted_forwarded_ip(&[String])` implements the existing trusted-header policy;
the runtime may use the returned IP with port zero, or retain the actual peer
address when it returns `None`.

The caller establishes TCP or another underlying byte stream, wraps TLS if
configured, and then upgrades it. TLS must negotiate HTTP/1.1. Client fallback
Host is the configured TLS serverName, otherwise the destination address without
the port. Explicit transport `host` overrides that fallback. Runtime connection
and client handshake timeouts remain the caller's responsibility.

PROXY protocol, socket settings, TCP masks, socket listener ownership, TLS, and
connection statistics remain outer layers. `from_json` returns `Unsupported`
for `acceptProxyProtocol: true`; an implemented PROXY-aware listener must consume
that setting before constructing this transport configuration. It is never
silently treated as an ordinary HTTP stream.

The WebSocket transport can share
`pub(crate) fn apply_browser_headers(&mut BTreeMap<String, String>)`. Both module
exports are required when WebSocket imports this function.

## Implemented behavior

- Native HTTP/1 client/server handshakes followed by raw bidirectional bytes;
  there is no WebSocket framing, masking, Sec-WebSocket-Key, subprotocol, or
  base64 early-data header.
- `early_data == 0` validates the response before returning the client stream.
  Any nonzero value returns after sending the request, permits raw writes, and
  validates the response on the first nonempty read. Its numeric value is not
  a write-size limit, matching this Go transport's `Ed` use.
- The JSON settings loader removes nonempty `ed` from the path query, converts
  its value using signed-integer parsing and a uint32 cast, and sorts/encodes
  remaining query pairs. Remaining query/fragment text becomes literal path
  text when the HTTP request is written, as in the Go dialer's `URL.Path` use.
- Client Host selection, leading-slash path normalization and Go URL.Path
  percent-escaping; case-preserving custom header names; forced canonical
  `Connection: Upgrade` and `Upgrade: websocket`; Go's special request-header
  exclusions and User-Agent ordering; safe CR/LF replacement in header values.
- Absent User-Agent defaults to the source Chrome profile. Chrome, Edge,
  Firefox, Safari, curl and golang aliases expand with the source WebSocket
  header families. Explicit literal/empty User-Agent values remain explicit.
- Server configured Host comparison is case-insensitive, stripping a request
  port only if Go `SplitHostPort` would succeed. Configured ports are not removed.
  Request path comparison uses its percent-decoded path, ignoring an actual
  request-target query. Absolute request-target authority takes precedence over
  the Host field. The source server does not explicitly require method GET.
- Upgrade/Connection validation is exact after ASCII case folding; a comma
  separated token list such as `keep-alive, Upgrade` is rejected. The first
  duplicate field controls the result, as with Go `Header.Get`.
- Client response status text must be exactly `101 Switching Protocols` after
  the source response parser's leading-space handling. Server emits the source
  101 response bytes without WebSocket key/accept fields.
- Four-second server request-read deadline and 12,288-byte request-header cap.
  Partial reads, LF/CRLF lines, folded header values, duplicate Host rejection,
  and conflicting Content-Length rejection are handled.
- Cancellation during a deferred response read preserves accumulated bytes.
  Fragmented header scanning is incremental. Reads and writes retain ordinary
  stream half-close semantics.

## Deliberate differences and remaining work

- Buffered tunnel data is preserved on both sides, including early data
  coalesced with HTTP headers. The Go server drops its buffered reader, which
  can discard such bytes; this implementation does not reproduce that bug.
- A failed deferred response is a persistent error, including on later writes.
  It cannot become an unvalidated raw stream after a failed first read.
- Client response headers have an explicit 65,536-byte limit. The Go dialer
  does not specify a corresponding limit.
- Browser version distributions, UA formats, GREASE ordering and process-wide
  caching follow the source. Rust uses its existing OS-seeded RNG rather than
  reproducing Go's CPU-metadata-seeded PRNG. Exact per-machine browser version
  fingerprint identity is therefore not claimed. Safari's calendar uses UTC
  dates; the source uses the process-local calendar.
- Hosts supplied to the client must be ASCII DNS names or IP addresses.
  Automatic IDNA conversion and IPv6 zone canonicalization are not implemented.
  Non-UTF8 decoded request paths are rejected. This is a bounded transport
  parser, not a replacement for every obscure `net/url`/`net/http` behavior.
- Full Go/Rust external interoperability fixtures, TLS integration and runtime
  configuration wiring must run through the main integration owner.

## Validation

The module includes 16 tests covering golden request/response bytes, settings
and query conversion, browser aliases, strict headers, host/path matching, IPv6,
trusted forwarded addresses, coalesced payload preservation, deferred writes,
fragmented responses, cancellation, persistent handshake errors, bounded/slow
headers, and a native loopback TCP round trip with all byte values and half
closes. Tests use native Rust I/O, not a Go executable or FFI.

The implementation agent ran rustfmt on the owned module. Cargo builds/tests
were deliberately left to the integration owner to avoid shared target locks
and disk contention; their execution is not claimed by this note.
