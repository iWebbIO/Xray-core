# Native WebSocket transport

`rust/xray-core/src/transport/websocket.rs` implements Xray WebSocket framing
and HTTP/1.1 upgrade over an already connected `crate::transport::BoxStream`.
It does not invoke Go or an external WebSocket executable.

## Integration

Export `websocket` and `httpupgrade` under `crate::transport`. The WebSocket
module uses `httpupgrade::apply_browser_headers` so both transports share the
same browser-header aliases and defaults. All dependencies are already in the
crate: `tokio`, `base64`, `rand`, `sha1`, `httparse`, `serde`, and `serde_json`.
The implementation requires a running Tokio runtime.

Public entry points:

```rust
pub async fn client(
    stream: BoxStream,
    destination_host: &str,
    tls_server_name: Option<&str>,
    config: Config,
) -> std::io::Result<BoxStream>;

pub async fn server(stream: BoxStream, config: Config)
    -> std::io::Result<BoxStream>;

pub async fn server_with_metadata(stream: BoxStream, config: Config)
    -> std::io::Result<Accepted>;
```

`Config` contains `host: String`, `path: String`,
`headers: BTreeMap<String, String>`, `early_data_limit: usize`, and
`heartbeat_period: Duration`. `Default` selects the root path, no explicit
Host, no early data, and no heartbeat. `Config::from_json(&serde_json::Value)`
accepts a `wsSettings` object, extracts/removes `?ed=`, sorts the remaining
query as Go does, migrates the deprecated `headers.Host`, and converts the
heartbeat from seconds. `Config::normalized_path()` is also public.

The client Host priority is configured host, nonempty TLS server name, then
destination address. Supply the destination address without its port: the Go
transport deliberately does not include the destination port in this fallback
Host header. Establish TLS before calling `client`/`server` and select HTTP/1.1
ALPN. Socket settings, TCP masks, TCP/Unix listeners, cancellation of connecting
sockets, TLS certificate checks, and browser-dialer transport belong outside
this adapter.

`Accepted` contains `stream: BoxStream` and `request: RequestMetadata`.
Metadata includes `host`, `target`, `headers: Vec<(String, String)>`, and
`early_data_len`. All incoming headers, including `X-Forwarded-For`, remain
untrusted. The caller must combine them with the real socket peer and the
configured trusted-proxy list; the adapter does not invent a remote address.
The JSON helper rejects `acceptProxyProtocol: true` with `Unsupported` so
callers cannot silently ignore it. A listener that implements PROXY itself can
construct `Config` directly after consuming the preface.

## Behavior and source correspondence

- `transport/internet/websocket/config.go`: empty/relative path normalization,
  canonicalized configured request headers, browser-header processing.
- `infra/conf/transport_method.go:609`: `ed` query extraction and deprecated
  Host migration.
- `transport/internet/websocket/dialer.go`: eight-second upgrade timeout,
  Host precedence, raw URL-safe Base64 early data, handshake deferred until
  first application write. The **entire first write** is early data when it
  fits `early_data_limit`; an oversized write uses framed data, without
  splitting off an early-data prefix.
- `transport/internet/websocket/hub.go`: four-second server upgrade timeout,
  configured Host comparison, decoded URL path comparison, arbitrary Origin
  acceptance, and standard/URL-safe padded/unpadded early-data decoding. All
  `=` characters are removed as in Go's replacer. Noncanonical trailing Base64
  bits are accepted as Go's non-Strict decoder accepts them. Only successfully
  decoded nonempty data is prepended and echoed in `Sec-WebSocket-Protocol`.
- `transport/internet/websocket/connection.go`: binary writes, text/binary
  message boundaries hidden on read, ping heartbeat, normal-close payload.
- `transport/internet/internet.go`: case-insensitive Host comparison and
  request port removal, including bracketed IPv6.
- RFC 6455: SHA-1 accept, fresh random client masks, no server masks, 7/16/64-bit
  lengths, fragmentation, ping/pong/close, reserved-bit/opcode checks, close
  status and close-reason UTF-8 validation. No extensions are negotiated.

The reader streams payload chunks instead of allocating an advertised frame
size. The HTTP header cap is 8192 bytes and 128 fields. Incoming and outgoing
queues each have eight slots; data chunks are at most 16 KiB read and 64 KiB
write, plus one in-flight frame. The writer serializes application messages,
control replies, flush barriers, and heartbeat pings. Heartbeats and ping
responses run without application reads while the incoming queue has room.
Backpressure is retained when the application stops consuming data.

As an `AsyncWrite`, the adapter buffers accepted writes. Call `flush()` to
confirm that queued writes and a deferred handshake have completed. A first
write may be accepted before the deferred handshake finishes; any subsequent
read/write/flush reports handshake failure. Empty reads and writes complete
immediately without initiating that deferred handshake. Dropping the returned
stream aborts its two worker tasks; dropping a deferred stream also aborts its
handshake task. `shutdown()` sends close status 1000 after preceding writes.
After a successful peer-close reply, `flush()` and `shutdown()` remain
idempotently successful, including when used by `tokio::io::copy_bidirectional`.

## Explicit differences and remaining integration

- No runtime/config registration or listener wiring is included in this file.
- The shared browser helper uses OS-seeded randomness rather than Go's
  CPU-seeded PRNG, so exact generated browser fingerprints differ.
- This byte-stream adapter maps empty/1000/1001 close frames to clean EOF;
  other valid close statuses report `ConnectionAborted`. A bare TCP EOF remains
  `UnexpectedEof`. Go exposes a Gorilla `CloseError` even for a normal close.
- Invalid/nonminimal frame lengths, request body framing, unsolicited response
  extensions, invalid header fields, and oversized headers are rejected
  explicitly. These are intentionally stricter than some Gorilla/Go parser
  edge cases. Header-size allowance is a strict 8192 bytes, without Go HTTP's
  additional read-buffer allowance.
- Client request targets support Xray's normalized origin-form paths and
  percent escapes; proxy-style absolute-form server request targets are not
  accepted. Server configured paths are compared literally with decoded
  request paths, including Go's behavior where a configured query string does
  not match `request.URL.Path`.
- Browser dialing, TLS fingerprint impersonation, PROXY headers, XFF trust,
  and network-level deadlines need their own native outer components. They
  are not silently substituted with this stream adapter.

## Validation

Twenty-two in-module tests cover RFC accept/mask fixtures; Go configuration,
Host/path and early-data behavior; header injection and response validation;
client/server exchange; deferred handshakes; coalesced HTTP/frame bytes;
fragmented text/binary messages with interleaved controls; autonomous pings,
pongs, and heartbeat masking; 70,000-byte payloads through a 137-byte duplex;
flush/close ordering; invalid masks, lengths, fragmentation, controls, close
codes, and EOF; bounded HTTP headers; and zero-length I/O.
Additional closure tests cover shutdown/flush after peer Close,
`copy_bidirectional` completion, and error persistence after canceled reads or
flushes.

`rustfmt --edition 2024` passed. Independent Python standard-library checks of
the RFC accept hash, masked-Hello wire fixture, and Xray early-data Base64
fixture passed. Cargo compilation and test execution are assigned to the
migration lead to avoid shared build-lock and disk contention; no Cargo result
is claimed here.
