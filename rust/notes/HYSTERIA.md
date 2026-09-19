# Hysteria 2 migration package 20

The implementation is in `xray-core/src/protocol/hysteria.rs` and
`xray-core/src/transport/hysteria.rs`. It follows this checkout's
`proxy/hysteria/protocol.go`, `proxy/hysteria/client.go`, and
`transport/internet/hysteria/{config,conn,dialer,hub}.go`. The pinned Go QUIC
dependency is `github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e`.

## Implemented

- QUIC varints, including acceptance of legal non-minimal encodings and bounded
  reads of variable-length fields.
- TCP request bodies, the `0x401` bidirectional-stream prefix, and TCP response
  status/message/padding. Decoders preserve following application bytes.
- Complete raw QUIC UDP datagram frames: big-endian session ID and packet ID,
  fragment index/count, varint address, and payload. The Go proxy serializer
  intentionally leaves the session ID for `InterConn.Write`; this Rust encoder
  emits the complete wire packet in one operation.
- Datagram fragmentation with a 255-fragment cap and a bounded assembler keyed
  by session ID, packet ID, and address. It accepts out-of-order identical
  retransmissions, rejects conflicting counts or duplicate contents, limits
  pending packets/bytes/fragments/packet size, and expires incomplete packets
  from their original arrival time. Instantiate an assembler per authenticated
  QUIC connection; the runtime must call `expire` during idle periods as well.
- Hysteria HTTP/3 POST authentication at `https://hysteria/auth`, exact success
  status 233, authentication/UDP/bandwidth/padding headers, and source padding
  length ranges. Authentication secrets are redacted from debug output.
- A per-connection server authentication-state helper, including repeated-auth
  behavior and rejection to a caller-supplied masquerade handler. This is not a
  complete HTTP/3 server.
- Exact congestion-policy negotiation: Auto/Brutal uses the lesser of local
  transmit and peer receive rates, falls back to BBR when either is zero, and
  ForceBrutal ignores the peer rate. Rates are bytes per second. Invalid numeric
  bandwidth headers become zero, as in the pinned Go code.
- A real native Quinn client which verifies TLS using the supplied rustls
  configuration, negotiates `h3`, sends the HTTP/3 authentication request, and
  returns an authenticated wrapper only after validating status 233. It retains
  the HTTP/3 driver and request sender for the session lifetime. TLS early data
  is disabled. It opens proxy TCP streams and sends/receives UDP wire fragments.
- TCP stream wrappers implement Tokio AsyncRead/AsyncWrite and retain shared
  ownership of the authenticated session. The caller can drop its connection
  handle after opening a stream. Explicit `close()` closes the shared session;
  dropping the final connection handle/stream closes it and aborts the driver.

## Integration contract

The lead must add `pub mod hysteria;` to both protocol and transport module
registries and add workspace/core dependencies:

```toml
bytes = "1"
http = "1"
h3 = "0.0.8"
h3-quinn = "0.0.10"
quinn = { version = "0.11", default-features = false, features = ["runtime-tokio", "rustls-ring"] }
```

Existing `anyhow`, `rand` 0.8, `subtle`, `tokio`, and `tokio-rustls` provide the
other runtime dependencies. Existing dev dependency `rcgen` supports the native
loopback tests. No shared manifests, registry files, runtime files, or existing
tests were edited by this package.

Construct `ClientOptions::new(AuthRequest { .. }, NativeCongestion::QuinnNewReno)`
or explicitly select `NativeCongestion::QuinnBbr`. Call
`AuthenticatedConnection::connect(bind, remote, server_name, &tls, options)`
then `open_tcp(address)` or `send_udp(message)` /
`receive_udp_fragment()`. Only one receiver should drain a connection's UDP
queue. The runtime owns session-ID allocation, source/destination authorization,
session idle expiry, packet routing, and connection reuse. Fragmentation chooses
a random nonzero packet ID when required and the caller provided zero.

`NegotiatedCongestion::supported_native_controller()` rejects pinned BBR and
Brutal selections. It never silently substitutes Quinn BBR for the pinned BBR
profiles. Users of the explicit Quinn BBR alternative must accept that its
congestion behavior differs from Xray's pinned controller.

## Intentional validation differences

The Rust codecs require UTF-8 destination strings, valid nonzero fragment counts,
fragment IDs below the declared count, nonempty UDP payloads, and reassembled
payloads no larger than 65,535 bytes. Go strings can carry non-UTF-8 bytes and its
defragmenter treats counts zero and one identically. These stricter inputs do not
change valid destination-string packets. Address/message/padding limits follow
the source (2048/2048/4096 bytes). The Rust reassembler supports interleaving,
where the Go helper remembers just one packet ID at a time.

## Remaining work and limits

- No native Hysteria inbound listener or general HTTP/3 stream hijacker is wired
  into runtime. The server auth helper must be connected to authenticated
  `0x401` stream dispatch and masquerade behavior. User-account validators and
  statistics also require integration.
- Xray's pinned BBR profile implementation and Brutal's pacing/loss compensation
  have not been ported. Quinn NewReno/BBR are explicitly named alternatives.
- No Chrome QUIC fingerprint imitation, zero-length CID policy, pinned path
  manager behavior, or custom quic-go transport-parameter imitation. In
  particular, the Go client conditionally omits its datagram-size parameter
  after September 1, 2026; Quinn performs standard datagram negotiation.
- No finalmask socket integration, connection pooling, TCP Fast Open, shared
  runtime/config dispatch, or outbound policy routing. The client currently
  creates one bound UDP endpoint for one remote SocketAddr. It caps Hysteria
  application datagrams at 1200 bytes and also honors Quinn's smaller negotiated
  maximum.
- The client retains the caller's certificate verifier and roots; it does not
  translate the project TLS configuration. HTTP/3 and QUIC setup are separately
  time-bounded. Default receive windows and idle timeout follow the Go defaults,
  but not every quic-go receive-window/packet-network setting has a Quinn mapping.

## Validation

Source-derived literal tests cover RFC 9000 varint vectors, TCP/UDP layouts,
truncation, field limits, fragmentation, out-of-order reassembly, session/address
isolation, conflicting duplicates/counts, memory limits, expiry, auth headers,
auth state, bandwidth negotiation, padding, and application-byte boundaries.
Two native loopback tests exercise real TLS/QUIC/HTTP3 authentication followed by
TCP and UDP, stream lifetime after dropping the client handle, and rejection of
HTTP status 200 with close code `0x101`.

Individual rustfmt passed. An independent Python implementation checked seven
literal varint/TCP/UDP fixtures. Cargo build/test/check was intentionally not run
by this package because the lead owns the combined build and lockfile. The Rust
tests therefore remain pending until that combined validation; there has not
been an end-to-end run against a Go Hysteria peer.
