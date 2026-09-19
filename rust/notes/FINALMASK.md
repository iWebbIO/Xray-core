# Native finalmask building blocks

Implemented in `rust/xray-core/src/transport/finalmask.rs` and its subtree. This
package does **not** install masks in configured transports or claim full
finalmask parity. It contains real Rust wire transforms, explicit asynchronous
write/handshake helpers, and unit tests derived from the checked-in Go source.

## Integration contract

The parent module must export `pub mod finalmask;` in `transport.rs`. Add
`blake2 = "0.10"` to workspace dependencies and `blake2.workspace = true` to
`xray-core`. Existing `rand` 0.8 and Tokio features are sufficient. No shared
manifest, runtime, configuration, or module-registry files were edited by this
work package.

| Module | Public entry points | Implemented behavior |
| --- | --- | --- |
| `fragment` | `Config`, `Fragmenter::plan`, `Fragmenter::write` | Write-call range selection; first TLS handshake-record splitting; per-segment lengths and delays with final-entry clamping; split limits; merged zero-delay TLS records; untouched trailing records. |
| `noise` | `Item`, `Payload`, `Noise::before_payload`, `record_payload`, `send_to`, `forget_peer` | Static/random noise before a payload, ordered delays, per-destination idle reset, zero-reset once-per-peer behavior, ignored noise-send errors followed by the actual payload result. |
| `salamander` | `Salamander::encode`, `encode_with_salt`, `decode` | Exact eight-byte salt plus repeating XOR key, where the key is BLAKE2b-256 of PSK concatenated with salt. A four-byte minimum PSK matches Go. |
| `salamander` | `Gecko`, `GeckoHeader`, `GeckoReassembler` | Gecko 2–8-way long-header fragmentation, five-byte header, random padding and Salamander wrapping; short-header pass-through; reordered fragment assembly, duplicate/count checks, eight-second deadlines, per-source/global caps and oldest-entry eviction. |
| `custom` | `Expr`, `Op`, `Context`, `Source`, `Item`, `encode_items`, `match_items` | All current expression operations, strict numeric/byte types, save/reuse, wildcard random-field capture, size measurement, IPv4/port metadata and source/destination aliases. |
| `custom` | `read_sequence`, `write_sequence`, `TcpConfig::{client_handshake,server_handshake}` | Exact-length reads, merged writes around item delays, alternating client/server sequences, extra server sequences and configured mismatch response. |
| `custom` | `UdpHeaders::{encode_to,decode_from,expire,forget_peer}` | Regular header-per-datagram client/server custom UDP, source-isolated saved fields with five-second expiry, header-size checks and bounded datagrams. |

Use `rand::rngs::OsRng`, or another `CryptoRng`, in production. The deterministic
salt entry point is for integration with an existing cryptographic RNG and wire
fixtures; salts must be freshly random. Salamander is obfuscation and provides
no integrity or peer authentication.

`SampleRange` reproduces `common/crypto/crypto.go`: integer ranges are upper
exclusive except fixed endpoints, and reversed endpoints are normalized. Byte
ranges are inclusive and use the Go modulo transformation. Config adapters must
map Go custom item precedence to the explicit `Source` enum: nonzero random
length, nonempty packet, variable, expression, empty. Delay units are milliseconds
and noise reset units are seconds.

The explicit helpers require an integration owner: `Fragmenter` must observe
the original write boundaries; `TcpConfig` handshakes must run once before
application I/O; a UDP wrapper must send every returned Gecko datagram, repeatedly
read until reassembly completes, drop decoding failures, preserve the peer
address, and maintain/expire state. `Noise::record_payload` belongs after the
noise burst and before sending the payload, even if a noise write failed.

## Validation

All new Rust files were parsed/formatted with `rustfmt --edition 2024`. Per the
shared migration coordination rule, this worker did **not** run Cargo, Rust unit
tests, or shared builds. The parent should run
`cargo test -p xray-core transport::finalmask` after exporting the module and
adding the dependency.

The migration lead subsequently added an explicit `usize` annotation to the
fragment planner's offset, compiled the combined workspace, and reported all
20 finalmask tests passing. That integration fix is preserved.

The embedded tests cover source-derived TLS record bytes, packet count and
split/delay behavior; noise bytes, deadlines and peer separation; Salamander
key/wire bytes and bounds; Gecko header bytes, malformed/truncated frames,
ordering, duplicates, empty chunks, limits, expiry, long/short-header behavior;
custom expression golden vectors, overflow/type/depth errors, metadata aliases,
atomic capture failure, cross-peer/expired UDP state; and asynchronous TCP
handshakes over a two-byte-capacity duplex stream plus mismatch responses.

The Salamander fixture was independently generated with Python 3.12's standard
`hashlib.blake2b(psk + salt, digest_size=32)` and the specified repeating XOR.
For PSK `correct horse battery staple`, salt `0001020304050607`, and payload
bytes 0 through 47, the derived key is
`fa36362f9dcd4501ec365b4c6ca406a3d1a31a3daae087c7f649dcc6c0c5c720`.
The test asserts the full 56-byte wire result; using truncated BLAKE2b-512 would
fail it. No Go runtime, FFI, or subprocess is part of the Rust implementation.

## Deliberate bounds and remaining work

This implementation rejects UDP packets above 4096 bytes, custom headers above
65536 bytes, expressions nested beyond 64 calls, and assembled Gecko datagrams
above 4096 bytes. Regular custom UDP state is capped at 4096 peers with oldest
expiry eviction. These are explicit limits; some direct Go wrappers allocate
more freely. UDP saved values are isolated per peer: the Go client's fallback
to the last captured values from a different peer is deliberately omitted.
Expired entries are removed on use or explicit expiry rather than a background
timer. Noise peer records require caller cleanup to preserve once-per-peer
semantics. TCP handshake persistence across separately created connections is
left to the caller's `Context` ownership.

Still unimplemented:

- Configuration/protobuf adapters, mask registry and ordering, chain composition,
  header-manager allocation/overhead aggregation, packet-socket wrappers,
  listener/accept wrapping, cancellation/deadline forwarding, and stream splice
  eligibility/unwrapping. The source manager reverses mask registration before
  constructing wrappers; an integrating runtime must preserve the resulting
  wire order.
- Custom standalone UDP authentication, handshake retransmission/waiters,
  packet queueing and per-peer session lifecycle. `UdpHeaders` implements only
  the regular per-datagram header variant.
- mKCP finalmask original checksum/XOR, AES-128-GCM masking, and all mKCP
  pseudo-header variants (DNS, DTLS, SRTP, uTP, WeChat and WireGuard).
- Sudoku TCP/UDP and packed TCP codecs/table generation; UDP hopping, port
  management and migration; Realm rendezvous/STUN/NAT traversal and port mapping;
  XDNS DNS/record transport; XICMP packet/OOB socket handling; XMC Minecraft
  protocol profiles, RSA handshake, key derivation, CFB8 stream framing and
  padding policies.
- Full native/Go live network interoperability and end-to-end configured
  transport tests, which require the runtime integration above.
