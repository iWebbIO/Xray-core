# Native PROXY protocol listener adapter

Implementation: `rust/xray-core/src/transport/proxy_protocol.rs`.

The source contract is `transport/internet/system_listener.go` and the pinned
`github.com/pires/go-proxyproto v0.15.0` dependency, especially `protocol.go`,
`header.go`, `v1.go`, `v2.go`, `addr_proto.go`, `tlv.go`, and the AWS NLB fixture
in `tlvparse/aws_test.go`. The primary wire specification is HAProxy's
`https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt`.

## API and listener integration

Only existing dependencies are used: bytes, tokio, and the standard library.
Export the module with `pub mod proxy_protocol;` in `transport.rs`.

```rust,ignore
use crate::transport::proxy_protocol::{self, Config, PeerTrust};

// Decide trust using the actual accepted socket's peer before this call.
let trust = if trusted_proxy_policy(real_peer) {
    PeerTrust::Trusted
} else {
    PeerTrust::Untrusted
};
let accepted = proxy_protocol::accept(raw_stream, &Config::default(), trust).await?;
let reported_source = accepted.header.as_ref().and_then(|header| header.source_addr());
let effective_source = reported_source.unwrap_or(real_peer);
let stream = accepted.stream;
// TLS/REALITY and then WebSocket/HTTP Upgrade/application processing follow.
```

`Config::default()` selects Required, a ten-second deadline, and a 4096-byte v2
payload cap. Required matches the policy Xray explicitly passes to
go-proxyproto for `acceptProxyProtocol`. Optional is available only when selected
explicitly; it passes an absent header through without discarding any bytes.
An explicit `None` timeout disables the deadline. The configurable v2 payload
cap cannot exceed its 16-bit wire length. The v1 line cap is 107 bytes including
CRLF.

`PeerTrust` is a mandatory argument with no default. Required+Untrusted and
Optional+Untrusted both return PermissionDenied before any read. The module
does not infer trust from a claimed source address, localhost in a header,
SSL flags, or the mere presence of a PROXY signature. For a listener that permits
direct untrusted clients, the caller may explicitly bypass this adapter for
those actual peers; their application bytes never become PROXY metadata.

`Accepted` contains a `BoxStream` and optional `Header`. Coalesced application or
TLS bytes are replayed before reading the underlying connection. Writes,
vectored writes, flushes, and half-close are forwarded. The adapter owns the
input stream: cancellation, timeout, or parse failure closes it, and no detached
read task survives.

The pure `decode(data, max_v2_payload)` API returns Incomplete, Absent, or
Complete with the parsed header and exact consumed byte count. It never consumes
bytes after the header and validates an advertised v2 size before waiting for
or allocating its payload.

## Addresses, commands, and TLVs

V1 supports TCP4, TCP6, and UNKNOWN. Ports use the source's decimal grammar:
zero is permitted, other leading zeroes/signs/out-of-range values are rejected.
IPv4 and IPv6 must match the advertised family; scoped IPv6 literals are rejected.
IPv4-mapped IPv6 remains IPv6. UNKNOWN ignores following fields and never supplies
replacement connection endpoints.

V2 supports the defined IPv4, IPv6, and Unix stream/datagram address layouts.
PROXY+UNSPEC and undefined family/transport combinations are rejected, matching
the pinned Go library. The 108-byte Unix slots are retained byte-for-byte,
including non-UTF8 and abstract-name bytes. `pathname()` supplies the conventional
first-NUL terminated view used by the Go dependency; raw slots remain available.

LOCAL always preserves actual transport endpoints. The defined family/transport
byte is checked syntactically, as the pinned Go dependency requires, but payload
layout is ignored: exactly its declared length is skipped and retained as opaque
`local_payload`. No LOCAL payload is promoted into source/destination addresses,
TLVs, SSL identity, or checksum claims. `source_addr()` and `destination_addr()`
return None for both LOCAL and UNKNOWN.

The pure decoder can inspect a PROXY+DGRAM header. The stream adapter returns
Unsupported for it; implementing PROXY over UDP requires parsing every datagram
and preserving its message boundaries. LOCAL with an otherwise defined DGRAM
family is accepted because its advertised transport is ignored.

V2 PROXY TLV lengths are checked; unknown/custom types and NOOP bytes are retained.
SSL TLV structure and its nested TLV vector are checked, with client flags,
verification result, and sub-TLVs exposed as proxy-provided metadata. These do
not authenticate a client or prove TLS on the current connection.

A supplied CRC32C TLV must appear exactly once, contain four bytes, and match
the checksum over the complete header with its checksum value zeroed. Absence
is allowed. `checksum_verified` means only this integrity check succeeded;
it does not establish trust or TLS identity. The implementation uses native
Castagnoli CRC code and requires no additional crate.

## Intentional differences and remaining integration

- The pinned Go v1 parser rejects a line that does not arrive in one buffered
  read. This adapter tolerates fragmentation within the absolute deadline,
  consistent with the specification's recommended receiver behavior.
- TLV structure, SSL vector structure, and an advertised checksum are validated
  eagerly. The pinned Go listener retains raw TLVs and defers their interpretation.
- LOCAL payload is always opaque. The Go dependency may decode fitting LOCAL
  address layouts for informational round-trip serialization; neither applies
  these addresses to the real endpoints.
- Optional EOF/timeout before a complete recognized signature returns the exact
  buffered prefix as application bytes. EOF/timeout after a recognized signature
  fails explicitly, preventing partial malformed headers from becoming data.
- V1 embedded CR/NUL and malformed text are rejected. UNKNOWN still ignores
  arbitrary extra fields up to the final CRLF within the fixed line-size bound.
- This module adapts an already accepted stream. TCP/Unix listener creation,
  peer allowlists, endpoint propagation into session metadata, and transport
  config wiring remain with the runtime. It makes no host networking changes.
- Header generation, UDP listener integration, and interpreting vendor TLVs
  beyond their bounded opaque values are outside this module.

## Validation

Twenty-four authored tests cover wire fixtures, strict v1 grammar, exact length
limits, IPv4/IPv6/Unix address families, LOCAL/UNKNOWN, malformed commands and
TLVs, SSL metadata, CRC32C, all fragmented prefixes, optional passthrough,
coalesced TLS bytes, deadlines, EOF, trust rejection, cancellation, DGRAM
rejection, and a real loopback TCP listener round trip.

The CRC32C value in the pinned Go AWS NLB fixture was independently checked with
a standalone Python calculation: 100-byte header, checksum `0xe8d6892d`.
The Rust worker ran rustfmt and its check mode on owned files. Cargo compilation
and Rust test execution belong to the migration lead's shared build lane;
authored tests are not a claim that they have already passed.
