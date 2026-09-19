# Native REALITY authenticated server

`transport::reality::handshake::server::accept` owns an async byte stream, applies
an explicit `ServerPolicy`, completes TLS 1.3, verifies the client Finished, and
only then returns the encrypted stream and authenticated connection metadata.
`accept_boxed` is the adapter when callers only need `BoxStream`.

The server supports AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and
ChaCha20-Poly1305/SHA-256, with server-configured preference order. Both standalone
X25519 and X25519MLKEM768 are implemented. Hybrid shares use the pinned Go/uTLS
ordering: client ML-KEM encapsulation key followed by X25519 public key, server
ML-KEM ciphertext followed by X25519 public key, and ML-KEM secret followed by the
X25519 secret. Fresh ephemeral keys and encapsulation randomness come from the OS.

The static private key and intermediate shared secrets use zeroizing storage.
The admission policy checks the authenticated version, time, short ID, and SNI
before sending a server response. This native server profile requires nonempty
SNI/short-ID lists and a positive time window; unlike the lower-level compatible
policy primitive, a zero time window is rejected here. It does not maintain a
ClientHello replay cache. A replay alone cannot produce a verified client
Finished without the original client's ephemeral key material.

The authenticated server flight contains EncryptedExtensions, a freshly generated
Ed25519 certificate carrying the REALITY HMAC marker, Ed25519 CertificateVerify,
and Finished. `rcgen` is a normal dependency for DER certificate construction;
the final Ed25519 certificate signature is replaced by the REALITY marker. The
normal certificate-chain trust model does not apply to that temporary certificate.

The shared encrypted stream runs in server role, rejecting client-sent
NewSessionTicket messages while retaining shared KeyUpdate processing, bounded
record parsing, separate read/write shutdown, and authenticated close_notify.
ClientHello and Finished fragmentation are supported. Record lengths, handshake
message budgets, and a configurable handshake deadline bound incoming work.
For the standalone `accept` entry point, error, timeout, or cancellation drops
the owned connection. This entry point never forwards rejected input.

## Optional target mirroring and forwarding

`accept_with_target(client, preconnected_target, config)` adds a bounded subset of
the pinned Go REALITY server contract. The caller dials the target first and owns
its network choice, connection lifetime, and cancellation. A single handshake
deadline bounds client inspection, target observation, and local Finished
verification. Forwarding after rejection is outside that deadline.

The result is `TargetOutcome::Authenticated { stream, info }` or
`TargetOutcome::Forwarded { client_to_target, target_to_client, reason }`. The
latter has already relayed the connection to completion and must never be passed
to an authenticated protocol dispatcher. Byte counts include observed prefixes.
The target connection closes after successful local Finished verification, or
when the authenticated handshake fails. Application data and client Finished are
never copied to the target after committing to the local handshake.

The target receives the exact consumed client records. For admitted clients, the
server accepts a TLS 1.3 ServerHello with either supported key exchange, matching
session ID, and an allowed/offered cipher suite. It keeps the target's random,
session echo, extension order, and other ServerHello bytes, replacing only its
ephemeral key share. It requires the exact compatibility CCS record. As in the
pinned Go implementation, a first encrypted record larger than 512 wire bytes is
treated as a coalesced flight; otherwise four encrypted records are interpreted
as EE, Certificate, CertificateVerify, and Finished. Local authenticated messages
are padded to those wire sizes. Insufficient space or malformed/unsupported
profiles fall back before any locally generated server bytes are sent. The
temporary certificate is locally generated, not copied from the target. Target
ALPN is encrypted and is not inspected; the mirrored profile sends empty
EncryptedExtensions and no ALPN, matching the pinned Go path.

Consumed client/target bytes are captured separately up to
`max_handshake_bytes` per direction. Cancellation during partial reads or writes
retains the consumed bytes and transmitted offset. Prefix replay uses concurrent
bidirectional forwarding, including half-closes, so a backpressured peer cannot
deadlock sequential prefix replay. A malformed client, failed admission, unknown
target profile, capture limit, or observation timeout can choose fallback. Once
the locally generated flight is committed, later failures only close the
connection; they can never select fallback or expose an authenticated stream.

Unlike Go's concurrent `MirrorConn`, this implementation buffers the inspected
client prefix before forwarding it and observes the target afterward. It does
not reproduce Go's early-target-response scheduling race or packet timing. Both
paths preserve stream bytes, not TCP packet boundaries. Target flight ciphertext
is opaque profiling input, not proof of the target's identity.

## Deliberate scope

This is not complete Go camouflage parity. Global target probes, cached
post-handshake traffic shapes, NewSessionTicket-sized dummy records, target
certificate copying, server ML-DSA certificate signing, PSK/resumption, early
data, HelloRetryRequest, and client certificates are absent. Unsupported
handshake profiles are rejected by standalone acceptance or forwarded by the
target entry point before any local server flight is committed.

There are no built-in target dialer settings, PROXY protocol encoder, master-key
logger, or fallback rate limiter. An integrating configuration layer must reject
nonzero `xver`, `limitFallbackUpload`, `limitFallbackDownload`, `mldsa65Seed`, and
key-log requests unless the corresponding behavior is explicitly supplied by
the caller. A caller can send a PROXY header on its target stream before calling
this API; this module neither generates nor verifies it. Configured non-TCP
target transports similarly require caller-owned adapters. The facade/runtime
is intentionally outside this module's implementation scope.

## Validation

The native test module covers all three suites and both groups, including
hybrid-only client authentication, large application writes, and both half-closes.
It also covers policy rejection before a response, malformed/truncated offers,
duplicate or incorrect key shares, invalid ML-KEM keys, low-order X25519, the
certificate marker, fragmented ClientHello/Finished, bad Finished, premature
application records, client-sent tickets, timeout, and cancellation.
Target tests cover all six suite/group combinations with both supported record
layouts, exact ServerHello preservation, padded record sizes, fallback byte
identity and half-closes, insufficient padding, capture limits, and cancellation
during partial target reads/writes. They also ensure forwarding can outlive the
handshake timeout and that a bad Finished cannot fall back after a forged flight.

`handshake/server/interop/main.go` is a test-only executable using the repository's
pinned Go REALITY/uTLS client. From the repository root, build it with:

```powershell
go build -o reality-go-client.exe ./rust/xray-core/src/transport/reality/handshake/server/interop
$env:XRAY_REALITY_GO_CLIENT = (Resolve-Path ./reality-go-client.exe)
cargo test -p xray-core pinned_go_reality_client_interoperability -- --ignored --nocapture
cargo test -p xray-core pinned_go_target_and_reality_client_interoperability -- --ignored --nocapture
```

The first ignored test exercises all six suite/group combinations over loopback
TCP. The second uses both a genuine Go TLS target and a Go REALITY/uTLS client
around the native target-mirroring server for both groups. The same Go executable
has a `target hybrid|x25519` mode for that harness.
Normal Rust tests never build or execute Go. Implementation was formatted by its
worker; the integration owner runs compilation, native tests, and the optional
interop test. This note does not claim an interop pass before that run completes.
