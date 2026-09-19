# VLESS encryption and Vision building blocks

This bounded followup adds `xray-core/src/protocol/vless_security.rs` and its
`derive.rs`, `encryption.rs`, and `vision.rs` submodules. It does not replace or
modify the existing base VLESS header implementation.

Sources are this checkout's `proxy/vless/encryption/{common,xor,client,server}.go`,
`proxy/proxy.go`, and pinned `lukechampine.com/blake3 v1.4.1`. The key exchange was
read to establish record contexts, nonce usage, header-mask skips, and remaining
scope; a complete key exchange is not implemented here.

## Encryption primitives

`derive_key(context: &[u8], material: &[u8]) -> [u8; 32]` implements standard
BLAKE3 derive-key mode using binary contexts. This distinction is required:
Go converts IVs, key-exchange bytes, and entire encrypted rekey records to a
string without UTF-8 validation. Rust's normal `blake3::derive_key(&str, ...)`
cannot represent all these contexts. Encoding them as hex/text would change
every derived key. The local one-shot implementation follows standard BLAKE3
compression/tree rules with a logarithmic bounded tree stack; it is not a new
KDF design. Tests compare against the Rust blake3 crate at block/chunk/tree
boundaries as well as independent binary-context vectors.

`encryption::SessionAead` derives AES-256-GCM or ChaCha20-Poly1305 keys. Implicit
nonces start at zero and increment as a big-endian 96-bit integer *before* each
operation. Explicit-nonce operations support the source key exchange's reserved
MAX_NONCE operation and do not change the implicit counter. Callers must ensure
nonce uniqueness and must not mix directions or unrelated transcripts. Any
implicit- or explicit-nonce authentication failure poisons the object.

`RecordCipher::{seal_record,seal_records,open_record}` implements the pinned
`17 03 03 length16be` record header, authenticates the five-byte header as AAD,
emits up to 8192 plaintext bytes per record, and accepts encrypted body sizes
17 through 16640 inclusive. Empty writes generate no records. The special
nonce-wrap record uses nonce zero under the old key, then derives a new AEAD
using the complete header+ciphertext record as context and the united key as
material. The receiver only installs the new key after successful verification.
Record authentication/framing failures are terminal.

`RecordDecoder::{push,finish}` incrementally accepts arbitrary stream splits,
buffers at most one bounded encrypted record, returns only authenticated
plaintext records, and detects truncated EOF. It does not guess handshake
contexts or consume handshake padding/tickets.

`HeaderMask::{new,apply,finish}` implements `XorConn` header-only AES-256-CTR
transformation in either direction. Its key is derived with context `VLESS`;
the 128-bit initial counter is the source IV. The configured initial handshake
skip and all record payload bytes leave CTR position unchanged. Arbitrarily
split five-byte headers are handled consistently. Invalid headers and truncated
EOF fail closed rather than continuing with the Go helper's ignored parse error.

## Vision primitives

`vision::Encoder` emits the UUID exactly once followed by command/content-length/
padding-length headers, content, and padding. Commands are Continue=0, End=1,
Direct=2. The encoder enforces the pinned 8192-byte buffer budget, including the
source's always-reserved 21-byte overhead. It supports explicit padding fixtures
and the default source random-length policy `[900, 500, 900, 256]`, including
half-open draw ranges and remaining-buffer clamping. Generated padding contents
are random; padding bytes carry no protocol meaning.

`vision::Decoder` is a strict framed decoder for a direction which the caller
has already selected as Vision. It handles split UUIDs, headers, bodies, and
padding. `DecodedChunk` returns content, the exact input byte count consumed,
and an End/Direct transition only after the complete padding block is consumed.
Bytes following that boundary are untouched. Calls after the transition fail
instead of accidentally processing a new transport layer as another frame.
UUID/command/length failures and truncated EOF are rejected.

The decoder does not reproduce Go's heuristic pass-through of initial buffers
without a matching UUID. It also rejects oversized declarations that the source
writer does not emit. It is a building block, not a drop-in replacement for the
full `VisionReader`.

`complete_tls_application_records` checks nonempty concatenations of complete
TLS application records. `inspect_server_hello` parses a complete TLS handshake
record, ServerHello lengths, session ID, cipher suite, and supported_versions
extension. It reports TLS 1.3 eligibility for ciphers 0x1301 through 0x1304 and
excludes 0x1305, as Vision does. It parses actual extension boundaries rather than
matching the supported_versions byte pattern inside unrelated extension data.
It does not buffer split TLS records or implement the Go eight-packet inspection
budget. A reported eligible cipher is not authorization to bypass TLS.

## Integration and remaining work

The lead should add only `pub mod vless_security;` to the protocol registry.
Existing dependencies suffice: `aes-gcm` (including its AES reexport),
`chacha20poly1305`, `rand` 0.8, `subtle`, and `zeroize`; tests use the existing
`blake3` crate. There is no additional ML-KEM dependency or overlap with the
REALITY worker's key-exchange implementation.

Not implemented:

- Native VLESS ML-KEM-768 + X25519 hybrid handshake, NFS relay chain negotiation,
  server/client hello assembly, encrypted tickets, ticket lifetime/replay cache,
  0-RTT resumption, handshake padding schedules, and AES capability negotiation.
- Automatic selection of client/server directional contexts or united keys.
  These must come from a successfully authenticated handshake; callers must not
  reuse session contexts/keys/nonces across connections.
- Flow-addon/account/config/runtime changes, base VLESS header changes, and a
  complete Vision reader/writer traffic state machine.
- Automatic End/Direct decisions, outer TLS buffer draining, changing to a raw
  socket, direct-copy/splice support, and traffic statistics. The runtime must
  explicitly decide when and how to act on a transition; these modules never
  silently change the underlying encryption layer.

## Validation

Individual rustfmt passed. A standalone dependency-free Rust KDF probe compiled
into a temporary directory verified four independent ASCII/binary context
vectors. The independent Python BLAKE3 reference used a recursive tree strategy
and was checked against the optimized blake3 Python extension at 13 boundaries;
Python cryptography produced fixed AES-GCM, ChaCha20-Poly1305, and AES-CTR vectors.

Inline Rust tests cover these vectors, full-header/body/tag tampering, truncated
records, wrong contexts, implicit nonce ordering, wrap-record rekeying, stream
splits, header-only masking, Vision framing and transition boundaries, invalid
UUID/commands/lengths, truncated EOF, padding policy, cipher eligibility, and
false supported_versions byte patterns. No Cargo build/test/check was run by
this worker. Combined Rust compilation/tests remain the lead's responsibility;
there has not been a full interoperability run against a Go VLESS peer.
