# Native VLESS encrypted handshake

The new `protocol::vless_security::handshake` module implements the pinned
`proxy/vless/encryption/client.go` and `server.go` **native, 1-RTT**
wire exchange. It performs real RustCrypto ML-KEM-768 and X25519 operations; it
does not invoke Go or another process at runtime.

Supported configuration profiles:

- Client: `mlkem768x25519plus.native.1rtt.<base64url-public-key>`.
- Server: `mlkem768x25519plus.native.0s.<base64url-private-key>` (`0` and `0-0s`
  also express the supported zero-lifetime profile).
- Both forms accept an ordered chain of one to eight keys, separated by dots.
  Keys can mix X25519 and ML-KEM-768. Raw plural-key builders are available as
  `from_public_keys` / `from_private_keys`, and `public_keys_bytes` returns the
  complete server chain. The existing singular public-key accessor returns the
  first key for compatibility; use the plural accessor for multi-key chains.
- Configured public keys are 32-byte X25519 or 1184-byte ML-KEM-768 values.
  Server private keys are 32-byte X25519 values or the Go-compatible 64-byte
  ML-KEM seed. Malformed ML-KEM public encodings are rejected.
- The PFS exchange always combines an ephemeral ML-KEM-768 secret with an
  ephemeral X25519 secret. The 96-byte united key is `ML-KEM || X25519 || NFS`.
- Clients can select AES-256-GCM or ChaCha20-Poly1305. Servers authenticate the
  length using AES first, then a fresh ChaCha state, matching the pinned peer.
- Padding is authenticated and bounded by the on-wire u16 ciphertext length.
  Generated padding defaults to 77 plaintext bytes (111 total padding bytes).
  Builders support other fixed lengths. Padding bytes are zero before AEAD, as
  in the pinned implementation; no configurable timing/fragmentation is added.

The parser returns `Unsupported` for XOR disguises, chains exceeding eight keys, 0-RTT,
nonzero server ticket lifetimes, and configured padding schedules. It does not
silently reinterpret these settings. A client authenticates tickets offered by
a Go server but does not retain or reuse them; this server advertises zero
lifetime. Extended future hybrid-share layouts are rejected explicitly.

Native relay links match the pinned source: each intermediate NFS secret feeds
AES-256-CTR with the BLAKE3 `VLESS` context and the connection IV. Its first 32
keystream bytes mask the next configured public-key BLAKE3 hash; the next 32 mask
the following relay's first 32 bytes. Server decoding preserves this continuous
CTR position and verifies every next-key hash before proceeding. The final NFS
secret authenticates the ordinary hybrid flight. Prefix allocation is bounded
by eight ML-KEM shares plus seven hash links (8944 bytes including the IV).

Received NFS X25519 shares must have a zero high bit and represent a field element
strictly below `2^255 - 19`. This intentionally tightens the pinned Go high-bit
check: X25519's reduction accepts `9` and `p+9` as the same input. Generated native
shares are canonical. This input rule applies to every relay and is separate
from inner VLESS account validation. Canonical encodings can also derive equal
secrets (for example, `u` and `1/u`), so canonical-field checks alone cannot
establish replay identity.

## Integration

`ClientConfig::parse` and `ServerConfig::parse` accept the full configuration
strings. Raw-key builders are also available. `server_handshake(stream,
&server_config)` and `client_handshake(stream, &client_config)` own the transport
and return `EncryptedStream<S>`, which implements Tokio `AsyncRead`/`AsyncWrite`.
The caller supplies connection deadlines. A handshake failure drops the owned
transport; no plaintext fallback is attempted.

Keep one `ServerConfig` shared across inbound connections. Its additional
process-local authenticated-flight replay cache defaults to 4096 entries and 180 seconds;
builders can change both nonzero limits. Complete authenticated flights with
valid hybrid keys are recorded. Invalid, incomplete, or tampered flights cannot
fill this cache. The cache uses a monotonic clock and fails closed at capacity.
Replay identity is a domain-separated hash of the IV, effective final NFS secret,
and every authenticated ciphertext record, including the initial length record.
Raw relay-prefix bytes are excluded: equivalent X25519 shares at any relay hop
must share one replay identity when the authenticated flight is unchanged.
This bounds 1-RTT replay detection; it does not implement ticket history or
distributed persistence.

The default ceiling is 4096 accepted, distinct encrypted hellos within the
180-second retention window: the next hello fails while all slots remain live.
Reservation precedes inner VLESS user authentication. A later RNG/output error,
connection drop, or inner-account authentication failure does not remove that
entry. Production callers must size `with_replay_limits` alongside an enforced
hello-admission budget; the default is not an unlimited inbound admission rate.
Live entries are retained rather than weakening replay rejection at saturation.

The channel exchange establishes server-key possession. Runtime code must still
authenticate the inner VLESS request/user and apply routing/account policy.
Vision, TLS direct-I/O switching, ticket stores, and listener/config dispatch
remain separate integration work.

`RecordCipher::from_aead` preserves handshake state: server outbound/client
inbound consume ticket nonce 1, padding-length nonce 2, and padding nonce 3, so
the first server application record uses nonce 4. The client application
direction starts at nonce 1. The client verifies the explicit all-FF-nonce NFS
server-flight tag before ML-KEM decapsulation (the pinned Go client ignores the
error returned by that particular `Open` call).

The stream buffers one record per direction, authenticates before releasing
plaintext, preserves partial I/O across Pending, and rejects partial-record EOF.
Reads also drive pending writes without blocking incoming progress behind a
backpressured write. Authentication or framing failure poisons the stream.

## Validation

Unit tests cover both configured key types and both AEADs; exact nonce handoff;
configuration rejection; noncanonical/low-order keys; a complete client-flight
truncation sweep; tampering at each field/tag boundary; response authentication;
replay/capacity/expiry; preservation of following stream bytes; and encrypted
records over a 37-byte Tokio duplex transport. Stream tests include simultaneous
write-then-read without an explicit flush, large transfers, tampering, and EOF
inside a record.

Relay tests add mixed-key chains, the eight-key boundary, key-order mismatch,
every relay-prefix byte mutation and prefix truncation, continuous CTR position
including numeric carry, noncanonical-field rejection, and canonical reciprocal
aliases on valid authenticated handshakes in both algorithms and every hop of a
three-key chain. The independent `relay_aes.json` fixture covers
a two-X25519-key native chain using OpenSSL CTR, ML-KEM, X25519, and AES-GCM.

The checked-in `handshake/fixtures/native_{aes,chacha}.json` fixtures were
generated independently with Python cryptography 50/OpenSSL ML-KEM-768, X25519,
AES-GCM, and ChaCha20-Poly1305. A separate recursive BLAKE3 implementation supplies
binary contexts and checks hash/text-context cases against the optimized Python
blake3 package. Tests compare the complete deterministic client flight, consume
the independent server flight, and compare independent first application
records in both directions. The accompanying `fixtures/generate.py` documents
the oracle and can regenerate the fixtures; its OpenSSL encapsulation randomness
means regenerated server flights differ. It is never used by Rust at runtime or
build time.

Shared Cargo builds and test execution are performed by the migration lead.
