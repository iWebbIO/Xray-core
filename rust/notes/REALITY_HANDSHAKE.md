# Native REALITY TLS client

The new `transport::reality::handshake` module implements an authenticated native
TLS 1.3 client. It is a separate, explicit ClientHello profile. It does not claim
to reproduce a Chrome, Firefox, Safari, randomized, or other browser fingerprint.
It is not a Rust REALITY server, and does not implement the Go client's HTTP/2
spider camouflage after an unauthenticated public certificate.

The implementation uses the exact server protocol pinned by this repository:
`github.com/xtls/reality v0.0.0-20260908062103-8cdf7bf9c7f0`.

## Integration API

```rust
let config = ClientConfig::new(
    server_name,
    server_public_key, // [u8; 32], after raw URL-safe Base64 decoding
    short_id,          // [u8; 8], using reality::decode_short_id
    client_version,    // the actual three-byte Xray version, not Cargo semver
);
let (stream, information) = handshake::client(input_box_stream, config).await?;
// Or handshake::client_boxed(input_box_stream, config).await?
```

`client` returns only after server authentication and after writing the client's
Finished. `ConnectionInfo` reports the negotiated cipher suite, key-share group,
and optional ALPN protocol. `ClientStream` implements Tokio `AsyncRead` and
`AsyncWrite`, including flush and directional shutdown.

Additional explicit native options on `ClientConfig`:

- `alpn`: defaults to `h2`, then `http/1.1`; a selected protocol must have been
  offered. These bytes describe the TLS connection and do not themselves insert
  an HTTP transport.
- `hybrid_only`: false advertises a genuine `X25519MLKEM768` share followed by a
  separate X25519 share; true advertises only the hybrid share.
- `mldsa65_verify`: an optional 1952-byte verification key. Empty is disabled,
  matching the Go client's zero-length behavior.
- `handshake_timeout`: defaults to 15 seconds and must be positive.
- `max_handshake_bytes`: defaults to 1 MiB per buffered handshake message, with
  accepted values from 4096 bytes through 4 MiB.

These options must not be confused with pre-existing Go JSON fields. The parent
owns configuration/runtime integration and should require `fingerprint: native`
explicitly while browser profile support remains absent.

## Implemented security and wire behavior

1. Generate fresh ML-KEM-768 keys from 64 bytes of OS randomness and two distinct
   ephemeral X25519 keys. ML-KEM public bytes precede the hybrid X25519 share.
   The REALITY authentication key uses the standalone share when offered, or
   the hybrid X25519 share when it is the sole choice. No synthetic key shares
   are transmitted.
2. Build a complete TLS 1.3 ClientHello with a zeroed 32-byte session ID. Invoke
   the existing REALITY authenticated-session-ID primitive before hashing or
   sending the hello. The exact authenticated bytes form the TLS transcript.
3. Validate ServerHello framing, version, echoed encrypted session ID, cipher
   suite, offered group, and extension uniqueness. For the hybrid group,
   decapsulate the 1088-byte ML-KEM ciphertext and concatenate its 32-byte secret
   **before** the X25519 secret. Reject all-zero X25519 shared secrets.
4. Perform RFC 8446 HKDF key derivation with SHA-256 or SHA-384 as selected by
   the cipher suite. Support AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
   TLS record sequence numbers are per direction and per traffic secret.
5. Authenticate the REALITY temporary certificate's Ed25519 key using the
   existing HMAC-SHA512 signature marker. An ordinary certificate never becomes
   an authenticated proxy connection. Certificate validity dates and WebPKI
   roots are not substituted for REALITY authentication.
6. When ML-DSA-65 verification is configured, verify the first X.509 extension
   exactly as Go does: FIPS 204 verification with an empty context over
   `HMAC-SHA512(auth_key, ed25519_public_key || original_client_hello ||
   original_server_hello)`. A missing extension, wrong key, noncanonical signature,
   or failed verification rejects the connection. The Ed25519 marker remains
   mandatory.
7. Independently verify TLS CertificateVerify using Ed25519, the standard
   server context string, and the transcript hash. Verify the server Finished
   MAC before deriving application traffic keys and sending the client's
   Finished. No application stream is returned before these checks pass.
8. Parse fragmented/coalesced handshake records within bounded memory. Enforce
   message order, record bounds (including decrypted content type and padding),
   nonempty Alert/Handshake content, supported inner content types, and a finite
   compatibility-CCS allowance. ClientHello records are fragmented at the TLS
   plaintext limit when needed.
9. Process TLS KeyUpdate, reply under the previous write key when requested,
   then change the write secret. Initiate outbound key updates at a conservative
   2^20-record threshold. Bound pending update responses. A KeyUpdate may follow
   other handshake messages or span old-key records, but must end exactly at
   the record boundary where the peer changes keys.
10. Preserve read/write half-close separation. Send close_notify on write
   shutdown and treat EOF without a received close_notify as truncation. Reject
   close_notify or application data that interrupts a buffered handshake fragment.
    Preserve a fatal stream error instead of resuming after authentication or
    transport failure. Pending writes do not prevent polling reads, avoiding a
    full-duplex backpressure deadlock.

The module receives and validates session tickets but does not retain them or
enable resumption/0-RTT. Ephemeral scalar/seed material and derived traffic secrets
use zeroizing storage. The workspace must enable the `ml-kem` `zeroize` feature
so its expanded private key is erased on drop as well.

## Validation

The parent reported these passing on September 19, 2026:

- All 405 default core tests, with the explicit Go interoperability test ignored
  during the normal suite.
- The explicit pinned-Go interoperability test, including hybrid and standalone
  X25519 target negotiation; both hybrid-only and hybrid-plus-standalone client
  profiles; 65,539-byte bidirectional echo; and rejection of a wrong short ID.
- The expanded REALITY validation run: all 33 selected tests passed with no
  skips, including real Go/CIRCL ML-DSA-65 handshakes, wrong-verification-key
  rejection, and the three independent-review regression fixes. The expanded
  run completed in 10.69 seconds.

The native tests include:

- RFC 8448 handshake traffic secrets and AES key/IV vectors.
- Independently produced Python `cryptography`/OpenSSL record vectors for all
  three suites at sequence numbers zero and one.
- Every-byte record tampering, replay rejection, genuine ML-KEM encapsulation/
  decapsulation, low-order X25519 rejection, and both ClientHello auth profiles.
- Every truncated ServerHello prefix, invalid session/group selection, bounded
  fragmented handshake parsing, ordinary-certificate rejection, and independent
  CertificateVerify and Finished failure cases.
- Large payloads with bidirectional half-close, requested KeyUpdate followed by
  application data under changed keys, fragmented old-key KeyUpdate messages,
  coalesced NewSessionTicket/KeyUpdate messages, and unclean EOF rejection.
- Authenticated overlong padding, empty Alert/Handshake records, misplaced
  key-change boundaries, and close_notify interrupting a partial ticket are
  rejected; empty application records remain valid.
- ML-DSA key/message/signature binding and rejection of a missing configured
  certificate proof.

The independent fixture lives in
`rust/xray-core/src/transport/reality/handshake/interop/main.go`. It uses the
repository's pinned Go REALITY implementation and a local TLS 1.3 camouflage
target, listens only on loopback, and exits when its stdin closes. It is test
infrastructure, not a dependency or implementation delegate of the Rust client.

Reproduction from the repository root on Windows:

```powershell
go build -o target/reality-reference-server.exe ./rust/xray-core/src/transport/reality/handshake/interop
$env:XRAY_REALITY_GO_SERVER = (Resolve-Path target/reality-reference-server.exe).Path
cargo test -p xray-core transport::reality::handshake
cargo test -p xray-core pinned_go_reality_server_interoperability -- --ignored --nocapture
```

The fixture/test now additionally exercise a real Go/CIRCL ML-DSA-65 server,
both hybrid client variants with configured verification, and denial for a wrong
ML-DSA verification key. Those additions require rebuilding the Go fixture.
The parent executed the expanded suite successfully, as recorded above.

## Configuration boundaries and remaining parity

Recommended strict client configuration mapping, following
`infra/conf/transport_security.go`:

- Require `fingerprint: native` while native is the only implemented profile.
  A blank fingerprint must not silently claim the default Go/browser behavior.
- Resolve an omitted `serverName` from the outbound destination. The native
  client currently requires a nonempty ASCII name up to 253 bytes; IDNA
  normalization, if desired, belongs before this boundary.
- A nonempty `password` overrides `publicKey`. Decode raw URL-safe Base64 to
  exactly 32 bytes. Use the existing short-ID parser; the empty short ID is
  valid. Decode nonempty `mldsa65Verify` to exactly 1952 bytes.
- Reject unknown options and server-only target/dest, private-key, server-name
  lists, short-ID lists, policy bounds, fallback limits, and ML-DSA seed fields
  in this client path.
- Reject nonempty `spiderX` and `masterKeyLog`, and `show: true` unless their
  actual behavior is implemented by the caller. A successful handshake is
  supported; Go's unauthenticated public-certificate spider path is not.

Still unimplemented here: REALITY server target mirroring/fallback, browser
fingerprint construction, HelloRetryRequest, ECH, client authentication,
resumption/0-RTT, WebPKI fallback and spider concurrency/delay behavior, key log
output, and the wider transport/runtime configuration wiring. The strict
native client fails closed on unsupported handshake behavior; it does not
silently negotiate ordinary TLS or weaken configured authentication.

Primary protocol references: repository-pinned Go REALITY `tls.go`,
`handshake_server_tls13.go`, `conn.go`, and this repository's
`transport/internet/reality/reality.go`; RFC 8446 and RFC 8448; the checked-out
RustCrypto `ml-kem 0.3.2` and `ml-dsa 0.1.1` APIs.
