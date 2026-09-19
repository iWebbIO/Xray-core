# Native CLI utility migration

`rust/xray/src/commands.rs` exposes the Clap `Subcommand` enum `Command` and
`execute(Command) -> anyhow::Result<()>`. It can be flattened into the main
CLI enum. `execute_to` supports output capture without redirecting process
stdout. The parent executable owns Go-style single-dash flag normalization.

Implemented commands:

- `mlkem768 [-i seed]`: RustCrypto ML-KEM-768 key generation from the exact
  64-byte `(d, z)` seed format used by Go `crypto/mlkem`; outputs `Seed`,
  `Client`, and the BLAKE3 `Hash32` in unpadded URL-safe base64.
- `mldsa65 [-i seed]`: RustCrypto FIPS 204 ML-DSA-65 key generation from a
  32-byte seed; outputs `Seed` and `Verify` in the source format.
- `vlessenc`: both source X25519 and ML-KEM-768 authentication alternatives,
  source key clamping and complete source configuration strings.
- `tls ech`: X25519 ECH key/config generation, the source's nine HPKE suite
  combinations, source binary key-set format, restoration of one or multiple
  sets, and base64 or 64-column PEM output. Generating these assets does not
  imply that the Rust transport supports ECH handshakes.
- `tls cert`: rcgen ECDSA P-256 self-signed certificates, 128-bit random
  serials, one-hour backdating, 90-day default lifetime, repeated DNS SANs,
  CA flag, organization/common name, source key usages, Go duration syntax,
  JSON arrays and `.crt` / `.key` files. The source labels PKCS#8 private keys
  `RSA PRIVATE KEY` despite generating ECDSA keys; the utility retains this
  output convention for compatibility.
- `tls hash`: complete-certificate SHA-256, PEM and concatenated DER input,
  leaf/CA labels and aligned columns. This hashes the entire DER certificate,
  not SubjectPublicKeyInfo.
- `tls ping`: real rustls TLS 1.2/1.3 connections, ALPN, no-SNI untrusted
  inspection followed by authenticated SNI inspection against native system
  roots, negotiated group/version and source certificate detail fields.
  The untrusted probe still verifies handshake signatures.

Verification is in module tests: complete Go ML-KEM/ML-DSA stdout fixtures,
independent X25519/ECH encoding with Go restoration, fixed Go certificate
hash, certificate extension/profile parsing, signed/fractional duration
edges, malformed/truncated inputs, Clap flags, and local TLS handshakes
covering absent SNI, accepted trust and rejected trust. No runtime command
invokes Go or an external crypto executable.

Remaining compatibility boundaries:

- TLS ping uses the ring rustls provider rather than Go/uTLS's evolving
  browser ClientHello profile. This provider currently does not offer
  X25519MLKEM768, so it correctly reports a classical negotiated group. A
  shared native hybrid TLS provider and browser handshake implementation
  are required for complete parity.
- System trust handling goes through `rustls-native-certs` and webpki; OS
  platform verifier and Go verification-policy differences remain possible.
- Invalid target-port diagnostics, certificate parser diagnostics and
  operating-system IO diagnostics follow Rust library wording. The source's
  success-status stdout behavior is retained for invalid seed length and
  certificate-hash failures.
- ECH public names longer than 255 bytes fail explicitly. Go truncates the
  encoded one-byte length while emitting all name bytes, producing malformed
  configurations in this case. ECH key restoration intentionally performs
  the same structural length checks as the source, without asserting that
  unknown versions or private keys are accepted by a TLS implementation.
- rcgen is a standards-based certificate generator. Extension/ASN.1 ordering,
  random ECDSA signatures and parser acceptance of malformed PEM/DER are not
  promised to match Go byte-for-byte. The generated certificate fields,
  extension semantics, key algorithm and output structure are covered.

These utilities do not establish full CLI or transport feature parity for
the entire repository; run/config/API commands belong to separate modules.
