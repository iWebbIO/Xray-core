# REALITY port: implemented primitives and integration requirements

Status: native authentication primitives implemented; a functioning REALITY TLS
transport is **not** implemented by this module. The module must not cause
`security: reality` to be accepted by an ordinary TLS transport. TLS interoperability
with the pinned Go reference has not been demonstrated.

## Pinned protocol evidence

The repository pins `github.com/xtls/reality` to
`v0.0.0-20260908062103-8cdf7bf9c7f0` in `go.mod`. This matters: descriptions of older
REALITY releases do not capture the current key-share requirement.

Primary implementation sources:

- This repository's `transport/internet/reality/reality.go`, `UClient` and
  `UConn.VerifyPeerCertificate`.
- This repository's `infra/conf/transport_security.go`, `REALITYConfig.Build`.
- <https://github.com/XTLS/REALITY/blob/8cdf7bf9c7f0/tls.go>, `Server`, particularly
  the key-share selection, session ID authentication and policy checks.
- <https://github.com/XTLS/REALITY/blob/8cdf7bf9c7f0/handshake_messages.go>,
  `clientHelloMsg.unmarshal`.
- <https://github.com/XTLS/REALITY/blob/8cdf7bf9c7f0/handshake_server_tls13.go>,
  `serverHandshakeStateTLS13.handshake` and the temporary certificate construction.

Implemented in `rust/xray-core/src/transport/reality.rs`:

1. Decode a complete TLS ClientHello handshake message. Its four-byte handshake
   header is included; TLS record headers are excluded. Reject inconsistent
   lengths, duplicated extensions, wrong session ID size, invalid SNI encoding,
   and lack of TLS 1.3 support.
2. Match the pinned server's authentication key-share selection. A correctly
   sized `X25519MLKEM768` share (group `0x11ec`, 1184-byte ML-KEM public key followed
   by 32-byte X25519 public key) must precede optional standalone X25519 (`0x001d`).
   Prefer the standalone key when present; otherwise use the hybrid's X25519 tail.
   The reference stops selecting after the standalone share, while the TLS parser
   still validates the encoding of later shares. The Rust implementation preserves
   that distinction. It does not validate the ML-KEM public key mathematically.
3. X25519 ECDH with the static server key, rejecting all-zero shared secrets;
   HKDF-SHA256 with `ClientHello.random[0..20]` as salt, `REALITY` as info, and
   a 32-byte output.
4. AES-256-GCM with nonce `ClientHello.random[20..32]`. The plaintext is version
   (3 bytes), reserved (1 byte), Unix seconds (4 bytes, big endian), short ID
   (8 bytes). The 16-byte plaintext plus 16-byte tag occupies the 32-byte legacy
   session ID. AAD is the entire handshake message with all session ID bytes zero.
   The reserved byte is authenticated but ignored by policy, as in Go.
5. Server-name exact matching, inclusive three-byte version bounds, absolute
   timestamp difference with millisecond/nanosecond precision and the zero-duration
   disable behavior, and allowed short IDs. Short IDs accept 0–16 hexadecimal
   digits with even length and are right-padded with zeroes.
6. HMAC-SHA512 over the temporary certificate's Ed25519 public key, with
   constant-time verification. This HMAC occupies the X.509 signature field;
   it does **not** replace the TLS CertificateVerify proof of possession.
7. The optional ML-DSA-65 message is HMAC-SHA512 over
   `ed25519_public_key || original_client_hello || original_server_hello`, using
   the same auth key. It is not HMAC over the certificate marker. Only this
   message construction is implemented; ML-DSA signing/verification and
   certificate extension parsing remain to be integrated.

Secrets are held in `Zeroizing` storage and are not exposed by `Debug`. The
high-level client helper checks that its ephemeral private key actually matches
the ClientHello authentication share before mutation. Parsing/authentication
failures leave the caller's ClientHello unchanged.

## Validation and reproducible independent vectors

The module has unit tests for independent HKDF/AES-GCM and HMAC fixtures,
all-byte ClientHello tampering, every truncated prefix, low-order X25519 public
keys, hybrid-only and hybrid-plus-X25519 selection, duplicate/out-of-order shares,
duplicate extensions, TLS version, policy bounds and short ID parsing.

Fixture bytes were independently generated with Python `cryptography 50.0.1`
(OpenSSL-backed X25519/HKDF/AESGCM) and the standard `hmac` module, rather than
derived from the Rust implementation. The generator was executed successfully.
The Rust tests are intended for the parent's workspace cargo test run; the
implementation subagent did not run cargo because of the shared disk constraint.

Fixture inputs:

- RFC 7748 Alice private key
  `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`.
- RFC 7748 Bob private key
  `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`.
- Client random: consecutive bytes `00` through `1f`.
- Client version: `26.3.27`, reserved byte `00`, timestamp `1700000000`,
  short ID `0102030405060708`.
- SNI `example.com`; cipher suites `1301`, `1302`, `1303`; compression `00`.
- Extensions in order: SNI, supported_versions (`0304`), key_share, and unknown
  extension `aaaa` containing `1234`.
- Hybrid share: 1184 synthetic bytes `a5`, then 32 bytes `5a`; standalone X25519
  share: Alice's public key. The hybrid bytes are deliberately synthetic: this
  fixture validates authentication, not a complete ML-KEM/TLS handshake.

Independent outputs:

| Item | Hex |
| --- | --- |
| Authentication key | `68e5a4d6fbfc0f93477d737fbdd45bd5f81578fbd172327b6db8e963e2ba4a3c` |
| SHA-256 of 1378-byte zero-session-ID ClientHello | `366e34753d8cdd30f91622574ff728c257bc0a4cbd215220d9fc6ae545380198` |
| Encrypted session ID | `161ddad168daf221363144ba2eb8cd580d20b586c293ae5bee3970271ed3b7a5` |
| SHA-256 of authenticated ClientHello | `6bd2402b7f615b517143ca7d047c425dd1e36a886b2a4ccd0d94134a95345acb` |

The essential independent derivation is:

```python
shared = alice.exchange(bob.public_key())
key = HKDF(algorithm=hashes.SHA256(), length=32,
           salt=random[:20], info=b"REALITY").derive(shared)
session_id = AESGCM(key).encrypt(random[20:], identity, zero_sid_client_hello)
marker = hmac.digest(key, ed25519_public_key, "sha512")
mldsa_message = hmac.digest(
    key, ed25519_public_key + authenticated_client_hello + server_hello, "sha512")
```

## Exact TLS integration gaps

A TLS client needs a callback after serializing the complete ClientHello with a
32-byte zero session ID and **before** adding that message to the TLS transcript.
That callback needs the X25519 ECDH result against a second, static server public
key, while retaining the ephemeral key for the TLS handshake. The callback can
use `RealityAuthKey::from_shared_secret` and `seal_client_hello` from this module.
Changing a Rustls-generated ClientHello only on the socket wire is insufficient:
the two TLS peers would hash different transcripts and fail Finished verification.

The key-exchange provider must emit a real X25519MLKEM768 share before optional
X25519. The authentication key must correspond to the share selected by the
reference. Synthetic hybrid bytes from the test fixture must never be emitted
as a functioning TLS key share. Existing browser fingerprint support and ECH,
resumption, HelloRetryRequest and extension ordering interactions need auditing.

The certificate verifier must parse the Ed25519 public key and X.509 signature,
verify the marker, enforce configured ML-DSA-65 verification over the original
hello messages, and still verify TLS CertificateVerify and Finished. Merely
disabling certificate verification does not implement REALITY. A valid public
WebPKI certificate is the reference client's camouflage path, not authenticated
proxy success. Its HTTP/2 spider behavior and configured delays remain unported.

The REALITY server requires more than an ordinary TLS server certificate resolver:
it simultaneously connects to the configured camouflage target, mirrors the
original client traffic until authentication, parses the target's ServerHello,
replaces key-share material, derives actual handshake keys, signs its generated
Ed25519 certificate, matches target handshake record sizes, checks client
Finished, and handles post-handshake camouflage records. It also forwards
unauthenticated traffic, honors PROXY protocol and upload/download fallback rate
limits, and preserves shutdown/half-close behavior. None of those network paths
are implemented by the authentication module.

Required interoperability gates before claiming transport support:

- Rust client against the pinned Go REALITY server, including application data,
  hybrid-only and hybrid-plus-X25519 variants, rejected credentials, and configured
  ML-DSA-65 verification.
- Pinned Go client against Rust server, including target mirroring, authentication,
  server CertificateVerify and both Finished messages, bidirectional payload,
  camouflage fallback, and connection shutdown.
- Negative peer cases must fail authentication without releasing proxy payload
  and must follow the configured camouflage path where the reference does so.

## Native Rust adapter research, September 19, 2026

An inspected client-hook fork is
<https://github.com/eycorsican/reality-rustls/commit/23d1c82a7fe33d98949833888f824d7638604fa7>,
rebased on Rustls 0.23.36. Its six-file patch adds:

- `ClientConfig.reality_callback` and exported `RealityCallback` in
  `rustls/src/client/client_conn.rs`.
- In `rustls/src/client/hs.rs`, a zeroed 32-byte session ID and callback receiving
  the serialized hello before transcript construction.
- `ActiveKeyExchange.extract_reality_key` in `rustls/src/crypto/mod.rs`.

This is a useful **hook design**, not a turnkey implementation. The extraction
method defaults to `None`; the commit adds no provider implementation. It also
adds no server hooks, browser fingerprint machinery, target mirroring, or ML-DSA
verification. Adopting it requires a reviewed custom hybrid provider, checking
session-ID state used when validating the ServerHello echo, and interoperability
tests. It should not be selected blindly as a finished dependency.

A second inspected fork is **incompatible with the pinned wire protocol**:
<https://github.com/undead-undead/rustls-reality/commit/cdae8d922a94ef8896df21da1eb13e6461315783>.
Its `rustls/src/reality.rs::verify_client` compares the first eight session-ID
bytes against HMAC-SHA256(auth key, client random), and its `inject_auth` writes
an HMAC into `server_random[20..32]`. Those operations are not the pinned
AES-GCM session-ID / HMAC-SHA512 certificate scheme above. The repository's
description alone is not interoperability evidence.

Recommended next implementation step: introduce audited pre-transcript TLS client
hooks and a provider with genuine X25519MLKEM768 support, then exercise the current
native primitives against the pinned Go server. Treat the server's target-mirroring
TLS record engine as a separate substantial port. No TLS fork or dependency was
added as part of this module.
