# Native TLS transport

`rust/xray-core/src/transport/tls.rs` implements TLS over the common `BoxStream`
interface. `TlsSettings` deserializes Xray TLS JSON with unknown-field rejection.
Call `build_client_config` / `build_server_config` at configuration compilation,
or retain `TlsClient` / `TlsServer` wrappers and call their asynchronous stream
methods. The caller owns connection and handshake timeouts.

Implemented:

- TLS 1.2 and TLS 1.3, with explicit minimum/maximum version validation.
- Certificate chain, validity, hostname/IP SAN, and handshake signature
  verification through rustls. `serverName` overrides the destination name.
- Native operating-system roots, explicit `usage: verify` certificates, and
  `disableSystemRoot`. Mozilla WebPKI roots are available on targets without
  Unix/Windows native stores. An empty/failed native store never silently falls
  back to a larger public trust store.
- PEM certificate chains and unencrypted PKCS#1, PKCS#8, or SEC1 private keys,
  either inline arrays or files. Key/certificate mismatches are rejected before
  accepting connections. Debug output omits inline private-key contents.
- Multiple inbound identities, certificate SAN selection for SNI,
  `rejectUnknownSni`, and first usable certificate fallback when allowed.
- One outbound client identity for servers requesting client authentication.
- Hourly lazy certificate reload for file-based identities unless
  `oneTimeLoading` is true; reloads retain the last valid certificate/key pair
  on malformed or partially replaced files. Reload reads happen on the first
  handshake after the hour elapses. Verification roots are configuration-time
  snapshots.
- ALPN, including Xray's `h2`, `http/1.1` default and array/comma-string input.
- TLS session resumption controlled by `enableSessionResumption`.
- Ring-supported TLS 1.2 cipher selection and X25519/P-256/P-384 preferences.
  TLS 1.3 cipher selection follows rustls defaults, as Go's `CipherSuites`
  setting applies only to TLS 1.2.

Not complete parity: browser/uTLS fingerprints, REALITY, TLS 1.0/1.1, legacy
ciphers, post-quantum groups, certificate pinning, alternate verification names,
ECH, MITM values, master key logging, automatic CA issuance, OCSP stapling, and
multiple outbound client identities are explicit configuration errors. Native
name selection uses modern SAN verification; legacy common-name-only identity
matching is not implemented. A transport adapter needing metadata such as
negotiated ALPN should use the returned rustls configuration directly instead
of erasing the concrete stream through `BoxStream`.

Dependencies: `tokio-rustls = 0.26` with default features disabled and `ring`,
`tls12` enabled; `rustls-pemfile = 2`; `rustls-native-certs = 0.8`;
`webpki-roots = 1`; test dependency `rcgen = 0.14`. No global crypto provider is
installed. The upstream tokio-rustls 0.26.4 manifest specifies Rust 1.71 and
rustls 0.23.27 or newer. Its own tests use rcgen 0.14 and webpki-roots 1.
The workspace requires Rust 1.88.

The module's tests cover both TLS versions and data exchange, ALPN negotiation,
trust and hostname rejection, ALPN/version mismatch, SNI certificate selection,
outbound client-certificate authentication, key mismatch, configuration
rejection, IP names, reload rollback, and one-time loading. The implementing
agent ran `rustfmt --edition 2024 --check`; Cargo execution and integration
validation belong to the parent migration task because builds are centralized.

Primary API references:

- https://github.com/rustls/tokio-rustls/blob/v/0.26.4/Cargo.toml
- https://docs.rs/rustls/0.23.35/rustls/struct.ClientConfig.html
- https://docs.rs/rustls/0.23.35/rustls/struct.ServerConfig.html
- https://docs.rs/rustls-native-certs/0.8.2/rustls_native_certs/
- https://github.com/rustls/rustls/blob/v/0.23.35/rustls/src/webpki/verify.rs

Go comparison sources: `infra/conf/transport_security.go`,
`transport/internet/tls/config.go`, and platform trust-store implementations in
that directory.
