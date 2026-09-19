# Encrypted DNS transport delivery

`rust/xray-core/src/dns/encrypted.rs` implements real, certificate-verified
HTTP/2 DNS-over-HTTPS and DNS-over-TLS wire exchanges. It is an isolated
transport component for the existing DNS resolver, not a replacement cache,
nameserver selector or complete Xray DNS configuration implementation.

## Source and dependencies

The inspected source files are `app/dns/nameserver.go`, `nameserver_doh.go`,
`nameserver_tcp.go`, `dnscommon.go`, and `common/utils/padding.go`.

The current Go nameserver factory recognizes DoH, cleartext h2c, DoQ, TCP and
classic UDP schemes; **it has no DoT branch**. DoH below carries over the source
HTTP/2/wire behavior. `tls` / `tls+local` are an explicit standards-based DoT
extension, not a claim that Go already accepts those schemes.

The only new direct dependency needed is `h2 = "0.4"` in the workspace and
`h2.workspace = true` in xray-core. This implementation was compiled against
the existing Hyperium h2 0.4.19 artifact. Existing `http`, `bytes`, `rand` 0.8,
`tokio`, `tokio-rustls`, `tokio-util` and `anyhow` supply all other functionality;
tests use the existing `rcgen` dev dependency. TLS uses the shared
`TlsSettings::build_client_config` and `server_name` APIs and inherits their
trust-root, name verification and unsupported-setting checks.

Primary references inspected on 2026-09-19:

- https://github.com/hyperium/h2/blob/master/examples/client.rs
- https://docs.rs/h2/0.4.19/h2/client/struct.Builder.html
- https://crates.io/api/v1/crates/h2
- https://www.rfc-editor.org/rfc/rfc8484
- https://www.rfc-editor.org/rfc/rfc7858

## Public API

The lead registers `pub mod encrypted;` in `dns.rs`; this package does not edit
that shared file, manifests, transport helpers or resolver implementation.

```rust,ignore
let endpoint = EncryptedEndpoint::parse(
    "https+local://resolver.example/dns-query",
)?;
let mut config = EncryptedConfig::new(endpoint);
config.bootstrap = vec!["192.0.2.53".parse()?];
// Optional custom trust roots or verification name belong in config.tls.
let client = EncryptedClient::new(config)?;
let question = Question::new("example.com", RecordType::A)?;
let message = client.query(&question, &cancel_token).await?;
```

The example bootstrap address is documentation-only; it is not a live resolver.

| API | Behavior |
| --- | --- |
| `EncryptedEndpoint::parse(url)` | Parse HTTPS/DoT scheme, routing mode, authority/port and original encoded path/query. |
| `EncryptedConfig::new(endpoint)` | Default to a five-second whole-exchange budget, normal verified TLS, no implicit DNS bootstrap and no client subnet. |
| `EncryptedClient::new(config)` | Validate settings, build trust configuration and enforce protocol ALPN. |
| `query(question, cancel)` | Generate a query and return decoded `wire::Message`, for `+local` endpoints. |
| `exchange(bytes, cancel)` | Exchange an existing wire query and return validated response bytes, for `+local` endpoints. |
| `query_with_dialer` / `exchange_with_dialer` | Same exchange through a caller-provided `FnOnce(DialTarget) -> Future<Result<BoxStream>>`. |
| `dial_target()` | Inspect owned hostname, port, mode and concrete bootstrap socket addresses. |
| `connect_bootstrap(target)` | Explicit sequential TCP dialing of the supplied socket addresses, with no hidden system resolver. |

The runtime dialer returns raw TCP-equivalent bytes; this module performs TLS
over that stream. It can therefore compose over the existing dispatcher or a
proxy transport without weakening certificate validation. Dialing an IP from
`bootstrap` changes neither HTTPS authority nor TLS identity. A numeric URL host
is its own bootstrap; a hostname requires explicit bootstrap addresses or a
runtime dialer. The URL port applies to every bootstrap address.

`https` and `tls` require the dialer APIs. The convenience methods reject these
routed schemes instead of silently creating a direct connection. `https+local`
and `tls+local` permit direct dialing. A configured `serverName` overrides TLS
verification identity while preserving the original URL/HTTP authority. An IP
identity is verified as an IP SAN and does not produce DNS SNI.

The return type is `anyhow::Result`. DNS validation and timeout failures retain
the existing `DnsError` as a downcastable cause; cancellation is `DnsError::Io`
with `ErrorKind::Interrupted`. TLS, HTTP and dialing errors retain their own
context. The caller should feed validated messages into its existing DNS answer,
rcode, CNAME, TTL and cache processing.

## Wire, TLS and resource behavior

- Source-compatible DoH uses HTTP/2 POST with `Accept` and `Content-Type` set to
  `application/dns-message`. TLS must negotiate `h2`; there is no HTTP/1 fallback.
- The original escaped URL path/query is retained. An empty HTTPS URL path is
  `/`, matching net/http behavior; the module does not silently add `/dns-query`.
- DoH wire IDs are zero. For an existing caller query, the original ID is restored
  only after validating ID zero, QR, opcode, one matching question, class/type and
  truncation. DoT preserves caller IDs and uses DNS TCP two-byte length framing.
- Generated DoH queries carry the source's 100–300-byte zero EDNS padding,
  optional /24 IPv4 or /96 IPv6 client subnet and the existing codec's OPT flags.
  The X-Padding header uses source-style Base62 padding and its HPACK length
  correction. Raw exchange preserves caller options and flags apart from DoH ID.
- Response DNS messages are limited to 12–65,535 bytes. DoH headers are limited
  to 16 KiB by h2, body growth is checked incrementally, and any supplied length
  must be in bounds and match the body. DNS TCP framing uses the existing bounded
  exact-read helper. Oversized responses never become successful DNS replies.
- DoH requires status 200 and one DNS-message media type, comparing the media
  type case-insensitively and accepting parameters. Compressed bodies are rejected;
  the request advertises `Accept-Encoding: identity`. Redirects are not followed.
  These content-type, compression, redirect and size checks are stricter than the
  inspected Go helper, which uses net/http defaults and io.ReadAll.
- DoT defaults to port 853, rejects port 53 as required by RFC 7858, and offers
  ALPN `dot`; a server selecting no ALPN is
  accepted for legacy DoT compatibility, but another negotiated protocol is not.
- TLS verification is mandatory. `allowInsecure` and unsupported TLS settings
  are rejected by the shared helper. A TLS failure never triggers a cleartext
  retry or system bootstrap lookup.
- A single timeout includes dialing, TLS, HTTP/2 handshake, headers and body.
  Cancellation is checked before polling the operation. Every exchange owns its
  h2 driver and stream in the same future; cancellation, timeout or future drop
  destroys them. There is no detached background driver task.

## Deliberate remaining gaps

Each query owns one connection. Connection pooling, shared HTTP/2 multiplexing,
idle/keepalive policy and cached TLS session behavior across resolver instances
are not equivalent to the source's long-lived http.Client. Resolver cache,
serve-stale, concurrent A/AAAA merging, address fallback, geodata selection and
configuration wiring remain with the existing resolver/lead.

No uTLS Chrome fingerprint or browser header impersonation is implemented.
Cleartext `h2c` modes, DoQ/HTTP3, DoH GET, proxies specified by HTTP environment
variables, automatic redirects, HTTP content decompression, IDNA normalization
and scoped IPv6 URL hosts are unsupported. Hostname bootstrapping is explicit;
there is no automatic hosts-file or system-DNS fallback. The runtime dialer is
the extension point for that policy and for socket marks/interfaces/outbounds.

This file contains no mock production response, success placeholder, Go process,
FFI bridge or call to a public DNS service during its tests.

## Verification

On 2026-09-19 all **11 standalone tests passed** against the exact root-built
dependency artifacts, using a temporary `rustc --test` harness rather than a
Cargo build or shared target output. Tests use local generated certificates and
real Tokio TCP/TLS/h2 connections. They cover:

- Verified DoH SNI/authority/path, POST headers, source padding, wire ID zero and
  restoration of the caller's ID.
- Bad media/status/encoding, advertised and streamed oversize responses, length
  mismatch, wrong ID/question/QR and truncated DNS replies.
- Wrong server name and untrusted certificate roots.
- Real DoT with `dot` ALPN and a no-ALPN server, preserving DNS IDs and accepting
  a length prefix split across TLS writes.
- Cancellation closing the h2 connection, timeout dropping the dial future,
  pre-cancellation avoiding dialing, explicit bootstrap and routed dialer behavior.

The owned file passes rustfmt. Parent-owned integrated Cargo checks remain the
next verification step; standalone transport tests do not establish full Xray
resolver parity or prove the surrounding runtime is wired.
