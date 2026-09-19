# Native Shadowsocks UDP building blocks

`rust/xray-core/src/protocol/shadowsocks_udp.rs` implements UDP cryptography,
framing and account/session replay admission. Existing `shadowsocks.rs` and
`shadowsocks_session.rs` are unchanged. This is not yet a configured UDP listener
or outbound dispatcher.

The implementation follows the repository's legacy `proxy/shadowsocks` code,
`github.com/sagernet/sing-shadowsocks@v0.2.7/shadowaead_2022/{protocol,service,slidingwindow}.go`,
and the SOCKS address serializer in `github.com/sagernet/sing@v0.5.1`. These are
the versions pinned by the repository's `go.mod`.

## Supported methods and wire formats

| Methods | Wire format |
| --- | --- |
| Legacy `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | Fresh 16/32-byte salt followed by one AEAD record containing SOCKS address/port and payload. The nonce is zero. Subkeys use existing EVP_BytesToKey MD5 password expansion and HKDF-SHA1 with `ss-subkey`. There are no TCP length records. |
| `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` | AES-ECB encrypts the separate 16-byte session/packet-ID header using the PSK. BLAKE3 derives the body key from PSK plus the eight-byte session ID with context `shadowsocks 2022 session subkey`. AES-GCM uses clear header bytes 4 through 15 as its nonce. |
| `2022-blake3-chacha20-poly1305` | A fresh 24-byte nonce precedes one XChaCha20-Poly1305 record containing both the session/packet-ID header and body, using the PSK directly. UDP does not use the TCP ChaCha20 nonce/subkey layout. |

All 2022 bodies contain direction, eight-byte timestamp, two-byte padding length,
padding, SOCKS destination and payload. Replies additionally include the client
session ID between timestamp and padding length. Packet IDs start at zero. The
codec checks the exact direction, timestamp difference of at most 30 seconds,
padding bounds and destination before returning plaintext. High-level senders
add 1 through `900 - payload length` padding bytes for DNS destinations when
payloads are shorter than 900 bytes, matching the pinned selection policy.
Random padding bytes are valid wire contents.

Base64 PSKs shorter than the method's key size are rejected. Longer PSKs follow
the pinned normalization: SHA-256 and truncation to the key size. Colon-separated
identity/relay chains are explicitly rejected.

## APIs and integration

The parent owns `pub mod shadowsocks_udp;` in `protocol/mod.rs` and
`blake3.workspace = true` in `xray-core/Cargo.toml`. The workspace already has
the `blake3` dependency. Other dependencies already exist, and AES block
operations use the `aes_gcm::aes` reexport. No Cargo/manifests/module registries
were changed by this work package.

- `LegacyCipher::{from_key,from_password,seal,seal_with_salt,open}` are stateless
  wire primitives. `LegacyUdp::{encode,decode}` adds account-scoped admission of
  authenticated received salts and locally generated salts. The default cache
  retains 65536 salts for ten minutes and fails closed at capacity; `with_limits`
  makes that retention policy explicit. Old legacy packets can be accepted again
  after the configured retention window, because legacy UDP has no timestamp.
- `Cipher2022::{new,from_password,seal,seal_with_nonce,open}` handles stateless
  single-key framing and cryptography. `Packet2022` carries authenticated IDs,
  timestamp, direction, client-session binding and the existing UDP `Datagram`
  type. Raw deterministic seal methods require externally guaranteed nonce and
  session/packet-ID uniqueness.
- `Client2022::{new,encode,decode}` owns a fresh random local session ID, a packet
  counter that refuses to wrap, and current/previous server replay windows.
  Replies are bound to the correct client session before replay state changes.
  A second server rotation is rejected until sixty seconds after the previous
  session was last seen, matching the pinned policy.
- `Server2022::{new,accept,encode_reply,expire}` owns a bounded account-specific
  session table, authenticated packet admission and reply counters. Default
  capacity is 4096 sessions and idle lifetime is 500 seconds. `with_limits`
  requires at least 61 seconds to retain history beyond the entire timestamp
  acceptance interval. Capacity errors do not evict live replay state.
- `SlidingWindow` ports the pinned 128-block ring exactly: an inclusive 8128-ID
  window permits reordering and rejects duplicate/too-old packet IDs. IDs near
  `u64::MAX` are handled without truncation or arithmetic overflow.

Use a cryptographic RNG such as `rand::rngs::OsRng`. Supply Unix time in seconds
for protocol timestamps and a monotonic `Instant` for cache lifetimes. Keep
client/server states alive for the account/association; recreating a state for
each packet loses replay protection. Do not reuse externally supplied client
session IDs after counters reset.

Server sessions are indexed by authenticated client session ID, allowing UDP
source-address rebinding as in the source protocol. The integration must retain
the source socket address, update it only after `accept` succeeds, route the
returned destination/payload, and call `encode_reply` with that client session
ID. Serialize access to each state. Network sockets, NAT mappings and timeout
tasks remain the caller's responsibility.

## Validation

All new Rust code passed `rustfmt --edition 2024` parsing/format checks. This
worker did **not** run Cargo, shared builds or Rust tests, per migration
coordination. Parent validation command after module export:
`cargo test -p xray-core protocol::shadowsocks_udp`.

The migration lead subsequently compiled the combined workspace and reported
all 13 Shadowsocks UDP tests passing. This worker has not repeated that build.

Thirteen embedded tests include nine independent full-wire known answers:
three legacy methods and client/server packets for each of the three 2022
methods. Fixtures were generated separately using Python 3.12,
`cryptography` 50.0.1 (MD5/HKDF-SHA1/AES-GCM/ChaCha20-Poly1305), `blake3` 1.0.9
(derive-key mode) and PyCryptodome 3.23.0 (AES-ECB/XChaCha20-Poly1305). The latter
two fixture-only packages were isolated under the system temporary directory;
they are not runtime or repository dependencies. No Go implementation, FFI or
subprocess is used by the Rust module.

Fixture inputs are fixed and visible in the tests: legacy password `password`,
salt bytes starting at `a0`, destination `203.0.113.7:5353`, and payload
`udp fixture`; 2022 PSK bytes starting at zero, request session
`0102030405060708`/packet 7, reply session `1112131415161718`/packet 9, timestamp
1700000000, padding `pad`, destination `8.8.8.8:53`, payload `1234646e73`, and
XChaCha nonce bytes 0 through 23. AES BLAKE3 subkeys are also independently
asserted.

The tests reject every truncation and every one-byte mutation of the known
answers, test authenticated malformed padding/addresses, verify timestamp edges,
exercise source-derived replay-window boundary counters against a set reference,
check salt-cache poisoning/capacity/reflection, session rotation/client binding,
counter exhaustion, all-method request/reply handling, and server expiry.

## Remaining scope and differences

- Runtime/configuration dispatch, account lookup, UDP socket lifecycle,
  source-address/NAT tracking, policy/stats, cancellation and live network
  interoperability tests remain unimplemented.
- 2022 extended identity headers, multi-user identity selection and relay key
  chains are unsupported; they are not treated as single-key packets.
- Legacy stream ciphers and `none` are unsupported. Existing TCP codecs are not
  expanded by this file. Legacy TCP and UDP salt caches are currently separate;
  shared account-level replay accounting requires parent integration.
- The codec limits wire packets to 65535 bytes. Actual path MTU and UDP socket
  payload limits are smaller and must be enforced by the dispatcher. Destination
  validation uses the native `Destination` model and rejects zero ports, empty
  domains, invalid UTF-8 and control/whitespace in domain names.
- Authentication, structural checks and client binding happen before replay
  state is committed. The pinned code commits some counters earlier; this port
  deliberately prevents invalid packets from poisoning valid replay state.
- The native server fails closed at session capacity instead of evicting live
  entries. Received authenticated packets and sent replies refresh its idle
  lifetime. Expiration is explicit or on use, without a background task.
