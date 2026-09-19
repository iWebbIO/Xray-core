# Protocol and security migration handoff

Checkpoint: **September 19, 2026. Implementation is paused at the user's request.**

This document records work coordinated by task `01a0baed-94c1-7b90-aa4c-2ae56c41595d` for migration lead `01a0bad7-07ec-7ab3-b62c-a66f92e3cb66`. It is a documentation-only checkpoint, not permission to resume. Commands below are a future validation checklist and were **not executed during the pause**.

## Ownership, stopped work, and evidence boundaries

- The three most recently reused workers, `finalmask`, `vmess_crypto`, and `vmess_encoding`, had completed before the pause. All received explicit instructions not to resume implementation, reviews, tests, builds, or assignments. No worker remains active in this coordinator's tree.
- This coordinator has no goal object to pause. No implementation write was in progress. Only this authorized document was created after the pause.
- Shared Cargo/Go builds, manifests, lockfiles, runtime/configuration integration, and shared transport helpers belong to the migration lead. This coordinator and its workers did not run shared Cargo or Go builds during the delegated batches.
- No owned child process or outstanding execution session remains. A read-only process snapshot showed generic Python processes with unestablished ownership; they were not terminated. The lead must account for any processes it or another helper started. No blanket claim is made that all machine-wide processes have stopped.
- Implementations are native Rust. Go programs mentioned below are explicitly test-only interoperability peers, not runtime dependencies, subprocess implementations, or FFI.
- Files are preserved in the shared checkout. No commits or deployment were performed by this coordinator. Known VLESS staging/backup files were removed before the pause after verifying live publication. The final read-only check found no zero-byte files in the three newest module subtrees.
- Historical package notes sometimes describe integration as pending at their original delivery. The lead's current status/validation documents should decide repository-wide integration and pass/fail status. This handoff distinguishes source delivery, independent review, independent fixture generation, and executed Rust tests.

## Source inventory and implemented contracts

| Area | Sources and supporting notes | Delivered behavior |
| --- | --- | --- |
| VMess | `rust/xray-core/src/protocol/vmess.rs`, `vmess/{crypto,encoding,stream}.rs` | AEAD authentication, request/response and body codecs, shared replay accounting, native asynchronous TCP adapter. |
| Generic UDP helpers | `rust/xray-core/src/protocol/udp.rs`; [UDP note](../rust/notes/UDP.md) | SOCKS5 packets/association state, Trojan datagram framing, VLESS length packets. |
| Final masks | `rust/xray-core/src/transport/finalmask.rs`, `finalmask/{fragment,noise,salamander,custom}.rs`; [note](../rust/notes/FINALMASK.md) | Fragment/noise helpers, Salamander/Gecko, custom expressions and TCP/regular UDP headers. |
| Hysteria | `rust/xray-core/src/protocol/hysteria.rs`, `transport/hysteria.rs`; [note](../rust/notes/HYSTERIA.md) | Hysteria 2 framing, authentication helpers, bounded reassembly, native Quinn/H3 client transport. |
| Shadowsocks UDP primitives | `rust/xray-core/src/protocol/shadowsocks_udp.rs`; [note](../rust/notes/SHADOWSOCKS_UDP.md) | Legacy AEAD and single-key 2022 UDP cryptography, replay windows, client/server session state. |
| Shadowsocks 2022 TCP | `rust/xray-core/src/protocol/shadowsocks2022.rs`, `shadowsocks2022/{codec,stream,tests}.rs`; [note](../rust/notes/SHADOWSOCKS2022.md) | Single-account AES-128/AES-256 TCP with authenticated request/response binding and persistent asynchronous I/O state. |
| Shadowsocks 2022 UDP adapter | `rust/xray-core/src/protocol/shadowsocks2022/udp.rs`, `udp/{tests.rs,README.md}` | Account-backed authenticated return routing over the existing UDP primitives; no duplicate cryptography. |
| VLESS primitives | `rust/xray-core/src/protocol/vless_security.rs`, `vless_security/{derive,encryption,vision}.rs`; [primitive note](../rust/notes/VLESS_SECURITY.md) | Binary-context BLAKE3 KDF, session/record AEAD, header masking and Vision framing primitives. |
| VLESS native handshake | `rust/xray-core/src/protocol/vless_security/handshake.rs`, `handshake/{config,keys,relay,wire,stream,tests}.rs`, `handshake/fixtures/`; [current note](../rust/notes/VLESS_HANDSHAKE.md) | Native 1-RTT hybrid handshake, up to eight ordered NFS relay keys, encrypted stream, semantic replay identity. |
| REALITY server/target | `rust/xray-core/src/transport/reality/handshake/server.rs`, `server/{hello,certificate,target,tests}.rs`, `server/interop/main.go`; [current note](../rust/notes/REALITY_SERVER.md) | Authenticated native TLS 1.3 server plus bounded target ServerHello/record-size mirroring and byte-preserving fallback. |

### VMess and generic UDP

VMess `Account::{new,from_user_id}` and `ServerAuthenticator` support account lookup, AuthID replay protection, and the three-minute `(user, body key, body IV)` history. Keep one authenticator per inbound, shared through `stream::SharedAuthenticator`; constructing one for each connection defeats replay protection. Capacity exhaustion fails closed without evicting live entries.

`vmess::stream::{accept,connect,connect_with_options}` use `BoxStream`. Inbound response output is deferred until first write/flush/shutdown after routing. Outbound response authentication is lazy. Partial headers/records and cancelled I/O remain in stream state; the adapter rejects UDP/Mux dispatch and refuses nonce-counter wrap. It permits at most 65,536 body frames per direction, including EOF. Socket deadlines and dispatch remain caller responsibilities. Address fixes preserve source hostname/IP behavior, IPv4-mapped IPv6 normalization, and consistency between synchronous/asynchronous codecs.

`protocol::udp` exposes SOCKS5 encode/decode, `Socks5UdpSession`, Trojan slice/async frames, and VLESS slice/async length frames. Association state ties SOCKS UDP to the TCP control connection and permitted source, with explicit idle/closure handling. Trojan malformed CRLF is rejected. VLESS length framing is not XUDP or multiplexing. Refer to the UDP note for buffer limits, zero-length differences, source pinning, and caller lifecycle requirements. Other helpers subsequently worked on runtime SOCKS UDP; this coordinator does not claim their final integration status.

### Final masks and Hysteria

Finalmask includes source-derived fragment/noise plans and async writers, BLAKE2b-256 Salamander salt/XOR framing, bounded Gecko reassembly, custom typed expressions and saved state, alternating TCP handshake sequences, and regular per-datagram UDP headers. Salamander is obfuscation, not integrity or peer authentication. Saved UDP values are isolated per peer. Limits include bounded expression depth, header/datagram sizes, peer tables, and reassembly lifetimes. Full configured packet-socket wrappers, special UDP waiter/retransmission modes, and additional mask families were not delivered by this package; other helpers may have extended the repository separately.

Hysteria includes QUIC varints, TCP request/response records, UDP fragmentation/reassembly, HTTP/3 authentication, and a native Quinn/H3 client. Returned streams retain shared session ownership. A bandwidth-parser follow-up matches the Go parser's sequential overflow behavior, including overflow before later invalid input. Pinned BBR/Brutal behavior is not silently replaced by Quinn controllers; native alternatives are explicit. Full inbound HTTP/3 dispatch, controller parity, UDP routing/session allocation, and platform-specific behavior remain separate integration work.

### Shadowsocks UDP primitives

`LegacyCipher`/`LegacyUdp` implement legacy AES-128-GCM, AES-256-GCM, and ChaCha20-IETF-Poly1305 datagrams. `Cipher2022` implements single-key AES 2022 and UDP XChaCha 2022 formats. `Client2022`, `Server2022`, and `SlidingWindow` manage authenticated session IDs, counters, client-response binding, source-derived current/previous server rotation policy, and replay admission.

The 2022 replay window is the pinned 8,128-ID window. Server defaults are 4,096 sessions and 500 seconds idle lifetime; configured retention must be at least 61 seconds to cover the inclusive ±30-second timestamp interval. Live replay history is not evicted on capacity exhaustion. Session-ID/counter uniqueness and state retention are required. Oversized payloads are rejected before cloning. Colon/EIH/multi-user relay chains are not accepted as single-key packets. Raw deterministic codec entry points do not manage nonce/replay policy for callers.

### Shadowsocks 2022 TCP and new UDP adapter

The source reference is `sing-shadowsocks v0.2.7`, with `sing v0.5.1` metadata behavior. TCP supports `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm` only. `Account::{new,from_key}` normalizes overlong decoded PSKs with SHA-256 truncation, rejects short keys and colon/EIH chains, and shares bounded replay caches through clones.

`accept(BoxStream, &Account)` returns authenticated stream/request; `connect(BoxStream, &Account, &Destination)` returns an encrypted stream before its response arrives. Variable-header initial payload stays buffered in the stream, so `Request.initial_payload` is empty. Preserve the pinned single-read salt/fixed-header gate. The response binds the original request salt and starts on first write/flush/shutdown. Ordinary records tolerate partial/cancelled I/O, support 65,535-byte payloads, and reject truncated EOF. Replay salt retention is 61 seconds, with 65,536-entry fail-closed caches. Deadlines, socket draining/linger, and routing policy are caller responsibilities. The lead reported config/runtime wiring for both TCP ciphers and a passing 140,017-byte chain/half-close test.

The new `shadowsocks2022::udp` export is present. `cipher(&Account)` reuses `Cipher2022`. `Client::{new,encode_request,accept_from}` binds a configured server endpoint. `Server::{new,with_limits,accept_from,encode_reply,expire,session_count}` adds bounded authenticated return-address associations over `Server2022`. `AcceptedDatagram` contains an opaque `SessionToken`, source peer, and plaintext datagram; `RoutedDatagram` contains destination peer and encrypted wire bytes.

Rebinding occurs only after successful authentication, timestamp/address validation, and replay admission. Private allocation identity makes old/foreign tokens invalid even if a numeric session ID is reused. Tokens follow valid rebinding. Caller-owned sockets, serialized state access, clocks/RNG, upstream routing, and actual reply-origin metadata are still required. This account adapter adds AES128/AES256 only, not a UDP-only XChaCha account or multi-user identity selection. Thirteen new deterministic tests cover fixtures, normalization, address/empty payload cases, endpoint/client binding, corruption/truncation, replay/metadata poisoning, rebinding, capacity, expiry, token identity, and source isolation.

## VLESS native handshake and final replay fix

The live `handshake` module supports `mlkem768x25519plus.native` 1-RTT. `ClientConfig`/`ServerConfig` parse configurations and offer singular/plural raw-key builders. Up to eight ordered NFS keys may independently use X25519 or ML-KEM-768. Every connection also establishes fresh hybrid ML-KEM-768 + X25519 PFS. Intermediate relays use the pinned continuous AES-256-CTR stream: mask the next public-key BLAKE3 hash, then the first 32 bytes of the next relay without resetting CTR position. Prefix allocation is bounded.

`client_handshake(stream, &ClientConfig)` and `server_handshake(stream, &ServerConfig)` return `EncryptedStream<S>`. These exchanges do not authenticate the inner VLESS account. The runtime must validate the inner request/user and apply account/routing policy. Vision/direct TLS I/O switching is separate.

0-RTT was deliberately not implemented: matching the pinned client's ticket rejection/reconnect/retry behavior needs a caller dial/reconnect contract outside this module. Server ticket lifetime is zero. XOR disguises, configured fragmented/timed padding, chains beyond eight keys, and resumption are explicitly rejected. Client server-flight AEAD authentication is checked before decapsulation, rather than reproducing the pinned Go client's ignored error.

The lead added `RecordCipher::from_aead(aead, united_key)` to preserve counters and poisoned state. Ticket, padding-length, and padding payload consume server-direction nonces 1, 2, 3; first server application record uses nonce 4. Client application records start at nonce 1. Independent fixtures assert this transition.

### Semantic replay identity: published, review complete, final Rust run pending

The final live `wire.rs` uses BLAKE3 derive-key context `xray-core VLESS native 1-RTT authenticated replay identity v1`, then hashes the exact IV, effective final NFS secret, initial authenticated length record, and authenticated PFS/padding records. Raw relay-prefix bytes are excluded. Reservation remains after all authentication and hybrid-key validation, preserving the malformed-flight/no-poison guarantee.

Two review findings motivated this change:

1. Noncanonical X25519 field encodings such as `9` and `p + 9` reduce to the same input. NFS admission now rejects high-bit encodings and every field value at or above `p = 2^255 - 19`, at every relay hop.
2. Distinct **canonical** shares, including `u` and `1/u`, can produce equal X25519 shared keys. Therefore canonical checks alone cannot secure a raw-prefix replay hash. The final semantic identity folds equivalent authenticated flights into one cache entry.

This is replay accounting for the outer handshake, not an inner-account authentication bypass. The cache remains process-local and bounded: default 4,096 entries/180 seconds, configurable via `with_replay_limits`. Capacity fails closed; live entries remain after later output/RNG/drop/inner-account failures. Production admission budgets must be sized with this ceiling. It is not persistent/distributed ticket replay protection.

Both replay orders, both AEADs, direct handshakes, and reciprocal aliases at every hop of a generated three-X25519 chain have regressions. The independent reviewer verified the published inputs/reservation position and recomputed all three generated reciprocal pairs with Python cryptography. A separate Python/OpenSSL oracle authenticated all four affected ciphertext records under both equivalent shares, demonstrated differing old raw hashes, and matching new semantic hashes. No remaining concrete finding was reported in the bounded review. These checks do **not** replace the pending Rust regression run.

Exact test filters after explicit resume:

```text
protocol::vless_security::handshake
noncanonical_nfs_field_alias_cannot_bypass_authenticated_hello_replay_history
canonical_reciprocal_aliases_at_every_relay_hop_share_replay_identity
authenticated_malformed_hybrid_shares_do_not_fill_replay_history
client_hello_tampering_truncation_wrong_keys_and_replay_are_rejected
replay_capacity_and_expiration_fail_closed
native_relay_chains_preserve_hybrid_sessions_for_mixed_key_types
relay_binding_rejects_reordered_keys_tampering_and_all_prefix_truncations
relay_configuration_has_explicit_key_count_bounds
independent_relay_wire_fixture_checks_hash_and_continuous_ctr_binding
```

`handshake/fixtures/native_aes.json`, `native_chacha.json`, and `relay_aes.json` are independent complete-wire fixtures. `fixtures/generate.py` uses Python cryptography/OpenSSL and an independent binary-context BLAKE3 implementation. They are not runtime/build dependencies. Regeneration can produce different server flights because OpenSSL encapsulation is randomized.

The earlier primitive-only VLESS note does not supersede this later handshake implementation. Primitive work also fixed the header-mask borrow issue and AES-CTR numeric wrap behavior: crossing zero is permitted until the counter returns to its starting IV.

## REALITY server and target path

Standalone `ServerConfig`, `ServerConnectionInfo`, `accept`, and `accept_boxed` implement authenticated TLS 1.3 for configured peers with X25519 and X25519MLKEM768, all three supported cipher suites, SNI/short-ID/time/version admission, certificate marker, Ed25519 CertificateVerify, Finished, and encrypted application streams. An initial bounded record reader permits legacy record version `0301`. The lead added production `rcgen` and `ClientStream::new_server`; server-role streams reject client-sent NewSessionTicket while retaining shared KeyUpdate handling.

`server::accept_with_target(client, preconnected_target, config)` returns `TargetOutcome::Authenticated { stream, info }` or `Forwarded { client_to_target, target_to_client, reason }`. Forwarded connections are already handled and must not enter the authenticated protocol dispatcher. Caller owns target dialing, any PROXY header, forwarding lifetime, and cancellation.

For supported TLS 1.3 targets, the implementation preserves ServerHello bytes except the ephemeral key share, and preserves supported encrypted-flight record sizes using the lead's `RecordCipher::seal_padded`. Supported layouts are a coalesced record larger than 512 wire bytes, or four EE/Certificate/CertificateVerify/Finished records, with exact compatibility CCS. The replacement certificate is generated locally; target certificates are not copied. Target ALPN is omitted in the supported profile.

Rejected admission and unsupported/too-small target profiles fall back before publishing local TLS output. Captured prefixes, partial reads, and partial writes preserve exact bytes and offsets; concurrent bidirectional replay avoids prefix backpressure deadlock. After committing a local server flight, errors/timeouts close streams and cannot switch to forwarding. A single deadline bounds inspection and authenticated handshake; fallback forwarding has caller-owned lifetime beyond that deadline.

This is **bounded target behavior, not complete Go camouflage parity**. It buffers the client prefix before forwarding, rather than reproducing Go MirrorConn scheduling/timing. It omits global target probes, post-handshake/ticket-size mimicry, target certificate copying, server ML-DSA signing, PSK/resumption, early data, HRR, client certificates, built-in dialer/PROXY/rate-limit/key-log behavior. Integration must explicitly supply or reject `xver`, fallback upload/download limits, `mldsa65Seed`, key-log requests, and non-TCP target adapters.

There are 19 native server tests: 12 retained plus seven target tests, including 12 suite/group/layout cases. Two ignored Go tests cover the standalone server and genuine Go target + pinned uTLS client path. Independent reviews found no actionable issue in target shape/share-offset/padding validation or capture/cancellation/prefix replay/transition handling. This is a bounded review, not a general security certification.

Earlier read-only review of the shared REALITY client found fragmented/coalesced KeyUpdate rejection, TLSInnerPlaintext/empty-handshake bounds, and close_notify with an incomplete handshake. The lead reported all three fixed with regressions. Those earlier client fixes and test results must not be confused with execution of the newly added server/target tests.

## Validation evidence received before pause

| Evidence | Status and boundary |
| --- | --- |
| Older combined native-TUN run | Lead reported 508 core + 17 runtime tests passed; included prior VLESS primitives, Hysteria parser correction, and SSUDP size checks. Historical snapshot, not the newest tree. |
| Earlier package tests | Notes record lead-confirmed 20 finalmask and 13 Shadowsocks UDP tests passing. |
| Earlier REALITY client suite | Lead reported 33 selected native/primitive/actual pinned-Go tests passed, no skips, including its ML-DSA fixture. This is the earlier client suite. |
| Restored pre-extension core library | Lead reported exit 0 after disk recovery. |
| Later core snapshot | Lead reported 679 total: 672 passed, 3 failed, 4 ignored. Failures assigned to a KCP race and two XDRIVE cases; no SS2022/VLESS/REALITY failures in that snapshot. New target/relay additions still needed another build. |
| SS2022 TCP runtime | Lead reported both AES ciphers passing the new 140,017-byte chain and half-close test. |
| Go fixture binaries | Lead reported updated REALITY and SS2022 fixture builds complete. This coordinator received no completed execution result for the newest ignored server/target/SS2022 tests. |
| Newest source | Workers reported formatting/whitespace checks complete and source stable. New UDP tests, target/relay additions, and the final semantic replay fix require the lead's current validation ledger; no final whole-tree or final replay-regression pass was received here. |
| Independent fixtures/review | Independent SS/finalmask/VLESS fixtures and bounded reviews are described above/in package notes. No Cargo/Go test execution by this coordinator or its workers during the delegated batches. |

Disk exhaustion previously truncated the owned VLESS test file during a write. It was restored, then extended; the pause-time file is **26,919 bytes**. The current REALITY note is 8,291 bytes, VLESS handshake note 7,855 bytes, and UDP adapter README 4,229 bytes. These sizes identify this checkpoint only. Atomic staged publication was used for later sensitive changes. Do not infer test completion from file restoration or formatting.

## Commands retained for a future explicit resume

Do not execute these while paused. Keep builds centralized and sequential according to the lead's disk/process policy.

```powershell
cargo test -p xray-core protocol::vmess
cargo test -p xray-core protocol::udp
cargo test -p xray-core transport::finalmask
cargo test -p xray-core protocol::hysteria
cargo test -p xray-core transport::hysteria
cargo test -p xray-core protocol::shadowsocks_udp
cargo test -p xray-core protocol::shadowsocks2022
cargo test -p xray-core protocol::shadowsocks2022::udp
cargo test -p xray-core protocol::vless_security::handshake
cargo test -p xray-core transport::reality::handshake::server
```

Test-only Go peers, built from repository root:

```powershell
go build -o "$env:TEMP/ss2022-go-peer.exe" ./rust/xray-core/src/protocol/shadowsocks2022/fixtures/go-peer
$env:XRAY_SS2022_GO_PEER = "$env:TEMP/ss2022-go-peer.exe"
cargo test -p xray-core pinned_go_tcp_interoperability_both_directions_and_ciphers -- --ignored --nocapture

go build -o "$env:TEMP/reality-go-client.exe" ./rust/xray-core/src/transport/reality/handshake/server/interop
$env:XRAY_REALITY_GO_CLIENT = "$env:TEMP/reality-go-client.exe"
cargo test -p xray-core pinned_go_reality_client_interoperability -- --ignored --nocapture
cargo test -p xray-core pinned_go_target_and_reality_client_interoperability -- --ignored --nocapture
```

The REALITY helper also supports `target hybrid|x25519` for the target harness. Normal Rust tests never build Go. There is no claimed new pinned-Go UDP network pass or native VLESS Go interoperability pass in this coordinator's evidence.

After an explicit resume, the outstanding priority is to run the final semantic replay/no-poison regressions and the current native/Go suites, resolve any failures through their owners, and only then decide runtime integration. The lead explicitly withheld native VLESS handshake runtime integration until the semantic replay fix validates. No implementation, test, or new assignment should restart merely because this document exists.
