# Validation ledger at pause

**Paused September 19, 2026. Commands below are for a future authorized resume.**
No build or test was launched after the pause.

A written test is not a pass. A library pass is not runtime integration, and
native-to-native tests do not establish Go interoperability. Missing reference
environment variables print skips. Existing binaries describe their compiled
snapshot, not later source edits.

## Actual evidence

| Checkpoint | Result | Qualification |
|---|---|---|
| Earlier executable Go/Rust matrix | **30/30 passed** | SOCKS/HTTP auth and noauth, VLESS, Trojan, VMess two ciphers, legacy SS three ciphers, TLS1.2/1.3, XHTTP packet-up |
| REALITY client against pinned Go | **33 selected tests passed**, including actual fixture | ML-DSA, hybrid/standalone key shares and reviewed regressions; no server/browser parity claim |
| Earlier native-tun checkpoint | 508 core +17 runtime passed, one ignored | Historical source snapshot |
| Disk-episode library checkpoint | 595 passed, three ignored | Overlapped truncated-file incident; not sole evidence |
| Restored library suite | Exit 0 after restoration | Exact count not retained; later edits followed |
| Latest broad library run | **679: 672 passed, 3 failed, 4 ignored** | Not green |
| gRPC runtime executable | **8/8 passed** | Plain/TLS, actual ALPN, logical streams, close/cancellation |
| KCP runtime executable | **5/5 passed** | Before final cancellation/drop/immediate rollback changes |
| Accounting runtime executable | **6/6 passed** | Framing, failed handshakes, API lifetime, stalled setup, buffered HTTP |
| Proxy runtime executable | **18/18 passed** | Includes 140,017-byte SS2022 AES128/AES256 chains and half-close |
| XHTTP H1 streaming components | 10 passed at earlier snapshot | Earlier clean upload-response EOF correction |
| XHTTP executable modes | First 7/8, then 7/8 | Different plaintext failures; final Windows echo correction not rerun |
| DNS config / observer libraries | 13 standalone passes each earlier | Later adapters/runtime changes separate |
| Original UDP library | 30 standalone tests/Clippy passed earlier | Later routing/runtime changes pending; extracted shutdown-drain regression subsequently passed |
| Go reference fixture builds | REALITY client, SS2022 peer, XDRIVE peer built successfully | Their ignored Rust interoperability tests remain unrun |
| Protobuf basic fixture | Go conversion and run -test passed | Real binary with non-UTF8 bytes; not a TLS fixture |
| Last workspace cargo check | **Failed E0433, protobuf HTTP Upgrade type** | Symbol corrected afterward; correction uncompiled |
| Current full fmt / Clippy / tests | **Not established** | Do not describe final tree as green |

The broad library failure stopped Cargo before selected integration test suites.
Those suites were subsequently run directly from these compiled executables:

- grpc_runtime-b88e58b7a6a39801.exe
- kcp_runtime-bae4cbd6fed9fcf4.exe
- runtime_accounting-0f45c7bee9e6f197.exe
- proxy-849eb3dde050aee7.exe

## Failed tests and corrections awaiting rebuild

| Test | Diagnosis | Final on-disk change |
|---|---|---|
| KCP cancellation_and_listener_close_wake_waiting_io | Cancelled reader closes queue; fair select can report ConnectionAborted first | Explicit cancellation wins queue-close classification; 32 actual-actor races plus uncancelled control authored |
| XDRIVE wire_names_sequences_and_nanosecond_announcements_match_go | Windows SystemTime rounds to 100 ns | Representable timestamp fixture plus full-nanosecond integer parser |
| XDRIVE read_and_write_deadlines_can_be_cleared_without_poisoning_the_stream | Tokio Sleep rounds expired deadline to next tick, allowing ready flush | Compare actual deadline before polling Sleep; deterministic regression |

Both XDRIVE failures reproduced single-threaded. None of the three corrections
has a rebuilt passing result.

## Authored/pending tests

- Observatory runtime: six.
- SOCKS UDP runtime: three.
- DNS network: 19, owner-reported; runner count is authoritative.
- XHTTP H2 stream-one: 20.
- XDRIVE: 33 ordinary plus one ignored bidirectional Go test at final handoff.
- Protobuf: nine converter, two added loader, three CLI cases. Final TLS patch
  still lacks real file-backed TLS protobuf regression fixtures.
- Management CLI: ten authored tests, no separately captured pass.
- REALITY native server: 19 plus two ignored Go tests, reported by owner.
- SS2022 UDP wrapper: 13 authored cases; new executable TCP Go matrix adds four.
- VLESS relay/equivalent-point replay, KCP latest cleanup/race, PROXY and other
  newly integrated component tests require current-tree validation.

Independent Python/OpenSSL VLESS fixtures and reciprocal-key checks validate
the security reasoning; they do not replace executing the Rust tests.

## Existing reference artifacts

| Workspace-relative file | Bytes at pause | Purpose |
|---|---:|---|
| target/reference-xray.exe | 48,104,448 | Original Go Xray |
| target/reality-reference-server.exe | 12,703,744 | Pinned Go REALITY server |
| target/reality-reference-client.exe | 17,249,792 | Pinned uTLS client and real TLS target mode |
| target/ss2022-reference.exe | 4,963,840 | Pinned Go SS2022 TCP peer |
| target/xdrive-reference.exe | 18,362,368 | Pinned Go XDRIVE local peer |

These ignored files are test artifacts, not releases. Their fixture source is
under the corresponding Rust modules.

rust/fixtures/protobuf/basic.pb SHA-256:
`6a4c7a0a909af315df9253a5ffbf78af66869d53a3f0a85c6fcb07f8ca611dab`.
Adjacent basic.json is the input. Go reported Configuration OK. It has no TLS.

## Commands for an explicitly authorized resume

First address the protobuf certificate-location issue in REMAINING_WORK.md.
Verify disk space and use one central build queue.

```powershell
cargo check --workspace --all-targets --features xray-core/native-tun --jobs 1
cargo fmt --all -- --check
cargo test -p xray-core --features native-tun --lib --jobs 1 --quiet
cargo test -p xray-core --features native-tun --test grpc_runtime --test kcp_runtime --test runtime_accounting --test proxy --test observatory_runtime --test socks_udp_runtime --jobs 1
cargo test -p xray --features xray-core/native-tun --test protobuf --jobs 1
cargo test -p xray --features xray-core/native-tun --bin xray --jobs 1
```

Focused regressions:

```powershell
cargo test -p xray-core --features native-tun protocol::vless_security::handshake --jobs 1
cargo test -p xray-core --features native-tun receive_loop_shutdown_preserves_explicit_cancellation --jobs 1
cargo test -p xray-core --features native-tun transport::xdrive --jobs 1
cargo test -p xray-core --features native-tun transport::xhttp::http2 --jobs 1
cargo test -p xray-core --features native-tun dns::network::tests --jobs 1
```

Final VLESS regression names:

- noncanonical_nfs_field_alias_cannot_bypass_authenticated_hello_replay_history
- canonical_reciprocal_aliases_at_every_relay_hop_share_replay_identity
- authenticated_malformed_hybrid_shares_do_not_fill_replay_history
- client_hello_tampering_truncation_wrong_keys_and_replay_are_rejected
- replay_capacity_and_expiration_fail_closed

Actual executable interoperability:

```powershell
$env:XRAY_GO_BINARY = 'C:/Users/W/Documents/iwebbio/Xray-core/target/reference-xray.exe'
cargo test -p xray --features xray-core/native-tun --test interop --jobs 1 -- --nocapture --test-threads=1
cargo test -p xray --features xray-core/native-tun --test xhttp_modes --jobs 1 -- --nocapture --test-threads=1
cargo test -p xray --features xray-core/native-tun --test transport_interop --jobs 1 -- --nocapture --test-threads=1
```

The interop matrix now has 34 authored cases; xhttp_modes has eight.
transport_interop has six KCP/gRPC cases, using native library transports plus
VLESS on the Rust side; it does not itself prove CLI configuration.
Repeat corrected plaintext Rust-to-Go stream-one to cover the prior intermittent
failure.

```powershell
$env:XRAY_REALITY_GO_SERVER = 'C:/Users/W/Documents/iwebbio/Xray-core/target/reality-reference-server.exe'
$env:XRAY_REALITY_GO_CLIENT = 'C:/Users/W/Documents/iwebbio/Xray-core/target/reality-reference-client.exe'
$env:XRAY_SS2022_GO_PEER = 'C:/Users/W/Documents/iwebbio/Xray-core/target/ss2022-reference.exe'
$env:XRAY_XDRIVE_GO_FIXTURE = 'C:/Users/W/Documents/iwebbio/Xray-core/target/xdrive-reference.exe'
cargo test -p xray-core --features native-tun pinned_go --jobs 1 -- --ignored --nocapture --test-threads=1
```

Rebuild fixture binaries when their source changes:

```powershell
go build -o target/reality-reference-client.exe ./rust/xray-core/src/transport/reality/handshake/server/interop
go build -o target/ss2022-reference.exe ./rust/xray-core/src/protocol/shadowsocks2022/fixtures/go-peer
go build -o target/xdrive-reference.exe ./rust/xray-core/src/transport/xdrive/interop
```

After focused issues are resolved:

```powershell
cargo clippy --workspace --all-targets --features xray-core/native-tun --locked -- -D warnings
cargo test --workspace --all-targets --features xray-core/native-tun --locked --jobs 1 -- --test-threads=1
```

Then run platform CI. Do not retire Go or change release defaults based only
on local passes.

