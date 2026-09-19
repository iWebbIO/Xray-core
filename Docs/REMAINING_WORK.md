# Remaining work and resumption order

**Implementation remains paused. This queue is not authorization to resume.**

## Immediate known defect: protobuf certificate locations

The final TLS projection in rust/xray-core/src/config/protobuf.rs is formatted
but uncompiled. Go TLS protobuf records normally contain initial PEM bytes and
file paths together; the native JSON model rejects that combination.

The latest patch retains embedded bytes for one-time/verification/incomplete
pairs. For reloadable encipherment pairs it compares current files to the
embedded snapshots before keeping paths and dropping inline data.

It currently calls std::fs::read(path) directly. Reference relative paths resolve
through xray.location.cert / XRAY_LOCATION_CERT, with executable-directory
fallback. See common/platform/windows.go, common/platform/others.go and
common/platform/filesystem/file.go. Implement that source rule and preserve
resolved paths before declaring file-backed protobuf TLS supported.

Add real Go-produced protobuf fixtures covering absolute/relative paths,
environment precedence, executable-directory fallback, oneTimeLoading,
verification certificates, missing/changed reload files, initial snapshot
preservation, and actual validation/handshake/reload. These tests were not
written before pause. Do not silently change the initial certificate or disable
reload. PROTOBUF_CONFIG.md has not incorporated this final issue yet.

## First validation gate

Rebuild before trusting current executables. See VALIDATION.md.

- Check corrected HttpUpgradeConfig name and all new module exports.
- Validate final KCP cancellation/drop/immediate startup-rollback changes.
- Validate XDRIVE deadline/nanosecond fixes and HTTP-template storage.
- Run VLESS authenticated-semantic replay regressions and REALITY target/server.
- Test configured observatory and SOCKS UDP ownership.
- Run DNS network, XHTTP H2, protobuf, API CLI and process tests.
- Rerun corrected Windows XHTTP fixture and actual Go matrices.
- Obtain current workspace fmt, Clippy, tests and cross-platform evidence.
- Finish the interrupted PARITY_AUDIT.md review, keeping historical counts dated.

No failed test was waived. There is no final-tree green checkpoint.

## Next integrations

### DNS

Top-level configured DNS is still rejected. Libraries and exact recipe are
config/dns.rs, dns/network.rs, dns/network/connector.rs and
dns/network/WIRING.md.

Preserve the reviewed contracts:

- Compile with the appropriate shared geodata/routing context.
- NetworkDns owns its Connector. Use Weak<Dispatcher> or separate routing
  state to avoid an Arc cycle when Dispatcher owns NetworkDns.
- Configured DNS uses explicit/static bootstrap pins, never an error fallback
  to OS DNS. Current UDP SystemResolver is explicit only because DNS config
  is unsupported.
- Separate numeric DNS target candidates from OUTER proxy-hop endpoints.
  For a proxy DNS route, target is the selected numeric DNS destination;
  establish's resolved argument pins the separately admitted proxy server.
- Reject freedom redirects until the changed destination has a separately
  checked pin plan.
- Use DNS client inbound tag and empty inbound protocol, matching source;
  do not apply the original VLESS/VMess user's protocol default here.
- Unsupported proxy UDP errors rather than bypassing routing.
- Preserve original TLS SNI/DoH authority. Own refresh cancellation/shutdown.
- Avoid self-recursive bootstrap lookups.

### REALITY / VLESS encryption

Server/target REALITY and encrypted VLESS remain libraries. Keep configuration
rejections until tested runtime adapters exist.

REALITY target mirroring remains bounded: no browser fingerprint emulation,
HRR/PSK resumption, server ML-DSA signing, full target-probe/post-handshake
mimicry, built-in fallback rate limits or PROXY injection. Prefix buffering
differs from Go concurrent mirroring. Unsupported behavior must fail explicitly.

For VLESS, preserve handshake-to-record nonce continuity, inner user
authentication, shared replay state, and fail-closed capacity. Default replay
history is 4096 entries/180s; size it against admission budget and expose
saturation before production runtime integration. Never evict live entries.
Resumption, XOR modes, timed padding and complete Vision socket switching remain.

### Transports

XHTTP H2 requires actual negotiated h2 ALPN before a stream is erased into
BoxStream. Standalone H2 cannot inspect that metadata. Runtime H2/H3 selection,
auto/split modes, Xmux/pooling/downloadSettings and broader parity remain.

XDRIVE is storage polling, not a TCP listener/dial. Integrate its lifecycle
accordingly. Google Drive and custom TLS/REALITY fronting are still unsupported;
HTTP-template storage is implemented but unvalidated.

PROXY decoding, final masks, mux/reverse, Hysteria server/congestion,
WireGuard/TUN runtime/platforms and broad socket settings require further wiring.

### UDP / applications

- SOCKS UDP currently permits bare freedom/blackhole only. Proxy UDP,
  per-protocol UDP, SS2022 EIH/multi-user/relay are incomplete.
- Higher user policy levels, complete buffer/timeouts and platform semantics.
- DNS routing strategies, sniffing/content overrides, advanced route conditions,
  balancers/observatory feedback and dynamic handler registry.
- Handler/user/routing/source-IP/metrics API services and complete management CLI.
- Full HTTP proxy request/response semantics.
- Complete source configuration/env/default/null/legacy behavior.

## Full conversion completion criteria

The request was the entire project. Completion requires every supported
protocol/transport/security combination, native applications/configuration/CLI,
compatible malformed-input and lifecycle behavior, independent interoperability,
platform tests, and validated native packaging/CI.

Only after that should release defaults and retirement of Go be considered.
Original Go code/releases remain intact. No release or deployment was published.

## Preservation constraints

Preserve uncommitted work and reference fixtures. Automatic approval review
blocked deletion of target/debug and the protected geodata validation directory.
Do not retry the same removal through another command.

Recheck disk space before expensive builds. Earlier exhaustion truncated two
files, both restored. This handoff documents the safe pause state; do not start
implementation or scheduled follow-ups until the user resumes.

