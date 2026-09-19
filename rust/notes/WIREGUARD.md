# Native WireGuard packet engine

Assignment 21 provides an actual Rust Noise IKpsk2 / WireGuard packet engine and
source-derived configuration and cryptokey routing. It does **not yet provide a
working Xray WireGuard inbound or outbound stream proxy**: the runtime socket
pump and TCP/IP stack adapter are separate remaining work.

## Dependency and provider

Add `boringtun = { version = "0.7.1", default-features = false }` to the workspace
and `boringtun.workspace = true` to xray-core. Existing `anyhow`, `base64`, `ipnet`,
`serde`, and `zeroize` dependencies supply the other APIs used by this module.
The conversion lead owns manifests, lockfile, module registration and Cargo
builds; this assignment only edits `protocol/wireguard.rs`, its subtree, and this
note.

Cloudflare's BoringTun 0.7.1 is the latest non-yanked crates.io release inspected
on 2026-09-19; published 2026-05-01. It provides portable `noise::Tunn` without
its optional platform device or FFI features. The provider uses ring for its
session AEAD, x25519-dalek for X25519, and its Rust Noise implementation. The
wrapper contains no unsafe code, subprocess, or Go runtime bridge. It does not
select Rustls's TLS crypto provider: WireGuard cryptography is independent.

Primary references inspected:

- https://crates.io/api/v1/crates/boringtun
- https://github.com/cloudflare/boringtun/blob/master/boringtun/Cargo.toml
- https://github.com/cloudflare/boringtun/blob/master/boringtun/src/noise/mod.rs
- https://github.com/cloudflare/boringtun/blob/master/boringtun/src/noise/session.rs
- https://github.com/cloudflare/boringtun/blob/master/boringtun/src/noise/rate_limiter.rs
- https://github.com/cloudflare/boringtun/blob/master/boringtun/src/device/mod.rs

## API and runtime contract

`WireGuardConfig` deserializes source JSON settings. `build(Role::Client)` or
`build(Role::Server)` returns a validated `DeviceConfig`. The role is supplied by
the inbound/outbound context. `SecretKey` redacts Debug and zeroizes owned bytes;
raw JSON settings have no Debug implementation and still hold their original
string keys until the caller drops them.

`WireGuardDevice::new(config)` creates peer sessions. Peer IDs are zero-based
configuration positions and remain stable for the life of the device.

| Method | Contract |
| --- | --- |
| `encapsulate(&[u8])` | Supply one complete IPv4/IPv6 packet; select destination's longest-prefix peer, then encrypt or queue while handshaking. |
| `decapsulate(SocketAddr, &[u8])` | Supply one received UDP payload and its actual source; authenticate, demultiplex peers, enforce source-IP ownership and process roaming. |
| `initiate_handshake(peer, force_resend)` | Generate a real WireGuard handshake; normally use `false`, allowing provider timers to handle retransmission. |
| `update_timers()` | Poll approximately every 250ms, deliver all actions, and inspect per-peer errors. Other peers continue when one expires. |
| `set_peer_endpoint(peer, SocketAddr)` | Set an administratively trusted or DNS-resolved endpoint; required before initiating to a hostname. |
| `route(IpAddr)` | Return longest-prefix peer owner, or `None`. |
| `peer_stats(peer)` | Read provider handshake age, byte counters, loss estimate, RTT and current endpoint. |
| `config()` / `public_key()` | Read validated settings and local public identity. |

Each operation returns owned `PacketAction` values. `Network` contains an
encrypted UDP payload plus its destination and optional peer ID; send it without
adding another WireGuard header. `Tunnel` contains a full decrypted IP packet
plus authenticated peer ID; feed it to the TCP/IP stack. Stateless cookie replies
can have no peer ID. An empty action list is legitimate (a received keepalive,
cookie, queued packet, or already-running handshake), not a successful TCP dial.

The engine has no sockets, tasks, threads or clock sleeps. Serialize mutable
access in the caller's task. Do not hold unrelated runtime locks while doing
network I/O for returned actions. Timer errors expose provider expiration; no
application connection success is synthesized on failure.

Before session establishment BoringTun buffers at most 256 outgoing packets per
peer, dropping further queued packets. The wrapper pads to 16 bytes, bounded by
the inner MTU, because BoringTun 0.7.1 does not add this padding itself. Provider
transmit-byte totals therefore include this plaintext padding. Stats are not yet
connected to Xray traffic counters or user policy.

## Source behaviors carried over

Reviewed `infra/conf/wireguard.go`, `proxy/wireguard/{config,client,server,bind,
tun,netstack}.go`, and `testing/scenarios/wireguard_test.go`.

- Hex, standard Base64 and URL-safe Base64 keys are accepted, with or without
  the standard trailing padding; actual keys must be exactly 32 bytes.
- Omitted/null address defaults to `10.0.0.1` and `fd59:7153:2388:b5fd::1`;
  explicit `[]` remains empty. Interface CIDRs retain their host address.
- Omitted/null allowedIPs means both default routes; explicit `[]` owns no
  routes. Allowed prefixes normalize their host bits. Longest prefix wins;
  a reassigned exact prefix belongs to the last configured peer. Inbound IP
  source ownership must match that selected peer, including overlapping ranges.
- MTU zero selects 1420; nonpositive or unencapsulatable MTUs are rejected.
- Reserved accepts Go JSON byte-array, standard Base64 and null forms and must
  be empty or three bytes. Receive normalizes reserved bytes before crypto;
  transmit applies the configured marker after crypto. Source JSON inbound
  ignores outgoing reserved and peer endpoint settings, just as server.go does;
  a caller constructing typed `DeviceConfig` can set an explicit marker.
- Client peers require endpoints; inbound peers learn endpoints through
  authenticated traffic. Cookie messages and failures never change endpoints.
- Keepalive intervals are bounded to the WireGuard u16 interval field.
- Server peers retain email/level. Client peers omit those server user fields.
- `DomainStrategy::select_addresses` produces the Go resolver's family candidate
  set, including fallback only when the preferred family has no answer. The
  runtime must still perform random selection, DNS caching/TTL and lookup.
- Remote DNS defaults to the four source Cloudflare addresses; `["local"]` is
  represented distinctly. DNS execution is still pending.

The wrapper validates MAC/cookies before the expensive anonymous identity
decrypt. BoringTun's public `Tunn` API also verifies the same incoming packet;
both passes share one limiter and cookie key. Its 200-verification budget allows
roughly 100 accepted handshake packets per second; cookies remain valid across
both checks. Transport packets are authenticated and replay-protected by the
provider. Invalid IP framing is checked before outbound encryption and after
inbound decryption; TCP/UDP/ICMP checksums belong to the receiving stack.

Deliberate validation differences: duplicate public keys and self/low-order peer
keys are rejected instead of relying on repeated UAPI updates. MTU is capped at
65,475 for the portable 65,507-byte IPv4 UDP payload limit. This is not a claim
of full source configuration parity or all platform endpoint syntax support.

## Remaining stream and platform integration

The Go client calls `Net.DialContextTCPAddrPort` and `DialUDPAddrPort`; these are
gVisor sockets on an in-memory IP interface, not plain host TCP sockets. Go's
server additionally configures promiscuous/spoofed addressing and TCP/UDP
forwarders that recover each destination and dispatch the connection through
Xray. Passing application stream bytes directly to this packet engine would be
incorrect.

A native userspace implementation needs an IP-facing device backed by this
engine, a TCP/UDP/ICMP stack with connection and timer management, socket buffer
backpressure, an AsyncRead/AsyncWrite bridge for outbound TCP, datagram sessions
for UDP, and inbound destination-aware forwarding. Source-equivalent fragment,
checksum, retransmission, DNS-over-tunnel, timeout/cancellation and connection
lifecycle behavior must be tested there. smoltcp's maintained Rust `Interface`,
`SocketSet`, socket buffers and device abstraction are candidates, not an
implemented adapter. Inbound arbitrary-destination forwarding would need
additional admission/flow handling around those sockets.

The inspected primary smoltcp example is
https://github.com/smoltcp-rs/smoltcp/blob/main/examples/client.rs ; its current
crates.io stable version was 0.14.0 on 2026-09-19. No smoltcp dependency is added
by this assignment.

An alternative OS TUN backend needs separate Linux/Windows/macOS interface,
route, privilege and cleanup implementations. The source Linux kernel TUN path,
`noKernelTun` backend selection, socket marks/interfaces, UDP masks, runtime DNS
selection, live add/remove users, policy/stats wiring and protobuf config
conversion remain outside this packet-engine delivery.

## Verification

All owned Rust files pass individual-file rustfmt. Embedded tests cover source
scenario keypair fixtures, JSON defaults/null/empty semantics, endpoint and
family parsing, cryptokey routing, actual Noise handshakes, queued delivery,
IPv4/IPv6 round trips, padding, reserved bytes, AEAD corruption, replay,
authenticated roaming, forced cookie exchange, mismatched PSKs, overlapping
source owners and second-peer receiver-index demultiplexing. These are packet
exchange tests, not an interoperable Go/platform process test or a TCP proxy
integration test.

On 2026-09-19 a standalone `rustc --test` harness compiled these exact module
files against the lead-built `target/debug/deps` libraries and passed all 16
tests (0 failed). The harness and executable lived in the OS temporary directory;
it made no Cargo call or shared target writes. Go's scenario variable names refer
to the remote configured public key rather than the local public identity; the
tests explicitly verify the correctly paired private/public fixture values.

The lead subsequently registered the module and confirmed all WireGuard tests
passed in the integrated 340-test xray-core run on 2026-09-19. That overall run
had two unrelated WebSocket/stale-XHTTP failures; it was not a clean workspace
pass. Neither result verifies WireGuard stream/runtime integration.
