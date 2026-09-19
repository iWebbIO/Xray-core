# Native TUN migration boundary

This module implements portable raw-IP packet handling, source-keyed UDP session
lifecycle, route planning/rollback and an optional userspace TCP stack. The live
device adapter is Linux only. It is not a complete replacement for Go's gVisor
TUN implementation or a claim that configured TUN inbounds are already wired into
the Rust application's dispatcher.

## Source mapping

| Go source | Rust component |
| --- | --- |
| `proxy/tun/icmp/packet.go`, `stack_gvisor_icmp_handler.go` | `protocol/tun/packet.rs`: IPv4/IPv6 local echo replies, identifier/sequence/payload preservation, checksum rewrite and fresh IP headers |
| `proxy/tun/stack_gvisor.go:writeRawUDPPacket` | `packet::build_udp`: raw UDP/IP encoding, hop limit 64 and IPv4/IPv6 pseudo-header checksums |
| `proxy/tun/udp_fullcone.go` | `session::UdpSessions`, `native::run_udp`: key by client source address/port, preserve each datagram's destination, permit replies from other remote addresses |
| `proxy/tun/tun_linux.go` | `route`: host-preserving interface CIDRs, canonical route prefixes, metric 1, reverse-order teardown, default outbound selection excluding TUN/down/loopback interfaces |
| `proxy/tun/handler.go`, `stack_gvisor.go` | `native`: explicit lifecycle, packet pumps, TCP stream delivery to a caller-owned dispatcher |

The portable parsers validate checksums and declared lengths before dispatch. They
reject fragment reassembly and IPv6 extension headers with `Unsupported`; they do
not treat those bytes as a TCP or UDP header. Oversized UDP replies return an
error instead of wrapping a length field or claiming to have fragmented data.
Computed-zero UDP checksums are encoded as `0xffff`, including IPv6.

## Public integration API

The default module requires only the standard library:

- `TunConfig::{validate, validate_native}` validates all known configuration before
  device creation. `gateway: Vec<IpPrefix>` contains **interface addresses**, not
  router next hops. MTU is limited to the supported dual-stack range 1280–65535.
- `packet::{parse_ip, parse_udp, validate_tcp, parse_echo_request, build_echo_reply,
  build_udp, build_ip, checksum}` handles complete L3 packets without Ethernet or
  TUN packet-information headers.
- `route::{IpPrefix, plan_routes, select_outbound_interface}` plans addresses and
  route selection without changing the host. `RouteTransaction::{apply, close}`
  uses an explicit `RouteBackend`, reports errors, retains failed removals for
  retry, and never deletes an entry whose add operation failed. There is no OS
  route backend in this assignment. Call `close` before releasing an interface.
- `session::UdpSessions::{register, accept_reply, expire, remove, close}` manages
  bounded, idle-expiring associations. A `SessionKey` includes a generation so
  old replies cannot revive a reused client source port.

With `xray-core` feature `native-tun` enabled:

- `native::channels(capacity)` returns `(Endpoint, Dispatcher)`. Run the endpoint
  and consume `Dispatcher.events` concurrently. Its `udp` field is a cloneable
  reply handle.
- `native::run_native(config, endpoint, CancellationToken)` creates an L3 Linux
  TUN with the requested name, MTU and interface addresses. Device read/write,
  stack and event pumps share one lifetime. No spawned background pump survives
  the future. Dropping the owned descriptor destroys a newly created Linux TUN.
- `native::run_packets(config, ingress: Receiver<Vec<u8>>, egress: Sender<Vec<u8>>,
  endpoint, CancellationToken)` runs the same actual TCP stack and UDP/ICMP
  handlers over raw-packet channels. It does not open a device or alter the host.
- `TunEvent::Tcp { stream, source, destination }` provides a
  `netstack_smoltcp::TcpStream` implementing Tokio `AsyncRead + AsyncWrite +
  Unpin + Send`; it can be boxed as `crate::transport::BoxStream`. The addresses
  are client source and original target. Route this through the normal Xray
  dispatcher; the module never dials a target itself.
- `TunEvent::Udp { session, is_new, destination, payload }` retains per-packet
  destinations. Create one dispatcher association per `SessionKey` and close it
  on `TunEvent::UdpClosed`. Unlike the Go implementation, queues here are bounded
  globally, and the explicit source-session limit bounds the association table.
- `UdpReplies::send(session, remote, payload).await` validates the active
  generation, family and MTU and queues the raw return packet. Success means
  queued to the packet output channel; observe the runtime result for later
  device I/O errors. `UdpReplies::close(session).await` requests removal.

The caller must consume events concurrently with replies and close all its
dispatched TCP/UDP sessions when the runtime ends or its event channel closes.
Cancellation remains responsive even when an event or packet output consumer is
blocked. Packet/dispatcher channel closure is an error; cancellation is a normal
shutdown. Inbound malformed or unsupported traffic is dropped with debug logging.
Full UDP queues drop datagrams, matching Go's congestion behavior rather than
stalling all raw packet reception.

## Optional dependencies

The manifest owner adds these; this assignment does not edit shared manifests:

| Dependency | Version/features used |
| --- | --- |
| `tun-rs` | `2.8.9`, `async_tokio`, optional |
| `netstack-smoltcp` | `0.2.4`, optional |
| `futures-util` | `0.3`, `sink`, optional |

`native-tun = ["dep:tun-rs", "dep:netstack-smoltcp", "dep:futures-util"]`.
Tokio and tokio-util use the existing workspace dependencies.

Published crate sources and builder/stream APIs were inspected on September 19,
2026. `tun-rs` 2.8.9 was published September 1, 2026; `netstack-smoltcp` 0.2.4 was
published July 10, 2026. Upstream source locations:

- <https://github.com/tun-rs/tun-rs>
- <https://docs.rs/tun-rs/2.8.9/tun_rs/struct.DeviceBuilder.html>
- <https://github.com/cavivie/netstack-smoltcp>
- <https://docs.rs/netstack-smoltcp/0.2.4/netstack_smoltcp/>

The Linux builder has no `.persist(...)` option; the new Linux interface is
nonpersistent by default. Offloads and multiqueue are disabled so checksummed
individual L3 packets reach the strict parser. Existing named interfaces and
inherited `xray.tun.fd`/`XRAY_TUN_FD` descriptors are rejected. The preflight
existing-name check is not an atomic kernel-level reservation; startup assumes no
other process concurrently creates the same interface name.

## Explicit remaining work

- Integrate the module export, configuration conversion, dispatcher, inbound user
  level, sniffing, idle policy, accounting and runtime shutdown in the shared code.
  A parsed TUN configuration must not be accepted as operational without this.
- Automatic OS route installation, route monitoring and socket outbound-interface
  binding need a native OS backend. Route helpers alone do not install routes.
  Configuring `auto_system_routing_table` or `auto_outbounds_interface` currently
  fails before device creation.
- System DNS changes and interface descriptions fail explicitly. The current
  adapter supports one IPv4 interface prefix and multiple IPv6 prefixes; multiple
  IPv4 prefixes fail rather than silently replacing earlier ones.
- Live Windows, macOS, Android, FreeBSD and other OS adapters are unsupported.
  Dependency support for those systems does not establish Xray integration.
- No IPv4/IPv6 fragment reassembly, IPv6 extension headers/jumbograms, ICMP error
  translation, IPv6 neighbor discovery, PMTU handling or jumbo UDP fragmentation.
  ICMP support is the Go-style local echo response only.
- smoltcp is a different TCP stack from gVisor: congestion control, buffer tuning,
  keepalive/recovery and connection admission are not gVisor-equivalent. Its
  listener can expose a stream on the initial SYN before the handshake finishes.
  The application must impose outbound connection policy and concurrency limits.

## Verification

Ran `rustfmt` on owned Rust sources and an isolated standard-library-only
`rustc --test` harness, outside the shared Cargo target. The portable tests cover
independent Python-generated ICMP/UDP/TCP golden packets, odd-length checksums,
malformed/truncated packets, wire size limits, IPv6 mandatory UDP checksum,
fragment/extension rejection, CIDR rules, route cleanup failure/retry, full-cone
session reuse and stale-generation rejection, and unsupported settings.

Feature-gated tests in `native_tests.rs` are written for the actual userspace
stack: TCP SYN/SYN-ACK/ACK and bidirectional payload, UDP destination changes and
full-cone replies, ICMP golden replies, ingress failure, blocked-consumer
cancellation, and explicit non-Linux startup rejection. These require the lead's
Cargo integration run; the assignment worker did not run shared Cargo builds.

Lead-owned checks, after exporting `protocol::tun`:

```text
cargo test -p xray-core protocol::tun --lib
cargo test -p xray-core --features native-tun protocol::tun --lib
cargo check -p xray-core --features native-tun --target x86_64-unknown-linux-gnu
```

The Linux cross-check requires its target toolchain. No privileged live-device
test, host route change, DNS change, Go subprocess, Go FFI, or live tunnel success
is claimed by these tests.
