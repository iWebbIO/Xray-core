# Shadowsocks 2022 UDP account and routing adapter

`shadowsocks2022::udp` connects the AES-only `shadowsocks2022::Account` to the
existing `protocol::shadowsocks_udp` wire codecs and sessions. AES-ECB header
protection, BLAKE3 session keys, AES-GCM authentication, SOCKS destination parsing,
packet counters, replay windows, timestamp validation, and client/server session
rotation continue to live in that existing module. No cryptography is duplicated.

The new behavior is socket-free authenticated return routing:

- `cipher(&Account)` creates the existing stateless `Cipher2022` using the same
  normalized PSK as TCP, including the parent's base64 CR/LF behavior.
- `Client::new(&Account, server_endpoint, rng)` creates a fresh random client
  session. `encode_request` returns encrypted bytes and their configured server
  endpoint. `accept_from` checks that endpoint before authenticating and admitting
  a reply, returning the reply origin and plaintext payload.
- `Server::accept_from(peer, wire, unix_now, now, rng)` returns an
  `AcceptedDatagram` containing the authenticated destination/payload, the packet
  source, and an opaque `SessionToken`. Only successful lower-level admission can
  create or rebind the return route.
- `Server::encode_reply(token, origin, payload, unix_now, now, rng)` validates the
  token, encodes a reply, and returns the latest authenticated peer endpoint. A
  token spans a client's destinations, so the caller supplies the actual response
  origin. Outstanding tokens follow authenticated NAT rebinding.
- Tokens use private allocation identity, so expired tokens cannot address a
  later session that happens to reuse the same numeric ID. Tokens from another
  `Server` instance also fail. Tokens are cloneable and cannot be constructed from
  a numeric session ID.
- Inactivity expiry is refreshed only by successful accepts and replies. Both
  tables expire together. Limits match the existing library: default 500 seconds
  and 4096 sessions; a configured timeout must be at least 61 seconds and capacity
  must be positive. Live entries are never evicted to admit another session.

One server object belongs to one account/listener. A caller must serialize its
mutations, supply a consistent Unix clock and monotonic `Instant`, forward each
accepted datagram to its destination, and send each returned `RoutedDatagram` to
its endpoint. This library does not open sockets or establish outbound NAT flows.
The client endpoint is fixed for its lifetime; create another client to change
servers. Source changes at the server are authenticated by the shared account key,
not by any independent proof of ownership of the new network address.

Scope remains single-account AES128/AES256. No multi-user identity headers, relay
chains, new UDP-only XChaCha account, runtime wiring, socket policies, or UDP Go
interop harness are added here. Direct stateless codec users remain responsible
for unique session/counter pairs and replay handling.

Pinned behavior references are `sing-shadowsocks v0.2.7`,
`shadowaead_2022/protocol.go` and `service.go`: `Service.NewPacket` authenticates a
client datagram and dispatches NAT traffic by its client session ID;
`serverPacketWriter.WritePacket` uses the NAT connection's current local address
for reply routing. The existing Rust primitive intentionally commits replay/session
state after all authenticated metadata validation, and enforces bounded capacity
without evicting live replay history.

Thirteen deterministic Rust tests cover both AES ciphers, existing independent
wire fixtures, shared account normalization, all supported address forms and empty
payloads, authenticated NAT rebinding, endpoint and client binding, truncation and
bit corruption, metadata/replay poisoning, bounded capacity, expired and foreign
tokens, exact inactivity expiry, and independent sessions behind one peer.

The migration lead runs shared validation after exporting `pub mod udp;` from
`shadowsocks2022.rs`, for example:

```text
cargo test -p xray-core protocol::shadowsocks2022::udp
```

This worker ran no Cargo or Go builds. Tests reuse the existing independently
generated AES/BLAKE3 vectors; they do not claim new pinned-Go UDP interoperability.
