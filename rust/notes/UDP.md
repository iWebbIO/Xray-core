# Native UDP protocol helpers

Implemented in `xray-core/src/protocol/udp.rs` with the existing `anyhow` and
`tokio` dependencies. The module contains codecs and session state, not listener
or outbound dispatch integration.

## Integration

- Export `protocol::udp` from `protocol/mod.rs`.
- SOCKS5: after authenticating UDP ASSOCIATE (command 3), bind a UDP socket and
  return its relay address in the SOCKS success response. Construct
  `Socks5UdpSession::new(tcp_peer, requested_source, idle_timeout, Instant::now())`.
  `requested_source` may contain port zero and must not be constructed with
  `Destination::new`, which rejects zero. Keep the TCP control connection open.
  Feed `recv_from` results to `session.receive(source, packet, now)`; `Ok(None)`
  means the source or session state rejected the packet. Dispatch accepted
  `Datagram` values. Encode replies with `encode_socks5_packet`, obtain the client
  endpoint through `response_target`, and send there. Never use the UDP payload's
  destination as the client endpoint. Call `close_tcp` on TCP EOF/error, schedule
  timeout checks using `idle_remaining`/`is_open`, and close both sockets on
  closure. Session mutations must be serialized by the caller.
- Trojan: authenticate and accept request command 3 before calling
  `read_trojan_frame`/`write_trojan_frame`. Each frame carries its own destination;
  response frames use the actual remote sender as their destination field.
- VLESS: authenticate and accept request command 2 before calling
  `read_vless_frame`/`write_vless_frame`. These frames only contain a two-byte
  big-endian payload length. Use the destination from the VLESS request for every
  payload. Send/read the normal VLESS response header before response frames.
  XUDP/multiplexing and Vision flow rules are outside these base UDP helpers.
- Both stream readers return `Ok(None)` only at a frame boundary. EOF inside a
  frame is an error. Close the stream after a failed or cancelled frame operation
  because it may already have consumed/emitted a prefix. The slice decoders
  return consumed lengths so a caller can retain subsequent coalesced frames.

## Source behavior and deliberate differences

- SOCKS uses `proxy/socks/protocol.go`'s three-byte prefix and the common
  SOCKS address serializer. Reserved bytes are ignored; all nonzero fragment
  values are rejected. Empty payloads are represented without inventing data.
- `proxy/socks/protocol.go:handshake5` and `temp_udp_listen.go` define source
  selection: unspecified/domain sources use the TCP peer's IP and a learned UDP
  port; concrete source IPs preserve a specified port, or learn port zero.
  IPv4-mapped IPv6 addresses compare equal to IPv4. Wrong-source traffic does not
  refresh the timeout. The first permitted source is pinned even when the
  packet subsequently fails parsing, matching Go's read-before-decode order.
- SOCKS encoding enforces Go's 8192-byte total buffer limit. Oversize encoding
  returns an error instead of an empty drop buffer. The slice decoder accepts
  arbitrary input lengths; the socket owner controls its receive buffer size.
- Association expiry uses an exact monotonic inactivity deadline. Go's
  `ActivityTimer` checks periodically and can expire later within a check
  interval. Zero timeout closes immediately, and closure cannot be reversed.
  Selecting a reply target refreshes activity, as Go does before a socket write.
- Trojan uses `proxy/trojan/protocol.go`'s SOCKS address, big-endian payload
  length, CRLF, then payload. Its reader's 8192-byte payload limit is enforced on
  both encode and decode. Malformed CRLF is rejected rather than merely consumed
  as in Go. A zero-length frame remains a distinct decoded empty datagram.
- VLESS follows `proxy/vless/encoding/addons.go:LengthPacketReader` and
  `LengthPacketWriter`, supporting the full 16-bit length range without Go buffer
  splitting. Empty writes emit no bytes as in Go; received zero-length frames
  decode successfully. Oversize writes fail instead of wrapping the length.
- Domain decoding follows the common Go address parser's ASCII hostname
  validation. Only domain wire values beginning with `[` or an ASCII digit are
  considered for IP parsing, with matching brackets removed before trimming
  surrounding Unicode whitespace. If IP parsing fails, the original domain
  bytes must satisfy hostname validation. Raw `::1` and `abcd::1` domains are
  rejected; bracketed equivalents are accepted. Both slice and stream readers
  use the same raw-domain decoder. IPv4-mapped IPv6 values become IPv4 for binary
  addresses, parsed domain addresses, and encoding. Domain encoders preserve the
  supplied wire text but reject values the decoder cannot accept, a stricter
  check than Go's length-only domain writer. Empty or invalid domains are
  rejected. Port zero is preserved at the codec layer; destination dispatch
  policy belongs to the caller.

## Verification

Inline tests use literal source-derived IPv4/domain/IPv6 vectors, including the
IPv6 address and port from Go's `TestUDPEncoding`. They check all SOCKS fragment
values, malformed domains, truncation, size boundaries, coalesced packets,
one-byte-at-a-time stream reads, clean EOF versus truncation, session source
checks, activity renewal, and permanent closure. The migration lead owns combined
Cargo test execution; this workstream performs only individual rustfmt and
independent fixture checks to avoid shared build contention.
