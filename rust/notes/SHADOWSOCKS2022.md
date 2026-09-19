# Native Shadowsocks 2022 TCP

The implementation lives in `protocol/shadowsocks2022.rs` and its `codec`,
`stream`, and `tests` submodules. Wire behavior is derived from the repository's
pinned `github.com/sagernet/sing-shadowsocks v0.2.7`, specifically
`shadowaead_2022/{protocol,service}.go` and `shadowaead/aead.go`. Address handling
also uses the main module's `github.com/sagernet/sing v0.5.1` metadata serializer.

Supported scope is **single-account AES128/AES256 TCP**:
`2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`. Colon-separated identity
key chains are rejected explicitly. EIH, multi-user service/relay, ChaCha2022,
and UDP are not implemented by this module. Existing legacy Shadowsocks and UDP
modules are unchanged. No Go subprocesses or FFI are used.

## Integration

Export `pub mod shadowsocks2022;` from the parent protocol module. All dependencies
are already available: aes-gcm, blake3, base64, sha2, subtle, rand, zeroize,
anyhow, and Tokio.

Construct `Account::new(kind, base64_psk, email)` once per configured listener or
remote; clones share replay state. `Account::from_key` accepts decoded PSKs.
Like the pinned Go constructors, keys longer than the cipher key size use
SHA256 truncated to 16/32 bytes; shorter keys fail. Base64 CR/LF are ignored as
in Go. Debug output excludes the key.

- `accept(BoxStream, &Account) -> Result<(BoxStream, Request)>` authenticates the
  request, timestamp, destination, padding, and first variable record before
  returning. `Reply::None` is used. `initial_payload` is empty because any
  application bytes in the first variable record remain buffered in the returned
  stream. The encrypted response starts on first application write, flush, or
  shutdown, so accept/read alone cannot signal routing success.
- `connect(BoxStream, &Account, &Destination) -> Result<BoxStream>` emits a fresh
  request with salt and nonempty padding. It returns without waiting for a
  response. The first read validates response type, timestamp, echoed request
  salt, AEAD tags, and response-salt replay before exposing plaintext.

The caller supplies handshake deadlines and connection/socket policy. Following
the pinned server, the salt plus fixed request record must arrive in one initial
transport read; a short initial read fails. A generic BoxStream cannot implement
socket linger, probe draining, or traffic-shape camouflage. Cancellation of an
owning accept/connect future drops the transport. Once established, partial
read/write/flush/shutdown offsets persist in the stream. Pending writes are also
driven while reading without blocking the incoming direction on outgoing
backpressure.

## Wire and validation

Session subkeys use BLAKE3 derive-key context `shadowsocks 2022 session subkey`
over `PSK || salt`. AES-GCM uses a 12-byte little-endian nonce counter, initially
zero, with no associated data. Counters never wrap. Request fixed and variable
records consume nonces 0 and 1; ordinary length/payload records start at 2.
Response fixed records include the request salt. Records carry a full 16-bit
length, supporting up to 65,535 plaintext bytes. Buffers are bounded accordingly.

Timestamp acceptance is inclusive at +/-30 seconds. Replay caches fail closed
at 65,536 entries and do not evict live salts to admit new sessions. Unlike the
pinned server's pre-authentication insertion, received salts are inserted only
after complete first-record authentication and validation. Retention is 61
seconds rather than 60, covering the inclusive timestamp window's whole-second
rounding. Generated salts are independently checked for local reuse.

Clean transport EOF is accepted only between complete ordinary records. EOF
inside any salt, fixed header, length record, or payload record is a terminal
truncation error. Authentication errors remain terminal across read/write/flush/
shutdown. Zero-length authenticated body records do not become application EOF.
An empty first response includes the empty AES-GCM tag expected by the pinned
client's `ReadWithLength(0)`; the pinned Go server omits that tag on a zero-byte
initial Write, so this implementation follows the receiving layout in that case.
Domain destinations require valid UTF-8 through the existing Rust address API;
port zero is rejected. Literal and bracketed IPs are normalized on reception.

## Validation status

Twelve literal BLAKE3/AES-GCM request, response, empty-response, and subsequent
record fixtures were independently computed and rechecked with Python blake3
and cryptography. Module tests cover both ciphers, PSK/EIH validation, timestamps,
replay capacity/expiry, first payload preservation, request/response binding,
tampering, every truncated first-response/body-record prefix, maximum-size
records, half-close, and one-byte transport I/O interrupted by Pending and
cancelled operations. Individual rustfmt passed. The migration lead owns all
Cargo builds and test runs; tests are pending that combined validation. No
end-to-end interoperability run against a Go peer has been performed.

An executable test peer is supplied at
`rust/xray-core/src/protocol/shadowsocks2022/fixtures/go-peer/main.go`. It imports
the pinned Go implementation directly and tests actual TCP sessions in both
directions, both AES ciphers, and application writes spanning multiple 65,535-byte
records. To run it, the lead can build from the repository root:

```powershell
go build -o "$env:TEMP/ss2022-go-peer.exe" ./rust/xray-core/src/protocol/shadowsocks2022/fixtures/go-peer
$env:XRAY_SS2022_GO_PEER = "$env:TEMP/ss2022-go-peer.exe"
cargo test -p xray-core pinned_go_tcp_interoperability_both_directions_and_ciphers -- --ignored --nocapture
```

These commands have not been run by this worker. The fixture process is only
used by the explicitly ignored interoperability test, never by native sessions.
