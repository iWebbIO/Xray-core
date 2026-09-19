# Native DNS module

Assignment 9 adds `xray_core::dns` behind a lead-owned `pub mod dns;` export.
Only `rust/xray-core/src/dns.rs`, `rust/xray-core/src/dns/`, and this note are
owned by this assignment. No configuration/runtime/Cargo files are changed.

## Implemented APIs

`Resolver::new(ResolverConfig)` creates a cheaply cloned, shared-cache resolver.
Configuration contains:

- `servers: Vec<Upstream>`: ordered UDP/TCP endpoints with explicit numeric
  `SocketAddr` values. `Upstream::parse` accepts bare IPs, IP:port,
  `udp://IP[:port]`, and `tcp://IP[:port]`. An omitted port becomes 53.
- `timeout: Duration`: five seconds by default, per upstream including any TCP
  retry. Transport failures and SERVFAIL/REFUSED advance to the next configured
  server. A final DNS error reply retains its RCODE; NXDOMAIN/NODATA are final.
- `cache: CacheConfig`: enabled by default, maximum 4096 question entries,
  oldest-inserted eviction. `serve_stale` and `max_stale` implement stale reads
  with a one-second returned TTL and an asynchronous refresh. Zero `max_stale`
  permits unlimited stale age; stale serving is disabled by default.
- `client_ip: Option<IpAddr>`: Xray-compatible EDNS client subnet, IPv4 /24 or
  IPv6 /96, UDP payload 1350, DNSSEC OK. This deliberately reproduces the Go
  source's unusual `SetEDNS0(1350, 0xfe00, true)` OPT TTL `0xe0008000`.
- `tcp_fallback: bool`: false by default, preserving the classic Go UDP
  behavior. When enabled, a matching TC datagram triggers an explicit TCP retry
  even when its answer section ends mid-record.
- `hosts: HashMap<String, HostEntry>`: exact case-insensitive address lists,
  aliases, and response codes. Aliases allow at most five indirections; cycles
  fail explicitly. A resolver with no servers is valid for static-only use;
  an unmapped name then returns a configuration error.

`query(domain, RecordType::A | RecordType::AAAA)` returns `DnsAnswer` with
`ips`, `ttl`, `response_code`, `from_cache`, and `stale`. Successful empty
answers retain RCODE 0 (NODATA); missing names retain RCODE 3 (NXDOMAIN).
`lookup_ip(domain, QueryOptions::{IPV4,IPV6,BOTH})` returns `LookupResult`
or typed `DnsError::EmptyResponse`/`ResponseCode`. BOTH queries run concurrently
and combine valid IPv4 addresses before IPv6 addresses. The combined TTL is
capped at 300 seconds like Go's `merge`; a single-family TTL is not capped.
Matching IP literals require no DNS exchange. Disabled address families fail
explicitly. `clear_cache` and `cache_len` support runtime administration.

The cache keeps A/AAAA and negative results separate, uses minimum TTL across
all answer headers (including CNAME), clamps zero answer TTL to one second,
defaults to 300 seconds if there are no answers, and rounds remaining TTL
upward. Concurrent misses for a cache-enabled key share the exchange. Cache
disabled/zero-capacity operation does not deduplicate successful responses
after the first exchange completes. Negative TTL follows the Go answer-section
policy rather than RFC 2308 SOA minimum/TTL selection.

`DnsService::new(resolver, ServiceConfig)` provides:

- `handle_query(&[u8])` for full DNS messages and `handle_udp_query(&[u8])` for
  EDNS-aware datagram size limits.
- `Arc<DnsService>::serve_udp(UdpSocket, CancellationToken)` and
  `serve_tcp(TcpListener, CancellationToken)`. Callers explicitly bind sockets;
  the module never chooses a listening address. Both loops limit concurrent
  work and abort/drain active workers on cancellation. Default concurrency is
  256, maximum UDP output 1350 bytes, TCP idle timeout 60 seconds.
- `serve_connection(stream)` accepts any `AsyncRead + AsyncWrite + Unpin`,
  including `transport::BoxStream`. It handles multiple length-prefixed
  requests on one connection, preserving request order.
- `read_tcp_message` / `write_tcp_message` are separately exported generic
  two-byte framing helpers. Clean EOF, partial prefixes, partial bodies, and
  invalid frame sizes are distinguished.

The service mirrors `proxy/dns` default rules: A/AAAA are resolved internally;
other IN types get an empty NOERROR response. In the Go `Process` switch,
`RuleAction_Return` calls `rejectNonIPQuery`; only `RuleAction_Direct` forwards
upstream. Replies preserve the question/transaction ID and set AA, RD, RA, and
QR as Go does. Malformed requests receive FORMERR when an ID is available;
unsupported opcodes receive NOTIMP, non-IN classes REFUSED, and EDNS versions
other than zero BADVERS. Network failures remain errors for direct calls and
produce no fabricated successful reply in socket loops. UDP oversized replies
contain only complete records and set TC. Response packets sent to the query
service are ignored rather than answered.

`dns::wire` exposes strict name/query/response/message codecs. Decoder bounds
section counts, expanded names, pointer jumps, record lengths, and EDNS option
lengths. Unknown RDATA remains opaque and is never copied into a rewritten
message. UDP sockets are connected to the configured upstream; responses must
match random transaction ID, QR, opcode, one question, type, class, and name.
TCP replies use the same checks. Address extraction follows the queried name's
in-message CNAME chain and excludes unrelated answer names as a deliberate
hardening relative to Go's unfiltered address extraction.

## Integration and remaining gaps

Dependencies already available in the crate: `std`, `rand`, `tokio`, and
`tokio-util`. The lead must export the module and map supported configuration
into these typed constructors; unsupported settings must be rejected rather
than discarded.

Not implemented here:

- DoH/HTTP3, DoT, QUIC DNS, system/localhost resolution, FakeDNS and FakeDNS
  pool/reverse maps. `Upstream::parse` rejects those schemes and names.
- DNS-server hostname bootstrap, dispatcher/routing-tag/policy integration,
  custom outbound dialers, remote versus `tcp+local` selection. Upstream
  connections currently use Tokio's system UDP/TCP sockets directly.
- Domain/geodata/regexp/suffix host rules, expected/unexpected-IP filters,
  server priority/final-query policy, fallback-if-match, parallel server
  racing, per-server cache/policy/client-IP configuration, and UseSystem family
  selection. The resolver's explicit ordered endpoints are a smaller API.
- DNS outbound Direct/Drop/custom rules, server rewrites, and arbitrary-record
  forwarding. Unsupported record types are available in the wire codec, but
  `Resolver::query` accepts only A and AAAA.
- External follow-up queries for CNAME-only replies, DNSSEC validation,
  arbitrary binary/escaped DNS labels, IDNA conversion, EDNS padding, and
  general RR re-encoding. Name input is ASCII; callers may supply punycode.
- Fine-grained Go pubsub/singleflight cancellation semantics. Cache-disabled
  queries are serialized per key and can repeat rather than sharing a retained
  successful result. Stale refresh is detached and limited by query timeouts.

## Validation

The module includes 25 tests covering query/answer golden bytes, compressed
CNAME records and lengths, maximum names, malformed compression/counts/RDATA,
EDNS client subnet bytes/version/size negotiation, TTL expiry/staleness,
negative cache distinction and capacity, family selection, simultaneous cache
misses, UDP spoof/mismatch rejection, TCP short reads and mismatches, optional
TC retry from a partial UDP answer, timeouts, aliases/cycles, and local UDP/TCP
service round trips, malformed-request recovery, multiple frames, cancellation.

`rustfmt` parses all owned Rust files. Ten std-only wire/cache tests were also
compiled with `rustc --test` in a temporary standalone harness importing the
actual production files; all ten passed. No Cargo command or shared target
directory was used. Async/module integration tests are for the lead's normal
build/test pass; do not report them as executed based on this note alone.

Behavior references: `app/dns/dnscommon.go`, `app/dns/nameserver_udp.go`,
`app/dns/nameserver_tcp.go`, `app/dns/cache_controller.go`,
`app/dns/nameserver_cached.go`, `app/dns/hosts.go`, `proxy/dns/dns.go`, and
`features/dns/client.go`. EDNS bit layout checked against the repository's
cached `golang.org/x/net@v0.58.0/dns/dnsmessage/message.go` dependency.
