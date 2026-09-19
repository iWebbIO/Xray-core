# Network DNS runtime wiring

The adapter is implemented in `dns::network`; the top-level configuration and
dispatcher integration remain the integration owner's changes. Keep the existing
source policy in `config::dns::CompiledDns`: do not repeat server selection,
static-host lookup, address-family restrictions, filtering, or fallback in the
runtime connector.

## Compile and store

1. Add `pub dns: Option<dns::DnsConfig>` to `config::Config`.
2. Add `pub dns: Option<Arc<dns::CompiledDns>>` to `ValidatedConfig`.
3. In `Config::compile`, compile a present DNS configuration using the configured
   geodata store (or `GeoDataStore::from_env()?` where no shared store exists):

   ```rust,ignore
   let dns = self.dns.as_ref().map(|config| {
       let geodata = crate::geodata::GeoDataStore::from_env()?;
       config.compile(&geodata).map(std::sync::Arc::new)
   }).transpose()?;
   ```

   Store that `dns` in `ValidatedConfig`. The compiled policy owns its matchers;
   the store does not need to outlive compilation. Preserve `None` as the existing
   no-configured-DNS behavior. Replace the old test that rejects every top-level
   `dns` field with positive integration and unsupported-setting tests.

## Construct before accepting traffic

For each configured policy, construct exactly one shared `NetworkDns`:

```rust,ignore
let resolver = crate::dns::network::NetworkDns::new(
    compiled_dns.clone(),
    connector,                 // Arc<dyn dns::network::Connector>
    bindings,                  // HashMap<usize, ServerBinding>
    crate::dns::network::Limits::default(),
)?;
```

Binding keys are compiled server indices. An empty binding map uses normal TLS
verification, numeric URL hosts, and complete static-host results for named
encrypted endpoints. A programmatic `ServerBinding` can supply explicit numeric
`bootstrap: Vec<IpAddr>` and `tls: Option<TlsSettings>`. Do not invent a source JSON
bootstrap field. Missing bootstrap, unresolved static aliases, contradictory
numeric overrides, unknown binding indices, and resource-bound violations fail
construction. Neither construction nor query falls back to the system resolver.

Perform construction and bootstrap checks before binding/starting listeners or
probes. `NetworkDns::new` creates no asynchronous tasks. Actual stale refreshes
start only on lookups. Install the resolver on all intended DNS consumers before
those consumers can start work; propagate construction failure through startup.

**Avoid an ownership cycle:** `NetworkDns` owns `Arc<dyn Connector>`. If
`Dispatcher` stores `NetworkDns`, its connector must hold `Weak<Dispatcher>` or
separately shared routing state, never `Arc<Dispatcher>`. A practical pattern is
an initially empty `OnceLock<NetworkDns>` on an `Arc<Dispatcher>`: construct the
connector from `Arc::downgrade(&dispatcher)`, construct the resolver, set the slot
once, and only then start listeners/probes. An expired weak dispatcher must
return an I/O error. No recursive lookup is needed to initialize the slot.

## Implement the connector

`Connector` has three methods returning the supplied `IoFuture` alias:

- `route(RouteRequest, &CancellationToken) -> CheckedRoute`
- `connect_tcp(&CheckedRoute) -> BoxStream`
- `connect_udp(&CheckedRoute) -> Box<dyn Datagram>`

`RouteRequest` exposes the logical host, DNS tag, server index, source local/routed
mode, network, and immutable numeric candidates. Select the outbound using the
logical host/tag/network, then bind that decision to the original request. Source
`app/dns/nameserver.go` replaces the inbound with `Inbound { Tag: c.tag }` for a
nameserver request, leaving its inbound protocol empty. Preserve that behavior
when applying Freedom rules; do not inherit the original end-user protocol's
private-target default. TCP DNS separately sets content protocol `dns`, and DoH
sets content protocol `https`; these content values are not inbound protocols.

For explicit `DialMode::Local`, delegate both route and transport operations to
`LocalConnector`. This path dials numeric addresses directly and does not inherit
unrelated Freedom outbound rules. `LocalConnector` rejects routed endpoints.

For Freedom, call `CheckedRoute::admit_freedom(request, route_id, rules,
inbound_protocol, cancel).await`. This checks every original numeric candidate
with `FinalRules::block_delay` and the actual TCP/UDP network, honors cancellation
while delaying a block, and rejects the complete plan if any candidate is denied.
Do not call `FinalRules::admit(domain)`, which can resolve again and assumes TCP.
Reject a Freedom outbound with a redirect until a distinct admitted redirect
plan exists: the current checked plan authorizes the original DNS target only.

For a supported non-Freedom proxy, use
`CheckedRoute::for_proxy(request, route_id)`. The route ID must identify the
runtime's selected outbound plan. Independently pin and admit that proxy's outer
server endpoint; a named proxy endpoint needs explicit numeric/static bootstrap
or a clear rejection. Never recursively resolve it through the same DNS adapter
or silently call the system resolver. Freedom private-target rules are not
applied to DNS targets tunneled through a different outbound.

**Existing `runtime::establish` argument distinction:** its `resolved` parameter
is for the outer remote endpoint. For a proxy, pass the chosen numeric DNS target
as the tunneled `target`, and the separately pinned/admitted proxy endpoint list
as `resolved`. Do not pass DNS target candidates as proxy-server addresses. For
direct Freedom with no redirect, both refer to the admitted DNS destination.

Transport methods receive only `CheckedRoute::candidates()` and a route ID, not
a hostname to resolve. Select only from that numeric set. Return raw TCP; the
encrypted client retains original TLS identity, SNI, and HTTP authority. UDP must
provide a connected transport restricted to the chosen peer. Reject unsupported
outbound/transport combinations explicitly. Dropping any route/connect/exchange
future must release its owned I/O and tasks.

## Query, bridge UDP, and shut down

Call `resolver.lookup(name, QueryOptions::BOTH, &server_cancel).await` and consume
`LookupResult { ips, ttl }`. The existing UDP routing adapter accepts a resolver
closure with an owned hostname and an owned asynchronous result:

```rust,ignore
let dns = resolver.clone();
let cancel = server_cancel.clone();
let udp_resolver = move |host: String| {
    let dns = dns.clone();
    let cancel = cancel.clone();
    async move {
        dns.lookup(&host, crate::dns::QueryOptions::BOTH, &cancel)
            .await.map(|answer| answer.ips).map_err(std::io::Error::other)
    }
};
```

Preserve DNS failure as failure; never install `SystemResolver` as a fallback for
a configured resolver. It remains an explicit option only when DNS is absent.

Each foreground server attempt uses its configured timeout. Stale refreshes have
a separate eight-second budget, independent of the triggering caller's token.
On server shutdown, cancel foreground consumers and call
`resolver.shutdown().await` to join every tracked refresh. All clones share that
shutdown state and reject subsequent queries. Dropping the last resolver owner
cancels refreshes too; this is why the weak-connector ownership rule matters.

The implementation shares bounded per-server classic/encrypted caches and
coalesces identical in-flight family sets. It preserves source case-sensitive
cache keys, ceil TTLs, dual-family merge and negative-cache behavior. The native
wire parser intentionally validates response identities, record owners/classes,
and CNAME chains more strictly than the Go parser. DoT is a native extension.
