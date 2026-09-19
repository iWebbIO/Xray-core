# Geodata module integration

Register `pub mod geodata;` in the core library and add `prost.workspace = true`
to its dependencies. Other dependencies (`anyhow`, `regex`, `tracing`, and
`xray-proto`) already exist. No generated schema changes are needed.

For routing, create a `GeoDataStore::from_env()` (or `new(asset_directory)`),
parse strings using `parse_ip_rules` / `parse_domain_rules`, then compile using
`build_ip_matcher` / `build_domain_matcher`. Domain parsing takes the generated
`domain::Type`; routing uses `Substr`, while other consumers can choose `Domain`.
Pass the SAME store to several compilers to share file and decoded-entry caches.
All protobuf API types are reexported from the module for callers' convenience.

`DomainMatcher::match_host` applies the source router's lowercase conversion.
`match_any` and `matching_rules` are the raw case-sensitive geodata API. The
latter returns zero-based original rule indices (duplicates allowed).

`IpMatcher::match_ip` accepts either source or destination IPs; the router chooses
the appropriate address. `any_match` is the destination multi-address OR API.
`matches` preserves the source's more restrictive behavior: one of the four
groups must match every address. It is not an `all(match_ip)` convenience alias.
Byte APIs reject invalid addresses; filtering drops invalids from both outputs.

Use `GeoDataRegistry::new(store)` to construct `Arc<DynamicDomainMatcher>` and
`Arc<DynamicIpMatcher>` when hot reload is needed. Rules must have been parsed
before moving the store into the registry. `reload()` refreshes both types,
validates all survivors before publishing, and preserves reversal overrides.
Dropped matchers are held only weakly. Reload failure leaves existing matchers
and cached files unchanged. Publication is atomic per matcher, not globally
atomic across a concurrent request using several matchers.

## Source semantics implemented

- Current `xray.common.geodata` protobuf schema, code lookup, unknown primitive
  fields, first duplicate code, and reordered code fields.
- All current rule prefixes, uppercase dataset codes, lowercase attribute names,
  repeated IP `!` XOR semantics, dotless expressions, and configurable default
  domain type. Geosite `!` characters remain literal names.
- Exact attribute presence AND; attribute values including false and zero do
  not change presence. Invalid external domain/CIDR records are skipped, while
  invalid custom domain regexes and IP literals fail configuration.
- Separate positive/negative custom and external IP unions, family-limited
  complements, normalized CIDR ranges, IPv4-mapped matching, and legacy on-disk
  reverse flags ignored. Runtime reverse operations affect each group.
- Case-sensitive regexes, lowercase non-regex patterns, boundary-aware domain
  suffixes, exact domains, keywords, and original rule indices.
- Asset environment lookup and non-Windows fallback directories; slash-relative
  regular files only. Symlinks follow the same filesystem behavior as Go.

## Explicit remaining differences / boundaries

- Regex compilation uses Rust's `regex` crate. Its Unicode shorthand character
  classes, supported inline flags, and character-class expression syntax are
  not identical to Go's regexp dialect. Ordinary ASCII geosite patterns work,
  but this is not a claim of full RE2 syntax parity.
- Full/suffix lookup uses hash maps, CIDRs use merged numeric intervals and binary
  search, and keyword/regex matching is linear. Go's minimal perfect hashing,
  Aho-Corasick, and IP batch heuristics are not ported.
- This implementation retains complete indexed file bytes and decoded requested
  entries until cache clear/reload. Go streams a selected entry and uses weak
  matcher caches. Peak memory differs, particularly for large geoip databases.
- The index validates the entire protobuf file, so corruption after a requested
  entry fails loading too. Deprecated protobuf group wire types are rejected.
- Environment roots are captured when constructing the store. Reload refreshes
  its data, not process environment settings. Update/download scheduling belongs
  to `app/geodata` and is outside this module; no network operations are performed.

The unit tests live in this subtree. Fixtures are independently assembled wire
bytes documented in `fixtures/README.md`, not protobuf encoder round trips.
