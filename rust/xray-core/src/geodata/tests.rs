use std::{
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;

const IP_HEX: &str = include_str!("fixtures/geoip.hex");
const SITE_HEX: &str = include_str!("fixtures/geosite.hex");
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "xray-geodata-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(DEFAULT_GEOIP_FILE), hex(IP_HEX)).unwrap();
        fs::write(path.join(DEFAULT_GEOSITE_FILE), hex(SITE_HEX)).unwrap();
        Self(path)
    }
    fn store(&self) -> GeoDataStore {
        GeoDataStore::new(&self.0)
    }
    fn write(&self, file: &str, contents: &[u8]) {
        fs::write(self.0.join(file), contents).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hex(text: &str) -> Vec<u8> {
    let chars: Vec<_> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(chars.len() % 2, 0);
    chars
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}
fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}
fn ip_matcher(store: &GeoDataStore, values: &[&str]) -> IpMatcher {
    store
        .build_ip_matcher(&store.parse_ip_rules(&strings(values)).unwrap())
        .unwrap()
}
fn domain_matcher(store: &GeoDataStore, values: &[&str]) -> DomainMatcher {
    store
        .build_domain_matcher(
            &store
                .parse_domain_rules(&strings(values), domain::Type::Substr)
                .unwrap(),
        )
        .unwrap()
}
fn replace_bytes(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .unwrap();
    bytes[at..at + to.len()].copy_from_slice(to);
}

#[test]
fn independent_wire_fixtures_decode_through_asset_store() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let private = store.load_geoip(DEFAULT_GEOIP_FILE, "PRIVATE").unwrap();
    assert_eq!(private.len(), 2);
    assert_eq!(
        private[0],
        Cidr {
            ip: vec![10, 0, 0, 0],
            prefix: 8
        }
    );
    assert_eq!(private[1].ip.len(), 16);
    assert_eq!(
        store
            .load_geosite(DEFAULT_GEOSITE_FILE, "SITES", "")
            .unwrap()
            .len(),
        6
    );
    assert!(store.check_code(DEFAULT_GEOIP_FILE, "private").is_err());
    assert!(store.check_code(DEFAULT_GEOIP_FILE, "MISSING").is_err());
    assert!(store.check_code(DEFAULT_GEOIP_FILE, "").is_err());
}

#[test]
fn attributes_are_all_required_and_values_are_not_booleans() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let selected = store
        .load_geosite(DEFAULT_GEOSITE_FILE, "SITES", "ads@flag")
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].value, "EXAMPLE.COM");
    assert_eq!(
        store
            .load_geosite(DEFAULT_GEOSITE_FILE, "SITES", "ads")
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        store
            .load_geosite(DEFAULT_GEOSITE_FILE, "SITES", "!cn")
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .load_geosite(DEFAULT_GEOSITE_FILE, "SITES", "!ads")
            .unwrap()
            .is_empty()
    );
    let matcher = domain_matcher(&store, &["geosite:sites@ADS@FLAG"]);
    assert!(matcher.match_host("Sub.Example.Com"));
    assert!(!matcher.match_host("exact.example"));
}

#[test]
fn parsers_accept_source_aliases_and_validate_assets() {
    let fixture = Fixture::new();
    let store = fixture.store();
    for rule in ["geoip:v4", "ext:geoip.dat:v4", "ext-ip:geoip.dat:v4"] {
        let parsed = store.parse_ip_rule(rule).unwrap();
        let ip_rule::Value::Geoip(geo) = parsed.value.unwrap() else {
            panic!("wrong rule kind")
        };
        assert_eq!(geo.code, "V4");
    }
    for rule in [
        "geosite:sites",
        "ext:geosite.dat:sites",
        "ext-site:geosite.dat:sites",
        "ext-domain:geosite.dat:sites",
    ] {
        let parsed = store.parse_domain_rule(rule, domain::Type::Domain).unwrap();
        let domain_rule::Value::Geosite(geo) = parsed.value.unwrap() else {
            panic!("wrong rule kind")
        };
        assert_eq!(geo.code, "SITES");
    }
    for rule in [
        "geosite:",
        "geosite:sites@",
        "geosite:sites@@ads",
        "geosite:missing",
        "ext:missing.dat:sites",
        "ext::sites",
    ] {
        assert!(
            store.parse_domain_rule(rule, domain::Type::Substr).is_err(),
            "{rule}"
        );
    }
    for rule in [
        "geoip:",
        "ext:geoip.dat",
        "ext::V4",
        "192.0.2.1/33",
        "2001:db8::/129",
        "192.0.2.1/+1",
        "example.com",
        "!",
    ] {
        assert!(store.parse_ip_rule(rule).is_err(), "{rule}");
    }
}

#[test]
fn repeated_ip_bangs_xor_with_code_bangs() {
    let fixture = Fixture::new();
    let store = fixture.store();
    for (rule, expected) in [
        ("geoip:v4", false),
        ("!geoip:v4", true),
        ("!!geoip:v4", false),
        ("geoip:!v4", true),
        ("!geoip:!v4", false),
        ("!!ext-ip:geoip.dat:!!!v4", true),
    ] {
        let ip_rule::Value::Geoip(rule) = store.parse_ip_rule(rule).unwrap().value.unwrap() else {
            panic!("wrong kind")
        };
        assert_eq!(rule.reverse_match, expected);
    }
    for (rule, expected) in [
        ("192.0.2.1", false),
        ("!192.0.2.1", true),
        ("!!192.0.2.1", false),
    ] {
        let ip_rule::Value::Custom(rule) = store.parse_ip_rule(rule).unwrap().value.unwrap() else {
            panic!("wrong kind")
        };
        assert_eq!(rule.reverse_match, expected);
        assert_eq!(rule.cidr.unwrap().prefix, 32);
    }
}

#[test]
fn full_suffix_substring_regex_and_router_case_semantics() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let matcher = domain_matcher(&store, &["geosite:sites"]);
    for host in [
        "example.com",
        "sub.example.com",
        "exact.example",
        "re123.example",
        "a-needle.example",
    ] {
        assert!(matcher.match_any(host), "{host}");
    }
    for host in [
        "badexample.com",
        "example.com.evil",
        "example.com.",
        "sub.exact.example",
        "RE123.example",
        "ignored.example",
    ] {
        assert!(!matcher.match_any(host), "{host}");
    }
    assert!(matcher.match_host("EXAMPLE.COM"));
    assert!(!matcher.match_any("EXAMPLE.COM"));
    assert!(!domain_matcher(&store, &["regexp:^UPPER$"]).match_host("UPPER"));
}

#[test]
fn domain_indices_default_type_and_dotless_rules() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let matcher = domain_matcher(
        &store,
        &[
            "domain:example.com",
            "keyword:example",
            "full:example.com",
            "regexp:^example\\.com$",
        ],
    );
    let mut indices = matcher.matching_rules("example.com");
    indices.sort_unstable();
    assert_eq!(indices, [0, 1, 2, 3]);
    assert!(domain_matcher(&store, &["needle"]).match_any("a-needle-b"));
    let exact = store
        .parse_domain_rules(&strings(&["example.com"]), domain::Type::Domain)
        .unwrap();
    assert!(
        !store
            .build_domain_matcher(&exact)
            .unwrap()
            .match_any("badexample.com")
    );
    assert!(domain_matcher(&store, &["dotless:"]).match_any("localhost"));
    assert!(!domain_matcher(&store, &["dotless:"]).match_any("local.host"));
    assert!(domain_matcher(&store, &["dotless:host"]).match_any("localhost"));
    assert!(
        store
            .parse_domain_rule("dotless:host.name", domain::Type::Substr)
            .is_err()
    );
    let invalid = store
        .parse_domain_rules(&strings(&["regexp:["]), domain::Type::Substr)
        .unwrap();
    assert!(store.build_domain_matcher(&invalid).is_err());
    assert!(store.build_domain_matcher(&[]).is_err());
}

#[test]
fn cidrs_support_families_boundaries_mapped_literals_and_zero_prefix() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let matcher = ip_matcher(&store, &["192.0.2.129/25", "2001:db8::1/64"]);
    assert!(!matcher.match_ip(ip("192.0.2.127")));
    assert!(matcher.match_ip(ip("192.0.2.128")));
    assert!(matcher.match_ip(ip("192.0.2.255")));
    assert!(!matcher.match_ip(ip("192.0.3.0")));
    assert!(matcher.match_ip(ip("2001:db8::ffff")));
    assert!(!matcher.match_ip(ip("2001:db8:0:1::")));
    assert!(matcher.match_ip(ip("::ffff:192.0.2.255")));
    assert!(ip_matcher(&store, &["::ffff:192.0.2.1"]).match_ip(ip("192.0.2.1")));
    let all = ip_matcher(&store, &["0.0.0.0/0", "::/0"]);
    assert!(all.matches(&[
        ip("255.255.255.255"),
        ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    ]));
}

#[test]
fn negative_rules_complement_unions_only_within_present_families() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let matcher = ip_matcher(&store, &["!10.0.0.0/8", "!192.0.2.0/24"]);
    assert!(!matcher.match_ip(ip("10.1.2.3")));
    assert!(!matcher.match_ip(ip("192.0.2.7")));
    assert!(matcher.match_ip(ip("8.8.8.8")));
    assert!(!matcher.match_ip(ip("2001:db8::1")));
    let geo = ip_matcher(&store, &["!geoip:private", "!geoip:v4"]);
    assert!(!geo.match_ip(ip("10.1.2.3")));
    assert!(!geo.match_ip(ip("192.0.2.7")));
    assert!(!geo.match_ip(ip("fd00::1")));
    assert!(geo.match_ip(ip("2001:db8::1")));
    assert!(!ip_matcher(&store, &["!geoip:empty"]).match_ip(ip("8.8.8.8")));
}

#[test]
fn source_matches_requires_same_group_to_match_entire_address_list() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let matcher = ip_matcher(&store, &["192.0.2.0/24", "geoip:private"]);
    let addresses = [ip("192.0.2.1"), ip("10.0.0.1")];
    assert!(addresses.iter().all(|address| matcher.match_ip(*address)));
    assert!(!matcher.matches(&addresses));
    assert!(matcher.any_match(&addresses));
    assert!(matcher.matches(&[ip("10.0.0.1"), ip("fd00::1")]));
    assert!(!matcher.matches(&[]));
    assert!(!matcher.any_match(&[]));
    let single_group = ip_matcher(&store, &["192.0.2.0/24", "10.0.0.0/8"]);
    assert!(single_group.matches(&addresses));
}

#[test]
fn legacy_file_reverse_flag_is_ignored_and_bad_entries_are_skipped() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let v4 = ip_matcher(&store, &["geoip:v4"]);
    assert!(v4.match_ip(ip("192.0.2.1")));
    assert!(!v4.match_ip(ip("203.0.113.1")));
    let broken = ip_matcher(&store, &["geoip:broken"]);
    assert!(broken.match_ip(ip("198.51.100.1")));
    assert!(!broken.match_ip(ip("192.0.2.1")));
    assert!(store.build_ip_matcher(&[]).is_err());
    assert!(store.build_ip_matcher(&[IpRule { value: None }]).is_err());
}

#[test]
fn invalid_ips_are_not_matched_or_returned_in_either_partition() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let matcher = ip_matcher(&store, &["!192.0.2.0/24"]);
    let inputs = vec![
        vec![1, 2, 3],
        vec![192, 0, 2, 1],
        vec![8, 8, 8, 8],
        vec![8, 8, 8, 8],
    ];
    assert!(!matcher.match_bytes(&inputs[0]));
    assert!(!matcher.matches_bytes(&inputs));
    assert!(matcher.any_match_bytes(&inputs));
    let (matched, unmatched) = matcher.filter_ip_bytes(&inputs);
    assert_eq!(matched, [vec![8, 8, 8, 8], vec![8, 8, 8, 8]]);
    assert_eq!(unmatched, [vec![192, 0, 2, 1]]);
}

#[test]
fn asset_names_reject_escape_paths_and_accept_nested_files() {
    let fixture = Fixture::new();
    let store = fixture.store();
    for name in [
        "",
        ".",
        "..",
        "../geoip.dat",
        "nested/../geoip.dat",
        "nested//geoip.dat",
        "/geoip.dat",
        "C:/geoip.dat",
        "C:geoip.dat",
        "nested\\geoip.dat",
        "geo\0ip.dat",
    ] {
        assert!(store.resolve_asset(name).is_err(), "{name:?}");
    }
    fs::create_dir(fixture.0.join("nested")).unwrap();
    fs::write(fixture.0.join("nested/data.dat"), hex(IP_HEX)).unwrap();
    assert!(store.check_code("nested/data.dat", "V4").is_ok());
    assert!(store.resolve_asset("nested").is_err());
}

#[test]
fn cache_is_a_snapshot_and_can_be_explicitly_cleared() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let old = store.load_geoip(DEFAULT_GEOIP_FILE, "V4").unwrap();
    let mut changed = hex(IP_HEX);
    replace_bytes(&mut changed, &[192, 0, 2, 0], &[203, 0, 113, 0]);
    fixture.write(DEFAULT_GEOIP_FILE, &changed);
    let cached = store.load_geoip(DEFAULT_GEOIP_FILE, "V4").unwrap();
    assert!(Arc::ptr_eq(&old, &cached));
    store.clear_cache();
    let fresh = store.load_geoip(DEFAULT_GEOIP_FILE, "V4").unwrap();
    assert_eq!(fresh[0].ip, [203, 0, 113, 0]);
    assert_eq!(old[0].ip, [192, 0, 2, 0]);
}

#[test]
fn file_cache_is_shared_safely_between_threads() {
    let fixture = Fixture::new();
    let store = fixture.store();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    store
                        .load_geosite(DEFAULT_GEOSITE_FILE, "SITES", "")
                        .unwrap()
                })
            })
            .collect();
        let entries: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(entries.iter().all(|entry| Arc::ptr_eq(entry, &entries[0])));
    });
}

#[test]
fn reload_validates_all_matchers_before_publishing_and_preserves_reversal() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let ip_rules = store.parse_ip_rules(&strings(&["geoip:v4"])).unwrap();
    let site_rules = store
        .parse_domain_rules(&strings(&["geosite:alt"]), domain::Type::Substr)
        .unwrap();
    let registry = GeoDataRegistry::new(store);
    let dynamic_ip = registry.build_ip_matcher(&ip_rules).unwrap();
    let dynamic_site = registry.build_domain_matcher(&site_rules).unwrap();
    dynamic_ip.toggle_reverse();
    let mut sites = hex(SITE_HEX);
    replace_bytes(&mut sites, b"old.example", b"new.example");
    fixture.write(DEFAULT_GEOSITE_FILE, &sites);
    fixture.write(DEFAULT_GEOIP_FILE, &[0x0a, 0xff]);
    assert!(registry.reload().is_err());
    assert!(dynamic_site.match_any("old.example"));
    assert!(!dynamic_site.match_any("new.example"));
    assert!(!dynamic_ip.match_ip(ip("192.0.2.1")));
    let mut ips = hex(IP_HEX);
    replace_bytes(&mut ips, &[192, 0, 2, 0], &[203, 0, 113, 0]);
    fixture.write(DEFAULT_GEOIP_FILE, &ips);
    registry.reload().unwrap();
    assert!(!dynamic_site.match_any("old.example"));
    assert!(dynamic_site.match_any("new.example"));
    assert!(dynamic_ip.match_ip(ip("192.0.2.1")));
    assert!(!dynamic_ip.match_ip(ip("203.0.113.1")));
    dynamic_ip.set_reverse(false);
    registry.reload().unwrap();
    assert!(dynamic_ip.match_ip(ip("203.0.113.1")));
    assert!(!dynamic_ip.match_ip(ip("192.0.2.1")));
    dynamic_ip.toggle_reverse();
    registry.reload().unwrap();
    assert!(!dynamic_ip.match_ip(ip("203.0.113.1")));
}

#[test]
fn malformed_protobuf_is_rejected_without_panics() {
    for bytes in [
        vec![0],
        vec![0x0a, 2, 0x0a],
        vec![0x0a, 0xff],
        vec![0x0a, 3, 0x0a, 1, 0xff],
        vec![0x0a, 1, 0],
        vec![0x0f],
        vec![
            0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2,
        ],
    ] {
        assert!(IndexedFile::new(bytes.clone()).is_err(), "{bytes:?}");
    }
}

#[test]
fn protobuf_index_handles_unknown_fields_and_code_not_first() {
    // Top-level unknown varint, then one GeoSite entry: domain before code.
    // GeoSite.domain = Domain{type=Full,value="x"}; GeoSite.code = "A".
    let bytes = hex("7801 0a0a 12050803120178 0a0141");
    let indexed = IndexedFile::new(bytes).unwrap();
    let entry = GeoSite::decode(indexed.entry("A").unwrap()).unwrap();
    assert_eq!(entry.domain[0].value, "x");
    // First duplicate code wins, matching the original asset lookup.
    let indexed = IndexedFile::new(hex("0a030a0141 0a0a120508031201780a0141")).unwrap();
    assert!(
        GeoSite::decode(indexed.entry("A").unwrap())
            .unwrap()
            .domain
            .is_empty()
    );
}
