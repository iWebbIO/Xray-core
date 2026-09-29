//! Compile-surface tests for the TUN inbound (infra/conf/tun.go parity).
//!
//! Device creation needs the Wintun driver plus elevation on Windows and
//! CAP_NET_ADMIN elsewhere, so the runtime's session plumbing is exercised in
//! the lib tests over the netstack's packet channels; these tests cover the
//! JSON surface every platform shares: exact keys, Go's defaults, and one
//! named rejection per Go option the runtime cannot honor.

use serde_json::json;
use xray_core::runtime::tun_inbound::compile_inbound;

#[test]
fn go_json_defaults_and_exact_keys() {
    // infra/conf/tun.go Build: an empty name becomes a generated utun name,
    // a zero MTU becomes 1500, and every field is optional.
    let entry = compile_inbound(&json!({})).unwrap();
    assert_eq!(entry.config.mtu, 1500);
    let suffix: u16 = entry
        .config
        .name
        .strip_prefix("utun")
        .expect("generated name carries Go's utun prefix")
        .parse()
        .unwrap();
    assert!((10..=1024).contains(&suffix), "index {suffix} out of range");
    assert_eq!(entry.user_level, 0);
    assert!(entry.config.gateway.is_empty());
    assert!(entry.config.dns.is_empty());
    assert!(entry.config.auto_system_routing_table.is_empty());
    assert_eq!(entry.config.auto_outbounds_interface, None);

    // The exact camelCase keys of Go's TunConfig tags.
    let entry = compile_inbound(&json!({
        "name": "tun0",
        "desc": "",
        "mtu": 1400,
        "gateway": ["172.20.0.1/24", "fd00::1/64"],
        "dns": [],
        "userLevel": 7,
        "autoSystemRoutingTable": [],
        "autoOutboundsInterface": ""
    }))
    .unwrap();
    assert_eq!(entry.config.name, "tun0");
    assert_eq!(entry.config.mtu, 1400);
    assert_eq!(entry.config.gateway.len(), 2);
    assert_eq!(
        entry.config.gateway[0].to_string(),
        "172.20.0.1/24",
        "gateway keeps the host bits like Go's interface addresses"
    );
    assert_eq!(entry.user_level, 7);

    // An explicit empty autoOutboundsInterface means "disabled" in Go
    // (handler.go only acts on a non-empty value), not an error.
    compile_inbound(&json!({"name": "tun0", "autoOutboundsInterface": ""})).unwrap();
}

#[test]
fn unsupported_go_options_fail_with_the_option_named() {
    for (settings, needle) in [
        (json!({"desc": "Wintun"}), "desc"),
        (json!({"dns": ["1.1.1.1"]}), "dns"),
        (
            json!({"autoSystemRoutingTable": ["0.0.0.0/0"]}),
            "autoSystemRoutingTable",
        ),
        (
            json!({"autoOutboundsInterface": "auto"}),
            "autoOutboundsInterface",
        ),
        (
            json!({"autoOutboundsInterface": "eth0"}),
            "autoOutboundsInterface",
        ),
        (json!({"gateway": ["172.20.0.1"]}), "gateway"),
        (
            json!({"gateway": ["172.20.0.1/24", "172.21.0.1/24"]}),
            "IPv4",
        ),
        (json!({"mtu": 68}), "mtu"),
        (json!({"mtu": 70000}), "mtu"),
        (json!({"userLevel": 5000000000u64}), "userLevel"),
        (json!({"name": "tun%d"}), "name"),
        (json!({"name": "this-name-is-far-too-long"}), "name"),
        (json!({"unknownKey": 1}), "unknownKey"),
    ] {
        // The full anyhow chain: the named option rides the source, not the
        // generic "tun inbound settings" wrapper.
        let error = compile_inbound(&settings).err().unwrap();
        let error = format!("{error:#}");
        assert!(
            error.contains(needle),
            "expected the error for {settings} to name {needle:?}: {error}"
        );
    }
}

#[test]
fn mtu_zero_is_go_default_and_the_floor_is_the_deviation() {
    // Go accepts any uint32 MTU; the shared dual-stack netstack requires at
    // least 1280, which the compile error names.
    let entry = compile_inbound(&json!({"name": "tun0", "mtu": 0})).unwrap();
    assert_eq!(entry.config.mtu, 1500);
    let error = compile_inbound(&json!({"name": "tun0", "mtu": 1279}))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("1280"), "{error}");
}
