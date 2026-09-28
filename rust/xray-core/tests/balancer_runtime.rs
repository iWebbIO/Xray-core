//! `routing.balancers` + rules' `balancerTag` through the public config and
//! Router API (Go: infra/conf/router.go BalancingRule, app/router router.go
//! ReloadRules/routedDispatch, app/router/balancing.go Balancer.PickOutbound).

use std::sync::Arc;

use serde_json::{Value, json};
use xray_core::{
    address::Destination,
    config::Config,
    router::{
        RouteContext, Router, RoutingConfig,
        balancer::{ObservationResult, OutboundStatus},
    },
};

/// Hand-built observation provider fixture: a fixed health snapshot the
/// router consumes at selection time, like the runtime's observatory.
struct FixedObservations(Vec<OutboundStatus>);

impl xray_core::router::BalancerObservations for FixedObservations {
    fn observation_result(&self) -> ObservationResult {
        ObservationResult {
            status: self.0.clone(),
        }
    }
}

fn status(tag: &str, alive: bool, delay: i64) -> OutboundStatus {
    OutboundStatus {
        outbound_tag: tag.into(),
        alive,
        delay,
        ..Default::default()
    }
}

/// Outbound order: 0 direct, 1 node-a, 2 node-b, 3 blocked.
fn config_with(routing: Value) -> Config {
    serde_json::from_value(json!({
        "outbounds": [
            {"tag":"direct","protocol":"freedom"},
            {"tag":"node-a","protocol":"blackhole"},
            {"tag":"node-b","protocol":"blackhole"},
            {"tag":"blocked","protocol":"blackhole"},
        ],
        "routing": routing,
    }))
    .unwrap()
}

fn pick(router: &Router, host: &str) -> (usize, bool) {
    let destination = Destination::new(host, 443).unwrap();
    router.select_with_route(&RouteContext {
        destination: &destination,
        source: "127.0.0.1:1000".parse().unwrap(),
        inbound_tag: "edge",
        user: "alice",
        network: "tcp",
    })
}

#[test]
fn balancers_and_balancer_rules_parse_and_validate() {
    let config = config_with(json!({
        "domainStrategy": "AsIs",
        "balancers": [
            {"tag":"pool","selector":"node-","strategy":{"type":"roundRobin","settings":{}},"fallbackTag":"blocked"},
        ],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    config.validate().unwrap();
    assert_eq!(config.routing.balancers.len(), 1);
    assert_eq!(config.routing.balancers[0].tag, "pool");
    assert_eq!(config.routing.balancers[0].selectors, ["node-"]);
    assert_eq!(config.routing.balancers[0].fallback_tag, "blocked");
    assert_eq!(config.routing.rules[0].balancer_tag, "pool");
    // Serializing the parsed routing section keeps the same balancer.
    let reparsed: RoutingConfig =
        serde_json::from_value(serde_json::to_value(&config.routing).unwrap()).unwrap();
    assert_eq!(reparsed.balancers, config.routing.balancers);
}

#[test]
fn unknown_strategies_and_target_conflicts_are_rejected() {
    let error = serde_json::from_value::<RoutingConfig>(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"sticky"}}]
    }))
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown balancing strategy: sticky"),
        "{error}"
    );
    for (rule, message) in [
        (
            json!({"domain":["example.org"]}),
            "neither outboundTag nor balancerTag is specified in routing rule",
        ),
        (
            json!({"domain":["example.org"],"outboundTag":"direct","balancerTag":"pool"}),
            "routing rule cannot set both outboundTag and balancerTag",
        ),
        (
            json!({"domain":["example.org"],"balancerTag":"missing"}),
            "balancer missing not found",
        ),
    ] {
        let config = config_with(json!({
            "balancers": [{"tag":"pool","selector":["node-"]}],
            "rules": [rule],
        }));
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
    }
    let config = config_with(json!({
        "balancers": [
            {"tag":"pool","selector":["node-"]},
            {"tag":"pool","selector":["node-"]},
        ],
        "rules": [],
    }));
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate balancer tag")
    );
    let config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"fallbackTag":"missing"}],
        "rules": [],
    }));
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("fallbackTag")
    );
}

#[test]
fn round_robin_balancer_alternates_across_both_outbounds() {
    let config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"roundrobin"}}],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    config.validate().unwrap();
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    let mut picks = Vec::new();
    for _ in 0..4 {
        picks.push(pick(&router, "example.org"));
    }
    assert_eq!(
        picks,
        [(1, true), (2, true), (1, true), (2, true)],
        "node-a=1 and node-b=2 must alternate"
    );
    // A destination no rule matches keeps the default outbound.
    assert_eq!(pick(&router, "unlisted.test"), (0, false));
}

#[test]
fn random_balancer_distributes_over_both_outbounds() {
    let config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"random"}}],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    let mut seen_a = false;
    let mut seen_b = false;
    for _ in 0..100 {
        let (index, routed) = pick(&router, "example.org");
        assert!(routed);
        assert!(index == 1 || index == 2, "unexpected outbound {index}");
        seen_a |= index == 1;
        seen_b |= index == 2;
    }
    assert!(seen_a && seen_b, "random must reach both outbounds");
}

#[test]
fn fallback_tag_resolves_when_no_candidate_is_healthy() {
    for strategy in ["leastping", "random"] {
        let config = config_with(json!({
            "balancers": [{
                "tag":"pool","selector":["node-"],"strategy":{"type":strategy},
                "fallbackTag":"blocked"
            }],
            "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
        }));
        config.validate().unwrap();
        let router = Router::compile(&config.routing, &config.outbounds)
            .unwrap()
            .with_balancer_observations(Arc::new(FixedObservations(vec![
                status("node-a", false, 0),
                status("node-b", false, 0),
            ])));
        assert_eq!(
            pick(&router, "example.org"),
            (3, true),
            "{strategy} must fall back to the blocked outbound"
        );
    }
}

#[test]
fn least_ping_balancer_picks_the_healthy_lowest_delay_outbound() {
    let config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"leastping"}}],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    let router = Router::compile(&config.routing, &config.outbounds)
        .unwrap()
        .with_balancer_observations(Arc::new(FixedObservations(vec![
            status("node-a", true, 300),
            status("node-b", true, 100),
        ])));
    assert_eq!(pick(&router, "example.org"), (2, true));
    // A live node-a with an unobserved node-b still selects node-a: only
    // reported statuses can win least-ping.
    let router = Router::compile(&config.routing, &config.outbounds)
        .unwrap()
        .with_balancer_observations(Arc::new(FixedObservations(vec![status(
            "node-a", true, 300,
        )])));
    assert_eq!(pick(&router, "example.org"), (1, true));
}

#[test]
fn balancer_failure_without_fallback_uses_the_default_outbound() {
    // leastPing with no observation at all (no provider attached, like a
    // configuration Go would refuse to start): the strategy cannot choose,
    // so the connection takes the default outbound, exactly Go's PickRoute
    // error path in routedDispatch.
    let config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"leastping"}}],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    assert_eq!(pick(&router, "example.org"), (0, false));
}

#[test]
fn observatory_requirement_is_enforced_at_attach_time() {
    let config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"leastping"}}],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    assert!(router.balancers_require_observatory());
    let error = router.attach_observatory(None).unwrap_err().to_string();
    assert!(error.contains("require an observatory"), "{error}");
    router
        .attach_observatory(Some(Arc::new(FixedObservations(vec![]))))
        .unwrap();
    assert_eq!(pick(&router, "example.org"), (0, false));

    // random without fallbackTag needs no observatory (Go's RequireFeatures
    // is conditional there); an empty attached report keeps every candidate.
    let random_config = config_with(json!({
        "balancers": [{"tag":"pool","selector":["node-"],"strategy":{"type":"random"}}],
        "rules": [{"domain":["example.org"],"balancerTag":"pool"}],
    }));
    let router = Router::compile(&random_config.routing, &random_config.outbounds).unwrap();
    assert!(!router.balancers_require_observatory());
    router.attach_observatory(None).unwrap();
    let (index, routed) = pick(&router, "example.org");
    assert!(routed && (index == 1 || index == 2));
}
