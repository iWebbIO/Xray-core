//! Shared final outbound admission for proxy sessions and internal probes.
//!
//! Freedom's `domainStrategy` follows proxy/freedom/freedom.go plus
//! transport/internet's `LookupForIP`: `AsIs` keeps the final-rules behavior
//! (system-resolved check, dial by domain when no check is needed), every
//! other strategy resolves the target through the configured DNS app — or,
//! when no `dns` app exists, through the system resolver, which is what Go's
//! implicit localhost DNS client amounts to. `Force*` fails the connection
//! when resolution yields nothing; `Use*` still dials by domain, as Go's
//! "non-force may still dial with system DNS" comment documents. The v4/v6
//! pair strategies try the preferred family first and fall back to the other.
use std::{net::IpAddr, sync::Arc};

use anyhow::{Context, Result};

use crate::{
    address::{Address, Destination},
    config::Outbound,
    dns::{QueryOptions, app::DnsApp},
    protocol::freedom::{Admission, DomainStrategy},
};

pub(super) async fn admit(
    outbound: &Outbound,
    origin: &str,
    target: &Destination,
    dns: Option<&Arc<DnsApp>>,
) -> Result<Admission> {
    let Outbound::Freedom {
        redirect,
        final_rules,
        strategy,
        ..
    } = outbound
    else {
        return Ok(Admission::Allowed(None));
    };
    let destination = redirect.as_ref().unwrap_or(target);
    // AsIs, and every strategy on an IP-literal target, keep today's
    // final-rules admission: domains resolve with the system resolver for the
    // rule check, IP literals are checked as themselves.
    if !strategy.has_strategy() || matches!(destination.address, Address::Ip(_)) {
        return final_rules.admit(origin, destination).await;
    }
    let Address::Domain(host) = &destination.address else {
        unreachable!("IP destinations return through the AsIs arm above");
    };
    match resolve_strategy(host, *strategy, dns).await {
        // Go checks every resolved address against the final rules before the
        // dialer picks one; the runtime then dials the checked addresses.
        Ok(ips) => final_rules.admit_resolved(
            origin,
            ips.iter()
                .map(|ip| std::net::SocketAddr::new(*ip, destination.port))
                .collect(),
        ),
        Err(error) if strategy.is_force() => {
            Err(error.context("freedom force domain strategy resolved no IP address"))
        }
        // Go's non-force strategies log the failure and keep dialing by
        // domain ("non-force may still dial with system DNS").
        Err(error) => {
            tracing::debug!(
                %error,
                host,
                strategy = ?strategy,
                "failed to get IP address for domain; dialing by domain"
            );
            Ok(Admission::Allowed(None))
        }
    }
}

/// Go `internet.LookupForIP` with no outbound gateway address: one lookup
/// with the strategy's preferred families, an optional fallback lookup with
/// the other family, and `ErrEmptyResponse` when a successful lookup yields
/// nothing. A configured DNS app is the only resolver consulted; its errors
/// propagate instead of silently degrading to the system resolver. Without a
/// `dns` app the lookup runs against the system resolver, mirroring Go's
/// implicit localhost DNS client.
async fn resolve_strategy(
    host: &str,
    strategy: DomainStrategy,
    dns: Option<&Arc<DnsApp>>,
) -> Result<Vec<IpAddr>> {
    match dns {
        Some(app) => {
            let mut answer = app.lookup_ip(host, strategy.preferred_families()).await;
            // Go retries with the fallback family when the first lookup
            // fails or answers nothing.
            let first_empty = match &answer {
                Ok(result) => result.ips.is_empty(),
                Err(_) => true,
            };
            if first_empty && let Some(fallback) = strategy.fallback_families() {
                answer = app.lookup_ip(host, fallback).await;
            }
            let ips = answer
                .map(|result| result.ips)
                .with_context(|| format!("lookup {host:?} through the configured DNS app"))?;
            // Go's LookupForIP turns a successful empty answer into
            // ErrEmptyResponse, so non-force strategies keep dialing by
            // domain instead of failing.
            if ips.is_empty() {
                anyhow::bail!("domain strategy resolved no IP address: {host}");
            }
            Ok(ips)
        }
        None => {
            let addresses: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
                .await
                .with_context(|| format!("resolve {host:?} with the system resolver"))?
                .map(|address| address.ip())
                .collect();
            let filtered = filter_families(&addresses, strategy.preferred_families());
            if !filtered.is_empty() {
                return Ok(filtered);
            }
            if let Some(fallback) = strategy.fallback_families() {
                let filtered = filter_families(&addresses, fallback);
                if !filtered.is_empty() {
                    return Ok(filtered);
                }
            }
            anyhow::bail!("domain strategy resolved no IP address: {host}");
        }
    }
}

fn filter_families(addresses: &[IpAddr], options: QueryOptions) -> Vec<IpAddr> {
    addresses
        .iter()
        .copied()
        .filter(|ip| (ip.is_ipv4() && options.ipv4) || (ip.is_ipv6() && options.ipv6))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::net::TcpListener;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        task::JoinHandle,
        time::timeout,
    };

    use super::*;
    use crate::{
        address::Destination,
        dns::{RecordType, app::DnsApp, wire},
        protocol::freedom::{FinalRules, RuleConfig},
    };

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    /// Local UDP DNS fixture, built like `dns/app.rs`'s own tests: answers
    /// every query with `answers` filtered to the queried family and wrapped
    /// by `wire::encode_response`, recording (name, record type) per query.
    struct UdpFixture {
        address: SocketAddr,
        log: Arc<Mutex<Vec<(String, u16)>>>,
        task: JoinHandle<()>,
    }

    impl UdpFixture {
        async fn start(answers: Vec<IpAddr>, ttl: u32, code: u16) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let log = Arc::new(Mutex::new(Vec::new()));
            let logger = log.clone();
            let task = tokio::spawn(async move {
                let mut buffer = [0; 512];
                while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                    let Ok(query) = wire::decode(&buffer[..size]) else {
                        continue;
                    };
                    let question = query.questions[0].clone();
                    let ips: Vec<IpAddr> = answers
                        .iter()
                        .copied()
                        .filter(|answer| {
                            (question.record_type == RecordType::A) == answer.is_ipv4()
                        })
                        .collect();
                    logger
                        .lock()
                        .unwrap()
                        .push((question.name.clone(), question.record_type.0));
                    let Ok(response) = wire::encode_response(
                        query.header.id,
                        &question,
                        &ips,
                        ttl,
                        code,
                        None,
                        wire::MAX_MESSAGE_SIZE,
                    ) else {
                        continue;
                    };
                    let _ = socket.send_to(&response, peer).await;
                }
            });
            Self { address, log, task }
        }

        fn names(&self) -> Vec<String> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
        }

        fn types(&self) -> Vec<u16> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(_, kind)| *kind)
                .collect()
        }

        fn count(&self) -> usize {
            self.log.lock().unwrap().len()
        }
    }

    impl Drop for UdpFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn dns_app(fixture: &UdpFixture) -> Arc<DnsApp> {
        Arc::new(
            DnsApp::from_value(&serde_json::json!({
                "servers": [
                    {"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}
                ]
            }))
            .unwrap(),
        )
    }

    fn freedom(strategy: DomainStrategy, rules: serde_json::Value) -> Outbound {
        Outbound::Freedom {
            strategy,
            redirect: None,
            final_rules: FinalRules::compile(
                &serde_json::from_value::<Vec<RuleConfig>>(rules).unwrap(),
            )
            .unwrap(),
        }
    }

    async fn admit_bounded(
        outbound: &Outbound,
        origin: &str,
        host: &str,
        dns: Option<&Arc<DnsApp>>,
    ) -> Result<Admission> {
        let target = Destination::new(host, 443).unwrap();
        timeout(
            Duration::from_secs(5),
            admit(outbound, origin, &target, dns),
        )
        .await
        .expect("admission bounded")
    }

    fn resolved(admission: Admission) -> Vec<SocketAddr> {
        match admission {
            Admission::Allowed(Some(addresses)) => addresses,
            other => {
                let blocked = matches!(other, Admission::Blocked(_));
                panic!("expected resolved addresses, blocked = {blocked}")
            }
        }
    }

    #[tokio::test]
    async fn asis_keeps_today_admission_without_touching_the_dns_app() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.1")], 60, 0).await;
        let dns = dns_app(&fixture);
        // "socks" with no final rules resolves nothing at all.
        let admission = admit_bounded(
            &freedom(DomainStrategy::AsIs, serde_json::json!([])),
            "socks",
            "asis.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert!(matches!(admission, Admission::Allowed(None)));
        // With final rules the AsIs path resolves with the system resolver
        // (localhost), never through the app.
        let admission = admit_bounded(
            &freedom(
                DomainStrategy::AsIs,
                serde_json::json!([{"action": "allow", "port": 443}]),
            ),
            "socks",
            "localhost",
            Some(&dns),
        )
        .await
        .unwrap();
        assert!(!resolved(admission).is_empty());
        assert_eq!(fixture.count(), 0);
    }

    #[tokio::test]
    async fn useip_resolves_through_the_dns_app_and_dials_the_answer() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.20"), ip("2001:db8::20")], 60, 0).await;
        let dns = dns_app(&fixture);
        let admission = admit_bounded(
            &freedom(DomainStrategy::UseIp, serde_json::json!([])),
            "socks",
            "use.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert_eq!(
            resolved(admission),
            vec![
                SocketAddr::new(ip("192.0.2.20"), 443),
                SocketAddr::new(ip("2001:db8::20"), 443),
            ]
        );
        assert_eq!(fixture.names(), ["use.test.", "use.test."]);
        let mut types = fixture.types();
        types.sort_unstable();
        assert_eq!(types, [1, 28]);
    }

    #[tokio::test]
    async fn useip4_queries_one_family_and_returns_only_its_answers() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.21"), ip("2001:db8::21")], 60, 0).await;
        let dns = dns_app(&fixture);
        let admission = admit_bounded(
            &freedom(DomainStrategy::UseIp4, serde_json::json!([])),
            "socks",
            "v4.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert_eq!(
            resolved(admission),
            [SocketAddr::new(ip("192.0.2.21"), 443)]
        );
        assert_eq!(fixture.types(), [1]);
    }

    #[tokio::test]
    async fn useipv46_tries_the_families_in_order() {
        // No A records: the first (IPv4) lookup answers nothing, the IPv6
        // fallback then resolves the name.
        let fixture = UdpFixture::start(vec![ip("2001:db8::22")], 60, 0).await;
        let dns = dns_app(&fixture);
        let admission = admit_bounded(
            &freedom(DomainStrategy::UseIp46, serde_json::json!([])),
            "socks",
            "pair46.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert_eq!(
            resolved(admission),
            [SocketAddr::new(ip("2001:db8::22"), 443)]
        );
        assert_eq!(fixture.types(), [1, 28]);

        // The reversed pair prefers IPv6 and never needs the fallback.
        let fixture = UdpFixture::start(vec![ip("192.0.2.23"), ip("2001:db8::23")], 60, 0).await;
        let dns = dns_app(&fixture);
        let admission = admit_bounded(
            &freedom(DomainStrategy::UseIp64, serde_json::json!([])),
            "socks",
            "pair64.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert_eq!(
            resolved(admission),
            [SocketAddr::new(ip("2001:db8::23"), 443)]
        );
        assert_eq!(fixture.types(), [28]);
    }

    #[tokio::test]
    async fn force_pair_falls_back_before_failing() {
        // No AAAA records: ForceIPv6v4 fails the IPv6 lookup, then the IPv4
        // fallback resolves and the connection proceeds.
        let fixture = UdpFixture::start(vec![ip("192.0.2.24")], 60, 0).await;
        let dns = dns_app(&fixture);
        let admission = admit_bounded(
            &freedom(DomainStrategy::ForceIp64, serde_json::json!([])),
            "socks",
            "force64.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert_eq!(
            resolved(admission),
            [SocketAddr::new(ip("192.0.2.24"), 443)]
        );
        assert_eq!(fixture.types(), [28, 1]);
    }

    #[tokio::test]
    async fn forceip_with_an_empty_answer_fails_explicitly() {
        let empty = UdpFixture::start(vec![], 60, 0).await;
        let dns = dns_app(&empty);
        let error = admit_bounded(
            &freedom(DomainStrategy::ForceIp, serde_json::json!([])),
            "socks",
            "empty.test",
            Some(&dns),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("freedom force domain strategy resolved no IP address"),
            "{error}"
        );
        // A lookup error fails the connection just like an empty answer.
        let nxdomain = UdpFixture::start(vec![], 60, 3).await;
        let dns = dns_app(&nxdomain);
        assert!(
            admit_bounded(
                &freedom(DomainStrategy::ForceIp4, serde_json::json!([])),
                "socks",
                "nx.test",
                Some(&dns),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn useip_failures_still_dial_by_domain() {
        // Go: "non-force may still dial with system DNS" — empty answers and
        // lookup errors both degrade to a domain dial instead of failing.
        for (host, code) in [("nodata.test", 0), ("nx2.test", 3)] {
            let fixture = UdpFixture::start(vec![], 60, code).await;
            let dns = dns_app(&fixture);
            let admission = admit_bounded(
                &freedom(DomainStrategy::UseIp, serde_json::json!([])),
                "socks",
                host,
                Some(&dns),
            )
            .await
            .unwrap();
            assert!(matches!(admission, Admission::Allowed(None)), "{host}");
        }
    }

    #[tokio::test]
    async fn without_a_dns_app_the_system_resolver_serves_the_strategy() {
        // Go's implicit localhost DNS client is the system resolver; a v4
        // strategy on localhost must return only the v4 loopback.
        let admission = admit_bounded(
            &freedom(DomainStrategy::UseIp4, serde_json::json!([])),
            "socks",
            "localhost",
            None,
        )
        .await
        .unwrap();
        let addresses = resolved(admission);
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.is_ipv4()));
    }

    #[tokio::test]
    async fn ip_literal_targets_keep_final_rules_admission_under_any_strategy() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.25")], 60, 0).await;
        let dns = dns_app(&fixture);
        for strategy in [
            DomainStrategy::AsIs,
            DomainStrategy::UseIp,
            DomainStrategy::ForceIp,
        ] {
            // The private-IP default rule still blocks vless sessions.
            let target = Destination::new("127.0.0.1", 443).unwrap();
            let admission = timeout(
                Duration::from_secs(5),
                admit(
                    &freedom(strategy, serde_json::json!([])),
                    "vless",
                    &target,
                    Some(&dns),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(admission, Admission::Blocked(_)), "{strategy:?}");
            // Explicit final rules check the literal itself.
            let target = Destination::new("198.51.100.8", 443).unwrap();
            let admission = timeout(
                Duration::from_secs(5),
                admit(
                    &freedom(
                        strategy,
                        serde_json::json!([{"action": "allow", "port": 443}]),
                    ),
                    "socks",
                    &target,
                    Some(&dns),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                resolved(admission),
                vec!["198.51.100.8:443".parse().unwrap()]
            );
        }
        // IP literals never reach the resolver.
        assert_eq!(fixture.count(), 0);
    }

    #[tokio::test]
    async fn strategy_answers_are_final_rule_checked() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.30")], 60, 0).await;
        let dns = dns_app(&fixture);
        let admission = admit_bounded(
            &freedom(
                DomainStrategy::UseIp,
                serde_json::json!([
                    {"action": "block", "ip": ["192.0.2.0/24"], "blockDelay": 0}
                ]),
            ),
            "socks",
            "blocked.test",
            Some(&dns),
        )
        .await
        .unwrap();
        assert!(matches!(admission, Admission::Blocked(delay) if delay == Duration::ZERO));
    }

    /// TCP echo listener counting accepted connections, dropped with the test.
    struct EchoListener {
        address: SocketAddr,
        connections: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl EchoListener {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&connections);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let mut buffer = [0; 2048];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) | Err(_) => return,
                                Ok(size) => {
                                    if stream.write_all(&buffer[..size]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
            });
            Self {
                address,
                connections,
                task,
            }
        }
    }

    impl Drop for EchoListener {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn useip_end_to_end_resolves_and_dials_the_dns_answer() {
        let dns_fixture = UdpFixture::start(vec![ip("127.0.0.1")], 60, 0).await;
        let echo = EchoListener::start().await;
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "dns": {"servers": [
                {"address": "127.0.0.1", "port": dns_fixture.address.port(), "timeoutMs": 500}
            ]},
            "inbounds": [{
                "protocol": "dokodemo-door",
                "listen": "127.0.0.1",
                "port": 0,
                "settings": {"address": "service.test", "port": echo.address.port()}
            }],
            "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}]
        }))
        .unwrap();
        let server = timeout(Duration::from_secs(5), super::super::Server::start(config))
            .await
            .expect("server start bounded")
            .unwrap();
        let mut client = timeout(
            Duration::from_secs(5),
            TcpStream::connect(server.local_addresses()[0]),
        )
        .await
        .expect("connect bounded")
        .unwrap();
        timeout(Duration::from_secs(5), client.write_all(b"ping"))
            .await
            .expect("ping write bounded")
            .unwrap();
        let mut buffer = [0; 4];
        timeout(Duration::from_secs(5), client.read_exact(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer, b"ping");
        // The connection dialed the DNS answer, so resolution went through
        // the configured app, never the system resolver.
        let names = dns_fixture.names();
        assert!(!names.is_empty());
        assert!(names.iter().all(|name| name == "service.test."));
        assert_eq!(echo.connections.load(Ordering::SeqCst), 1);
    }
}
