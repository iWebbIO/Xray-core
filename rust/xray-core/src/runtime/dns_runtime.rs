//! CONTRACT (fixed by the integrator): DNS-app plumbing for the runtime.
//!
//! OWNER: wiring batch agent A-DNS. `resolver` adapts the configured
//! `dns::app::DnsApp` to the `udp_routing::UdpResolver` seam used by the SOCKS
//! and relay UDP dispatchers. The same agent also owns the freedom
//! `domainStrategy` resolution behavior in `runtime/admission.rs` and
//! `protocol/freedom.rs`, and the resolver selection in
//! `runtime/udp_integration.rs`. The resolver must consult `DnsApp::lookup_ip`
//! with the query family implied by the strategy and must never fall back to
//! the system resolver behind a configured app (Go's semantics).

use std::sync::Arc;

use crate::dns::{QueryOptions, app::DnsApp};

/// A `UdpResolver` backed by the configured DNS app.
///
/// Queries run with `QueryOptions::BOTH` and the app narrows the families per
/// its own configured `queryStrategy` (global and per-server) inside
/// `lookup_ip`, so the UDP routing path receives exactly the app's
/// configured answers and can keep its own address validation. The app's
/// errors propagate unchanged: a configured resolver is never silently
/// replaced by the system one.
pub(super) fn resolver(app: Arc<DnsApp>) -> Arc<dyn super::udp_routing::UdpResolver> {
    struct AppResolver(Arc<DnsApp>);

    impl super::udp_routing::UdpResolver for AppResolver {
        fn resolve(&self, host: String) -> super::udp_routing::ResolveFuture {
            let app = Arc::clone(&self.0);
            Box::pin(async move {
                let answer = app
                    .lookup_ip(&host, QueryOptions::BOTH)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(answer.ips)
            })
        }
    }

    Arc::new(AppResolver(app))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::{Arc, Mutex},
    };

    use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};

    use super::super::udp_routing;
    use super::*;
    use crate::dns::{RecordType, wire};

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

        fn types(&self) -> Vec<u16> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(_, kind)| *kind)
                .collect()
        }
    }

    impl Drop for UdpFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn app(fixture: &UdpFixture) -> Arc<DnsApp> {
        Arc::new(
            DnsApp::from_value(&serde_json::json!({
                "servers": [
                    {"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}
                ]
            }))
            .unwrap(),
        )
    }

    async fn resolve(
        resolver: &Arc<dyn udp_routing::UdpResolver>,
        host: &str,
    ) -> std::io::Result<Vec<IpAddr>> {
        timeout(
            std::time::Duration::from_secs(5),
            resolver.resolve(host.to_owned()),
        )
        .await
        .expect("resolve bounded")
    }

    #[tokio::test]
    async fn resolver_answers_through_the_configured_app() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.10"), ip("2001:db8::10")], 60, 0).await;
        let resolver = resolver(app(&fixture));
        let ips = resolve(&resolver, "www.test").await.unwrap();
        assert_eq!(ips, [ip("192.0.2.10"), ip("2001:db8::10")]);
        let mut types = fixture.types();
        types.sort_unstable();
        assert_eq!(types, [1, 28]);
    }

    #[tokio::test]
    async fn app_query_strategy_narrows_the_resolver_families() {
        let fixture = UdpFixture::start(vec![ip("192.0.2.11"), ip("2001:db8::11")], 60, 0).await;
        let app = Arc::new(
            DnsApp::from_value(&serde_json::json!({
                "queryStrategy": "UseIPv4",
                "servers": [
                    {"address": "127.0.0.1", "port": fixture.address.port(), "timeoutMs": 500}
                ]
            }))
            .unwrap(),
        );
        let ips = resolve(&resolver(app), "v4only.test").await.unwrap();
        assert_eq!(ips, [ip("192.0.2.11")]);
        assert_eq!(fixture.types(), [1]);
    }

    #[tokio::test]
    async fn app_errors_propagate_without_system_fallback() {
        let nxdomain = UdpFixture::start(vec![], 60, 3).await;
        let error = resolve(&resolver(app(&nxdomain)), "nx.test")
            .await
            .unwrap_err();
        // Go's "returning nil for domain" wrapper, carried by the app error.
        assert!(
            error
                .to_string()
                .contains("returning nil for domain nx.test"),
            "{error}"
        );
        // The app's policy error is returned verbatim every time, never
        // retried against the system resolver.
        assert_eq!(
            resolve(&resolver(app(&nxdomain)), "nx.test")
                .await
                .unwrap_err()
                .to_string(),
            error.to_string()
        );
    }
}
