//! Per-datagram SOCKS UDP routing and final freedom admission.
//!
//! Router matching uses the original destination and network="udp". Freedom
//! redirects are applied afterwards. DNS is an explicit dependency: a configured
//! resolver must be injected, and its errors never fall back to system DNS.
//! Every returned address is checked once and the chosen numeric endpoint is
//! passed directly to the relay, eliminating a check/resolve/dial race.

use std::{future::Future, io, net::IpAddr, pin::Pin, sync::Arc};

use crate::{
    address::{Address, Destination},
    config::{Outbound, StreamSettings},
    features::{StatsManager, policy::SystemStatsPolicy, stats::TrafficCounters},
    protocol::freedom::FinalRules,
    router::{RouteContext, Router},
};

use super::udp::{DispatchAction, DispatchContext, DispatchFuture, UdpDispatcher};

pub type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;

/// Resolve exactly through the caller's selected DNS service. Implementations
/// should return a bounded address list and must preserve configured DNS policy.
pub trait UdpResolver: Send + Sync {
    fn resolve(&self, host: String) -> ResolveFuture;
}

impl<F, Fut> UdpResolver for F
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: Future<Output = io::Result<Vec<IpAddr>>> + Send + 'static,
{
    fn resolve(&self, host: String) -> ResolveFuture {
        Box::pin(self(host))
    }
}

/// Explicit OS DNS choice for a runtime without configured DNS. Never install
/// this as an error fallback for a configured resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl UdpResolver for SystemResolver {
    fn resolve(&self, host: String) -> ResolveFuture {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .map(|address| address.ip())
                .collect())
        })
    }
}

#[derive(Clone, Debug)]
enum Capability {
    Direct {
        redirect: Option<Destination>,
        final_rules: FinalRules,
    },
    Drop,
    Unsupported,
}

/// One entry for every outbound, in exactly the Router's outbound order.
#[derive(Clone, Debug)]
pub struct RouteOutbound {
    tag: String,
    capability: Capability,
    counters: TrafficCounters,
}

impl RouteOutbound {
    pub fn from_config(
        outbound: &Outbound,
        stream: &StreamSettings,
        tag: impl Into<String>,
    ) -> Self {
        let bare = matches!(stream.network.as_str(), "" | "raw" | "tcp")
            && matches!(stream.security.as_str(), "" | "none")
            && stream.tls_settings.is_none()
            && stream.reality_settings.is_none()
            && stream.xhttp_settings.is_none()
            && stream.ws_settings.is_none()
            && stream.httpupgrade_settings.is_none()
            && stream.grpc_settings.is_none()
            && stream.kcp_settings.is_none();
        let capability = match outbound {
            Outbound::Freedom {
                redirect,
                final_rules,
                ..
            } if bare => Capability::Direct {
                redirect: redirect.clone(),
                final_rules: final_rules.clone(),
            },
            Outbound::Blackhole { .. } => Capability::Drop,
            _ => Capability::Unsupported,
        };
        Self {
            tag: tag.into(),
            capability,
            counters: TrafficCounters::default(),
        }
    }
}

struct Inner {
    router: Arc<Router>,
    outbounds: Vec<RouteOutbound>,
    inbound_protocol: Arc<str>,
    resolver: Arc<dyn UdpResolver>,
}

#[derive(Clone)]
pub struct RoutingDispatcher {
    inner: Arc<Inner>,
}

impl RoutingDispatcher {
    pub fn new(
        router: Arc<Router>,
        outbounds: Vec<RouteOutbound>,
        inbound_protocol: impl Into<Arc<str>>,
        resolver: Arc<dyn UdpResolver>,
    ) -> io::Result<Self> {
        if outbounds.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP routing requires outbounds",
            ));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                router,
                outbounds,
                inbound_protocol: inbound_protocol.into(),
                resolver,
            }),
        })
    }

    /// Select policy-enabled outbound counters before sharing this dispatcher.
    pub fn with_stats(mut self, stats: &StatsManager, policy: SystemStatsPolicy) -> Self {
        // A builder is normally unique; preserve safe semantics if called on a
        // clone by creating a new inner instead of changing active dispatchers.
        let outbounds = self
            .inner
            .outbounds
            .iter()
            .cloned()
            .map(|mut outbound| {
                outbound.counters = stats.outbound_counters(&outbound.tag, policy);
                outbound
            })
            .collect();
        self.inner = Arc::new(Inner {
            router: Arc::clone(&self.inner.router),
            outbounds,
            inbound_protocol: Arc::clone(&self.inner.inbound_protocol),
            resolver: Arc::clone(&self.inner.resolver),
        });
        self
    }
}

impl UdpDispatcher for RoutingDispatcher {
    fn dispatch(&self, context: DispatchContext) -> DispatchFuture {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            if context.network != "udp" || !super::udp::valid_destination(&context.destination) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid UDP dispatch context",
                ));
            }
            let selected = inner.router.select(&RouteContext {
                destination: &context.destination,
                source: context.source,
                inbound_tag: &context.inbound_tag,
                user: &context.user,
                network: "udp",
            });
            let outbound = inner.outbounds.get(selected).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP router/outbound order mismatch",
                )
            })?;
            let (redirect, final_rules) = match &outbound.capability {
                Capability::Drop => return Ok(DispatchAction::Drop),
                Capability::Unsupported => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound {:?} does not support native UDP", outbound.tag),
                    ));
                }
                Capability::Direct {
                    redirect,
                    final_rules,
                } => (redirect, final_rules),
            };
            let destination = redirect.as_ref().unwrap_or(&context.destination);
            if !super::udp::valid_destination(destination) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid UDP freedom redirect",
                ));
            }
            let addresses = match &destination.address {
                Address::Ip(address) => vec![*address],
                Address::Domain(host) => inner.resolver.resolve(host.clone()).await?,
            };
            if addresses.is_empty() || addresses.len() > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP DNS answer is empty or exceeds address limit",
                ));
            }
            let mut target = None;
            for address in addresses {
                let address = super::udp::canonical_ip(address);
                let endpoint = std::net::SocketAddr::new(address, destination.port);
                if !super::udp::valid_endpoint(endpoint) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP DNS returned a non-unicast endpoint",
                    ));
                }
                // Source freedom admission rejects a domain if any answer is
                // blocked. Do not skip blocked answers to find a permitted one.
                if final_rules
                    .block_delay(&inner.inbound_protocol, "udp", address, destination.port)
                    .is_some()
                {
                    return Ok(DispatchAction::Drop);
                }
                target.get_or_insert(endpoint);
            }
            Ok(DispatchAction::TrackedDirect {
                target: target.expect("nonempty address list checked above"),
                route: selected,
                counters: outbound.counters.clone(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::OutboundConfig, features::policy::SystemStatsPolicy, protocol::freedom::RuleConfig,
        router::RoutingConfig,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    fn context(host: &str) -> DispatchContext {
        DispatchContext {
            destination: Destination::new(host, 53).unwrap(),
            source: "192.0.2.10:4567".parse().unwrap(),
            inbound_tag: Arc::from("dns-in"),
            user: Arc::from("alice"),
            network: "udp",
        }
    }

    fn direct(rules: serde_json::Value, redirect: Option<Destination>) -> Outbound {
        Outbound::Freedom {
            strategy: Default::default(),
            redirect,
            final_rules: FinalRules::compile(
                &serde_json::from_value::<Vec<RuleConfig>>(rules).unwrap(),
            )
            .unwrap(),
        }
    }

    fn dispatcher(
        routing: serde_json::Value,
        outbounds: Vec<(Outbound, StreamSettings)>,
        resolver: Arc<dyn UdpResolver>,
    ) -> RoutingDispatcher {
        let configs: Vec<OutboundConfig> = (0..outbounds.len())
            .map(|index| {
                serde_json::from_value(
                    serde_json::json!({"tag": format!("out-{index}"), "protocol":"freedom"}),
                )
                .unwrap()
            })
            .collect();
        let router = Router::compile(
            &serde_json::from_value::<RoutingConfig>(routing).unwrap(),
            &configs,
        )
        .unwrap();
        RoutingDispatcher::new(
            Arc::new(router),
            outbounds
                .iter()
                .enumerate()
                .map(|(index, (outbound, stream))| {
                    RouteOutbound::from_config(outbound, stream, format!("out-{index}"))
                })
                .collect(),
            "socks",
            resolver,
        )
        .unwrap()
    }

    fn no_dns() -> Arc<dyn UdpResolver> {
        Arc::new(|_: String| async {
            panic!("numeric/unsupported/drop target must not resolve DNS")
        })
    }

    fn endpoint(action: DispatchAction) -> (std::net::SocketAddr, usize) {
        match action {
            DispatchAction::TrackedDirect { target, route, .. } => (target, route),
            other => panic!("expected admitted endpoint, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn route_uses_original_destination_and_all_udp_context_fields() {
        let dispatch = dispatcher(
            serde_json::json!({"rules":[{
                "type":"field", "outboundTag":"out-1", "domain":["full:original.test"],
                "network":"udp", "port":53, "sourcePort":4567,
                "source":["192.0.2.0/24"], "inboundTag":["dns-in"], "user":["alice"]
            }]}),
            vec![
                (
                    Outbound::Blackhole { response: vec![] },
                    StreamSettings::default(),
                ),
                (
                    direct(
                        serde_json::json!([]),
                        Some(Destination::new("198.51.100.8", 5353).unwrap()),
                    ),
                    StreamSettings::default(),
                ),
            ],
            no_dns(),
        );
        assert_eq!(
            endpoint(dispatch.dispatch(context("original.test")).await.unwrap()),
            ("198.51.100.8:5353".parse().unwrap(), 1)
        );
        let mut miss = context("original.test");
        miss.source.set_port(4568);
        assert!(matches!(
            dispatch.dispatch(miss).await.unwrap(),
            DispatchAction::Drop
        ));
        let mut miss = context("original.test");
        miss.user = Arc::from("bob");
        assert!(matches!(
            dispatch.dispatch(miss).await.unwrap(),
            DispatchAction::Drop
        ));
    }

    #[tokio::test]
    async fn final_rules_use_udp_and_redirect_port() {
        let dispatch = dispatcher(
            serde_json::json!({}),
            vec![(
                direct(
                    serde_json::json!([
                        {"action":"allow","network":"tcp"},
                        {"action":"block","network":"udp","port":5353,"blockDelay":0}
                    ]),
                    Some(Destination::new("198.51.100.8", 5353).unwrap()),
                ),
                StreamSettings::default(),
            )],
            no_dns(),
        );
        assert!(matches!(
            dispatch.dispatch(context("original.test")).await.unwrap(),
            DispatchAction::Drop
        ));
    }

    #[tokio::test]
    async fn dns_redirect_is_resolved_once_and_exact_checked_ip_is_pinned() {
        let queried = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&queried);
        let dispatch = dispatcher(
            serde_json::json!({}),
            vec![(
                direct(
                    serde_json::json!([]),
                    Some(Destination::new("redirect.test", 5353).unwrap()),
                ),
                StreamSettings::default(),
            )],
            Arc::new(move |host: String| {
                captured.lock().unwrap().push(host);
                async {
                    Ok(vec![
                        "::ffff:198.51.100.8".parse().unwrap(),
                        "198.51.100.9".parse().unwrap(),
                    ])
                }
            }),
        );
        assert_eq!(
            endpoint(dispatch.dispatch(context("original.test")).await.unwrap()).0,
            "198.51.100.8:5353".parse().unwrap()
        );
        assert_eq!(*queried.lock().unwrap(), ["redirect.test"]);
    }

    #[tokio::test]
    async fn any_blocked_dns_answer_blocks_without_skipping_or_retrying() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::clone(&calls);
        let dispatch = dispatcher(
            serde_json::json!({}),
            vec![(
                direct(
                    serde_json::json!([
                        {"action":"block","network":"udp","ip":["127.0.0.0/8"],"blockDelay":0}
                    ]),
                    None,
                ),
                StreamSettings::default(),
            )],
            Arc::new(move |_: String| {
                captured.fetch_add(1, Ordering::SeqCst);
                async {
                    Ok(vec![
                        "198.51.100.8".parse().unwrap(),
                        "127.0.0.1".parse().unwrap(),
                    ])
                }
            }),
        );
        assert!(matches!(
            dispatch.dispatch(context("target.test")).await.unwrap(),
            DispatchAction::Drop
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn configured_dns_failure_is_returned_without_os_fallback() {
        let dispatch = dispatcher(
            serde_json::json!({}),
            vec![(
                direct(serde_json::json!([]), None),
                StreamSettings::default(),
            )],
            Arc::new(|_: String| async {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "configured DNS policy",
                ))
            }),
        );
        assert_eq!(
            dispatch
                .dispatch(context("localhost"))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn every_proxy_and_layered_freedom_capability_is_explicitly_rejected() {
        let server = Destination::new("127.0.0.1", 1080).unwrap();
        let mut choices = vec![
            (
                Outbound::Socks {
                    server: server.clone(),
                    account: None,
                },
                StreamSettings::default(),
            ),
            (
                Outbound::Http {
                    server,
                    account: None,
                },
                StreamSettings::default(),
            ),
            (Outbound::Api, StreamSettings::default()),
        ];
        for stream in [
            serde_json::json!({"network":"ws"}),
            serde_json::json!({"network":"xhttp"}),
            serde_json::json!({"security":"tls"}),
            serde_json::json!({"security":"reality"}),
            serde_json::json!({"tlsSettings":{}}),
            serde_json::json!({"wsSettings":{}}),
            serde_json::json!({"grpcSettings":{}}),
            serde_json::json!({"network":"raw","kcpSettings":{}}),
            serde_json::json!({"network":"kcp"}),
            serde_json::json!({"network":"mkcp"}),
        ] {
            choices.push((
                direct(serde_json::json!([]), None),
                serde_json::from_value(stream).unwrap(),
            ));
        }
        for choice in choices {
            let dispatch = dispatcher(serde_json::json!({}), vec![choice], no_dns());
            assert_eq!(
                dispatch
                    .dispatch(context("target.test"))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[tokio::test]
    async fn invalid_dns_answers_never_produce_a_direct_action() {
        for answers in [
            vec![],
            vec!["0.0.0.0"],
            vec!["::"],
            vec!["224.0.0.1"],
            vec!["255.255.255.255"],
            vec!["ff02::1"],
        ] {
            let addresses: Vec<IpAddr> =
                answers.into_iter().map(|ip| ip.parse().unwrap()).collect();
            let dispatch = dispatcher(
                serde_json::json!({}),
                vec![(
                    direct(serde_json::json!([]), None),
                    StreamSettings::default(),
                )],
                Arc::new(move |_: String| {
                    let addresses = addresses.clone();
                    async move { Ok(addresses) }
                }),
            );
            assert_eq!(
                dispatch
                    .dispatch(context("target.test"))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn admission_does_not_increment_actual_io_counters() {
        let stats = StatsManager::new();
        let dispatch = dispatcher(
            serde_json::json!({}),
            vec![(
                direct(serde_json::json!([]), None),
                StreamSettings::default(),
            )],
            no_dns(),
        )
        .with_stats(
            &stats,
            SystemStatsPolicy {
                outbound_uplink: true,
                outbound_downlink: true,
                ..Default::default()
            },
        );
        let DispatchAction::TrackedDirect { counters, .. } =
            dispatch.dispatch(context("198.51.100.8")).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(counters.uplink.unwrap().value(), 0);
        assert_eq!(counters.downlink.unwrap().value(), 0);
    }
}
