use super::*;
use crate::{
    config::dns::DnsConfig,
    dns::encrypted::DialMode,
    geodata::GeoDataStore,
    protocol::freedom::{Delay, FinalRules, RuleConfig},
    transport::{BoxStream, tls::TlsCertificate},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;

fn policy(value: serde_json::Value) -> Arc<CompiledDns> {
    Arc::new(
        serde_json::from_value::<DnsConfig>(value)
            .unwrap()
            .compile(&GeoDataStore::new("."))
            .unwrap(),
    )
}

fn numeric_policy() -> Arc<CompiledDns> {
    policy(serde_json::json!({"servers":["192.0.2.53"]}))
}

#[derive(Clone, Copy)]
enum Reply {
    Good,
    NegativeV6,
    MissingV6,
    Negative,
    WrongIdThenGood,
    Truncated,
    SlowV6,
}

struct MockConnector {
    calls: Arc<AtomicUsize>,
    requests: Mutex<Vec<RouteRequest>>,
    messages: Arc<Mutex<Vec<Message>>>,
    reply: Reply,
    delay: Duration,
    change_route: bool,
}

impl MockConnector {
    fn new(reply: Reply) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            requests: Mutex::new(Vec::new()),
            messages: Arc::new(Mutex::new(Vec::new())),
            reply,
            delay: Duration::from_millis(10),
            change_route: false,
        }
    }
}

impl Connector for MockConnector {
    fn route<'a>(
        &'a self,
        mut request: RouteRequest,
        _: &'a CancellationToken,
    ) -> IoFuture<'a, CheckedRoute> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request.clone());
            if self.change_route {
                request.candidates = vec!["127.0.0.1:53".parse().unwrap()].into();
            }
            CheckedRoute::for_proxy(request, "test-proxy".into())
        })
    }
    fn connect_tcp<'a>(&'a self, _: &'a CheckedRoute) -> IoFuture<'a, BoxStream> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "test UDP connector",
            ))
        })
    }
    fn connect_udp<'a>(&'a self, _: &'a CheckedRoute) -> IoFuture<'a, Box<dyn Datagram>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(MockDatagram {
                messages: self.messages.clone(),
                query: Mutex::new(Vec::new()),
                reply: self.reply,
                delay: self.delay,
                receives: AtomicUsize::new(0),
            }) as Box<dyn Datagram>)
        })
    }
}

struct MockDatagram {
    messages: Arc<Mutex<Vec<Message>>>,
    query: Mutex<Vec<u8>>,
    reply: Reply,
    delay: Duration,
    receives: AtomicUsize,
}

impl Datagram for MockDatagram {
    fn send<'a>(&'a self, bytes: &'a [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            self.messages
                .lock()
                .unwrap()
                .push(wire::decode(bytes).unwrap());
            *self.query.lock().unwrap() = bytes.to_vec();
            Ok(bytes.len())
        })
    }
    fn recv<'a>(&'a self, buffer: &'a mut [u8]) -> IoFuture<'a, usize> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            let request = wire::decode(&self.query.lock().unwrap()).unwrap();
            let question = &request.questions[0];
            let v6 = question.record_type == RecordType::AAAA;
            if matches!(self.reply, Reply::SlowV6) && v6 {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            if matches!(self.reply, Reply::MissingV6) && v6 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "missing AAAA reply",
                ));
            }
            let negative = matches!(self.reply, Reply::Negative)
                || matches!(self.reply, Reply::NegativeV6) && v6;
            let addresses = if negative {
                vec![]
            } else {
                vec![
                    if v6 { "2001:db8::7" } else { "192.0.2.7" }
                        .parse()
                        .unwrap(),
                ]
            };
            let id = if matches!(self.reply, Reply::WrongIdThenGood)
                && self.receives.fetch_add(1, Ordering::SeqCst) == 0
            {
                request.header.id.wrapping_add(1)
            } else {
                request.header.id
            };
            let ttl = if matches!(self.reply, Reply::SlowV6) {
                2
            } else {
                600
            };
            let mut response = wire::encode_response(
                id,
                question,
                &addresses,
                ttl,
                u16::from(negative) * 3,
                None,
                wire::MAX_MESSAGE_SIZE,
            )
            .unwrap();
            if matches!(self.reply, Reply::Truncated) {
                response[2] |= 2;
                response.truncate(response.len() - 2);
            }
            buffer[..response.len()].copy_from_slice(&response);
            Ok(response.len())
        })
    }
}

fn adapter(policy: Arc<CompiledDns>, connector: Arc<dyn Connector>) -> NetworkDns {
    NetworkDns::new(policy, connector, HashMap::new(), Limits::default()).unwrap()
}

#[tokio::test]
async fn separate_family_cache_ecs_and_case_sensitive_keys() {
    let connector = Arc::new(MockConnector::new(Reply::Good));
    let plan = policy(
        serde_json::json!({"clientIp":"203.0.113.9","tag":"dns-test","servers":["192.0.2.53"]}),
    );
    let dns = adapter(plan, connector.clone());
    let cancel = CancellationToken::new();
    let answer = dns
        .lookup("Example.COM", QueryOptions::BOTH, &cancel)
        .await
        .unwrap();
    assert_eq!(answer.ips.len(), 2);
    assert_eq!(answer.ttl, 300); // Go's dual-family merge cap.
    assert_eq!(dns.cache_len(), 2);
    let cached = dns
        .lookup("Example.COM", QueryOptions::IPV4, &cancel)
        .await
        .unwrap();
    assert_eq!(cached.ttl, 600);
    assert_eq!(connector.calls.load(Ordering::SeqCst), 2);
    dns.lookup("example.com", QueryOptions::IPV4, &cancel)
        .await
        .unwrap();
    assert_eq!(connector.calls.load(Ordering::SeqCst), 3);
    let messages = connector.messages.lock().unwrap();
    assert!(messages.iter().all(|message| {
        message
            .additionals
            .iter()
            .any(|record| record.record_type == RecordType::OPT)
    }));
    let requests = connector.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.tag() == "dns-test" && request.network() == Network::Udp)
    );
    assert_eq!(
        requests[0].candidates(),
        &["192.0.2.53:53".parse().unwrap()]
    );
}

#[tokio::test]
async fn missing_family_fails_but_actual_negative_family_can_merge() {
    let cancel = CancellationToken::new();
    let missing = adapter(
        numeric_policy(),
        Arc::new(MockConnector::new(Reply::MissingV6)),
    );
    assert!(
        missing
            .lookup("example.com", QueryOptions::BOTH, &cancel)
            .await
            .is_err()
    );
    let negative = adapter(
        numeric_policy(),
        Arc::new(MockConnector::new(Reply::NegativeV6)),
    );
    assert_eq!(
        negative
            .lookup("example.com", QueryOptions::BOTH, &cancel)
            .await
            .unwrap()
            .ips,
        vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn early_family_ttl_ages_while_other_family_is_pending() {
    let dns = adapter(
        numeric_policy(),
        Arc::new(MockConnector::new(Reply::SlowV6)),
    );
    let answer = dns
        .lookup("example.com", QueryOptions::BOTH, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(answer.ips.len(), 2);
    assert_eq!(answer.ttl, 1);
}

#[test]
fn family_ttl_rounds_up_and_expired_merge_clamps_to_one() {
    let inserted = Instant::now();
    let answer = DnsAnswer {
        ips: vec![],
        ttl: 3,
        response_code: 0,
        from_cache: false,
        stale: false,
    };
    assert_eq!(
        age_answer(
            answer.clone(),
            inserted,
            inserted + Duration::from_millis(1999)
        )
        .ttl,
        2
    );
    assert_eq!(
        age_answer(answer, inserted, inserted + Duration::from_secs(4)).ttl,
        1
    );
}

#[tokio::test]
async fn negative_replies_cache_and_caches_are_per_server() {
    let connector = Arc::new(MockConnector::new(Reply::Negative));
    let dns = adapter(
        policy(serde_json::json!({"servers":["192.0.2.53","192.0.2.54"]})),
        connector.clone(),
    );
    for _ in 0..2 {
        assert!(matches!(
            dns.lookup(
                "empty.example",
                QueryOptions::IPV4,
                &CancellationToken::new()
            )
            .await,
            Err(DnsError::ResponseCode(3))
        ));
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 2);
    assert_eq!(dns.cache_len(), 2);
    dns.clear_cache();
    assert_eq!(dns.cache_len(), 0);
}

#[tokio::test]
async fn identical_uncached_queries_share_one_exchange() {
    let connector = Arc::new(MockConnector::new(Reply::Good));
    let dns = adapter(
        policy(serde_json::json!({"disableCache":true,"servers":["192.0.2.53"]})),
        connector.clone(),
    );
    let cancel = CancellationToken::new();
    let (first, second, third) = tokio::join!(
        dns.lookup("example.com", QueryOptions::IPV4, &cancel),
        dns.lookup("example.com", QueryOptions::IPV4, &cancel),
        dns.lookup("example.com", QueryOptions::IPV4, &cancel),
    );
    assert!(first.is_ok() && second.is_ok() && third.is_ok());
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    assert_eq!(dns.cache_len(), 0);
}

#[tokio::test]
async fn missing_cached_family_refetches_both_requested_families() {
    let connector = Arc::new(MockConnector::new(Reply::Good));
    let dns = adapter(numeric_policy(), connector.clone());
    let cancel = CancellationToken::new();
    dns.lookup("example.com", QueryOptions::IPV4, &cancel)
        .await
        .unwrap();
    dns.lookup("example.com", QueryOptions::BOTH, &cancel)
        .await
        .unwrap();
    assert_eq!(connector.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn wrong_identity_is_ignored_and_udp_truncation_does_not_retry_tcp() {
    let dns = adapter(
        numeric_policy(),
        Arc::new(MockConnector::new(Reply::WrongIdThenGood)),
    );
    assert!(
        dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
            .await
            .is_ok()
    );
    let plan = numeric_policy();
    let dns = adapter(plan.clone(), Arc::new(MockConnector::new(Reply::Truncated)));
    assert!(matches!(
        dns.query(&plan.servers[0], "example.com", QueryOptions::IPV4)
            .await,
        Err(DnsError::Truncated)
    ));
}

#[tokio::test]
async fn changed_route_is_rejected_before_transport_io() {
    let mut connector = MockConnector::new(Reply::Good);
    connector.change_route = true;
    let connector = Arc::new(connector);
    let dns = adapter(numeric_policy(), connector.clone());
    assert!(
        dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn bootstrap_and_resource_bounds_are_explicit() {
    let named = policy(serde_json::json!({"servers":["https://resolver.example/dns-query"]}));
    assert!(
        NetworkDns::new(
            named,
            Arc::new(LocalConnector),
            HashMap::new(),
            Limits::default()
        )
        .is_err()
    );
    let mut bindings = HashMap::new();
    bindings.insert(
        0,
        ServerBinding {
            bootstrap: vec!["192.0.2.54".parse().unwrap()],
            tls: None,
        },
    );
    assert!(
        NetworkDns::new(
            numeric_policy(),
            Arc::new(LocalConnector),
            bindings,
            Limits::default()
        )
        .is_err()
    );
    let limits = Limits {
        max_cache_entries_total: 1,
        ..Limits::default()
    };
    assert!(
        NetworkDns::new(
            numeric_policy(),
            Arc::new(LocalConnector),
            HashMap::new(),
            limits
        )
        .is_err()
    );
    let dns = adapter(
        policy(
            serde_json::json!({"hosts":{"resolver.example":"192.0.2.53"},"servers":["https://resolver.example/dns-query"]}),
        ),
        Arc::new(LocalConnector),
    );
    assert_eq!(
        dns.owner.state.servers[0].request.candidates(),
        &["192.0.2.53:443".parse().unwrap()]
    );
    assert_eq!(
        dns.owner.state.servers[0]
            .encrypted
            .as_ref()
            .unwrap()
            .endpoint()
            .host(),
        "resolver.example"
    );
}

#[tokio::test]
async fn local_connector_requires_explicit_local_and_preserves_numeric_pins() {
    let dns = adapter(numeric_policy(), Arc::new(LocalConnector));
    let request = dns.owner.state.servers[0].request.clone();
    let cancel = CancellationToken::new();
    assert!(
        LocalConnector
            .route(request.clone(), &cancel)
            .await
            .is_err()
    );
    let mut local = request;
    local.mode = DialMode::Local;
    let checked = LocalConnector.route(local, &cancel).await.unwrap();
    assert!(checked.is_local());
    assert_eq!(checked.candidates(), &["192.0.2.53:53".parse().unwrap()]);
}

#[tokio::test]
async fn freedom_checks_network_all_candidates_and_cancellation() {
    let dns = adapter(numeric_policy(), Arc::new(LocalConnector));
    let request = dns.owner.state.servers[0].request.clone();
    let rules = FinalRules::compile(&[RuleConfig {
        action: "block".into(),
        network: vec!["udp".into()],
        ip: vec!["192.0.2.54".into()],
        block_delay: Some(Delay::Seconds(0)),
        ..Default::default()
    }])
    .unwrap();
    let cancel = CancellationToken::new();
    let mut multi = request.clone();
    multi.candidates = vec![
        "192.0.2.53:53".parse().unwrap(),
        "192.0.2.54:53".parse().unwrap(),
    ]
    .into();
    assert_eq!(
        CheckedRoute::admit_freedom(multi.clone(), "direct".into(), &rules, "socks", &cancel)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    multi.network = Network::Tcp;
    assert!(
        CheckedRoute::admit_freedom(multi, "direct".into(), &rules, "socks", &cancel)
            .await
            .unwrap()
            .is_freedom()
    );
    let mut private = request;
    private.candidates = vec!["127.0.0.1:53".parse().unwrap()].into();
    cancel.cancel();
    assert_eq!(
        CheckedRoute::admit_freedom(
            private,
            "direct".into(),
            &FinalRules::default(),
            "vless",
            &cancel
        )
        .await
        .unwrap_err()
        .kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn cancellation_drops_foreground_and_releases_query_capacity() {
    let mut connector = MockConnector::new(Reply::Good);
    connector.delay = Duration::from_secs(60);
    let connector = Arc::new(connector);
    let dns = NetworkDns::new(
        numeric_policy(),
        connector.clone(),
        HashMap::new(),
        Limits {
            max_inflight_queries: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let lookup = dns.lookup("example.com", QueryOptions::BOTH, &cancel);
    let trigger = async {
        while connector.calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        cancel.cancel();
    };
    let (answer, _) = tokio::join!(lookup, trigger);
    assert!(
        matches!(answer, Err(DnsError::Io(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
    assert_eq!(dns.owner.state.queries.available_permits(), 1);
    assert!(
        dns.owner
            .state
            .flights
            .lock()
            .unwrap()
            .values()
            .all(|flight| flight.strong_count() == 0)
    );
}

#[tokio::test]
async fn stale_refresh_is_bounded_survives_caller_cancel_and_shutdown_joins() {
    let mut connector = MockConnector::new(Reply::Good);
    connector.delay = Duration::from_secs(60);
    let connector = Arc::new(connector);
    let plan = policy(serde_json::json!({"serveStale":true,"servers":["192.0.2.53"]}));
    let dns = NetworkDns::new(
        plan.clone(),
        connector.clone(),
        HashMap::new(),
        Limits {
            max_refresh_tasks: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    for name in ["one.example.", "two.example."] {
        dns.owner.state.servers[0].cache.lock().unwrap().insert(
            CacheKey {
                name: name.into(),
                record_type: RecordType::A,
            },
            DnsAnswer {
                ips: vec!["192.0.2.8".parse().unwrap()],
                ttl: 1,
                response_code: 0,
                from_cache: false,
                stale: false,
            },
            &plan.servers[0].cache,
            Instant::now() - Duration::from_secs(2),
        );
    }
    let cancel = CancellationToken::new();
    assert_eq!(
        dns.lookup("one.example", QueryOptions::IPV4, &cancel)
            .await
            .unwrap()
            .ttl,
        1
    );
    cancel.cancel();
    assert_eq!(
        dns.lookup("two.example", QueryOptions::IPV4, &CancellationToken::new())
            .await
            .unwrap()
            .ttl,
        1
    );
    while connector.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(dns.owner.state.refreshing.lock().unwrap().len(), 1);
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    dns.shutdown().await;
    assert!(dns.owner.state.tasks.is_empty());
    assert!(dns.owner.state.refreshing.lock().unwrap().is_empty());
    assert!(
        dns.lookup("one.example", QueryOptions::IPV4, &CancellationToken::new())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dropping_last_owner_cancels_background_state() {
    let dns = adapter(numeric_policy(), Arc::new(LocalConnector));
    let state = dns.owner.state.clone();
    let other = dns.clone();
    drop(dns);
    assert!(!state.cancel.is_cancelled());
    drop(other);
    assert!(state.cancel.is_cancelled());
}

struct NumericConnector {
    calls: AtomicUsize,
}
impl Connector for NumericConnector {
    fn route<'a>(
        &'a self,
        request: RouteRequest,
        _: &'a CancellationToken,
    ) -> IoFuture<'a, CheckedRoute> {
        Box::pin(async move { CheckedRoute::for_proxy(request, "loopback-test".into()) })
    }
    fn connect_tcp<'a>(&'a self, route: &'a CheckedRoute) -> IoFuture<'a, BoxStream> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(TcpStream::connect(route.candidates()[0]).await?) as BoxStream)
        })
    }
    fn connect_udp<'a>(&'a self, route: &'a CheckedRoute) -> IoFuture<'a, Box<dyn Datagram>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(route.candidates()[0]).await?;
            Ok(Box::new(socket) as Box<dyn Datagram>)
        })
    }
}

fn response(query: &[u8]) -> Vec<u8> {
    let request = wire::decode(query).unwrap();
    wire::encode_response(
        request.header.id,
        &request.questions[0],
        &["192.0.2.17".parse().unwrap()],
        123,
        0,
        None,
        wire::MAX_MESSAGE_SIZE,
    )
    .unwrap()
}

#[tokio::test]
async fn real_udp_and_local_tcp_use_injected_numeric_transports() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 1500];
        let (size, peer) = udp.recv_from(&mut bytes).await.unwrap();
        udp.send_to(&response(&bytes[..size]), peer).await.unwrap();
    });
    let connector = Arc::new(NumericConnector {
        calls: AtomicUsize::new(0),
    });
    let dns = adapter(
        policy(serde_json::json!({"servers":[{"address":"127.0.0.1","port":port}]})),
        connector.clone(),
    );
    assert_eq!(
        dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
            .await
            .unwrap()
            .ttl,
        123
    );
    server.await.unwrap();
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);

    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("tcp+local://{}", tcp.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let query = read_tcp_message(&mut stream).await.unwrap().unwrap();
        write_tcp_message(&mut stream, &response(&query))
            .await
            .unwrap();
    });
    let dns = adapter(
        policy(serde_json::json!({"servers":[address]})),
        Arc::new(LocalConnector),
    );
    assert_eq!(
        dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
            .await
            .unwrap()
            .ttl,
        123
    );
    server.await.unwrap();
}

fn tls_pair(alpn: &str) -> (TlsSettings, TlsSettings) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["resolver.example".into()]).unwrap();
    let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
    let server = TlsSettings {
        alpn: vec![alpn.into()],
        certificates: vec![TlsCertificate {
            certificate: certificate.clone(),
            key: signing_key
                .serialize_pem()
                .lines()
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let client = TlsSettings {
        disable_system_root: true,
        certificates: vec![TlsCertificate {
            certificate,
            usage: "verify".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    (server, client)
}

#[tokio::test]
async fn real_dot_uses_bootstrap_with_original_tls_identity_and_cache() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "tls://resolver.example:{}",
        listener.local_addr().unwrap().port()
    );
    let (server_tls, client_tls) = tls_pair("dot");
    let acceptor = TlsAcceptor::from(server_tls.build_server_config().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some("resolver.example"));
        let query = read_tcp_message(&mut stream).await.unwrap().unwrap();
        write_tcp_message(&mut stream, &response(&query))
            .await
            .unwrap();
    });
    let connector = Arc::new(NumericConnector {
        calls: AtomicUsize::new(0),
    });
    let dns = NetworkDns::new(
        policy(serde_json::json!({"servers":[endpoint]})),
        connector.clone(),
        HashMap::from([(
            0,
            ServerBinding {
                bootstrap: vec!["127.0.0.1".parse().unwrap()],
                tls: Some(client_tls),
            },
        )]),
        Limits::default(),
    )
    .unwrap();
    for _ in 0..2 {
        assert_eq!(
            dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
                .await
                .unwrap()
                .ttl,
            123
        );
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn foreground_encrypted_timeout_can_exceed_refresh_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "tls://resolver.example:{}",
        listener.local_addr().unwrap().port()
    );
    let (server_tls, client_tls) = tls_pair("dot");
    let acceptor = TlsAcceptor::from(server_tls.build_server_config().unwrap());
    let (received, observed) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let query = read_tcp_message(&mut stream).await.unwrap().unwrap();
        received.send(()).unwrap();
        released.await.unwrap();
        write_tcp_message(&mut stream, &response(&query))
            .await
            .unwrap();
    });
    let dns = NetworkDns::new(
        policy(serde_json::json!({"servers":[{"address":endpoint,"timeoutMs":12000}]})),
        Arc::new(NumericConnector {
            calls: AtomicUsize::new(0),
        }),
        HashMap::from([(
            0,
            ServerBinding {
                bootstrap: vec!["127.0.0.1".parse().unwrap()],
                tls: Some(client_tls),
            },
        )]),
        Limits::default(),
    )
    .unwrap();
    let lookup = tokio::spawn(async move {
        dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
            .await
    });
    observed.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert!(
        !lookup.is_finished(),
        "foreground DNS was cut off by the eight-second refresh budget"
    );
    release.send(()).unwrap();
    tokio::time::resume();
    assert!(lookup.await.unwrap().is_ok());
    server.await.unwrap();
}

#[tokio::test]
async fn real_doh_uses_static_bootstrap_http_authority_and_cache() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("https://resolver.example:{port}/dns-query");
    let (server_tls, client_tls) = tls_pair("h2");
    let acceptor = TlsAcceptor::from(server_tls.build_server_config().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            format!("resolver.example:{port}")
        );
        let mut body = request.into_body();
        let operation = async move {
            let mut query = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                query.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            assert_eq!(wire::decode(&query).unwrap().header.id, 0);
            let reply = http::Response::builder()
                .header("content-type", "application/dns-message")
                .body(())
                .unwrap();
            respond
                .send_response(reply, false)
                .unwrap()
                .send_data(bytes::Bytes::from(response(&query)), true)
                .unwrap();
        };
        tokio::pin!(operation);
        tokio::select! {
            _ = &mut operation => {},
            _ = connection.accept() => panic!("HTTP/2 connection closed before response"),
        }
        // Continue driving queued response frames until the client closes.
        while connection.accept().await.is_some() {}
    });
    let connector = Arc::new(NumericConnector {
        calls: AtomicUsize::new(0),
    });
    let dns = NetworkDns::new(
        policy(serde_json::json!({"hosts":{"resolver.example":"127.0.0.1"},"servers":[endpoint]})),
        connector.clone(),
        HashMap::from([(
            0,
            ServerBinding {
                bootstrap: vec![],
                tls: Some(client_tls),
            },
        )]),
        Limits::default(),
    )
    .unwrap();
    for _ in 0..2 {
        assert_eq!(
            dns.lookup("example.com", QueryOptions::IPV4, &CancellationToken::new())
                .await
                .unwrap()
                .ttl,
            123
        );
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    server.await.unwrap();
}
