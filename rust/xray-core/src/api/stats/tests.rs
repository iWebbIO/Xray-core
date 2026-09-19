use std::{collections::HashSet, time::Duration};

use prost::Message;
use tokio::{net::TcpListener, time::timeout};
use tonic::{Code, transport::Channel};

use super::*;
use crate::api::{ApiServer, RunningApiServer, incoming_channel};
use wire::{stats_service_client::StatsServiceClient, stats_service_server::StatsService as _};

fn request(name: &str, reset: bool) -> Request<wire::GetStatsRequest> {
    Request::new(wire::GetStatsRequest {
        name: name.into(),
        reset,
    })
}

fn manager_service() -> (Arc<StatsManager>, StatsService) {
    let manager = Arc::new(StatsManager::new());
    let service = StatsService::new(manager.clone());
    (manager, service)
}

#[tokio::test]
async fn missing_counter_and_map_keep_original_not_found_message() {
    let (_, service) = manager_service();
    let result = service
        .get_stats(request("missing", true))
        .await
        .unwrap_err();
    assert_eq!(result.code(), Code::NotFound);
    assert_eq!(result.message(), "missing not found.");
    assert_eq!(
        service
            .get_stats_online(request("missing", false))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        service
            .get_stats_online_ip_list(request("missing", false))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}

#[tokio::test]
async fn fetch_and_reset_return_the_previous_signed_64_bit_value() {
    let (manager, service) = manager_service();
    let counter = manager.get_or_register_counter("hits");
    for value in [i64::MIN, -1, 0, i64::MAX] {
        counter.set(value);
        assert_eq!(
            service
                .get_stats(request("hits", false))
                .await
                .unwrap()
                .into_inner()
                .stat
                .unwrap()
                .value,
            value
        );
        assert_eq!(
            service
                .get_stats(request("hits", true))
                .await
                .unwrap()
                .into_inner()
                .stat
                .unwrap()
                .value,
            value
        );
        assert_eq!(counter.value(), 0);
    }
}

#[tokio::test]
async fn query_is_literal_substring_and_resets_only_selected_counters() {
    let (manager, service) = manager_service();
    let matched = manager.get_or_register_counter("literal[ab].counter");
    let unmatched = manager.get_or_register_counter("literalacounter");
    matched.set(51);
    unmatched.set(73);
    let result = service
        .query_stats(Request::new(wire::QueryStatsRequest {
            pattern: "[ab].".into(),
            reset: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        result.stat,
        vec![wire::Stat {
            name: "literal[ab].counter".into(),
            value: 51
        }]
    );
    assert_eq!(matched.value(), 0);
    assert_eq!(unmatched.value(), 73);
    let all = service
        .query_stats(Request::new(wire::QueryStatsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(all.stat.len(), 2);
}

#[tokio::test]
async fn online_rpc_counts_unique_addresses_preserves_timestamps_and_ignores_reset() {
    let (manager, service) = manager_service();
    let map = manager.get_or_register_online_map("user>>>ada@example.test>>>online");
    map.add_ip_at("192.0.2.1", 1_700_000_001);
    map.add_ip_at("192.0.2.1", 1_700_000_002);
    map.add_ip_at("2001:db8::1", 1_700_000_003);
    let response = service
        .get_stats_online(request("user>>>ada@example.test>>>online", true))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 2);
    assert_eq!(map.count(), 2);
    let ips = service
        .get_stats_online_ip_list(request("user>>>ada@example.test>>>online", true))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ips.ips.len(), 2);
    assert_eq!(ips.ips["192.0.2.1"], 1_700_000_002);
    assert_eq!(ips.ips["2001:db8::1"], 1_700_000_003);
    map.remove_ip("192.0.2.1");
    assert_eq!(map.count(), 2);
    map.remove_ip("192.0.2.1");
    assert_eq!(map.count(), 1);
}

#[tokio::test]
async fn all_online_users_return_registered_map_names_including_noncanonical_names() {
    let (manager, service) = manager_service();
    manager
        .get_or_register_online_map("user>>>ada>>>online")
        .add_ip("192.0.2.1");
    manager
        .get_or_register_online_map("custom-map")
        .add_ip("192.0.2.2");
    manager.get_or_register_online_map("user>>>offline>>>online");
    let result = service
        .get_all_online_users(Request::new(wire::GetAllOnlineUsersRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        result.users.into_iter().collect::<HashSet<_>>(),
        HashSet::from(["user>>>ada>>>online".to_owned(), "custom-map".to_owned()])
    );
}

#[tokio::test]
async fn users_traffic_reset_is_limited_to_online_users_and_requested_traffic() {
    let (manager, service) = manager_service();
    manager
        .get_or_register_online_map("user>>>ada>>>online")
        .add_ip_at("192.0.2.1", 100);
    manager
        .get_or_register_online_map("user>>>missing-counters>>>online")
        .add_ip_at("192.0.2.2", 101);
    let up = manager.get_or_register_counter("user>>>ada>>>traffic>>>uplink");
    let down = manager.get_or_register_counter("user>>>ada>>>traffic>>>downlink");
    let offline = manager.get_or_register_counter("user>>>offline>>>traffic>>>uplink");
    up.set(123);
    down.set(456);
    offline.set(789);

    let without = service
        .get_users_stats(Request::new(wire::GetUsersStatsRequest {
            include_traffic: false,
            reset: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(without.users.iter().all(|user| user.traffic.is_none()));
    assert_eq!(up.value(), 123);
    let with = service
        .get_users_stats(Request::new(wire::GetUsersStatsRequest {
            include_traffic: true,
            reset: true,
        }))
        .await
        .unwrap()
        .into_inner();
    let ada = with.users.iter().find(|user| user.email == "ada").unwrap();
    assert_eq!(
        ada.traffic,
        Some(wire::TrafficUserStat {
            uplink: 123,
            downlink: 456
        })
    );
    let missing = with
        .users
        .iter()
        .find(|user| user.email == "missing-counters")
        .unwrap();
    assert_eq!(missing.traffic, Some(wire::TrafficUserStat::default()));
    assert_eq!(up.value(), 0);
    assert_eq!(down.value(), 0);
    assert_eq!(offline.value(), 789);
    assert!(!with.users.iter().any(|user| user.email == "offline"));
}

#[tokio::test]
async fn users_keep_go_cut_semantics_without_panicking_on_malformed_counter_names() {
    let (manager, service) = manager_service();
    manager
        .get_or_register_online_map("custom>>>person>>>whatever")
        .add_ip_at("192.0.2.1", 123);
    manager
        .get_or_register_online_map("no-delimiters")
        .add_ip_at("192.0.2.2", 456);
    manager
        .get_or_register_counter(">>>traffic>>>uplink")
        .set(99);
    // Go slices a seven-byte prefix rather than requiring "user>>>".
    manager
        .get_or_register_counter("prefix-person>>>traffic>>>uplink")
        .set(73);
    let result = service
        .get_users_stats(Request::new(wire::GetUsersStatsRequest {
            include_traffic: true,
            reset: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.users.len(), 2);
    assert!(result.users.iter().any(|user| user.email.is_empty()));
    assert_eq!(
        result
            .users
            .iter()
            .find(|user| user.email == "person")
            .unwrap()
            .traffic
            .as_ref()
            .unwrap()
            .uplink,
        73
    );
    assert_eq!(
        manager.get_counter(">>>traffic>>>uplink").unwrap().value(),
        99
    );
}

struct MeasuredSystem;

impl SystemStatsProvider for MeasuredSystem {
    fn snapshot(&self) -> Result<SystemStatsSnapshot, Status> {
        Ok(SystemStatsSnapshot {
            num_goroutine: Some(17),
            num_gc: Some(0),
            alloc: Some(9_001),
            total_alloc: Some(72_345),
            sys: Some(65_536),
            mallocs: Some(11),
            frees: Some(3),
            live_objects: Some(8),
            pause_total_ns: Some(0),
        })
    }
    fn name(&self) -> &'static str {
        "test-measured-allocator"
    }
}

#[tokio::test]
async fn system_provider_values_and_service_uptime_are_preserved() {
    let mut service =
        StatsService::with_system_stats(Arc::new(StatsManager::new()), Arc::new(MeasuredSystem));
    service.started = Instant::now() - Duration::from_secs(31);
    let response = service
        .get_sys_stats(Request::new(wire::SysStatsRequest {}))
        .await
        .unwrap();
    assert!(
        response
            .metadata()
            .get("x-xray-unsupported-fields")
            .is_none()
    );
    assert_eq!(
        response
            .metadata()
            .get("x-xray-system-stats-provider")
            .unwrap(),
        "test-measured-allocator"
    );
    let measured = response.into_inner();
    assert_eq!(measured.num_goroutine, 17);
    assert_eq!(measured.alloc, 9_001);
    assert_eq!(measured.total_alloc, 72_345);
    assert_eq!(measured.sys, 65_536);
    assert_eq!(measured.mallocs, 11);
    assert_eq!(measured.frees, 3);
    assert_eq!(measured.live_objects, 8);
    assert!((31..33).contains(&measured.uptime));
}

#[tokio::test]
async fn native_system_metrics_explicitly_identify_unavailable_allocator_fields() {
    let (_, service) = manager_service();
    let held_task = tokio::spawn(std::future::pending::<()>());
    let response = service
        .get_sys_stats(Request::new(wire::SysStatsRequest {}))
        .await
        .unwrap();
    assert_eq!(
        response
            .metadata()
            .get("x-xray-system-stats-provider")
            .unwrap(),
        "rust-tokio"
    );
    assert_eq!(
        response
            .metadata()
            .get("x-xray-num-goroutine-kind")
            .unwrap(),
        "tokio-tasks"
    );
    assert_eq!(
        response
            .metadata()
            .get("x-xray-unsupported-fields")
            .unwrap(),
        "alloc,total_alloc,sys,mallocs,frees,live_objects"
    );
    assert!(response.get_ref().num_goroutine >= 1);
    assert_eq!(response.get_ref().num_gc, 0);
    held_task.abort();
}

struct FailedSystem;

impl SystemStatsProvider for FailedSystem {
    fn snapshot(&self) -> Result<SystemStatsSnapshot, Status> {
        Err(Status::unavailable("allocator snapshot failed"))
    }
    fn name(&self) -> &'static str {
        "failed-provider"
    }
}

#[tokio::test]
async fn system_provider_errors_are_returned_not_replaced_with_zeroes() {
    let service =
        StatsService::with_system_stats(Arc::new(StatsManager::new()), Arc::new(FailedSystem));
    let error = service
        .get_sys_stats(Request::new(wire::SysStatsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "allocator snapshot failed");
}

async fn tcp_service(manager: Arc<StatsManager>) -> (RunningApiServer, Channel) {
    let server = ApiServer::new(manager)
        .bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    let channel = timeout(
        Duration::from_secs(5),
        Channel::from_shared(endpoint).unwrap().connect(),
    )
    .await
    .unwrap()
    .unwrap();
    (server, channel)
}

#[tokio::test]
async fn generated_client_exercises_all_stats_methods_over_http2() {
    let manager = Arc::new(StatsManager::new());
    manager
        .get_or_register_counter("user>>>ada>>>traffic>>>uplink")
        .set(81);
    manager
        .get_or_register_online_map("user>>>ada>>>online")
        .add_ip_at("192.0.2.9", 999);
    let (server, channel) = tcp_service(manager).await;
    let mut client = StatsServiceClient::new(channel);
    assert_eq!(
        client
            .get_stats(wire::GetStatsRequest {
                name: "missing".into(),
                reset: false
            })
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        client
            .get_stats(wire::GetStatsRequest {
                name: "user>>>ada>>>traffic>>>uplink".into(),
                reset: false
            })
            .await
            .unwrap()
            .into_inner()
            .stat
            .unwrap()
            .value,
        81
    );
    assert_eq!(
        client
            .query_stats(wire::QueryStatsRequest {
                pattern: "ada".into(),
                reset: false
            })
            .await
            .unwrap()
            .into_inner()
            .stat
            .len(),
        1
    );
    assert_eq!(
        client
            .get_stats_online(wire::GetStatsRequest {
                name: "user>>>ada>>>online".into(),
                reset: true
            })
            .await
            .unwrap()
            .into_inner()
            .stat
            .unwrap()
            .value,
        1
    );
    assert_eq!(
        client
            .get_stats_online_ip_list(wire::GetStatsRequest {
                name: "user>>>ada>>>online".into(),
                reset: false
            })
            .await
            .unwrap()
            .into_inner()
            .ips["192.0.2.9"],
        999
    );
    assert_eq!(
        client
            .get_all_online_users(wire::GetAllOnlineUsersRequest {})
            .await
            .unwrap()
            .into_inner()
            .users,
        ["user>>>ada>>>online"]
    );
    assert_eq!(
        client
            .get_users_stats(wire::GetUsersStatsRequest {
                include_traffic: true,
                reset: true
            })
            .await
            .unwrap()
            .into_inner()
            .users[0]
            .traffic
            .as_ref()
            .unwrap()
            .uplink,
        81
    );
    assert!(
        client
            .get_sys_stats(wire::SysStatsRequest {})
            .await
            .unwrap()
            .metadata()
            .get("x-xray-unsupported-fields")
            .is_some()
    );
    drop(client);
    timeout(Duration::from_secs(5), server.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[derive(Clone)]
struct LegacyClientChannel(Channel);

impl Service<http::Request<Body>> for LegacyClientChannel {
    type Response = <Channel as Service<http::Request<Body>>>::Response;
    type Error = <Channel as Service<http::Request<Body>>>::Error;
    type Future = <Channel as Service<http::Request<Body>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }
    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        let mut parts = request.uri().clone().into_parts();
        let path = parts.path_and_query.as_ref().unwrap().as_str().replace(
            "/xray.app.stats.command.StatsService/",
            "/v2ray.core.app.stats.command.StatsService/",
        );
        parts.path_and_query = Some(path.parse().unwrap());
        *request.uri_mut() = http::Uri::from_parts(parts).unwrap();
        self.0.call(request)
    }
}

#[tokio::test]
async fn legacy_service_name_reaches_the_same_registry_over_http2() {
    let manager = Arc::new(StatsManager::new());
    manager.get_or_register_counter("alias").set(67);
    let (server, channel) = tcp_service(manager.clone()).await;
    let mut client = StatsServiceClient::new(LegacyClientChannel(channel));
    let stat = client
        .get_stats(wire::GetStatsRequest {
            name: "alias".into(),
            reset: true,
        })
        .await
        .unwrap()
        .into_inner()
        .stat
        .unwrap();
    assert_eq!(stat.value, 67);
    assert_eq!(manager.get_counter("alias").unwrap().value(), 0);
    drop(client);
    timeout(Duration::from_secs(5), server.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn unknown_legacy_method_is_unimplemented() {
    let (_, service) = manager_service();
    let mut legacy = LegacyStatsService::new(service);
    let response = legacy
        .call(
            http::Request::builder()
                .uri("/v2ray.core.app.stats.command.StatsService/NoSuchMethod")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["grpc-status"], "12");
}

#[tokio::test]
async fn routed_stream_listener_serves_real_grpc_and_closes_sender_on_shutdown() {
    let manager = Arc::new(StatsManager::new());
    manager.get_or_register_counter("routed").set(901);
    let (sender, incoming) = incoming_channel(4).unwrap();
    let server = ApiServer::new(manager).start_incoming(incoming);
    let entrance = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = entrance.local_addr().unwrap();
    let accepting = sender.clone();
    let bridge = tokio::spawn(async move {
        let (stream, peer) = entrance.accept().await.unwrap();
        accepting
            .accept(Box::new(stream), Some(peer))
            .await
            .unwrap();
    });
    let mut client = timeout(
        Duration::from_secs(5),
        StatsServiceClient::connect(format!("http://{address}")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        client
            .get_stats(wire::GetStatsRequest {
                name: "routed".into(),
                reset: false
            })
            .await
            .unwrap()
            .into_inner()
            .stat
            .unwrap()
            .value,
        901
    );
    bridge.await.unwrap();
    drop(client);
    timeout(Duration::from_secs(5), server.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(sender.is_closed());
    let (stream, _) = tokio::io::duplex(32);
    assert_eq!(
        sender
            .accept(Box::new(stream), None)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn dropping_running_server_releases_listener() {
    let server = ApiServer::new(Arc::new(StatsManager::new()))
        .bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    drop(server);
    timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(listener) = TcpListener::bind(address).await {
                drop(listener);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn wire_messages_preserve_original_field_numbers() {
    let request = wire::GetStatsRequest {
        name: "hits".into(),
        reset: true,
    };
    assert_eq!(
        request.encode_to_vec(),
        [10, 4, b'h', b'i', b't', b's', 16, 1]
    );
    let response = wire::SysStatsResponse {
        num_goroutine: 3,
        uptime: 9,
        ..Default::default()
    };
    assert_eq!(response.encode_to_vec(), [8, 3, 80, 9]);
}
