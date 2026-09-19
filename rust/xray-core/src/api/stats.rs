use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use tonic::{
    Request, Response, Status,
    body::Body,
    codegen::{Service, http},
    metadata::MetadataValue,
    server::NamedService,
    service::Routes,
};

use crate::features::StatsManager;

use super::{
    NativeSystemStats, SystemStatsProvider, SystemStatsSnapshot,
    wire::{self, stats_service_server::StatsServiceServer},
};

/// The same registry is used by all clones and by both service-name aliases.
#[derive(Clone)]
pub struct StatsService {
    manager: Arc<StatsManager>,
    started: Instant,
    system: Arc<dyn SystemStatsProvider>,
}

impl StatsService {
    pub fn new(manager: Arc<StatsManager>) -> Self {
        Self::with_system_stats(manager, Arc::new(NativeSystemStats))
    }

    pub fn with_system_stats(
        manager: Arc<StatsManager>,
        system: Arc<dyn SystemStatsProvider>,
    ) -> Self {
        Self {
            manager,
            started: Instant::now(),
            system,
        }
    }

    pub fn manager(&self) -> &Arc<StatsManager> {
        &self.manager
    }

    pub fn into_server(self) -> StatsServiceServer<Self> {
        StatsServiceServer::new(self)
    }

    fn read_stat(&self, request: wire::GetStatsRequest) -> Result<wire::GetStatsResponse, Status> {
        let stat = self
            .manager
            .stat(&request.name, request.reset)
            .ok_or_else(|| not_found(&request.name))?;
        Ok(wire::GetStatsResponse {
            stat: Some(wire::Stat {
                name: stat.name,
                value: stat.value,
            }),
        })
    }

    fn read_online(
        &self,
        request: wire::GetStatsRequest,
    ) -> Result<wire::GetStatsResponse, Status> {
        let map = self
            .manager
            .get_online_map(&request.name)
            .ok_or_else(|| not_found(&request.name))?;
        // Go deliberately ignores the reset flag for online statistics.
        Ok(wire::GetStatsResponse {
            stat: Some(wire::Stat {
                name: request.name,
                value: map.count().try_into().unwrap_or(i64::MAX),
            }),
        })
    }

    fn read_online_ips(
        &self,
        request: wire::GetStatsRequest,
    ) -> Result<wire::GetStatsOnlineIpListResponse, Status> {
        let ips = self
            .manager
            .online_ips(&request.name)
            .ok_or_else(|| not_found(&request.name))?;
        Ok(wire::GetStatsOnlineIpListResponse {
            name: request.name,
            ips: ips
                .into_iter()
                .map(|entry| (entry.ip, entry.last_seen))
                .collect(),
        })
    }

    fn read_users(&self, request: wire::GetUsersStatsRequest) -> wire::GetUsersStatsResponse {
        // Match command.go's two strings.Cut calls, including noncanonical map
        // names. The feature-layer helper intentionally accepts canonical user
        // names only, whereas the RPC also visits arbitrary registered maps.
        let mut users = BTreeMap::<String, wire::UserStat>::new();
        self.manager.visit_online_maps(|name, map| {
            if map.count() == 0 {
                return true;
            }
            let rest = name.split_once(">>>").map_or("", |(_, rest)| rest);
            let email = rest.split_once(">>>").map_or(rest, |(email, _)| email);
            let ips: Vec<_> = map
                .snapshot()
                .into_iter()
                .map(|entry| wire::OnlineIpEntry {
                    ip: entry.ip,
                    last_seen: entry.last_seen,
                })
                .collect();
            if !ips.is_empty() {
                users.insert(
                    email.to_owned(),
                    wire::UserStat {
                        email: email.to_owned(),
                        ips,
                        traffic: request.include_traffic.then(wire::TrafficUserStat::default),
                    },
                );
            }
            true
        });

        if request.include_traffic {
            self.manager.visit_counters(|name, counter| {
                let (suffix, uplink) = if name.ends_with(">>>traffic>>>uplink") {
                    (">>>traffic>>>uplink", true)
                } else if name.ends_with(">>>traffic>>>downlink") {
                    (">>>traffic>>>downlink", false)
                } else {
                    return true;
                };
                // Go skips the first len("user>>>") bytes without checking the
                // prefix. Guard the bounds/UTF-8 here instead of reproducing its
                // panic for malformed short names.
                let Some(email) = name.get("user>>>".len()..name.len() - suffix.len()) else {
                    return true;
                };
                if let Some(traffic) = users.get_mut(email).and_then(|user| user.traffic.as_mut()) {
                    let value = if request.reset {
                        counter.set(0)
                    } else {
                        counter.value()
                    };
                    if uplink {
                        traffic.uplink = value;
                    } else {
                        traffic.downlink = value;
                    }
                }
                true
            });
        }
        wire::GetUsersStatsResponse {
            users: users.into_values().collect(),
        }
    }

    fn read_system(&self) -> Result<Response<wire::SysStatsResponse>, Status> {
        let snapshot = self.system.snapshot()?;
        let (mut response, missing) = system_response(snapshot, self.started.elapsed().as_secs());
        let metadata = response.metadata_mut();
        metadata.insert(
            "x-xray-system-stats-provider",
            metadata_value(self.system.name())?,
        );
        metadata.insert(
            "x-xray-num-goroutine-kind",
            metadata_value(self.system.task_kind())?,
        );
        if !missing.is_empty() {
            metadata.insert(
                "x-xray-unsupported-fields",
                metadata_value(&missing.join(","))?,
            );
        }
        Ok(response)
    }
}

fn not_found(name: &str) -> Status {
    Status::not_found(format!("{name} not found."))
}

fn metadata_value(value: &str) -> Result<MetadataValue<tonic::metadata::Ascii>, Status> {
    value
        .parse()
        .map_err(|_| Status::internal("system statistics provider returned invalid metadata"))
}

fn system_response(
    snapshot: SystemStatsSnapshot,
    uptime_seconds: u64,
) -> (Response<wire::SysStatsResponse>, Vec<&'static str>) {
    let mut missing = Vec::new();
    macro_rules! measured {
        ($field:ident) => {
            snapshot.$field.unwrap_or_else(|| {
                missing.push(stringify!($field));
                0
            })
        };
    }
    let response = Response::new(wire::SysStatsResponse {
        num_goroutine: measured!(num_goroutine),
        num_gc: measured!(num_gc),
        alloc: measured!(alloc),
        total_alloc: measured!(total_alloc),
        sys: measured!(sys),
        mallocs: measured!(mallocs),
        frees: measured!(frees),
        live_objects: measured!(live_objects),
        pause_total_ns: measured!(pause_total_ns),
        // Preserve the uint32 wire contract; a restart after 136 years is fine.
        uptime: uptime_seconds as u32,
    });
    (response, missing)
}

#[tonic::async_trait]
impl wire::stats_service_server::StatsService for StatsService {
    async fn get_stats(
        &self,
        request: Request<wire::GetStatsRequest>,
    ) -> Result<Response<wire::GetStatsResponse>, Status> {
        self.read_stat(request.into_inner()).map(Response::new)
    }

    async fn get_stats_online(
        &self,
        request: Request<wire::GetStatsRequest>,
    ) -> Result<Response<wire::GetStatsResponse>, Status> {
        self.read_online(request.into_inner()).map(Response::new)
    }

    async fn query_stats(
        &self,
        request: Request<wire::QueryStatsRequest>,
    ) -> Result<Response<wire::QueryStatsResponse>, Status> {
        let request = request.into_inner();
        let stat = self
            .manager
            .query_stats(&request.pattern, request.reset)
            .into_iter()
            .map(|stat| wire::Stat {
                name: stat.name,
                value: stat.value,
            })
            .collect();
        Ok(Response::new(wire::QueryStatsResponse { stat }))
    }

    async fn get_sys_stats(
        &self,
        _: Request<wire::SysStatsRequest>,
    ) -> Result<Response<wire::SysStatsResponse>, Status> {
        self.read_system()
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<wire::GetStatsRequest>,
    ) -> Result<Response<wire::GetStatsOnlineIpListResponse>, Status> {
        self.read_online_ips(request.into_inner())
            .map(Response::new)
    }

    async fn get_all_online_users(
        &self,
        _: Request<wire::GetAllOnlineUsersRequest>,
    ) -> Result<Response<wire::GetAllOnlineUsersResponse>, Status> {
        Ok(Response::new(wire::GetAllOnlineUsersResponse {
            users: self.manager.get_all_online_users(),
        }))
    }

    async fn get_users_stats(
        &self,
        request: Request<wire::GetUsersStatsRequest>,
    ) -> Result<Response<wire::GetUsersStatsResponse>, Status> {
        Ok(Response::new(self.read_users(request.into_inner())))
    }
}

/// Compatibility route registered by the original Go StatsService.
#[derive(Clone)]
pub struct LegacyStatsService {
    inner: StatsServiceServer<StatsService>,
}

impl LegacyStatsService {
    pub fn new(service: StatsService) -> Self {
        Self {
            inner: service.into_server(),
        }
    }
}

impl NamedService for LegacyStatsService {
    const NAME: &'static str = "v2ray.core.app.stats.command.StatsService";
}

impl Service<http::Request<Body>> for LegacyStatsService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = <StatsServiceServer<StatsService> as Service<http::Request<Body>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <StatsServiceServer<StatsService> as Service<http::Request<Body>>>::poll_ready(
            &mut self.inner,
            cx,
        )
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        const PREFIX: &str = "/v2ray.core.app.stats.command.StatsService/";
        if let Some(method) = request.uri().path().strip_prefix(PREFIX) {
            let replacement = format!("/xray.app.stats.command.StatsService/{method}");
            // HTTP path characters came from a valid URI. Unknown method names
            // remain unknown after rewriting and get the generated status 12.
            if let Ok(uri) = replacement.parse() {
                *request.uri_mut() = uri;
            }
        }
        self.inner.call(request)
    }
}

pub fn stats_routes(service: StatsService) -> Routes {
    Routes::new(service.clone().into_server()).add_service(LegacyStatsService::new(service))
}

#[cfg(test)]
mod tests;
