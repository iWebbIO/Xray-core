//! Observatory management transport with an explicit source of observations.
//!
//! This service does not invent probe results, run a health scheduler, or turn
//! counters into health measurements. Register it only with a real provider.

use std::sync::Arc;

use tonic::{Request, Response, Status, service::Routes};

pub use observation_wire::command as observatory_wire;
use observatory_wire::observatory_service_server::ObservatoryServiceServer;
pub use xray_proto::xray::core::app::observatory as observation_wire;

/// The runtime's ordinary or burst observer supplies the exact protobuf
/// observation. Delays are milliseconds; health-ping duration fields retain
/// the source's nanosecond values. This boundary performs no unit conversion.
///
/// Errors propagate unchanged; dropping an RPC drops the provider future.
/// The listening layer owns deadline enforcement. Implementations must not
/// block an async worker for network probes.
#[tonic::async_trait]
pub trait ObservationProvider: Send + Sync + 'static {
    async fn get_observation(&self) -> Result<observation_wire::ObservationResult, Status>;
}

#[derive(Clone)]
pub struct ObservatoryService {
    provider: Arc<dyn ObservationProvider>,
}

impl ObservatoryService {
    /// A provider is mandatory. There is no default provider returning empty
    /// or apparently healthy data when probing has not been implemented.
    pub fn new(provider: Arc<dyn ObservationProvider>) -> Self {
        Self { provider }
    }

    pub fn provider(&self) -> &Arc<dyn ObservationProvider> {
        &self.provider
    }

    pub fn into_server(self) -> ObservatoryServiceServer<Self> {
        ObservatoryServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl observatory_wire::observatory_service_server::ObservatoryService for ObservatoryService {
    async fn get_outbound_status(
        &self,
        _request: Request<observatory_wire::GetOutboundStatusRequest>,
    ) -> Result<Response<observatory_wire::GetOutboundStatusResponse>, Status> {
        let status = self.provider.get_observation().await?;
        Ok(Response::new(observatory_wire::GetOutboundStatusResponse {
            status: Some(status),
        }))
    }
}

/// The Go service registers only this exact service name, with no v2ray alias.
pub fn observatory_routes(service: ObservatoryService) -> Routes {
    Routes::new(service.into_server())
}

pub fn add_observatory_routes(routes: Routes, service: ObservatoryService) -> Routes {
    routes.add_service(service.into_server())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tonic::Code;

    use super::*;
    use observatory_wire::observatory_service_server::ObservatoryService as _;

    struct CountingProvider(AtomicU64);

    #[tonic::async_trait]
    impl ObservationProvider for CountingProvider {
        async fn get_observation(&self) -> Result<observation_wire::ObservationResult, Status> {
            let call = self.0.fetch_add(1, Ordering::SeqCst) as i64;
            Ok(observation_wire::ObservationResult {
                status: vec![observation_wire::OutboundStatus {
                    alive: call % 2 == 0,
                    delay: 17 + call,
                    last_error_reason: "source result".into(),
                    outbound_tag: "measured-outbound".into(),
                    last_seen_time: 1_800_000_000,
                    last_try_time: 1_800_000_001,
                    health_ping: Some(observation_wire::HealthPingMeasurementResult {
                        all: 7,
                        fail: 2,
                        deviation: 1_001_234,
                        average: 17_800_000,
                        max: 25_000_000,
                        min: 10_000_000,
                    }),
                }],
            })
        }
    }

    fn request() -> Request<observatory_wire::GetOutboundStatusRequest> {
        Request::new(observatory_wire::GetOutboundStatusRequest {})
    }

    #[tokio::test]
    async fn forwards_live_provider_data_and_original_measurement_units() {
        let provider = Arc::new(CountingProvider(AtomicU64::new(0)));
        let service = ObservatoryService::new(provider.clone());
        let clone = service.clone();
        let first = service
            .get_outbound_status(request())
            .await
            .unwrap()
            .into_inner()
            .status
            .unwrap()
            .status
            .remove(0);
        assert!(first.alive);
        assert_eq!(first.delay, 17);
        assert_eq!(first.last_error_reason, "source result");
        assert_eq!(first.outbound_tag, "measured-outbound");
        assert_eq!(first.last_seen_time, 1_800_000_000);
        assert_eq!(first.last_try_time, 1_800_000_001);
        let health = first.health_ping.unwrap();
        assert_eq!(health.all, 7);
        assert_eq!(health.fail, 2);
        assert_eq!(health.average, 17_800_000);
        assert_eq!(health.deviation, 1_001_234);
        let second = clone
            .get_outbound_status(request())
            .await
            .unwrap()
            .into_inner()
            .status
            .unwrap()
            .status
            .remove(0);
        assert!(!second.alive);
        assert_eq!(second.delay, 18);
        assert_eq!(provider.0.load(Ordering::SeqCst), 2);
    }

    struct FailingProvider;

    #[tonic::async_trait]
    impl ObservationProvider for FailingProvider {
        async fn get_observation(&self) -> Result<observation_wire::ObservationResult, Status> {
            Err(Status::unavailable("observer has stopped"))
        }
    }

    #[tokio::test]
    async fn provider_errors_do_not_become_empty_successful_observations() {
        let service = ObservatoryService::new(Arc::new(FailingProvider));
        let error = service.get_outbound_status(request()).await.unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.message(), "observer has stopped");
    }

    #[tokio::test]
    async fn generated_client_reads_provider_over_http2() {
        let provider = Arc::new(CountingProvider(AtomicU64::new(0)));
        let server = crate::api::ApiServer::from_routes(observatory_routes(
            ObservatoryService::new(provider.clone()),
        ))
        .bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
        let endpoint = format!("http://{}", server.local_addr().unwrap());
        let mut client =
            observatory_wire::observatory_service_client::ObservatoryServiceClient::connect(
                endpoint,
            )
            .await
            .unwrap();
        let reply = client
            .get_outbound_status(observatory_wire::GetOutboundStatusRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            reply.status.unwrap().status[0].outbound_tag,
            "measured-outbound"
        );
        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
        drop(client);
        server.shutdown().await.unwrap();
    }
}
