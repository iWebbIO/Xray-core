//! Native LoggerService backed by the runtime's existing logging instance.
//!
//! The source registers both the Xray and v2ray service names. Both routes
//! below hold clones of the same logger, whose writers/lifecycle are shared.

use std::{
    convert::Infallible,
    task::{Context, Poll},
};

use tonic::{
    Request, Response, Status,
    body::Body,
    codegen::{Service, http},
    server::NamedService,
    service::Routes,
};

use crate::logging::Logger;

use logger_wire::logger_service_server::LoggerServiceServer;
pub use xray_proto::xray::app::log::command as logger_wire;

#[derive(Clone)]
pub struct LoggerService {
    logger: Option<Logger>,
}

impl LoggerService {
    /// Pass a clone of the actual runtime logger; do not construct a second
    /// logger from its configuration just for the management service.
    pub fn new(logger: Logger) -> Self {
        Self {
            logger: Some(logger),
        }
    }

    /// Supports the source's explicit "unable to get logger instance" failure
    /// when a service is registered without a logging feature.
    pub fn from_optional_logger(logger: Option<Logger>) -> Self {
        Self { logger }
    }

    pub fn logger(&self) -> Option<&Logger> {
        self.logger.as_ref()
    }

    pub fn into_server(self) -> LoggerServiceServer<Self> {
        LoggerServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl logger_wire::logger_service_server::LoggerService for LoggerService {
    async fn restart_logger(
        &self,
        _request: Request<logger_wire::RestartLoggerRequest>,
    ) -> Result<Response<logger_wire::RestartLoggerResponse>, Status> {
        let logger = self
            .logger
            .clone()
            .ok_or_else(|| Status::unknown("unable to get logger instance"))?;
        // Opening/flushing files may block. The logger already serializes its
        // writers, so a management request need not block the async executor.
        tokio::task::spawn_blocking(move || logger.restart())
            .await
            .map_err(|error| Status::internal(format!("logger restart task failed: {error}")))?
            .map_err(|error| Status::unknown(format!("failed to restart logger: {error}")))?;
        Ok(Response::new(logger_wire::RestartLoggerResponse {}))
    }
}

#[derive(Clone)]
pub struct LegacyLoggerService {
    inner: LoggerServiceServer<LoggerService>,
}

impl LegacyLoggerService {
    pub fn new(service: LoggerService) -> Self {
        Self {
            inner: service.into_server(),
        }
    }
}

impl NamedService for LegacyLoggerService {
    const NAME: &'static str = "v2ray.core.app.log.command.LoggerService";
}

impl Service<http::Request<Body>> for LegacyLoggerService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = <LoggerServiceServer<LoggerService> as Service<http::Request<Body>>>::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <LoggerServiceServer<LoggerService> as Service<http::Request<Body>>>::poll_ready(
            &mut self.inner,
            context,
        )
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        const PREFIX: &str = "/v2ray.core.app.log.command.LoggerService/";
        if let Some(method) = request.uri().path().strip_prefix(PREFIX)
            && let Ok(uri) = format!("/xray.app.log.command.LoggerService/{method}").parse()
        {
            *request.uri_mut() = uri;
        }
        self.inner.call(request)
    }
}

/// Start a router containing both source service-name aliases.
pub fn logger_routes(service: LoggerService) -> Routes {
    Routes::new(service.clone().into_server()).add_service(LegacyLoggerService::new(service))
}

/// Add both aliases to a router that already contains StatsService or other
/// management services. The caller owns endpoint binding and access policy.
pub fn add_logger_routes(routes: Routes, service: LoggerService) -> Routes {
    routes
        .add_service(service.clone().into_server())
        .add_service(LegacyLoggerService::new(service))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use tokio::time::timeout;
    use tonic::{Code, transport::Channel};

    use super::*;
    use crate::{
        api::ApiServer,
        logging::{LogDestination, LoggerOptions, Severity},
    };
    use logger_wire::logger_service_server::LoggerService as _;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("xray-logger-rpc-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn logfile(&self) -> PathBuf {
            self.0.join("error.log")
        }

        fn logger(&self) -> Logger {
            Logger::from_options(LoggerOptions {
                error: LogDestination::File(self.logfile()),
                level: Severity::Info,
                ..LoggerOptions::default()
            })
            .unwrap()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.logfile());
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn request() -> Request<logger_wire::RestartLoggerRequest> {
        Request::new(logger_wire::RestartLoggerRequest {})
    }

    #[derive(Clone)]
    struct TestChannel {
        inner: Channel,
        legacy: bool,
    }

    impl Service<http::Request<Body>> for TestChannel {
        type Response = <Channel as Service<http::Request<Body>>>::Response;
        type Error = <Channel as Service<http::Request<Body>>>::Error;
        type Future = <Channel as Service<http::Request<Body>>>::Future;

        fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(context)
        }

        fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
            if self.legacy {
                let mut parts = request.uri().clone().into_parts();
                parts.path_and_query = Some(http::uri::PathAndQuery::from_static(
                    "/v2ray.core.app.log.command.LoggerService/RestartLogger",
                ));
                *request.uri_mut() = http::Uri::from_parts(parts).unwrap();
            }
            self.inner.call(request)
        }
    }

    #[tokio::test]
    async fn restart_changes_the_runtime_logger_shared_by_all_clones() {
        let directory = TempDir::new();
        let logger = directory.logger();
        let runtime_clone = logger.clone();
        let service = LoggerService::new(logger.clone());
        logger
            .write_general(Severity::Info, "before close")
            .unwrap();
        logger.close().unwrap();
        assert!(!runtime_clone.is_active());
        service.restart_logger(request()).await.unwrap();
        assert!(runtime_clone.is_active());
        runtime_clone
            .write_general(Severity::Info, "after management restart")
            .unwrap();
        runtime_clone.flush().unwrap();
        let contents = fs::read_to_string(directory.logfile()).unwrap();
        assert!(contents.contains("before close"));
        assert!(contents.contains("after management restart"));
        logger.close().unwrap();
    }

    #[tokio::test]
    async fn missing_logger_returns_source_unknown_error() {
        let error = LoggerService::from_optional_logger(None)
            .restart_logger(request())
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "unable to get logger instance");
    }

    #[tokio::test]
    async fn reopen_failure_is_reported_instead_of_success() {
        let directory = TempDir::new();
        let logger = directory.logger();
        let service = LoggerService::new(logger.clone());
        logger.close().unwrap();
        fs::remove_file(directory.logfile()).unwrap();
        fs::remove_dir(&directory.0).unwrap();
        let error = service.restart_logger(request()).await.unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert!(error.message().starts_with("failed to restart logger:"));
        assert!(!logger.is_active());
    }

    #[tokio::test]
    async fn both_service_aliases_restart_the_same_logger_over_http2() {
        let directory = TempDir::new();
        let logger = directory.logger();
        let server = ApiServer::from_routes(logger_routes(LoggerService::new(logger.clone())))
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
        for legacy in [false, true] {
            logger.close().unwrap();
            assert!(!logger.is_active());
            let mut client =
                logger_wire::logger_service_client::LoggerServiceClient::new(TestChannel {
                    inner: channel.clone(),
                    legacy,
                });
            let reply: Response<logger_wire::RestartLoggerResponse> =
                timeout(Duration::from_secs(5), client.restart_logger(request()))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(reply.into_inner(), logger_wire::RestartLoggerResponse {});
            assert!(logger.is_active());
        }
        drop(channel);
        timeout(Duration::from_secs(5), server.shutdown())
            .await
            .unwrap()
            .unwrap();
        logger.close().unwrap();
    }

    #[tokio::test]
    async fn unknown_legacy_methods_remain_unimplemented() {
        let mut service = LegacyLoggerService::new(LoggerService::from_optional_logger(None));
        let response = service
            .call(
                http::Request::builder()
                    .uri("/v2ray.core.app.log.command.LoggerService/NotARealMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["grpc-status"], "12");
    }
}
