//! Native management gRPC services and listener lifecycle.
//!
//! [`StatsService`] implements the original protobuf service, including the
//! legacy `v2ray.core.app.stats.command.StatsService` route. Other management
//! services can be attached to [`tonic::service::Routes`] before passing them
//! to [`ApiServer::from_routes`]. Unregistered methods return gRPC UNIMPLEMENTED.
//!
//! Runtime accounting must share the same [`crate::features::StatsManager`].
//! Listening does not enable counters or user-online tracking by itself.

pub mod logger;
pub mod observatory;
mod server;
mod stats;
mod system;

pub use logger::{LegacyLoggerService, LoggerService, add_logger_routes, logger_routes};
pub use server::{
    ApiConnection, ApiConnectionInfo, ApiIncoming, ApiServer, ApiStreamSender, RunningApiServer,
    incoming_channel,
};
pub use stats::{LegacyStatsService, StatsService, stats_routes};
pub use system::{NativeSystemStats, SystemStatsProvider, SystemStatsSnapshot};

/// Shared wire messages and generated clients/servers.
pub use xray_proto::xray::app::stats::command as wire;
