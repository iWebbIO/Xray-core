//! SOCKS UDP uses the immutable root route registry and owns its control stream.
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, ensure};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use super::{Dispatcher, udp, udp_routing};
use crate::{
    config::{Config, Outbound, SocksSettings, StreamSettings},
    features::{StatsManager, policy::SystemStatsPolicy},
    protocol::{Reply, socks::AssociateRequest},
    router::Router,
    transport::BoxStream,
};

pub(super) fn dispatcher(
    config: &Config,
    outbounds: &[Outbound],
    router: Arc<Router>,
    stats: Option<&StatsManager>,
    system: SystemStatsPolicy,
    resolver: Arc<dyn udp_routing::UdpResolver>,
) -> Result<Arc<dyn udp::UdpDispatcher>> {
    let routes = outbounds
        .iter()
        .enumerate()
        .map(|(index, outbound)| {
            if let Some(raw) = config.outbounds.get(index) {
                udp_routing::RouteOutbound::from_config(
                    outbound,
                    &raw.stream_settings,
                    raw.tag.clone(),
                )
            } else {
                udp_routing::RouteOutbound::from_config(
                    outbound,
                    &StreamSettings::default(),
                    config
                        .api
                        .as_ref()
                        .expect("internal API outbound")
                        .tag
                        .clone(),
                )
            }
        })
        .collect();
    // The caller picks the resolver: the configured DNS app when a `dns`
    // object exists, otherwise the explicit system-DNS choice. A configured
    // resolver is never silently replaced by the system one.
    let mut dispatcher = udp_routing::RoutingDispatcher::new(router, routes, "socks", resolver)?;
    if let Some(stats) = stats {
        dispatcher = dispatcher.with_stats(stats, system);
    }
    Ok(Arc::new(dispatcher))
}

/// Peer and locally bound addresses of one accepted inbound connection.
#[derive(Clone, Copy)]
pub(super) struct ConnectionEnds {
    pub(super) source: SocketAddr,
    pub(super) bound: SocketAddr,
}

pub(super) async fn serve(
    mut control: BoxStream,
    request: AssociateRequest,
    settings: &SocksSettings,
    ends: ConnectionEnds,
    tag: &str,
    dispatcher: &Dispatcher,
    cancel: &CancellationToken,
) -> Result<()> {
    let ConnectionEnds { source, bound } = ends;
    let policy = dispatcher.policy.for_level(0);
    ensure!(
        !policy.timeouts.connection_idle.is_zero(),
        "proxy session inactivity timeout"
    );
    let user = dispatcher
        .stats
        .as_ref()
        .map(|stats| {
            stats.user_session(
                &request.user,
                &super::source_ip_string(source),
                policy.stats,
            )
        })
        .unwrap_or_default();
    let deadline = Instant::now() + policy.timeouts.connection_idle;
    let limits = udp::Limits {
        idle_timeout: policy.timeouts.connection_idle,
        operation_timeout: policy
            .timeouts
            .connection_idle
            .min(udp::Limits::default().operation_timeout),
        ..Default::default()
    };
    let bind = udp::Association::bind(source, request, settings.ip.unwrap_or(bound.ip()), limits);
    let association = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        result = timeout_at(deadline, bind) => result.context("UDP association bind timed out")?,
    };
    let association = match association {
        Ok(association) => association.with_stats(user),
        Err(error) => {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => (),
                _ = timeout_at(deadline, Reply::Socks5.failure(&mut control, 1)) => (),
            }
            return Err(error.into());
        }
    };
    let outcome = association
        .serve(
            control,
            Arc::from(tag),
            dispatcher
                .udp
                .as_ref()
                .context("SOCKS UDP dispatcher unavailable")?
                .clone(),
            cancel.clone(),
        )
        .await?;
    tracing::debug!(inbound = tag, %source, reason = ?outcome.reason, "SOCKS UDP association closed");
    Ok(())
}
