//! Ordinary probes use the same exact outbound and final admission as sessions.
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use super::{Dispatcher, admission, establish};
use crate::{
    address::Destination,
    config::{Outbound, observatory::CompiledObservatory},
    features::observatory::runtime::{ObservatoryRuntime, RoutedProbeDialer},
    protocol::freedom::Admission,
    transport::BoxStream,
};

struct ObservatoryDialer(Arc<Dispatcher>);

#[tonic::async_trait]
impl RoutedProbeDialer for ObservatoryDialer {
    async fn connect_outbound(
        &self,
        outbound_tag: &str,
        target: &Destination,
    ) -> Result<BoxStream> {
        let dispatcher = &self.0;
        let index = dispatcher
            .outbound_tags
            .iter()
            .position(|tag| tag == outbound_tag)
            .context("unknown observatory outbound")?;
        let outbound = dispatcher
            .outbounds
            .get(index)
            .context("observatory outbound unavailable")?;
        if matches!(outbound, Outbound::Api | Outbound::Blackhole { .. }) {
            bail!("selected outbound cannot carry observatory TCP probes");
        }
        let transport = dispatcher
            .transports
            .get(index)
            .context("observatory outbound transport unavailable")?;
        let resolved =
            match admission::admit(outbound, "observatory", target, dispatcher.dns.as_ref()).await?
            {
                Admission::Allowed(addresses) => addresses,
                Admission::Blocked(_) => bail!("freedom final rule blocked observatory target"),
            };
        let counters = dispatcher
            .stats
            .as_ref()
            .map(|stats| {
                stats.outbound_counters(outbound_tag, dispatcher.policy.for_system().stats)
            })
            .unwrap_or_default();
        // The observer owns the full five-second deadline and cancellation,
        // including this future, outer transport security and proxy handshakes.
        // HTTPS for the probe origin is applied by the observer after return.
        let (stream, _) = establish(
            dispatcher,
            outbound,
            transport,
            target,
            resolved.as_deref(),
            counters,
        )
        .await?;
        Ok(stream)
    }
}

pub(super) fn new(
    compiled: CompiledObservatory,
    dispatcher: Arc<Dispatcher>,
) -> Result<Arc<ObservatoryRuntime>> {
    ObservatoryRuntime::new(
        compiled,
        dispatcher.outbound_tags.clone(),
        Arc::new(ObservatoryDialer(dispatcher)),
    )
    .map(Arc::new)
}
