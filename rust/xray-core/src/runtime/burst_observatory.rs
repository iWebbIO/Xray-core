//! Runtime startup for the root `burstObservatory` object, mirroring the
//! ordinary observer in `runtime/observatory.rs`: probes ride the runtime's
//! own admission + establish path, and outbound selection is the outbound
//! manager's prefix selector (Go `app/proxyman/outbound` `Manager.Select`: a
//! tag matches when any selector is a prefix of it; the result is sorted).

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use super::{Dispatcher, admission, establish};
use crate::{
    address::Destination,
    api::observatory::ObservationProvider,
    config::Outbound,
    features::observatory::{OutboundSelector, ProbeConnector, ProbeTarget},
    features::observatory_burst::{BurstObserver, BurstSettings},
    protocol::freedom::Admission,
    transport::BoxStream,
};

struct BurstProbeConnector(Arc<Dispatcher>);

#[tonic::async_trait]
impl ProbeConnector for BurstProbeConnector {
    async fn connect(&self, outbound_tag: &str, target: &ProbeTarget) -> Result<BoxStream> {
        let dispatcher = &self.0;
        let destination = Destination::new(&target.host, target.port)
            .with_context(|| format!("burst probe target {}", target.host))?;
        let index = dispatcher
            .outbound_tags
            .iter()
            .position(|tag| tag == outbound_tag)
            .context("unknown burst observatory outbound")?;
        let outbound = dispatcher
            .outbounds
            .get(index)
            .context("burst observatory outbound unavailable")?;
        if matches!(outbound, Outbound::Api | Outbound::Blackhole { .. }) {
            bail!("selected outbound cannot carry burst observatory probes");
        }
        let transport = dispatcher
            .transports
            .get(index)
            .context("burst observatory outbound transport unavailable")?;
        let resolved = match admission::admit(
            outbound,
            "burst-observatory",
            &destination,
            dispatcher.dns.as_ref(),
        )
        .await?
        {
            Admission::Allowed(addresses) => addresses,
            Admission::Blocked(_) => bail!("freedom final rule blocked a burst probe target"),
        };
        let counters = dispatcher
            .stats
            .as_ref()
            .map(|stats| {
                stats.outbound_counters(outbound_tag, dispatcher.policy.for_system().stats)
            })
            .unwrap_or_default();
        // The observer owns the probe deadline, TLS and cancellation; this
        // returns the raw stream its own measurement path reads.
        establish(
            dispatcher,
            outbound,
            transport,
            &destination,
            resolved.as_deref(),
            counters,
        )
        .await
        .map(|(stream, _)| stream)
    }
}

struct TagSelector {
    tags: Vec<String>,
}

#[tonic::async_trait]
impl OutboundSelector for TagSelector {
    async fn select(&self, selectors: &[String]) -> Result<Vec<String>> {
        // Go Manager.Select: one entry per tag that has any selector as a
        // prefix, in sorted order.
        let mut selected: Vec<String> = self
            .tags
            .iter()
            .filter(|tag| {
                selectors
                    .iter()
                    .any(|selector| tag.starts_with(selector.as_str()))
            })
            .cloned()
            .collect();
        selected.sort();
        selected.dedup();
        Ok(selected)
    }
}

pub(super) struct BurstRuntime {
    observer: BurstObserver,
    selector: Arc<TagSelector>,
    /// The settings' subject selector, captured for the enabled test (the
    /// observer keeps its settings private, like the ordinary runtime).
    enabled: bool,
}

pub(super) fn new(
    settings: BurstSettings,
    dispatcher: Arc<Dispatcher>,
) -> Result<Arc<BurstRuntime>> {
    let enabled = !settings.subject_selector.is_empty();
    let observer = BurstObserver::new(settings, Arc::new(BurstProbeConnector(dispatcher.clone())))?;
    let selector = Arc::new(TagSelector {
        tags: dispatcher.outbound_tags.clone(),
    });
    Ok(Arc::new(BurstRuntime {
        observer,
        selector,
        enabled,
    }))
}

impl BurstRuntime {
    /// True when the subject selector is configured, mirroring the ordinary
    /// observer's enabled test over its selectors.
    pub(super) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn provider(&self) -> Arc<dyn ObservationProvider> {
        Arc::new(self.observer.clone())
    }

    pub(super) async fn run(&self, cancel: &CancellationToken) -> Result<()> {
        self.observer.run(self.selector.clone(), cancel).await
    }
}
