//! CONTRACT (fixed by the integrator): runtime startup for the root
//! `burstObservatory` object, mirroring the ordinary observer in
//! `runtime/observatory.rs`.
//!
//! OWNER: wiring batch agent R-RUNTIME. Implement by mirroring the ordinary
//! observer's shape: a `ProbeConnector` adapter over the Dispatcher's own
//! admission + establish path (the ordinary `ObservatoryDialer` logic) and an
//! `OutboundSelector` over `dispatcher.outbound_tags` implementing Go's
//! app/observatory/burst prefix selection. The observer itself is
//! `features::observatory_burst::BurstObserver`; poll it under the server's
//! JoinSet exactly like the ordinary one and expose its `ObservationProvider`.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::api::observatory::ObservationProvider;
use crate::features::observatory_burst::BurstSettings;

pub(super) struct BurstRuntime {
    _private: (),
}

/// Build the burst observer over the runtime's own probe path. Must fail
/// explicitly (never start silently disabled) while unwired.
pub(super) fn new(
    settings: BurstSettings,
    dispatcher: Arc<Dispatcher>,
) -> anyhow::Result<Arc<BurstRuntime>> {
    let _ = (settings, dispatcher);
    anyhow::bail!("burst observatory runtime is not wired yet")
}

impl BurstRuntime {
    /// True when the subject selector selects at least one outbound.
    pub(super) fn is_enabled(&self) -> bool {
        false
    }

    pub(super) fn provider(&self) -> Arc<dyn ObservationProvider> {
        unreachable!("burst runtime construction fails until the wiring lands")
    }

    pub(super) async fn run(&self, cancel: &CancellationToken) -> anyhow::Result<()> {
        let _ = cancel;
        unreachable!("burst runtime construction fails until the wiring lands")
    }
}
