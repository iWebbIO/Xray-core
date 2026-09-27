//! CONTRACT (fixed by the integrator): runtime glue for the root `reverse`
//! object, implementing the module contract in `reverse.rs`: "The runtime
//! routes bridge-domain carriers to Portal::attach, sends portal outbound
//! requests through Portal::open, and supplies the bridge connector and
//! dispatcher."
//!
//! OWNER: wiring batch agent A-REV. Study Go's app/reverse (portal.go,
//! bridge.go) and the batch component `reverse/bridge.rs` (Portal::attach,
//! Portal::open, Bridge::new/start, Reverse::new/start) and implement:
//!
//! - `new`: build `reverse::Reverse::new(config, dialer, dispatcher, ...)`
//!   where the `PortalDialer` closure dials `domain:0`/TCP carriers through
//!   the outbound the router selects for the bridge inbound tag, and the
//!   `Dispatcher` closure pumps portal-requested sessions through the
//!   runtime's own dispatch path (coordinate the dispatch seam with
//!   R-RUNTIME's `dispatch_request` extraction).
//! - `start`: dial the bridges' control carriers under cancellation.
//! - `portal_tags`: the outbound tags the router may select to send traffic
//!   through a portal; R-RUNTIME registers them in the outbound tag list.
//! - `is_portal_destination`: true when an inbound request's destination is a
//!   configured bridge domain, i.e. the connection is a carrier arriving at
//!   the portal.
//! - `attach_carrier`/`open_session`: the two Portal operations above.

#![allow(dead_code)] // stub until the wiring batch lands

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::address::Destination;
use crate::reverse::bridge::ReverseConfig;
use crate::transport::BoxStream;

pub(super) struct ReverseRuntime {
    _private: (),
}

/// Build the reverse app over the runtime's dispatcher. Must fail explicitly
/// while unwired so a `reverse` config never starts half-alive.
pub(super) fn new(
    config: &ReverseConfig,
    dispatcher: Arc<Dispatcher>,
    cancel: CancellationToken,
) -> anyhow::Result<Arc<ReverseRuntime>> {
    let _ = (config, dispatcher, cancel);
    anyhow::bail!("reverse app runtime is not wired yet")
}

impl ReverseRuntime {
    /// Dial the bridges' control carriers; spawned tasks link to the server
    /// cancellation token.
    pub(super) fn start(&self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "reverse app runtime is not wired yet",
        ))
    }

    /// Outbound tags that route through a portal.
    pub(super) fn portal_tags(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether this destination is a carrier arriving at a portal.
    pub(super) fn is_portal_destination(&self, destination: &Destination) -> bool {
        let _ = destination;
        false
    }

    /// Hand a bridge-domain carrier connection to the portal.
    pub(super) async fn attach_carrier(&self, stream: BoxStream) -> anyhow::Result<()> {
        let _ = stream;
        anyhow::bail!("reverse app runtime is not wired yet")
    }

    /// Open one logical session through a portal for the tagged outbound.
    pub(super) async fn open_session(
        &self,
        tag: &str,
        target: &Destination,
    ) -> std::io::Result<BoxStream> {
        let _ = (tag, target);
        Err(std::io::Error::other(
            "reverse app runtime is not wired yet",
        ))
    }
}
