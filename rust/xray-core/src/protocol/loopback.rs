// P02 loopback: the loopback outbound, ported from Go proxy/loopback
// (loopback.go) with infra/conf/loopback.go's settings. The outbound hands
// an established proxied connection back to the dispatcher as a fresh
// inbound session on the configured inbound's tag (Go's DispatchLink with
// a copied session content), so routing rules can match the loopback hop.
#![allow(dead_code)]

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::{Context, Result};

use serde::{Deserialize, Serialize};

use crate::{address::Destination, transport::BoxStream};

/// Go's `LoopbackConfig` keys, exactly: `inboundTag` and the optional
/// `sniffing` object (the same shape as an inbound's, infra/conf's
/// SniffingConfig).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct LoopbackSettings {
    /// The inbound whose tag the re-dispatched session carries.
    pub inbound_tag: String,
    /// Go's `SniffingConfig`; the runtime compiles it through
    /// `runtime::sniffing::SniffingRequest::compile` exactly like an
    /// inbound's sniffing object.
    pub sniffing: Option<crate::config::SniffingConfig>,
}

impl LoopbackSettings {
    /// The single entry point the config layer calls.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid loopback settings")
    }
}

pub type LoopbackDispatchFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// The dispatcher seam: hand one established stream back to the runtime as
/// a fresh inbound session on `inbound_tag` targeting `destination` — Go's
/// `routing.Dispatcher.DispatchLink` with the loopback's session content.
///
/// The implementation (runtime glue) must:
/// - mark the session's content with Go's `SkipDNSResolve = true` and the
///   loopback's compiled sniffing request (replacing the original
///   inbound's), and
/// - copy the origin inbound session with its tag replaced by
///   `inbound_tag`, so routing and sniffing see the loopback hop.
///
/// The whole relay (route → establish → relay) runs inside this call,
/// exactly like Go's DispatchLink.
pub trait LoopbackDispatch: Send + Sync {
    fn dispatch_to_inbound(
        &self,
        inbound_tag: &str,
        destination: &Destination,
        stream: BoxStream,
        sniffing: &Option<crate::config::SniffingConfig>,
    ) -> LoopbackDispatchFuture;
}

/// Go's proxy/loopback `Loopback` outbound over the dispatcher seam.
pub struct Loopback {
    settings: LoopbackSettings,
    dispatch: Arc<dyn LoopbackDispatch>,
}

impl Loopback {
    pub fn new(settings: LoopbackSettings, dispatch: Arc<dyn LoopbackDispatch>) -> Self {
        Self { settings, dispatch }
    }

    pub fn settings(&self) -> &LoopbackSettings {
        &self.settings
    }

    /// Go's `Loopback.Process`: hand the whole connection to the
    /// dispatcher as a fresh inbound session tagged with the configured
    /// `inboundTag`; the relay runs inside the seam (the dispatcher), not
    /// here, exactly like Go.
    pub async fn process(&self, destination: &Destination, stream: BoxStream) -> Result<()> {
        self.dispatch
            .dispatch_to_inbound(
                &self.settings.inbound_tag,
                destination,
                stream,
                &self.settings.sniffing,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn settings_parse_go_keys_and_reject_unknowns() {
        let settings = LoopbackSettings::from_value(&json!({
            "inboundTag": "the-inbound"
        }))
        .unwrap();
        assert_eq!(settings.inbound_tag, "the-inbound");
        assert!(settings.sniffing.is_none());
        // Go's sniffing object rides along verbatim.
        let sniffing = LoopbackSettings::from_value(&json!({
            "inboundTag": "in",
            "sniffing": {"enabled": true, "destOverride": "http", "routeOnly": true}
        }))
        .unwrap();
        let sniffing = sniffing.sniffing.expect("parsed");
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, vec!["http".to_owned()]);
        assert!(sniffing.route_only);
        // Unknown keys fail explicitly.
        assert!(LoopbackSettings::from_value(&json!({"outboundTag": "x"})).is_err());
    }
}
