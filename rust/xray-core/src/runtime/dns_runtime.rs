//! CONTRACT (fixed by the integrator): DNS-app plumbing for the runtime.
//!
//! OWNER: wiring batch agent A-DNS. `resolver` adapts the configured
//! `dns::app::DnsApp` to the `udp_routing::UdpResolver` seam used by the SOCKS
//! and relay UDP dispatchers. The same agent also owns the freedom
//! `domainStrategy` resolution behavior in `runtime/admission.rs` and
//! `protocol/freedom.rs`, and the resolver selection in
//! `runtime/udp_integration.rs`. The resolver must consult `DnsApp::lookup_ip`
//! with the query family implied by the strategy and must never fall back to
//! the system resolver behind a configured app (Go's semantics).

use std::sync::Arc;

/// A `UdpResolver` backed by the configured DNS app.
pub(super) fn resolver(
    app: Arc<crate::dns::app::DnsApp>,
) -> Arc<dyn super::udp_routing::UdpResolver> {
    struct NotWired(Arc<crate::dns::app::DnsApp>);

    impl super::udp_routing::UdpResolver for NotWired {
        fn resolve(&self, host: String) -> super::udp_routing::ResolveFuture {
            let _ = (&self.0, host);
            Box::pin(async { Err(std::io::Error::other("DNS app resolver is not wired yet")) })
        }
    }

    Arc::new(NotWired(app))
}
