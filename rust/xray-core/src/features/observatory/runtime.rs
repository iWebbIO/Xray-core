//! Ordinary observatory construction for the owning server runtime.
//!
//! [`RoutedProbeDialer`] is the only network boundary. The root runtime retains
//! its private dispatcher, protocol establishment, and final admission code.
//! No transport, DNS resolver, environment proxy, or direct connector is created
//! here. See `WIRING.md` beside this module for the root integration recipe.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use tokio_util::sync::CancellationToken;

use super::{Observer, OutboundSelector, ProbeConnector, ProbeTarget};
use crate::{
    address::Destination, api::observatory::ObservationProvider,
    config::observatory::CompiledObservatory, transport::BoxStream,
};

/// Connect through exactly the supplied outbound tag and return its raw
/// TCP-equivalent stream to the probe destination. The observer adds HTTPS TLS.
///
/// Implementations MUST use the root dispatcher's normal outbound protocol and
/// transport path, including applicable final admission, redirect handling and
/// admitted DNS-address pinning. Missing/unsupported/API/blackhole outbounds and
/// blocked admission MUST return an error, never route to the default outbound
/// or dial the destination directly. An explicitly selected freedom outbound
/// is allowed only through that same admitted runtime path.
///
/// The returned future must own cancellable dialing work: dropping it must stop
/// pending I/O. Do not detach dialing tasks. The observer supplies the complete
/// five-second probe deadline, including this call, TLS, and response headers.
#[tonic::async_trait]
pub trait RoutedProbeDialer: Send + Sync + 'static {
    async fn connect_outbound(&self, outbound_tag: &str, target: &Destination)
    -> Result<BoxStream>;
}

struct RoutedOutbounds {
    /// Snapshot of the immutable root dispatcher registry. Empty tags are not
    /// registered in Go's taggedHandler map and therefore cannot be selected.
    tags: Vec<String>,
    dialer: Arc<dyn RoutedProbeDialer>,
}

impl RoutedOutbounds {
    fn new(mut tags: Vec<String>, dialer: Arc<dyn RoutedProbeDialer>) -> Result<Self> {
        tags.retain(|tag| !tag.is_empty());
        tags.sort();
        ensure!(
            !tags.windows(2).any(|pair| pair[0] == pair[1]),
            "duplicate observatory outbound tag"
        );
        Ok(Self { tags, dialer })
    }
}

#[tonic::async_trait]
impl OutboundSelector for RoutedOutbounds {
    async fn select(&self, selectors: &[String]) -> Result<Vec<String>> {
        // app/proxyman/outbound/outbound.go: literal HasPrefix, unique tags,
        // sorted result. Empty prefix selects every registered nonempty tag.
        Ok(crate::router::balancer::select_outbounds(
            &self.tags, selectors,
        ))
    }
}

#[tonic::async_trait]
impl ProbeConnector for RoutedOutbounds {
    async fn connect(&self, outbound_tag: &str, target: &ProbeTarget) -> Result<BoxStream> {
        ensure!(
            self.tags
                .binary_search_by(|tag| tag.as_str().cmp(outbound_tag))
                .is_ok(),
            "unknown observatory outbound tag {outbound_tag:?}"
        );
        let destination = Destination::new(&target.host, target.port)
            .context("invalid observatory probe destination")?;
        self.dialer
            .connect_outbound(outbound_tag, &destination)
            .await
            .with_context(|| format!("observatory outbound {outbound_tag:?} failed"))
    }
}

/// A real provider and an owned scheduler future; construction starts no task.
/// Root owns polling, cancellation and joining through its existing JoinSet.
/// An immutable tag registry matches the current immutable Dispatcher. Rebuild
/// this value alongside a replacement dispatcher when outbound config changes.
pub struct ObservatoryRuntime {
    observer: Observer,
    outbounds: Arc<RoutedOutbounds>,
    selectors: Vec<String>,
}

impl ObservatoryRuntime {
    pub fn new(
        compiled: CompiledObservatory,
        outbound_tags: Vec<String>,
        dialer: Arc<dyn RoutedProbeDialer>,
    ) -> Result<Self> {
        let outbounds = Arc::new(RoutedOutbounds::new(outbound_tags, dialer)?);
        let selectors = compiled.probe.subject_selector.clone();
        let observer = Observer::new(compiled.probe, outbounds.clone())?;
        Ok(Self {
            observer,
            outbounds,
            selectors,
        })
    }

    pub fn observer(&self) -> &Observer {
        &self.observer
    }

    /// The same shared completed measurements used by this runtime's scheduler.
    /// Before any completed probe the provider is empty, never assumed healthy.
    pub fn provider(&self) -> Arc<dyn ObservationProvider> {
        Arc::new(self.observer.clone())
    }

    /// Empty selector lists disable scheduling, as in the source Start method.
    pub fn is_enabled(&self) -> bool {
        !self.selectors.is_empty()
    }

    /// One immediate selected round, useful for explicit runtime diagnostics.
    pub async fn check(&self, cancel: &CancellationToken) -> Result<()> {
        let tags = self.outbounds.select(&self.selectors).await?;
        self.observer.check(tags, cancel).await
    }

    /// Cancellation interrupts selection, probe I/O and interval sleeps, and
    /// joins internal concurrent probe workers before returning. Dropping this
    /// future drops active sequential I/O and aborts its owned worker JoinSet.
    /// Root must cancel and join this future on shutdown; it is never detached.
    pub async fn run(&self, cancel: &CancellationToken) -> Result<()> {
        self.observer.run(self.outbounds.clone(), cancel).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use anyhow::bail;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{address::Address, config::observatory::ObservatoryConfig};

    struct RejectDialer {
        calls: Mutex<Vec<(String, Destination)>>,
    }

    #[tonic::async_trait]
    impl RoutedProbeDialer for RejectDialer {
        async fn connect_outbound(&self, tag: &str, target: &Destination) -> Result<BoxStream> {
            self.calls
                .lock()
                .unwrap()
                .push((tag.into(), target.clone()));
            bail!("root admission denied target")
        }
    }

    fn rejecting() -> Arc<RejectDialer> {
        Arc::new(RejectDialer {
            calls: Mutex::new(Vec::new()),
        })
    }

    fn compiled(selectors: &[&str]) -> CompiledObservatory {
        ObservatoryConfig {
            subject_selector: selectors.iter().map(|tag| (*tag).into()).collect(),
            probe_url: "http://probe.example:8080/check".into(),
            probe_interval: "10ms".into(),
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[tokio::test]
    async fn source_prefix_selection_is_literal_sorted_and_unique() {
        let routes = RoutedOutbounds::new(
            ["z", "proxy-b", "", "proxy-a", "proxy.*"]
                .map(String::from)
                .to_vec(),
            rejecting(),
        )
        .unwrap();
        assert_eq!(
            routes
                .select(&["proxy-".into(), "proxy-a".into()])
                .await
                .unwrap(),
            ["proxy-a", "proxy-b"]
        );
        assert_eq!(
            routes.select(&["proxy.*".into()]).await.unwrap(),
            ["proxy.*"]
        );
        assert!(routes.select(&["^proxy".into()]).await.unwrap().is_empty());
        assert!(routes.select(&[]).await.unwrap().is_empty());
        assert_eq!(routes.select(&["".into()]).await.unwrap().len(), 4);
        assert!(RoutedOutbounds::new(vec!["x".into(), "x".into()], rejecting()).is_err());
    }

    #[tokio::test]
    async fn only_known_exact_tag_reaches_admission_and_failure_stays_failed() {
        let dialer = rejecting();
        let runtime = ObservatoryRuntime::new(
            compiled(&["proxy-"]),
            vec!["proxy-a".into(), "other".into()],
            dialer.clone(),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        runtime.check(&cancel).await.unwrap();
        {
            let calls = dialer.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "proxy-a");
            assert_eq!(calls[0].1.address, Address::Domain("probe.example".into()));
            assert_eq!(calls[0].1.port, 8080);
        }
        let status = runtime.provider().get_observation().await.unwrap().status;
        assert_eq!(status.len(), 1);
        assert!(!status[0].alive);
        assert!(
            status[0]
                .last_error_reason
                .contains("root admission denied")
        );
        assert!(status[0].health_ping.is_none());
        let target = ProbeTarget {
            host: "::1".into(),
            port: 443,
            https: true,
        };
        assert!(runtime.outbounds.connect("missing", &target).await.is_err());
        assert!(runtime.outbounds.connect("", &target).await.is_err());
        assert_eq!(dialer.calls.lock().unwrap().len(), 1);
        assert!(runtime.outbounds.connect("other", &target).await.is_err());
        assert!(matches!(
            dialer.calls.lock().unwrap()[1].1.address,
            Address::Ip(_)
        ));
    }

    #[tokio::test]
    async fn empty_selectors_disable_scheduler_and_leave_provider_empty() {
        let dialer = rejecting();
        let runtime =
            ObservatoryRuntime::new(compiled(&[]), vec!["proxy-a".into()], dialer.clone()).unwrap();
        assert!(!runtime.is_enabled());
        runtime.run(&CancellationToken::new()).await.unwrap();
        assert!(!runtime.observer().is_running());
        assert!(dialer.calls.lock().unwrap().is_empty());
        assert!(
            runtime
                .provider()
                .get_observation()
                .await
                .unwrap()
                .status
                .is_empty()
        );
    }

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingDialer {
        started: tokio::sync::Notify,
        dropped: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl RoutedProbeDialer for PendingDialer {
        async fn connect_outbound(&self, _: &str, _: &Destination) -> Result<BoxStream> {
            let _guard = DropCount(self.dropped.clone());
            self.started.notify_one();
            pending().await
        }
    }

    #[tokio::test]
    async fn scheduler_cancellation_drops_pending_dial_without_publishing_failure() {
        let dialer = Arc::new(PendingDialer {
            started: tokio::sync::Notify::new(),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let runtime =
            ObservatoryRuntime::new(compiled(&["proxy"]), vec!["proxy".into()], dialer.clone())
                .unwrap();
        let cancel = CancellationToken::new();
        let stop = async {
            dialer.started.notified().await;
            cancel.cancel();
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            let (result, ()) = tokio::join!(runtime.run(&cancel), stop);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(dialer.dropped.load(Ordering::SeqCst), 1);
        assert!(!runtime.observer().is_running());
        assert!(
            runtime
                .provider()
                .get_observation()
                .await
                .unwrap()
                .status
                .is_empty()
        );
    }

    struct StreamDialer(Mutex<Option<BoxStream>>);

    #[tonic::async_trait]
    impl RoutedProbeDialer for StreamDialer {
        async fn connect_outbound(&self, tag: &str, _: &Destination) -> Result<BoxStream> {
            ensure!(tag == "proxy", "wrong outbound");
            self.0.lock().unwrap().take().context("stream already used")
        }
    }

    #[tokio::test]
    async fn supplied_proxy_stream_produces_the_registered_provider_measurement() {
        let (client, mut peer) = tokio::io::duplex(2048);
        let runtime = ObservatoryRuntime::new(
            compiled(&["proxy"]),
            vec!["proxy".into()],
            Arc::new(StreamDialer(Mutex::new(Some(Box::new(client))))),
        )
        .unwrap();
        let provider = runtime.provider();
        assert!(provider.get_observation().await.unwrap().status.is_empty());
        let response = async {
            let mut bytes = Vec::new();
            loop {
                bytes.push(peer.read_u8().await.unwrap());
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(bytes.starts_with(b"GET /check HTTP/1.1\r\n"));
            assert!(
                String::from_utf8(bytes)
                    .unwrap()
                    .contains("Host: probe.example:8080\r\n")
            );
            peer.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 999\r\n\r\n")
                .await
                .unwrap();
        };
        let cancel = CancellationToken::new();
        let (result, ()) = tokio::join!(runtime.check(&cancel), response);
        result.unwrap();
        let status = provider.get_observation().await.unwrap().status;
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].outbound_tag, "proxy");
        assert!(status[0].alive);
        assert!(status[0].health_ping.is_none());
    }
}
