// P45 reverse_bridge: port of app/reverse Bridge/Portal/Reverse plus the
// infra/conf/reverse.go JSON surface, built on the existing reverse carriers.
#![allow(dead_code)]

//! Reverse proxy bridge and portal.
//!
//! The [`Bridge`] keeps control connections (carriers) to the portal via the
//! [`PortalDialer`] trait, exactly like Go's `Bridge` dispatches to
//! `domain:0`/TCP: the portal becomes the Mux.Cool client on each carrier,
//! the first UDP session carries `Control` heartbeats (the reused
//! `reverse.rs` machinery and `control.rs` codec), and inbound sessions the
//! portal requests are pumped to the supplied dispatcher. Carriers are
//! scaled when the integer average of active sessions per active carrier
//! exceeds 16 and re-dialed after a drop (`bridge_supervisor` retries where
//! Go's periodic monitor logs the failure and returns nil).
//!
//! The [`Portal`] accepts control connections, matches the configured domain
//! selector, and relays plain streams across an established tunnel
//! (`open_stream`), mirroring `Portal.HandleConnection`. [`Reverse`] is the
//! Go `Reverse` container over both.

use crate::{
    mux::{Host, Network, OpenOptions, Session, Target},
    reverse::{
        self, BridgeOptions, Config as CarrierConfig, ConnectFuture, Connector, Dispatcher,
        Portal as MuxPortal, PortalOptions, WorkerStats,
    },
    transport::BoxStream,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// JSON configuration surface (infra/conf/reverse.go, app/reverse validation).
// ---------------------------------------------------------------------------

/// `infra/conf.BridgeConfig`; `tag` is the bridge-side inbound tag, `domain`
/// the selector the portal's carriers are routed by.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct BridgeConfig {
    pub tag: String,
    pub domain: String,
}

impl BridgeConfig {
    /// Validation order and messages of Go `NewBridge`.
    pub fn validate(&self) -> Result<()> {
        if self.tag.is_empty() {
            anyhow::bail!("bridge tag is empty");
        }
        if self.domain.is_empty() {
            anyhow::bail!("bridge domain is empty");
        }
        Ok(())
    }
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let config: Self = serde_json::from_value(value.clone())?;
        config.validate()?;
        Ok(config)
    }
}

/// `infra/conf.PortalConfig`; `tag` is the outbound handler tag the runtime
/// registers for this portal, `domain` the selector it accepts.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct PortalConfig {
    pub tag: String,
    pub domain: String,
}

impl PortalConfig {
    /// Validation order and messages of Go `NewPortal`.
    pub fn validate(&self) -> Result<()> {
        if self.tag.is_empty() {
            anyhow::bail!("portal tag is empty");
        }
        if self.domain.is_empty() {
            anyhow::bail!("portal domain is empty");
        }
        Ok(())
    }
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let config: Self = serde_json::from_value(value.clone())?;
        config.validate()?;
        Ok(config)
    }
}

/// `infra/conf.ReverseConfig` (the top-level `"reverse"` JSON object).
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ReverseConfig {
    pub bridges: Vec<BridgeConfig>,
    pub portals: Vec<PortalConfig>,
}

impl ReverseConfig {
    /// Parses and validates every entry in Go `Reverse.Init` order: bridges
    /// first, then portals; the first invalid entry aborts with its message.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let config: Self = serde_json::from_value(value.clone())?;
        for bridge in &config.bridges {
            bridge.validate()?;
        }
        for portal in &config.portals {
            portal.validate()?;
        }
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Bridge -> portal dialer.
// ---------------------------------------------------------------------------

/// Supplies the bridge->portal carrier stream. The runtime implementation
/// routes `domain:0`/TCP through the outbound chosen for the bridge inbound
/// `tag`, exactly the dispatch Go's `NewBridgeWorker` performs.
pub trait PortalDialer: Send + Sync {
    fn dial(&self, domain: &str, tag: &str) -> ConnectFuture;
}

impl<F> PortalDialer for F
where
    F: Fn(&str, &str) -> ConnectFuture + Send + Sync,
{
    fn dial(&self, domain: &str, tag: &str) -> ConnectFuture {
        self(domain, tag)
    }
}

/// Adapts a [`PortalDialer`] to the carrier connector consumed by the
/// existing `run_bridge` monitor.
fn carrier_connector(dialer: Arc<dyn PortalDialer>) -> Connector {
    Arc::new(move |target, tag| {
        let dialer = Arc::clone(&dialer);
        Box::pin(async move {
            // Go always constructs a domain destination for the carrier.
            let domain = match target.host {
                Host::Domain(domain) => domain,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "reverse bridge carrier target must be a domain",
                    ));
                }
            };
            dialer.dial(&domain, &tag).await
        })
    })
}

// ---------------------------------------------------------------------------
// Bridge.
// ---------------------------------------------------------------------------

/// Go `Bridge`: a monitor that maintains carrier workers to the portal.
/// Worker bookkeeping (state, activity timers, the 16-connections-per-worker
/// scaling rule and `Control` handling) lives in the reused `run_bridge` /
/// `BridgeWorker` machinery this type supervises.
pub struct Bridge {
    config: CarrierConfig,
    dialer: Arc<dyn PortalDialer>,
    dispatcher: Dispatcher,
    options: BridgeOptions,
    cancel: Option<CancellationToken>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Bridge {
    /// Go `NewBridge` validation ("bridge tag is empty" / "bridge domain is
    /// empty") plus the carrier domain-shape validation.
    pub fn new(
        config: BridgeConfig,
        dialer: Arc<dyn PortalDialer>,
        dispatcher: Dispatcher,
        options: BridgeOptions,
    ) -> io::Result<Self> {
        if config.tag.is_empty() {
            return Err(invalid("bridge tag is empty"));
        }
        if config.domain.is_empty() {
            return Err(invalid("bridge domain is empty"));
        }
        let carrier = CarrierConfig {
            tag: config.tag.clone(),
            domain: config.domain.clone(),
        };
        carrier.validate()?;
        Ok(Self {
            config: carrier,
            dialer,
            dispatcher,
            options,
            cancel: None,
            task: None,
        })
    }

    pub fn tag(&self) -> &str {
        &self.config.tag
    }
    pub fn domain(&self) -> &str {
        &self.config.domain
    }
    pub fn is_running(&self) -> bool {
        self.task.is_some()
    }

    /// Starts the carrier monitor (Go `Bridge.Start`): dials the first worker
    /// immediately, then every monitor tick re-dials dropped carriers and
    /// adds workers past the 16-average scaling threshold.
    pub fn start(&mut self) -> io::Result<()> {
        if self.task.is_some() {
            return Err(invalid("reverse bridge already started"));
        }
        let cancel = CancellationToken::new();
        let task = tokio::spawn(bridge_supervisor(
            self.config.clone(),
            carrier_connector(Arc::clone(&self.dialer)),
            Arc::clone(&self.dispatcher),
            self.options.clone(),
            cancel.clone(),
        ));
        self.cancel = Some(cancel);
        self.task = Some(task);
        Ok(())
    }

    /// Stops the monitor and closes every carrier worker (Go `Bridge.Close`,
    /// which never surfaces the periodic monitor's logged failures).
    pub async fn close(&mut self) -> io::Result<()> {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        match self.task.take() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(io::Error::other(format!(
                    "reverse bridge monitor task failed: {error}"
                ))),
            },
            None => Ok(()),
        }
    }
}

/// Go's periodic monitor logs carrier failures and returns nil, so the next
/// tick retries; the reused `run_bridge` exits on a dial error instead. This
/// supervisor restores the Go behavior by restarting it after one monitor
/// interval until cancelled.
async fn bridge_supervisor(
    config: CarrierConfig,
    connector: Connector,
    dispatcher: Dispatcher,
    options: BridgeOptions,
    cancel: CancellationToken,
) -> io::Result<()> {
    loop {
        match reverse::run_bridge(
            config.clone(),
            connector.clone(),
            dispatcher.clone(),
            options.clone(),
            cancel.clone(),
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(error) => {
                if cancel.is_cancelled() {
                    // Go's Close does not surface monitor failures.
                    return Ok(());
                }
                tracing::warn!(%error, "failed to create bridge worker; retrying");
                tokio::time::sleep(options.monitor_interval).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Portal.
// ---------------------------------------------------------------------------

/// Go `Portal` plus its registered `Outbound` handler: accepts bridge
/// carriers for the configured domain selector and relays other traffic
/// across the established tunnels. Clone-able handle; `close` is terminal.
#[derive(Clone)]
pub struct Portal {
    config: PortalConfig,
    portal: MuxPortal,
}

impl Portal {
    /// Go `NewPortal` validation ("portal tag is empty" / "portal domain is
    /// empty") plus carrier validation.
    pub fn new(config: PortalConfig, options: PortalOptions) -> io::Result<Self> {
        if config.tag.is_empty() {
            return Err(invalid("portal tag is empty"));
        }
        if config.domain.is_empty() {
            return Err(invalid("portal domain is empty"));
        }
        let carrier = CarrierConfig {
            tag: config.tag.clone(),
            domain: config.domain.clone(),
        };
        let portal = MuxPortal::new(carrier, options)?;
        Ok(Self { config, portal })
    }

    pub fn tag(&self) -> &str {
        &self.config.tag
    }
    pub fn domain(&self) -> &str {
        &self.config.domain
    }

    /// Domain-selector match (Go `isDomain`): only carriers addressed to this
    /// portal's domain are control connections.
    pub fn accepts(&self, target: &Target) -> bool {
        target.is_domain(&self.config.domain)
    }

    /// Go `Portal.HandleConnection`: a domain-matched connection is a bridge
    /// carrier (control connection), anything else is relayed over a tunnel.
    pub async fn handle_connection(&self, stream: BoxStream, target: Target) -> io::Result<()> {
        if self.accepts(&target) {
            self.attach(stream).await
        } else {
            self.open_stream(stream, target).await
        }
    }

    /// Accepts a bridge control connection: the portal becomes the Mux.Cool
    /// client, opens the `reverse:0` control session and starts heartbeats.
    pub async fn attach(&self, stream: BoxStream) -> io::Result<()> {
        self.portal.attach(stream).await
    }

    /// Relays a plain TCP stream over an established bridge tunnel (Go
    /// `client.Dispatch`): opens a session, converts it to a byte stream
    /// and copies in both directions until either side closes.
    pub async fn open_stream(&self, mut stream: BoxStream, target: Target) -> io::Result<()> {
        if target.network != Network::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "reverse portal relay supports only TCP streams; UDP requires XUDP dispatch",
            ));
        }
        if self.accepts(&target) {
            return Err(invalid(
                "reverse portal carrier target must be attached, not relayed",
            ));
        }
        let session = self.portal.open(target, OpenOptions::default()).await?;
        let mut tunneled = session.into_stream()?;
        tokio::io::copy_bidirectional(&mut stream, &mut tunneled).await?;
        Ok(())
    }

    /// Opens a raw Mux session over the least-loaded non-draining carrier
    /// (Go `StaticMuxPicker.PickAvailable`), falling back to draining
    /// workers when every non-draining carrier is full.
    pub async fn open_session(&self, target: Target, options: OpenOptions) -> io::Result<Session> {
        self.portal.open(target, options).await
    }

    /// Snapshot of the carrier workers this portal currently holds.
    pub fn workers(&self) -> Vec<WorkerStats> {
        self.portal.workers()
    }

    /// Closes the portal and every carrier (terminal; Go `Portal.Close`
    /// removes the outbound handler instead, which the runtime performs).
    pub fn close(&self) {
        self.portal.close();
    }
}

// ---------------------------------------------------------------------------
// Reverse container.
// ---------------------------------------------------------------------------

/// Go `Reverse`: all configured bridges and portals. The runtime registers
/// each portal under its tag so router-selected connections reach
/// [`Portal::handle_connection`]; bridges dial out as soon as [`Reverse::start`]
/// runs.
pub struct Reverse {
    bridges: Vec<Bridge>,
    portals: Vec<Portal>,
}

impl Reverse {
    /// Go `Reverse.Init`: builds every bridge then every portal, aborting on
    /// the first invalid entry with the Go message.
    pub fn new(
        config: &ReverseConfig,
        dialer: Arc<dyn PortalDialer>,
        dispatcher: Dispatcher,
        bridge_options: BridgeOptions,
        portal_options: PortalOptions,
    ) -> Result<Self> {
        let mut bridges = Vec::with_capacity(config.bridges.len());
        for entry in &config.bridges {
            bridges.push(
                Bridge::new(
                    entry.clone(),
                    Arc::clone(&dialer),
                    Arc::clone(&dispatcher),
                    bridge_options.clone(),
                )
                .with_context(|| format!("invalid reverse bridge '{}'", entry.tag))?,
            );
        }
        let mut portals = Vec::with_capacity(config.portals.len());
        for entry in &config.portals {
            portals.push(
                Portal::new(entry.clone(), portal_options.clone())
                    .with_context(|| format!("invalid reverse portal '{}'", entry.tag))?,
            );
        }
        Ok(Self { bridges, portals })
    }

    /// Starts the bridges' carrier monitors (portals are passive handles the
    /// runtime routes into).
    pub fn start(&mut self) -> io::Result<()> {
        for bridge in &mut self.bridges {
            bridge.start()?;
        }
        Ok(())
    }

    /// Go `Reverse.Close`: closes bridges and portals, reporting the first
    /// failure without skipping the rest.
    pub async fn close(&mut self) -> io::Result<()> {
        let mut failure = None;
        for bridge in &mut self.bridges {
            if let Err(error) = bridge.close().await {
                failure = Some(error);
            }
        }
        for portal in &self.portals {
            portal.close();
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn bridges(&self) -> &[Bridge] {
        &self.bridges
    }
    pub fn portals(&self) -> &[Portal] {
        &self.portals
    }
    pub fn portal(&self, tag: &str) -> Option<&Portal> {
        self.portals.iter().find(|portal| portal.tag() == tag)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// ---------------------------------------------------------------------------
// Tests: in-process bridge <-> portal pairs over local TCP.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        pin::Pin,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context as TaskContext, Poll, Waker},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
        net::{TcpListener, TcpStream},
    };

    const BRIDGE_DOMAIN: &str = "bridge.example";
    const BRIDGE_TAG: &str = "bridge-in";

    /// Cooperative kill signal: registers wakers so a reader or writer parked
    /// on the socket is woken the moment the test severs the carrier. Safe
    /// to poll any number of times, from both wrapped ends.
    #[derive(Default)]
    struct KillSignal {
        killed: AtomicBool,
        wakers: Mutex<Vec<Waker>>,
    }

    impl KillSignal {
        fn poll_killed(&self, cx: &mut TaskContext<'_>) -> bool {
            if self.killed.load(Ordering::Acquire) {
                return true;
            }
            let mut wakers = self.wakers.lock().unwrap();
            // Re-check under the lock so a kill racing the waker
            // registration is never missed.
            if self.killed.load(Ordering::Acquire) {
                return true;
            }
            let waker = cx.waker();
            if !wakers.iter().any(|registered| registered.will_wake(waker)) {
                wakers.push(waker.clone());
            }
            false
        }
        fn kill(&self) {
            self.killed.store(true, Ordering::Release);
            for waker in std::mem::take(&mut *self.wakers.lock().unwrap()) {
                waker.wake();
            }
        }
    }

    /// A TCP stream that can be severed from the test on demand, so the
    /// carrier drop-reconnect path is exercisable without privileged tricks.
    struct KillableStream {
        inner: TcpStream,
        signal: Arc<KillSignal>,
    }
    fn broken_pipe() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "test carrier killed")
    }
    impl tokio::io::AsyncRead for KillableStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.signal.poll_killed(cx) {
                return Poll::Ready(Err(broken_pipe()));
            }
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }
    impl tokio::io::AsyncWrite for KillableStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.signal.poll_killed(cx) {
                return Poll::Ready(Err(broken_pipe()));
            }
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// One kill signal per dialed carrier, in dial order.
    type Carriers = Arc<Mutex<Vec<Arc<KillSignal>>>>;

    fn wrap_killable(stream: TcpStream, signal: Arc<KillSignal>) -> KillableStream {
        KillableStream {
            inner: stream,
            signal,
        }
    }

    /// Wires a bridge and a portal over a local TCP pair: the bridge dials a
    /// real TCP socket to the listener and the accepted side is fed to the
    /// portal, both ends killable so a test can sever the carrier. The bridge
    /// dispatcher echoes every session payload back.
    async fn rig(
        monitor_interval: Duration,
    ) -> (Portal, Bridge, Carriers, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let portal = Portal::new(
            PortalConfig {
                tag: "portal-out".into(),
                domain: BRIDGE_DOMAIN.into(),
            },
            PortalOptions::default(),
        )
        .unwrap();

        // Portal side: every accepted TCP connection is a carrier addressed
        // to the portal domain, so handle_connection attaches it.
        let carriers: Carriers = Arc::new(Mutex::new(Vec::new()));
        let accept_carriers = Arc::clone(&carriers);
        let accept_portal = portal.clone();
        let accept = tokio::spawn(async move {
            let mut accepted = 0_usize;
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                // Match the dial that produced this connection, in order;
                // the dialer registers its signal before connecting.
                let signal = accept_carriers
                    .lock()
                    .unwrap()
                    .get(accepted)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(KillSignal::default()));
                accepted += 1;
                let stream = wrap_killable(stream, signal);
                let portal = accept_portal.clone();
                let target = Target::new(Network::Tcp, BRIDGE_DOMAIN, 0).unwrap();
                tokio::spawn(async move {
                    let _ = portal.handle_connection(Box::new(stream), target).await;
                });
            }
        });

        // Bridge side: dial the listener, registering the kill signal
        // before the connect so the accept side can always match it.
        let dial_carriers = Arc::clone(&carriers);
        let dialer: Arc<dyn PortalDialer> = Arc::new(move |domain: &str, tag: &str| {
            assert_eq!(domain, BRIDGE_DOMAIN);
            assert_eq!(tag, BRIDGE_TAG);
            let carriers = Arc::clone(&dial_carriers);
            let dial: ConnectFuture = Box::pin(async move {
                let signal: Arc<KillSignal> = Arc::new(KillSignal::default());
                carriers.lock().unwrap().push(Arc::clone(&signal));
                let stream = match TcpStream::connect(addr).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        let mut list = carriers.lock().unwrap();
                        list.retain(|entry| !Arc::ptr_eq(entry, &signal));
                        return Err(error);
                    }
                };
                Ok(Box::new(wrap_killable(stream, signal)) as BoxStream)
            });
            dial
        });

        let dispatcher: Dispatcher = Arc::new(|mut session: Session, tag: String| {
            Box::pin(async move {
                assert_eq!(tag, BRIDGE_TAG);
                while let Some(packet) = session.recv().await? {
                    session.send(&packet.payload, packet.target).await?;
                }
                Ok(())
            })
        });

        let mut bridge = Bridge::new(
            BridgeConfig {
                tag: BRIDGE_TAG.into(),
                domain: BRIDGE_DOMAIN.into(),
            },
            dialer,
            dispatcher,
            BridgeOptions {
                monitor_interval,
                ..BridgeOptions::default()
            },
        )
        .unwrap();
        bridge.start().unwrap();
        (portal, bridge, carriers, accept)
    }

    async fn wait_for_live_carrier(portal: &Portal) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if portal.workers().iter().any(|worker| !worker.closed) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bridge carrier attaches to the portal");
    }

    /// Sever every carrier dialed so far; both wrapped ends observe the drop.
    fn kill_carriers(carriers: &Carriers) {
        for signal in carriers.lock().unwrap().iter() {
            signal.kill();
        }
    }

    /// One request/response through the portal's session API.
    async fn echo_once(portal: &Portal, payload: &[u8]) -> Vec<u8> {
        let mut session = portal
            .open_session(
                Target::new(Network::Tcp, "echo.example", 80).unwrap(),
                OpenOptions::default(),
            )
            .await
            .unwrap();
        session.send(payload, None).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("echo within 5s")
            .unwrap()
            .unwrap();
        session.close(false).await.unwrap();
        packet.payload
    }

    #[tokio::test]
    async fn bridge_registers_and_relays_over_local_tcp_pair() {
        let (portal, mut bridge, _kills, accept) = rig(Duration::from_millis(50)).await;

        // The bridge registered its selector: a carrier attached.
        wait_for_live_carrier(&portal).await;
        assert!(portal.accepts(&Target::new(Network::Tcp, BRIDGE_DOMAIN, 0).unwrap()));
        assert!(!portal.accepts(&Target::new(Network::Tcp, "other.example", 0).unwrap()));

        // A client request through the portal is relayed to the bridge side
        // and echoed back over the same carrier.
        let (mut client, carrier) = tokio::io::duplex(64 * 1024);
        let relay_portal = portal.clone();
        let relay = tokio::spawn(async move {
            relay_portal
                .handle_connection(
                    Box::new(carrier),
                    Target::new(Network::Tcp, "echo.example", 80).unwrap(),
                )
                .await
        });
        client.write_all(b"reverse-bridge-payload").await.unwrap();
        let mut echo = vec![0_u8; b"reverse-bridge-payload".len()];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, b"reverse-bridge-payload");

        // One carrier; the control session plus the relay session used it.
        let workers = portal.workers();
        assert_eq!(workers.len(), 1);
        assert!(workers[0].total_connections >= 2);

        drop(client);
        relay
            .await
            .unwrap_or_else(|error| panic!("relay task: {error}"))
            .unwrap();

        assert!(bridge.close().await.is_ok());
        portal.close();
        accept.abort();
    }

    #[tokio::test]
    async fn concurrent_connections_share_the_tunnel() {
        let (portal, mut bridge, _kills, accept) = rig(Duration::from_millis(50)).await;
        wait_for_live_carrier(&portal).await;

        let mut tasks = Vec::new();
        for index in 0..4_u8 {
            let portal = portal.clone();
            tasks.push(tokio::spawn(async move {
                let payload = format!("concurrent-payload-{index}");
                let (mut client, carrier) = tokio::io::duplex(16 * 1024);
                let relay = tokio::spawn(async move {
                    portal
                        .open_stream(
                            Box::new(carrier),
                            Target::new(Network::Tcp, "echo.example", 1000 + u16::from(index))
                                .unwrap(),
                        )
                        .await
                });
                client.write_all(payload.as_bytes()).await.unwrap();
                let mut echo = vec![0_u8; payload.len()];
                client.read_exact(&mut echo).await.unwrap();
                assert_eq!(echo, payload.as_bytes());
                drop(client);
                tokio::time::timeout(Duration::from_secs(5), relay)
                    .await
                    .expect("relay finishes")
                    .unwrap()
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        // All four sessions crossed the single carrier (plus control).
        assert!(portal.workers()[0].total_connections >= 5);

        assert!(bridge.close().await.is_ok());
        portal.close();
        accept.abort();
    }

    #[tokio::test]
    async fn bridge_redials_after_control_connection_drop() {
        let (portal, mut bridge, carriers, accept) = rig(Duration::from_millis(25)).await;
        wait_for_live_carrier(&portal).await;

        assert_eq!(echo_once(&portal, b"first").await, b"first");

        // Sever the carrier; both ends observe the drop and the bridge
        // monitor re-dials (a second dial is registered).
        kill_carriers(&carriers);
        tokio::time::timeout(Duration::from_secs(5), async {
            while carriers.lock().unwrap().len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bridge re-dials a second carrier");

        // The new carrier attaches and traffic flows again; the portal's
        // picker must have disposed of the dead worker to route this.
        wait_for_live_carrier(&portal).await;
        assert_eq!(echo_once(&portal, b"second").await, b"second");
        assert_eq!(carriers.lock().unwrap().len(), 2);

        assert!(bridge.close().await.is_ok());
        portal.close();
        accept.abort();
    }

    #[tokio::test]
    async fn udp_relay_and_carrier_relay_are_rejected_explicitly() {
        let portal = Portal::new(
            PortalConfig {
                tag: "portal-out".into(),
                domain: BRIDGE_DOMAIN.into(),
            },
            PortalOptions::default(),
        )
        .unwrap();
        let (_udp_client, carrier) = tokio::io::duplex(1024);
        let error = portal
            .open_stream(
                Box::new(carrier),
                Target::new(Network::Udp, "echo.example", 53).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        let (_tcp_client, carrier) = tokio::io::duplex(1024);
        let error = portal
            .open_stream(
                Box::new(carrier),
                Target::new(Network::Tcp, BRIDGE_DOMAIN, 0).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        portal.close();
    }

    #[test]
    fn config_rejection_matrix_matches_go_messages() {
        // Bridge entries: Go NewBridge order and messages.
        for (value, message) in [
            (json!({}), "bridge tag is empty"),
            (json!({"domain": "bridge.example"}), "bridge tag is empty"),
            (json!({"tag": ""}), "bridge tag is empty"),
            (json!({"tag": "bridge-in"}), "bridge domain is empty"),
        ] {
            let error = BridgeConfig::from_value(&value).unwrap_err();
            assert!(
                format!("{error:#}").contains(message),
                "{value:?}: {error:#}"
            );
        }
        // Portal entries: Go NewPortal order and messages.
        for (value, message) in [
            (json!({}), "portal tag is empty"),
            (json!({"domain": "bridge.example"}), "portal tag is empty"),
            (json!({"tag": "portal-out"}), "portal domain is empty"),
        ] {
            let error = PortalConfig::from_value(&value).unwrap_err();
            assert!(
                format!("{error:#}").contains(message),
                "{value:?}: {error:#}"
            );
        }
        // Malformed shapes fail at parse time (unknown fields, wrong types).
        for value in [
            json!({"tag": "b", "domain": "d", "extra": true}),
            json!({"tag": 1, "domain": "d"}),
            json!({"domain": null}),
        ] {
            assert!(BridgeConfig::from_value(&value).is_err(), "{value:?}");
            assert!(PortalConfig::from_value(&value).is_err(), "{value:?}");
        }
        // Full reverse config: entry validation in Go Init order.
        let error = ReverseConfig::from_value(&json!({"bridges": [{}]})).unwrap_err();
        assert!(
            format!("{error:#}").contains("bridge tag is empty"),
            "{error:#}"
        );
        let error = ReverseConfig::from_value(&json!({"portals": [{"tag": "p"}]})).unwrap_err();
        assert!(
            format!("{error:#}").contains("portal domain is empty"),
            "{error:#}"
        );
        assert!(ReverseConfig::from_value(&json!({"bridge": []})).is_err());
        let config = ReverseConfig::from_value(&json!({
            "bridges": [{"tag": "bridge-in", "domain": "bridge.example"}],
            "portals": [{"tag": "portal-out", "domain": "bridge.example"}]
        }))
        .unwrap();
        assert_eq!(
            config.bridges,
            [BridgeConfig {
                tag: "bridge-in".into(),
                domain: "bridge.example".into(),
            }]
        );
        assert_eq!(config.portals.len(), 1);
        // Go allows an empty reverse block.
        assert!(
            ReverseConfig::from_value(&json!({}))
                .unwrap()
                .portals
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reverse_container_validates_entries_and_manages_lifecycle() {
        let dialer: Arc<dyn PortalDialer> = Arc::new(|_domain: &str, _tag: &str| {
            let dial: ConnectFuture =
                Box::pin(async { Err(io::Error::other("no portal in this test")) });
            dial
        });
        let dispatcher: Dispatcher = Arc::new(|session: Session, _tag: String| {
            Box::pin(async move {
                let _ = session;
                Ok(())
            })
        });
        // Invalid entry aborts Reverse.Init with the Go message.
        let invalid = ReverseConfig::from_value(&json!({
            "bridges": [{"tag": "", "domain": "d"}],
            "portals": [{"tag": "p", "domain": "d"}]
        }))
        .unwrap_err();
        assert!(
            format!("{invalid:#}").contains("bridge tag is empty"),
            "{invalid:#}"
        );

        let config = ReverseConfig::from_value(&json!({
            "bridges": [{"tag": "b", "domain": "bridge.example"}],
            "portals": [{"tag": "p", "domain": "bridge.example"}]
        }))
        .unwrap();
        let mut reverse = Reverse::new(
            &config,
            dialer,
            dispatcher,
            BridgeOptions {
                monitor_interval: Duration::from_millis(10),
                ..BridgeOptions::default()
            },
            PortalOptions::default(),
        )
        .unwrap();
        assert!(reverse.start().is_ok());
        assert!(reverse.bridges().iter().all(|bridge| bridge.is_running()));
        assert_eq!(reverse.portal("p").unwrap().domain(), "bridge.example");
        assert_eq!(reverse.portal("p").unwrap().tag(), "p");
        assert!(reverse.portal("missing").is_none());
        assert!(reverse.close().await.is_ok());
    }
}
