//! Native reverse portal and bridge components from app/reverse.
//!
//! The runtime routes bridge-domain carriers to Portal::attach, sends portal
//! outbound requests through Portal::open, and supplies the bridge connector
//! and dispatcher. No global route/outbound configuration is changed here.

pub mod control;

use crate::{
    mux::{Connection, Network, OpenOptions, Options as MuxOptions, Session, Target},
    transport::BoxStream,
};
pub use control::{Control, State};
use rand::RngCore;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

pub const INTERNAL_DOMAIN: &str = "reverse";
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
pub const BRIDGE_CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
pub const DRAIN_LINGER: Duration = Duration::from_secs(24 * 60 * 60);

pub type DispatchFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
/// Callback owns the complete accepted session lifetime. Returning closes it;
/// errors produce an End frame with OptionError. Tag is the bridge inbound tag.
pub type Dispatcher = Arc<dyn Fn(Session, String) -> DispatchFuture + Send + Sync>;
pub type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;
/// The connector routes target domain:0 using the supplied bridge inbound tag.
pub type Connector = Arc<dyn Fn(Target, String) -> ConnectFuture + Send + Sync>;

#[derive(Clone, Debug)]
pub struct Config {
    pub tag: String,
    pub domain: String,
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if self.tag.is_empty() {
            return Err(invalid("reverse tag is empty"));
        }
        if self.domain.is_empty() {
            return Err(invalid("reverse domain is empty"));
        }
        Target::new(Network::Tcp, &self.domain, 0)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PortalOptions {
    pub mux: MuxOptions,
    pub heartbeat_interval: Duration,
    pub drain_after_connections: usize,
    pub drain_linger: Duration,
}
impl Default for PortalOptions {
    fn default() -> Self {
        Self {
            mux: MuxOptions::default(),
            heartbeat_interval: HEARTBEAT_INTERVAL,
            drain_after_connections: 256,
            drain_linger: DRAIN_LINGER,
        }
    }
}

struct PortalWorker {
    connection: Connection,
    draining: AtomicBool,
}
struct PortalInner {
    config: Config,
    options: PortalOptions,
    workers: Mutex<Vec<Arc<PortalWorker>>>,
    cancel: CancellationToken,
}

impl Drop for PortalInner {
    fn drop(&mut self) {
        self.cancel.cancel();
        for worker in self
            .workers
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            worker.connection.close();
        }
    }
}

#[derive(Clone)]
pub struct Portal {
    inner: Arc<PortalInner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerStats {
    pub active_connections: usize,
    pub total_connections: usize,
    pub draining: bool,
    pub closed: bool,
}

impl Portal {
    pub fn new(config: Config, options: PortalOptions) -> io::Result<Self> {
        config.validate()?;
        if options.heartbeat_interval.is_zero() || options.drain_linger.is_zero() {
            return Err(invalid(
                "reverse heartbeat/linger intervals must be positive",
            ));
        }
        Ok(Self {
            inner: Arc::new(PortalInner {
                config,
                options,
                workers: Mutex::new(Vec::new()),
                cancel: CancellationToken::new(),
            }),
        })
    }
    pub fn accepts(&self, target: &Target) -> bool {
        target.is_domain(&self.inner.config.domain)
    }
    pub fn tag(&self) -> &str {
        &self.inner.config.tag
    }
    /// A bridge-domain carrier reverses the usual roles: portal is Mux client,
    /// bridge is Mux server. The first UDP session is reverse:0 control traffic.
    pub async fn attach(&self, stream: BoxStream) -> io::Result<()> {
        if self.inner.cancel.is_cancelled() {
            return Err(closed());
        }
        let connection = Connection::client(stream, self.inner.options.mux.clone())?;
        let first = random_control(State::Active).encode();
        let control = match connection
            .open(
                Target::new(Network::Udp, INTERNAL_DOMAIN, 0)?,
                OpenOptions {
                    initial_data: Some(first),
                    ..OpenOptions::default()
                },
            )
            .await
        {
            Ok(control) => control,
            Err(error) => {
                connection.close();
                return Err(error);
            }
        };
        let worker = Arc::new(PortalWorker {
            connection,
            draining: AtomicBool::new(false),
        });
        {
            let mut workers = self.inner.workers.lock().unwrap_or_else(|p| p.into_inner());
            workers.retain(|worker| !worker.connection.is_closed());
            workers.push(Arc::clone(&worker));
        }
        let cancel = self.inner.cancel.clone();
        let options = self.inner.options.clone();
        tokio::spawn(async move {
            portal_heartbeat(worker, control, options, cancel).await;
        });
        Ok(())
    }
    /// Least active available worker, preferring non-draining workers. The
    /// source deliberately falls back to draining workers if necessary.
    pub async fn open(&self, target: Target, options: OpenOptions) -> io::Result<Session> {
        if self.inner.cancel.is_cancelled() {
            return Err(closed());
        }
        let connection = {
            let mut workers = self.inner.workers.lock().unwrap_or_else(|p| p.into_inner());
            workers.retain(|worker| !worker.connection.is_closed());
            let active = workers
                .iter()
                .filter(|worker| {
                    !worker.draining.load(Ordering::Acquire) && !worker.connection.is_full()
                })
                .min_by_key(|worker| worker.connection.active_connections());
            let selected = active.or_else(|| {
                workers
                    .iter()
                    .filter(|worker| !worker.connection.is_full())
                    .min_by_key(|worker| worker.connection.active_connections())
            });
            selected
                .map(|worker| worker.connection.clone())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "no reverse portal worker available",
                    )
                })?
        };
        connection.open(target, options).await
    }
    pub fn workers(&self) -> Vec<WorkerStats> {
        self.inner
            .workers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|worker| WorkerStats {
                active_connections: worker.connection.active_connections(),
                total_connections: worker.connection.total_connections(),
                draining: worker.draining.load(Ordering::Acquire),
                closed: worker.connection.is_closed(),
            })
            .collect()
    }
    pub fn close(&self) {
        self.inner.cancel.cancel();
        for worker in self
            .inner
            .workers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            worker.connection.close();
        }
    }
}

async fn portal_heartbeat(
    worker: Arc<PortalWorker>,
    control: Session,
    options: PortalOptions,
    cancel: CancellationToken,
) {
    let mut timer = tokio::time::interval_at(
        Instant::now() + options.heartbeat_interval,
        options.heartbeat_interval,
    );
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Initial Active control was emitted by attach (counter == 1 in Go).
    let mut counter = 1_u8;
    loop {
        tokio::select! { _ = cancel.cancelled() => { worker.connection.close(); return; }, _ = worker.connection.closed() => return, _ = timer.tick() => {} }
        let draining = worker.connection.total_connections() > options.drain_after_connections;
        counter = (counter + 1) % 5;
        if draining || counter == 1 {
            let state = if draining {
                State::Drain
            } else {
                State::Active
            };
            if control
                .send(&random_control(state).encode(), None)
                .await
                .is_err()
            {
                worker.connection.close();
                return;
            }
            if draining {
                worker.draining.store(true, Ordering::Release);
                let _ = control.close(false).await;
                drop(control);
                tokio::select! { _ = cancel.cancelled() => {}, _ = worker.connection.closed() => return, _ = tokio::time::sleep(options.drain_linger) => {} }
                worker.connection.close();
                return;
            }
        }
    }
}

pub fn random_control(state: State) -> Control {
    let mut rng = rand::rngs::OsRng;
    // Rejection-free because 64 divides 2^32, matching Go's uniform 1..64.
    let mut random = vec![0; (rng.next_u32() % 64 + 1) as usize];
    rng.fill_bytes(&mut random);
    Control { state, random }
}

#[derive(Clone, Debug)]
pub struct BridgeOptions {
    pub mux: MuxOptions,
    pub control_timeout: Duration,
    pub control_closed_linger: Duration,
    pub monitor_interval: Duration,
}
impl Default for BridgeOptions {
    fn default() -> Self {
        Self {
            mux: MuxOptions::default(),
            control_timeout: BRIDGE_CONTROL_TIMEOUT,
            control_closed_linger: DRAIN_LINGER,
            monitor_interval: Duration::from_secs(2),
        }
    }
}

struct BridgeInner {
    connection: Connection,
    state: AtomicU8,
    failure: Mutex<Option<(io::ErrorKind, String)>>,
}

#[derive(Clone)]
pub struct BridgeWorker {
    inner: Arc<BridgeInner>,
}

impl BridgeWorker {
    pub fn attach(
        stream: BoxStream,
        tag: String,
        dispatcher: Dispatcher,
        options: BridgeOptions,
    ) -> io::Result<Self> {
        if tag.is_empty()
            || options.control_timeout.is_zero()
            || options.control_closed_linger.is_zero()
        {
            return Err(invalid("invalid reverse bridge worker settings"));
        }
        let (connection, incoming) = Connection::server(stream, options.mux.clone())?;
        let inner = Arc::new(BridgeInner {
            connection,
            state: AtomicU8::new(0),
            failure: Mutex::new(None),
        });
        let worker = Self {
            inner: Arc::clone(&inner),
        };
        tokio::spawn(async move {
            if let Err(error) =
                serve_bridge(Arc::clone(&inner), incoming, tag, dispatcher, options).await
            {
                *inner.failure.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some((error.kind(), error.to_string()));
            }
            inner.connection.close();
        });
        Ok(worker)
    }
    pub fn state(&self) -> State {
        if self.inner.state.load(Ordering::Acquire) == 0 {
            State::Active
        } else {
            State::Drain
        }
    }
    pub fn is_active(&self) -> bool {
        self.state() == State::Active && !self.is_closed()
    }
    pub fn is_closed(&self) -> bool {
        self.inner.connection.is_closed()
    }
    pub fn active_connections(&self) -> usize {
        self.inner.connection.active_connections()
    }
    pub fn close(&self) {
        self.inner.connection.close();
    }
    pub async fn closed(&self) -> io::Result<()> {
        let carrier_result = self.inner.connection.closed().await;
        if let Some((kind, message)) =
            &*self.inner.failure.lock().unwrap_or_else(|p| p.into_inner())
        {
            return Err(io::Error::new(*kind, message.clone()));
        }
        carrier_result
    }
}

enum BridgeEvent {
    Control(Control),
    ControlClosed,
    Failed(io::Error),
}

async fn serve_bridge(
    inner: Arc<BridgeInner>,
    mut incoming: mpsc::Receiver<Session>,
    tag: String,
    dispatcher: Dispatcher,
    options: BridgeOptions,
) -> io::Result<()> {
    let (events, mut event_rx) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    let mut deadline = Instant::now() + options.control_timeout;
    let result = async {
        loop {
            tokio::select! {
                result = inner.connection.closed() => return result,
                _ = tokio::time::sleep_until(deadline) => return Err(io::Error::new(io::ErrorKind::TimedOut, "reverse bridge control inactivity timeout")),
                Some(event) = event_rx.recv() => match event {
                    BridgeEvent::Control(control) => { inner.state.store(if control.state == State::Active { 0 } else { 1 }, Ordering::Release); deadline = Instant::now() + options.control_timeout; }
                    BridgeEvent::ControlClosed => deadline = Instant::now() + options.control_closed_linger,
                    BridgeEvent::Failed(error) => return Err(error),
                },
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result { return Err(io::Error::other(format!("reverse dispatcher task failed: {error}"))); }
                }
                session = incoming.recv() => {
                    let Some(mut session) = session else { return Ok(()); };
                    if session.target.is_domain(INTERNAL_DOMAIN) {
                        let events = events.clone();
                        tasks.spawn(async move {
                            loop {
                                match session.recv().await {
                                    Ok(Some(packet)) => match Control::decode(&packet.payload) {
                                        Ok(control) => { if events.send(BridgeEvent::Control(control)).is_err() { return; } }
                                        Err(error) => { let _ = events.send(BridgeEvent::Failed(error)); return; }
                                    }
                                    Ok(None) => { let _ = events.send(BridgeEvent::ControlClosed); return; }
                                    Err(error) => { let _ = events.send(BridgeEvent::Failed(error)); return; }
                                }
                            }
                        });
                    } else {
                        let sender = session.sender(); let dispatch = Arc::clone(&dispatcher); let tag = tag.clone();
                        tasks.spawn(async move { let result = dispatch(session, tag).await; let _ = sender.close(result.is_err()).await; });
                    }
                }
            }
        }
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

/// Source scaling policy: maintain at least one Active bridge carrier; add
/// another when integer average active sessions per Active carrier exceeds 16.
/// A connector error is returned explicitly for the runtime's retry/log policy.
/// Cancellation closes active and draining workers, including their sessions.
pub async fn run_bridge(
    config: Config,
    connector: Connector,
    dispatcher: Dispatcher,
    options: BridgeOptions,
    cancel: CancellationToken,
) -> io::Result<()> {
    config.validate()?;
    if options.monitor_interval.is_zero() {
        return Err(invalid("reverse monitor interval must be positive"));
    }
    let mut workers: Vec<BridgeWorker> = Vec::new();
    let mut monitor = tokio::time::interval(options.monitor_interval);
    monitor.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = async {
        loop {
            tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = monitor.tick() => {} }
            workers.retain(|worker| !worker.is_closed());
            let active: Vec<_> = workers.iter().filter(|worker| worker.is_active()).collect();
            let sessions: usize = active.iter().map(|worker| worker.active_connections()).sum();
            if active.is_empty() || sessions / active.len() > 16 {
                // Go explicitly constructs DomainAddress even if the configured
                // domain happens to look like an IP literal.
                let target = Target { network: Network::Tcp, host: crate::mux::Host::Domain(config.domain.clone()), port: 0 };
                let stream = tokio::select! { _ = cancel.cancelled() => return Ok(()), result = connector(target, config.tag.clone()) => result? };
                workers.push(BridgeWorker::attach(stream, config.tag.clone(), Arc::clone(&dispatcher), options.clone())?);
            }
        }
    }.await;
    for worker in workers {
        worker.close();
    }
    result
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "reverse portal closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            tag: "reverse-test".into(),
            domain: "bridge.example".into(),
        }
    }
    fn echo_dispatcher() -> Dispatcher {
        Arc::new(|mut session, tag| {
            Box::pin(async move {
                assert_eq!(tag, "reverse-test");
                while let Some(packet) = session.recv().await? {
                    session.send(&packet.payload, packet.target).await?;
                }
                Ok(())
            })
        })
    }
    #[tokio::test]
    async fn portal_and_bridge_forward_application_sessions_with_internal_control() {
        let portal = Portal::new(config(), PortalOptions::default()).unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let bridge = BridgeWorker::attach(
            Box::new(b),
            "reverse-test".into(),
            echo_dispatcher(),
            BridgeOptions::default(),
        )
        .unwrap();
        portal.attach(Box::new(a)).await.unwrap();
        let mut session = portal
            .open(
                Target::new(Network::Tcp, "localhost", 8080).unwrap(),
                OpenOptions::default(),
            )
            .await
            .unwrap();
        session.send(b"native reverse payload", None).await.unwrap();
        assert_eq!(
            session.recv().await.unwrap().unwrap().payload,
            b"native reverse payload"
        );
        assert_eq!(bridge.state(), State::Active);
        assert!(portal.accepts(&Target::new(Network::Tcp, "bridge.example", 0).unwrap()));
        portal.close();
        bridge.closed().await.unwrap();
    }
    #[tokio::test]
    async fn drain_keeps_existing_sessions_and_picker_can_fallback() {
        let portal = Portal::new(
            config(),
            PortalOptions {
                heartbeat_interval: Duration::from_millis(5),
                drain_after_connections: 1,
                ..PortalOptions::default()
            },
        )
        .unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let bridge = BridgeWorker::attach(
            Box::new(b),
            "reverse-test".into(),
            echo_dispatcher(),
            BridgeOptions::default(),
        )
        .unwrap();
        portal.attach(Box::new(a)).await.unwrap();
        let mut existing = portal
            .open(
                Target::new(Network::Tcp, "localhost", 80).unwrap(),
                OpenOptions::default(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while bridge.state() != State::Drain {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(portal.workers()[0].draining);
        existing.send(b"still alive", None).await.unwrap();
        assert_eq!(
            existing.recv().await.unwrap().unwrap().payload,
            b"still alive"
        );
        let fallback = portal
            .open(
                Target::new(Network::Tcp, "localhost", 81).unwrap(),
                OpenOptions::default(),
            )
            .await
            .unwrap();
        assert!(fallback.id > existing.id);
        portal.close();
    }
    #[tokio::test]
    async fn portal_chooses_least_loaded_non_draining_worker() {
        let portal = Portal::new(config(), PortalOptions::default()).unwrap();
        let mut bridges = Vec::new();
        for _ in 0..2 {
            let (a, b) = tokio::io::duplex(65536);
            bridges.push(
                BridgeWorker::attach(
                    Box::new(b),
                    "reverse-test".into(),
                    echo_dispatcher(),
                    BridgeOptions::default(),
                )
                .unwrap(),
            );
            portal.attach(Box::new(a)).await.unwrap();
        }
        let first = portal
            .open(
                Target::new(Network::Tcp, "localhost", 80).unwrap(),
                OpenOptions::default(),
            )
            .await
            .unwrap();
        let second = portal
            .open(
                Target::new(Network::Tcp, "localhost", 80).unwrap(),
                OpenOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(first.id, 2);
        assert_eq!(second.id, 2);
        assert_eq!(
            portal
                .workers()
                .iter()
                .map(|w| w.active_connections)
                .collect::<Vec<_>>(),
            vec![2, 2]
        );
        portal.close();
    }
    #[tokio::test]
    async fn malformed_control_closes_bridge_with_explicit_error() {
        let (a, b) = tokio::io::duplex(4096);
        let client = Connection::client(Box::new(a), MuxOptions::default()).unwrap();
        let bridge = BridgeWorker::attach(
            Box::new(b),
            "reverse-test".into(),
            echo_dispatcher(),
            BridgeOptions::default(),
        )
        .unwrap();
        let _control = client
            .open(
                Target::new(Network::Udp, INTERNAL_DOMAIN, 0).unwrap(),
                OpenOptions {
                    initial_data: Some(vec![8, 2]),
                    ..OpenOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            bridge.closed().await.unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
    #[tokio::test]
    async fn absent_control_expires_bridge_worker() {
        let (_peer, stream) = tokio::io::duplex(4096);
        let bridge = BridgeWorker::attach(
            Box::new(stream),
            "reverse-test".into(),
            echo_dispatcher(),
            BridgeOptions {
                control_timeout: Duration::from_millis(10),
                ..BridgeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            bridge.closed().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[test]
    fn source_random_padding_is_one_to_sixty_four_bytes() {
        for _ in 0..100 {
            let control = random_control(State::Active);
            assert!((1..=64).contains(&control.random.len()));
            assert_eq!(Control::decode(&control.encode()).unwrap(), control);
        }
        assert!(
            Config {
                tag: String::new(),
                domain: "example.com".into()
            }
            .validate()
            .is_err()
        );
    }
}
