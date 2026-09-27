//! Source-derived ordinary observatory probes and a management API provider.
//!
//! The caller must supply an outbound-tag-aware [`ProbeConnector`] and poll
//! [`Observer::run`] (or invoke manual checks). There is no direct-dial fallback,
//! environment proxy, detached scheduler, or invented successful observation.
//! Dropping/cancelling a check owns cancellation of its HTTP streams and workers.
//!
//! `app/observatory/observer.go` considers any final HTTP response alive, including
//! 3xx/4xx/5xx. It does not follow redirects or consume the response body. Latency
//! covers dialing, TLS and response headers; timestamps are Unix seconds and
//! delays are milliseconds. Failed status uses the source sentinel 99,999,999,
//! updates last_try_time and retains the last successful last_seen_time.
//!
//! This is the ordinary observer, not a burst observer. Inspected burst sources
//! differ: GET drains the body, HEAD does not, and ping.go does not enforce the
//! 204 mentioned in its config comment. Burst sampling/jitter, nanosecond health
//! statistics, direct connectivity fallback and least-load policy are unimplemented
//! here. `health_ping` remains None, never a fabricated burst measurement. The
//! existing router owns balancer selection; the runtime owns selector matching,
//! config wiring, outbound routing and any connection error collector.
//!
//! Other bounded differences: concurrent probes are capped; response headers are
//! bounded to 32 KiB/128 fields and eight interim responses. TLS uses the shared
//! verified native helper and HTTP/1.1, without browser fingerprint/header
//! impersonation. Each probe uses a fresh connection. URL userinfo, fragments,
//! scoped IPv6 and non-HTTP schemes are rejected at configuration time.

pub mod runtime;

use std::{
    collections::HashSet,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use http::Uri;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    api::observatory::{
        ObservationProvider,
        observation_wire::{ObservationResult, OutboundStatus},
    },
    transport::{
        BoxStream,
        tls::{TlsClient, TlsSettings},
    },
};

pub const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";
pub const FAILED_DELAY_MS: i64 = 99_999_999;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADER_FIELDS: usize = 128;
const MAX_INTERIM_RESPONSES: usize = 8;

/// Target supplied to the connector. Return a raw TCP-equivalent stream;
/// this module performs verified TLS itself when https is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
    pub https: bool,
}

#[tonic::async_trait]
pub trait ProbeConnector: Send + Sync + 'static {
    async fn connect(&self, outbound_tag: &str, target: &ProbeTarget) -> Result<BoxStream>;
}

/// Selection is delegated to the real outbound manager. Prefix matching and
/// availability must not be guessed by this health-probe library.
#[tonic::async_trait]
pub trait OutboundSelector: Send + Sync + 'static {
    async fn select(&self, selectors: &[String]) -> Result<Vec<String>>;
}

#[derive(Debug, Clone)]
pub struct ObservatoryConfig {
    pub subject_selector: Vec<String>,
    pub probe_url: String,
    pub probe_interval: Duration,
    pub timeout: Duration,
    pub enable_concurrency: bool,
    pub max_concurrency: usize,
    pub tls: TlsSettings,
}

impl Default for ObservatoryConfig {
    fn default() -> Self {
        Self {
            subject_selector: Vec::new(),
            probe_url: DEFAULT_PROBE_URL.into(),
            probe_interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            enable_concurrency: false,
            max_concurrency: 16,
            tls: TlsSettings::default(),
        }
    }
}

impl ObservatoryConfig {
    /// Check the URL, TLS settings, and runtime bounds without opening a socket.
    pub fn validate(&self) -> Result<()> {
        PreparedConfig::new(self.clone()).map(|_| ())
    }

    /// Source protobuf durations are nanoseconds; zero interval selects 10s.
    /// Negative intervals are rejected instead of creating a busy polling loop.
    pub fn from_wire(config: &crate::api::observatory::observation_wire::Config) -> Result<Self> {
        ensure!(
            config.probe_interval >= 0,
            "observatory probe interval must not be negative"
        );
        let mut result = Self {
            subject_selector: config.subject_selector.clone(),
            enable_concurrency: config.enable_concurrency,
            ..Self::default()
        };
        if !config.probe_url.is_empty() {
            result.probe_url.clone_from(&config.probe_url);
        }
        if config.probe_interval != 0 {
            result.probe_interval = Duration::from_nanos(config.probe_interval as u64);
        }
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub outbound_tag: String,
    pub alive: bool,
    /// Zero on a failed attempt; the stored OutboundStatus uses FAILED_DELAY_MS.
    pub delay_ms: i64,
    pub last_error_reason: String,
    pub completed_at: i64,
    /// An observed status code is diagnostic; no HTTP status is a health filter.
    pub http_status: Option<u16>,
}

#[derive(Debug)]
pub struct ProbeCancelled;

impl fmt::Display for ProbeCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("observatory probe cancelled")
    }
}
impl std::error::Error for ProbeCancelled {}

#[derive(Clone)]
pub struct Observer {
    inner: Arc<Inner>,
}

struct Inner {
    config: ObservatoryConfig,
    target: ProbeTarget,
    authority: String,
    path: String,
    tls: Option<TlsClient>,
    connector: Arc<dyn ProbeConnector>,
    status: Mutex<Vec<OutboundStatus>>,
    /// Serializes manual runs and scheduler cycles; concurrency is internal to
    /// one owned cycle so pruning cannot race a previous cycle's publication.
    cycle: AsyncMutex<()>,
    running: AtomicBool,
}

struct RunningGuard<'a>(&'a AtomicBool);
impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct PreparedConfig {
    config: ObservatoryConfig,
    target: ProbeTarget,
    authority: String,
    path: String,
    tls: Option<TlsClient>,
}

impl PreparedConfig {
    fn new(mut config: ObservatoryConfig) -> Result<Self> {
        if config.probe_url.is_empty() {
            config.probe_url = DEFAULT_PROBE_URL.into();
        }
        ensure!(
            !config.timeout.is_zero(),
            "observatory probe timeout must be nonzero"
        );
        ensure!(
            !config.probe_interval.is_zero(),
            "observatory probe interval must be nonzero"
        );
        ensure!(
            config.max_concurrency > 0,
            "observatory maximum concurrency must be nonzero"
        );
        ensure!(
            !config.probe_url.contains('#'),
            "observatory probe URL fragments are unsupported"
        );
        let uri: Uri = config
            .probe_url
            .parse()
            .context("invalid observatory probe URL")?;
        let https = match uri.scheme_str().unwrap_or("").to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => bail!("observatory probe URL must use http or https"),
        };
        let authority = uri
            .authority()
            .context("observatory probe URL requires a host")?
            .as_str()
            .to_owned();
        ensure!(
            !authority.contains('@'),
            "observatory probe URL userinfo is unsupported"
        );
        let raw_host = uri
            .host()
            .context("observatory probe URL requires a host")?;
        let host = raw_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();
        ensure!(
            !host.is_empty() && !host.contains('%'),
            "invalid observatory host; scoped IP addresses are unsupported"
        );
        let port_text = if authority.starts_with('[') {
            let end = authority
                .find(']')
                .context("invalid observatory IPv6 authority")?;
            let suffix = &authority[end + 1..];
            if suffix.is_empty() {
                None
            } else {
                Some(
                    suffix
                        .strip_prefix(':')
                        .context("invalid observatory authority")?,
                )
            }
        } else {
            authority.rsplit_once(':').map(|(_, port)| port)
        };
        let port = if let Some(port) = port_text {
            port.parse::<u16>().context("invalid observatory port")?
        } else if https {
            443
        } else {
            80
        };
        ensure!(port != 0, "observatory probe port must be nonzero");
        let path = uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        let tls = if https {
            ensure!(
                config.tls.alpn.is_empty() || config.tls.alpn == ["http/1.1"],
                "ordinary observatory probes require HTTP/1.1 ALPN"
            );
            config.tls.alpn = vec!["http/1.1".into()];
            config.tls.server_name(&host)?;
            Some(TlsClient::new(&config.tls)?)
        } else {
            None
        };
        Ok(Self {
            config,
            target: ProbeTarget { host, port, https },
            authority,
            path,
            tls,
        })
    }
}

impl Observer {
    pub fn new(config: ObservatoryConfig, connector: Arc<dyn ProbeConnector>) -> Result<Self> {
        let PreparedConfig {
            config,
            target,
            authority,
            path,
            tls,
        } = PreparedConfig::new(config)?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                target,
                authority,
                path,
                tls,
                connector,
                status: Mutex::new(Vec::new()),
                cycle: AsyncMutex::new(()),
                running: AtomicBool::new(false),
            }),
        })
    }

    /// Returns only completed real measurements. Untested outbounds are absent;
    /// snapshots remain the last measured state after the scheduler stops.
    pub fn snapshot(&self) -> ObservationResult {
        ObservationResult {
            status: self
                .inner
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Acquire)
    }

    /// Perform and publish one attempt. Cancellation returns ProbeCancelled
    /// without turning a shutdown into a failed health observation.
    pub async fn probe_once(&self, tag: &str, cancel: &CancellationToken) -> Result<ProbeReport> {
        ensure!(
            !tag.is_empty(),
            "observatory outbound tag must not be empty"
        );
        let _guard = tokio::select! { biased; _ = cancel.cancelled() => return Err(ProbeCancelled.into()), guard = self.inner.cycle.lock() => guard };
        let report = self.measure(tag.to_owned(), cancel).await?;
        self.publish(&report);
        Ok(report)
    }

    /// One immediate round, pruning observations for tags no longer selected.
    /// The periodic scheduler additionally applies source interval spacing.
    pub async fn check(&self, tags: Vec<String>, cancel: &CancellationToken) -> Result<()> {
        self.check_inner(tags, cancel, false).await
    }

    /// Poll this future under the runtime's own task handle. Sequential mode
    /// sorts tags and sleeps after each probe; concurrent mode joins a complete
    /// bounded batch then sleeps once. Empty selectors mean no scheduled probes,
    /// matching the source Start rule. Selector errors stop this run and return
    /// to its owner; they do not mark all outbounds dead.
    pub async fn run(
        &self,
        selector: Arc<dyn OutboundSelector>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if self.inner.config.subject_selector.is_empty() {
            return Ok(());
        }
        ensure!(
            self.inner
                .running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "observatory scheduler is already running"
        );
        let _running = RunningGuard(&self.inner.running);
        loop {
            let tags = tokio::select! { biased; _ = cancel.cancelled() => return Ok(()), tags = selector.select(&self.inner.config.subject_selector) => tags.context("observatory outbound selection failed")? };
            let empty = tags.is_empty();
            if let Err(error) = self.check_inner(tags, cancel, true).await {
                if error.is::<ProbeCancelled>() {
                    return Ok(());
                }
                return Err(error);
            }
            if (empty || self.inner.config.enable_concurrency)
                && sleep_until_cancelled(self.inner.config.probe_interval, cancel).await
            {
                return Ok(());
            }
        }
    }

    async fn check_inner(
        &self,
        mut tags: Vec<String>,
        cancel: &CancellationToken,
        periodic: bool,
    ) -> Result<()> {
        let _guard = tokio::select! { biased; _ = cancel.cancelled() => return Err(ProbeCancelled.into()), guard = self.inner.cycle.lock() => guard };
        ensure!(
            tags.iter().all(|tag| !tag.is_empty()),
            "observatory selected an empty outbound tag"
        );
        let mut seen = HashSet::new();
        tags.retain(|tag| seen.insert(tag.clone()));
        if !self.inner.config.enable_concurrency {
            tags.sort();
        }
        self.inner
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|status| seen.contains(&status.outbound_tag));
        if !self.inner.config.enable_concurrency {
            for tag in tags {
                let report = self.measure(tag, cancel).await?;
                self.publish(&report);
                if periodic && sleep_until_cancelled(self.inner.config.probe_interval, cancel).await
                {
                    return Err(ProbeCancelled.into());
                }
            }
            return Ok(());
        }
        let mut pending = tags.into_iter();
        let mut tasks = JoinSet::new();
        loop {
            while tasks.len() < self.inner.config.max_concurrency {
                let Some(tag) = pending.next() else { break };
                let observer = self.clone();
                let cancel = cancel.clone();
                tasks.spawn(async move { observer.measure(tag, &cancel).await });
            }
            if tasks.is_empty() {
                break;
            }
            let completed = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(ProbeCancelled.into());
                },
                completed = tasks.join_next() => completed,
            };
            let report = completed
                .expect("nonempty probe task set")
                .context("observatory probe worker failed")??;
            self.publish(&report);
        }
        Ok(())
    }

    async fn measure(&self, tag: String, cancel: &CancellationToken) -> Result<ProbeReport> {
        let start = Instant::now();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ProbeCancelled.into()),
            result = tokio::time::timeout(self.inner.config.timeout, self.http_probe(&tag)) => result.context("observatory HTTP probe timed out").and_then(|result| result),
        };
        let completed_at = unix_seconds();
        Ok(match result {
            Ok(code) => ProbeReport {
                outbound_tag: tag,
                alive: true,
                delay_ms: millis(start.elapsed()),
                last_error_reason: String::new(),
                completed_at,
                http_status: Some(code),
            },
            Err(error) => ProbeReport {
                last_error_reason: format!(
                    "the outbound {tag} is dead: GET request failed: {error:#}"
                ),
                outbound_tag: tag,
                alive: false,
                delay_ms: 0,
                completed_at,
                http_status: None,
            },
        })
    }

    async fn http_probe(&self, tag: &str) -> Result<u16> {
        let mut stream = self
            .inner
            .connector
            .connect(tag, &self.inner.target)
            .await
            .context("outbound connector failed")?;
        if let Some(tls) = &self.inner.tls {
            stream = tls.connect(stream, &self.inner.target.host).await?;
        }
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            self.inner.path, self.inner.authority
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        // Closing after headers matches ordinary observer.go. Do not wait for a
        // Content-Length body: that would implement burst GET timing instead.
        read_final_response(&mut stream).await
    }

    fn publish(&self, report: &ProbeReport) {
        let mut status = self
            .inner
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = status
            .iter()
            .position(|status| status.outbound_tag == report.outbound_tag)
            .unwrap_or_else(|| {
                status.push(OutboundStatus {
                    outbound_tag: report.outbound_tag.clone(),
                    ..Default::default()
                });
                status.len() - 1
            });
        let status = &mut status[index];
        status.last_try_time = report.completed_at;
        status.alive = report.alive;
        if report.alive {
            status.delay = report.delay_ms;
            status.last_seen_time = report.completed_at;
            status.last_error_reason.clear();
        } else {
            status.delay = FAILED_DELAY_MS;
            status
                .last_error_reason
                .clone_from(&report.last_error_reason);
        }
    }
}

#[tonic::async_trait]
impl ObservationProvider for Observer {
    async fn get_observation(&self) -> std::result::Result<ObservationResult, tonic::Status> {
        Ok(self.snapshot())
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
fn millis(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
}

async fn sleep_until_cancelled(duration: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! { biased; _ = cancel.cancelled() => true, _ = tokio::time::sleep(duration) => false }
}

async fn read_final_response(stream: &mut BoxStream) -> Result<u16> {
    let mut buffer = Vec::new();
    let mut consumed = 0usize;
    let mut interim = 0;
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
        let mut response = httparse::Response::new(&mut headers);
        match response
            .parse(&buffer)
            .context("invalid observatory HTTP response")?
        {
            httparse::Status::Complete(length) => {
                ensure!(
                    length + consumed <= MAX_HEADER_BYTES,
                    "observatory response headers exceed limit"
                );
                let code = response.code.context("HTTP response lacks status")?;
                ensure!((100..=999).contains(&code), "invalid HTTP status");
                validate_framing(response.headers)?;
                if (100..200).contains(&code) && code != 101 {
                    interim += 1;
                    ensure!(
                        interim <= MAX_INTERIM_RESPONSES,
                        "too many interim HTTP responses"
                    );
                    consumed += length;
                    buffer.drain(..length);
                    continue;
                }
                return Ok(code);
            }
            httparse::Status::Partial => {
                ensure!(
                    buffer.len() + consumed < MAX_HEADER_BYTES,
                    "observatory response headers exceed limit"
                );
                let mut bytes = [0; 2048];
                let maximum = bytes.len().min(MAX_HEADER_BYTES - buffer.len() - consumed);
                let read = stream.read(&mut bytes[..maximum]).await?;
                ensure!(read != 0, "EOF before complete observatory HTTP response");
                buffer.extend_from_slice(&bytes[..read]);
            }
        }
    }
}

fn validate_framing(headers: &[httparse::Header<'_>]) -> Result<()> {
    let mut length = None;
    let mut transfer_encoding = false;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let value = std::str::from_utf8(header.value)?.trim();
            ensure!(
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                "invalid HTTP Content-Length"
            );
            let value: u64 = value.parse().context("invalid HTTP Content-Length")?;
            ensure!(value <= i64::MAX as u64, "HTTP Content-Length overflow");
            if let Some(previous) = length {
                ensure!(previous == value, "conflicting HTTP Content-Length headers");
            }
            length = Some(value);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            ensure!(
                !transfer_encoding && header.value.eq_ignore_ascii_case(b"chunked"),
                "unsupported HTTP Transfer-Encoding"
            );
            transfer_encoding = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls::{TlsCertificate, TlsServer};
    use std::{collections::VecDeque, sync::atomic::AtomicUsize};
    use tokio::{io::duplex, sync::Notify, task::JoinHandle};

    enum Script {
        Reply {
            bytes: Vec<u8>,
            delay: Duration,
            tls: Option<TlsServer>,
        },
        Fail,
        ConnectStall,
    }

    fn response(code: u16) -> Script {
        Script::Reply { bytes: format!("HTTP/1.1 {code} fixture\r\nContent-Length: 9000000\r\nLocation: https://never-follow.invalid/\r\n\r\n").into_bytes(), delay: Duration::ZERO, tls: None }
    }

    struct Active {
        count: Arc<AtomicUsize>,
    }
    impl Drop for Active {
        fn drop(&mut self) {
            self.count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct MockConnector {
        scripts: Mutex<VecDeque<Script>>,
        calls: Mutex<Vec<(String, ProbeTarget, Instant)>>,
        requests: Arc<Mutex<Vec<String>>>,
        tasks: Mutex<Vec<JoinHandle<()>>>,
        active: Arc<AtomicUsize>,
        peak: AtomicUsize,
        called: Notify,
    }

    impl MockConnector {
        fn new(scripts: Vec<Script>) -> Arc<Self> {
            Arc::new(Self {
                scripts: Mutex::new(scripts.into()),
                calls: Mutex::new(Vec::new()),
                requests: Arc::new(Mutex::new(Vec::new())),
                tasks: Mutex::new(Vec::new()),
                active: Arc::new(AtomicUsize::new(0)),
                peak: AtomicUsize::new(0),
                called: Notify::new(),
            })
        }

        async fn calls_at_least(&self, count: usize) {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let notified = self.called.notified();
                    if self.calls.lock().unwrap().len() >= count {
                        break;
                    }
                    notified.await;
                }
            })
            .await
            .expect("probe connector was not called");
        }

        async fn finish(&self) {
            let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
            for task in tasks {
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("probe did not close fixture connection")
                    .unwrap();
            }
        }
    }

    impl Drop for MockConnector {
        fn drop(&mut self) {
            for task in self.tasks.get_mut().unwrap() {
                task.abort();
            }
        }
    }

    #[tonic::async_trait]
    impl ProbeConnector for MockConnector {
        async fn connect(&self, tag: &str, target: &ProbeTarget) -> Result<BoxStream> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let _active = Active {
                count: Arc::clone(&self.active),
            };
            self.calls
                .lock()
                .unwrap()
                .push((tag.into(), target.clone(), Instant::now()));
            self.called.notify_one();
            let script = self
                .scripts
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| response(204));
            match script {
                Script::Fail => bail!("fixture outbound route unavailable"),
                Script::ConnectStall => std::future::pending::<Result<BoxStream>>().await,
                Script::Reply { bytes, delay, tls } => {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let (client_io, server_io) = duplex(4096);
                    let requests = Arc::clone(&self.requests);
                    let task = tokio::spawn(async move {
                        let mut stream: BoxStream = if let Some(tls) = tls {
                            let Ok(stream) = tls.accept(Box::new(server_io)).await else {
                                return;
                            };
                            stream
                        } else {
                            Box::new(server_io)
                        };
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            if stream.read_exact(&mut byte).await.is_err() {
                                return;
                            }
                            request.push(byte[0]);
                        }
                        requests
                            .lock()
                            .unwrap()
                            .push(String::from_utf8(request).unwrap());
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                        if stream.flush().await.is_err() {
                            return;
                        }
                        // No response body is sent. Ordinary probes must close
                        // immediately after headers, even with a huge length.
                        let mut closed = [0];
                        let _ = stream.read(&mut closed).await;
                    });
                    self.tasks.lock().unwrap().push(task);
                    Ok(Box::new(client_io))
                }
            }
        }
    }

    fn config() -> ObservatoryConfig {
        ObservatoryConfig {
            probe_url: "http://probe.example:8080/a%2Fb?fixture=yes".into(),
            timeout: Duration::from_millis(150),
            probe_interval: Duration::from_millis(20),
            ..Default::default()
        }
    }

    #[test]
    fn source_defaults_duration_units_and_url_validation() {
        let wire = crate::api::observatory::observation_wire::Config {
            subject_selector: vec!["prefix".into()],
            probe_url: String::new(),
            probe_interval: 37_000_000,
            enable_concurrency: true,
        };
        let decoded = ObservatoryConfig::from_wire(&wire).unwrap();
        assert_eq!(decoded.probe_interval, Duration::from_millis(37));
        assert_eq!(decoded.timeout, Duration::from_secs(5));
        assert_eq!(decoded.probe_url, DEFAULT_PROBE_URL);
        assert!(decoded.enable_concurrency);
        assert_eq!(
            ObservatoryConfig::default().probe_interval,
            Duration::from_secs(10)
        );
        let bad = crate::api::observatory::observation_wire::Config {
            probe_interval: -1,
            ..wire
        };
        assert!(ObservatoryConfig::from_wire(&bad).is_err());
        for url in [
            "ftp://example.test",
            "http://user@example.test",
            "http://example.test:0",
            "http://example.test:65536",
            "http://example.test:noport",
            "http://example.test/#fragment",
            "http://example.test/\r\ninjection",
        ] {
            assert!(
                Observer::new(
                    ObservatoryConfig {
                        probe_url: url.into(),
                        ..config()
                    },
                    MockConnector::new(Vec::new())
                )
                .is_err(),
                "accepted {url:?}"
            );
        }
    }

    #[tokio::test]
    async fn every_valid_final_status_is_alive_without_redirect_or_body_consumption() {
        let connector = MockConnector::new(
            [200, 204, 302, 404, 500, 503]
                .into_iter()
                .map(response)
                .collect(),
        );
        let observer = Observer::new(config(), connector.clone()).unwrap();
        assert!(observer.snapshot().status.is_empty());
        for code in [200, 204, 302, 404, 500, 503] {
            let report = observer
                .probe_once("chosen-outbound", &CancellationToken::new())
                .await
                .unwrap();
            assert!(report.alive, "status {code} unexpectedly failed");
            assert_eq!(report.http_status, Some(code));
            assert!(report.last_error_reason.is_empty());
        }
        connector.finish().await;
        let calls = connector.calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        assert!(calls.iter().all(|(tag, target, _)| tag == "chosen-outbound"
            && target
                == &ProbeTarget {
                    host: "probe.example".into(),
                    port: 8080,
                    https: false
                }));
        let requests = connector.requests.lock().unwrap();
        assert!(requests.iter().all(|request| {
            request.starts_with("GET /a%2Fb?fixture=yes HTTP/1.1\r\nHost: probe.example:8080\r\n")
        }));
        let status = &observer.snapshot().status[0];
        assert!(status.alive);
        assert!(status.last_seen_time > 0);
        assert_eq!(status.last_seen_time, status.last_try_time);
        assert!(status.health_ping.is_none());
    }

    #[tokio::test]
    async fn interim_headers_are_skipped_and_101_is_a_final_response() {
        let connector = MockConnector::new(vec![
            Script::Reply { bytes: b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 204 Done\r\n\r\n".to_vec(), delay: Duration::ZERO, tls: None },
            Script::Reply { bytes: b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: fixture\r\nConnection: Upgrade\r\n\r\n".to_vec(), delay: Duration::ZERO, tls: None },
        ]);
        let observer = Observer::new(config(), connector.clone()).unwrap();
        assert_eq!(
            observer
                .probe_once("a", &CancellationToken::new())
                .await
                .unwrap()
                .http_status,
            Some(204)
        );
        assert_eq!(
            observer
                .probe_once("a", &CancellationToken::new())
                .await
                .unwrap()
                .http_status,
            Some(101)
        );
        connector.finish().await;
    }

    #[tokio::test]
    async fn malformed_headers_and_oversize_are_dead_not_synthetic_successes() {
        let malformed = vec![
            b"not an HTTP response\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec(),
            format!(
                "HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n",
                "x".repeat(MAX_HEADER_BYTES)
            )
            .into_bytes(),
            format!(
                "{}HTTP/1.1 204 Done\r\n\r\n",
                "HTTP/1.1 103 Hint\r\n\r\n".repeat(MAX_INTERIM_RESPONSES + 1)
            )
            .into_bytes(),
        ];
        let count = malformed.len();
        let connector = MockConnector::new(
            malformed
                .into_iter()
                .map(|bytes| Script::Reply {
                    bytes,
                    delay: Duration::ZERO,
                    tls: None,
                })
                .collect(),
        );
        let observer = Observer::new(config(), connector.clone()).unwrap();
        for _ in 0..count {
            let report = observer
                .probe_once("bad", &CancellationToken::new())
                .await
                .unwrap();
            assert!(!report.alive);
            assert!(!report.last_error_reason.is_empty());
            let status = &observer.snapshot().status[0];
            assert_eq!(status.delay, FAILED_DELAY_MS);
            assert_eq!(status.last_seen_time, 0);
        }
        connector.finish().await;
    }

    #[test]
    fn source_status_transition_preserves_last_seen_and_clears_recovered_error() {
        let observer = Observer::new(config(), MockConnector::new(Vec::new())).unwrap();
        let mut report = ProbeReport {
            outbound_tag: "tag".into(),
            alive: true,
            delay_ms: 42,
            last_error_reason: String::new(),
            completed_at: 111,
            http_status: Some(204),
        };
        observer.publish(&report);
        report.alive = false;
        report.completed_at = 222;
        report.last_error_reason = "real connection failure".into();
        observer.publish(&report);
        let status = &observer.snapshot().status[0];
        assert_eq!(
            (
                status.alive,
                status.delay,
                status.last_seen_time,
                status.last_try_time
            ),
            (false, 99_999_999, 111, 222)
        );
        assert_eq!(status.last_error_reason, "real connection failure");
        report.alive = true;
        report.completed_at = 333;
        report.delay_ms = 17;
        observer.publish(&report);
        let status = &observer.snapshot().status[0];
        assert_eq!(
            (
                status.alive,
                status.delay,
                status.last_seen_time,
                status.last_try_time
            ),
            (true, 17, 333, 333)
        );
        assert!(status.last_error_reason.is_empty());
    }

    #[tokio::test]
    async fn connector_errors_and_timeouts_publish_real_failure_causes() {
        let connector = MockConnector::new(vec![Script::Fail, Script::ConnectStall]);
        let observer = Observer::new(
            ObservatoryConfig {
                timeout: Duration::from_millis(20),
                ..config()
            },
            connector.clone(),
        )
        .unwrap();
        let failed = observer
            .probe_once("route", &CancellationToken::new())
            .await
            .unwrap();
        assert!(!failed.alive);
        assert!(
            failed
                .last_error_reason
                .contains("fixture outbound route unavailable")
        );
        let timed_out = observer
            .probe_once("route", &CancellationToken::new())
            .await
            .unwrap();
        assert!(!timed_out.alive);
        assert!(timed_out.last_error_reason.contains("timed out"));
        assert_eq!(connector.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_retains_previous_health_and_drops_pending_connector() {
        let connector = MockConnector::new(vec![response(204), Script::ConnectStall]);
        let observer = Observer::new(config(), connector.clone()).unwrap();
        observer
            .probe_once("tag", &CancellationToken::new())
            .await
            .unwrap();
        connector.finish().await;
        let previous = observer.snapshot();
        let cancel = CancellationToken::new();
        let task_observer = observer.clone();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move { task_observer.probe_once("tag", &task_cancel).await });
        connector.calls_at_least(2).await;
        cancel.cancel();
        assert!(task.await.unwrap().unwrap_err().is::<ProbeCancelled>());
        assert_eq!(observer.snapshot(), previous);
        assert_eq!(connector.active.load(Ordering::SeqCst), 0);
        let calls = connector.calls.lock().unwrap().len();
        assert!(
            observer
                .probe_once("new", &cancel)
                .await
                .unwrap_err()
                .is::<ProbeCancelled>()
        );
        assert_eq!(connector.calls.lock().unwrap().len(), calls);
    }

    #[tokio::test]
    async fn observed_latency_includes_connector_and_provider_exposes_same_measurement() {
        let connector = MockConnector::new(vec![Script::Reply {
            bytes: b"HTTP/1.1 204 Done\r\n\r\n".to_vec(),
            delay: Duration::from_millis(20),
            tls: None,
        }]);
        let observer = Observer::new(config(), connector.clone()).unwrap();
        let report = observer
            .probe_once("slow", &CancellationToken::new())
            .await
            .unwrap();
        assert!(report.alive);
        assert!(report.delay_ms >= 20);
        let provider: Arc<dyn ObservationProvider> = Arc::new(observer.clone());
        assert_eq!(
            provider.get_observation().await.unwrap(),
            observer.snapshot()
        );
        assert_eq!(observer.snapshot().status[0].delay, report.delay_ms);
        connector.finish().await;
    }

    #[tokio::test]
    async fn check_sorts_sequential_tags_and_prunes_removed_outbounds() {
        let connector = MockConnector::new(Vec::new());
        let observer = Observer::new(config(), connector.clone()).unwrap();
        observer
            .check(
                vec!["b".into(), "a".into(), "b".into()],
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            observer
                .snapshot()
                .status
                .iter()
                .map(|status| status.outbound_tag.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        observer
            .check(vec!["b".into()], &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(observer.snapshot().status.len(), 1);
        assert_eq!(observer.snapshot().status[0].outbound_tag, "b");
        observer
            .check(Vec::new(), &CancellationToken::new())
            .await
            .unwrap();
        assert!(observer.snapshot().status.is_empty());
        connector.finish().await;
    }

    #[tokio::test]
    async fn concurrency_is_bounded_and_cancelled_children_are_owned() {
        let scripts = (0..5)
            .map(|_| Script::Reply {
                bytes: b"HTTP/1.1 204 Done\r\n\r\n".to_vec(),
                delay: Duration::from_millis(15),
                tls: None,
            })
            .collect();
        let connector = MockConnector::new(scripts);
        let cfg = ObservatoryConfig {
            enable_concurrency: true,
            max_concurrency: 2,
            ..config()
        };
        let observer = Observer::new(cfg.clone(), connector.clone()).unwrap();
        observer
            .check(
                (0..5).map(|i| i.to_string()).collect(),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(connector.peak.load(Ordering::SeqCst), 2);
        assert_eq!(observer.snapshot().status.len(), 5);
        connector.finish().await;
        let connector = MockConnector::new(vec![Script::ConnectStall, Script::ConnectStall]);
        let observer = Observer::new(cfg, connector.clone()).unwrap();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_observer = observer.clone();
        let task = tokio::spawn(async move {
            task_observer
                .check(vec!["a".into(), "b".into(), "c".into()], &task_cancel)
                .await
        });
        connector.calls_at_least(2).await;
        cancel.cancel();
        assert!(task.await.unwrap().unwrap_err().is::<ProbeCancelled>());
        assert_eq!(connector.active.load(Ordering::SeqCst), 0);
        assert!(observer.snapshot().status.is_empty());
        assert_eq!(connector.calls.lock().unwrap().len(), 2);
    }

    struct Selector {
        tags: Vec<String>,
        fails: bool,
        calls: AtomicUsize,
    }
    #[tonic::async_trait]
    impl OutboundSelector for Selector {
        async fn select(&self, selectors: &[String]) -> Result<Vec<String>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(selectors, ["prefix"]);
            if self.fails {
                bail!("fixture selector failed");
            }
            Ok(self.tags.clone())
        }
    }

    #[tokio::test]
    async fn periodic_sequential_spacing_and_scheduler_lifecycle() {
        let connector = MockConnector::new(Vec::new());
        let observer = Observer::new(
            ObservatoryConfig {
                subject_selector: vec!["prefix".into()],
                ..config()
            },
            connector.clone(),
        )
        .unwrap();
        let selector = Arc::new(Selector {
            tags: vec!["b".into(), "a".into()],
            fails: false,
            calls: AtomicUsize::new(0),
        });
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_observer = observer.clone();
        let task_selector = selector.clone();
        let task =
            tokio::spawn(async move { task_observer.run(task_selector, &task_cancel).await });
        connector.calls_at_least(2).await;
        assert!(observer.is_running());
        assert!(
            observer
                .run(selector, &CancellationToken::new())
                .await
                .is_err()
        );
        cancel.cancel();
        task.await.unwrap().unwrap();
        assert!(!observer.is_running());
        {
            let calls = connector.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(
                (&calls[0].0, &calls[1].0),
                (&"a".to_owned(), &"b".to_owned())
            );
            assert!(calls[1].2.duration_since(calls[0].2) >= Duration::from_millis(20));
        }
        connector.finish().await;
    }

    #[tokio::test]
    async fn disabled_or_failed_selector_does_not_create_healthy_entries() {
        let connector = MockConnector::new(Vec::new());
        let observer = Observer::new(config(), connector.clone()).unwrap();
        let selector = Arc::new(Selector {
            tags: vec!["a".into()],
            fails: true,
            calls: AtomicUsize::new(0),
        });
        observer
            .run(selector.clone(), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(selector.calls.load(Ordering::SeqCst), 0);
        let observer = Observer::new(
            ObservatoryConfig {
                subject_selector: vec!["prefix".into()],
                ..config()
            },
            connector.clone(),
        )
        .unwrap();
        assert!(
            observer
                .run(selector, &CancellationToken::new())
                .await
                .unwrap_err()
                .to_string()
                .contains("selection failed")
        );
        assert!(!observer.is_running());
        assert!(observer.snapshot().status.is_empty());
        assert!(connector.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn https_through_connector_verifies_trust_and_server_name() {
        for valid in [true, false] {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["probe.example".into()]).unwrap();
            let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
            let server = TlsServer::new(&TlsSettings {
                alpn: vec!["http/1.1".into()],
                certificates: vec![TlsCertificate {
                    certificate: certificate.clone(),
                    key: signing_key
                        .serialize_pem()
                        .lines()
                        .map(str::to_owned)
                        .collect(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
            let connector = MockConnector::new(vec![Script::Reply {
                bytes: b"HTTP/1.1 204 Done\r\n\r\n".to_vec(),
                delay: Duration::ZERO,
                tls: Some(server),
            }]);
            let cfg = ObservatoryConfig {
                probe_url: "https://probe.example/generate_204".into(),
                tls: TlsSettings {
                    server_name: if valid {
                        String::new()
                    } else {
                        "wrong.example".into()
                    },
                    disable_system_root: true,
                    certificates: vec![TlsCertificate {
                        certificate,
                        usage: "verify".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..config()
            };
            let observer = Observer::new(cfg, connector.clone()).unwrap();
            let report = observer
                .probe_once("tls-route", &CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(report.alive, valid);
            assert!(connector.calls.lock().unwrap()[0].1.https);
            connector.finish().await;
        }
    }
}
