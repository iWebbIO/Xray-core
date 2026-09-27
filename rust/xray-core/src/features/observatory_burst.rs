// P31 burst_observatory: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]

//! Burst observatory, ported from Go `app/observatory/burst`
//! (`burstobserver.go`, `healthping.go`, `healthping_result.go`, `ping.go`)
//! plus the JSON layer `infra/conf/observatory.go` (BurstObservatoryConfig)
//! and `infra/conf/router_strategy.go` (HealthCheckSettings).
//!
//! The observer probes outbounds selected through an
//! [`OutboundSelector`](super::observatory::OutboundSelector) callback over
//! the shared
//! [`ProbeConnector`](super::observatory::ProbeConnector) seam of the
//! ordinary observer module; this file never edits that module. Probes are
//! HTTP requests to the configured destination (Go `pingClient.MeasureDelay`:
//! a GET also drains the response body before the clock stops) or, as a native
//! extension, connection-establishment-only checks. In-flight probe workers
//! are bounded by `max_concurrency`; Go schedules one unbounded timer per
//! sample, so the cap is a Rust-side bound like the ordinary observer's.
//!
//! Samples feed per-tag ring buffers (`HealthPingRtts`) of the last
//! `sampling` RTTs with a validity of `interval * sampling * 2`, exactly as
//! `healthping_result.go` computes them. The published record is the Go
//! Observatory protobuf shape: `alive` is `all != fail`, `delay` is the
//! average in milliseconds, `last_error_reason` is empty and
//! `last_seen_time`/`last_try_time` are 0, with the health-ping statistics in
//! nanoseconds - the values `burstobserver.go createResult` produces.
//!
//! Rejected Go options: `pingConfig.connectivity` (Go's direct, non-outbound
//! network-down check has no dialer in this architecture and is refused with
//! a named error instead of silently ignored) and malformed duration strings
//! (Go `duration.Duration` accepts only strings). `GetWithCache` is not
//! ported (no Go caller outside the package); `get()` always computes fresh
//! statistics. Scheduled rounds cancel the previous unfinished round, and
//! cleanup removes results for tags the selector no longer returns, both as
//! in `healthping.go`. Selector errors are logged and the round skipped; the
//! scheduler keeps running, unlike the ordinary observer's fatal policy.
//!
//! Other bounded differences: results are reported in tag order (Go iterates
//! a map, unspecified order); chunked GET bodies drain to connection close
//! instead of being chunk-decoded; whitespace-only `httpMethod` selects the
//! default instead of failing every probe; `HealthPingRtts` with capacity 0
//! ignores puts where Go would panic. Browser `nav` header impersonation is
//! not performed; probes send `Accept: */*` like the ordinary observer.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use http::Uri;
use rand::Rng;
use serde::{Deserialize, Serialize};
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
        observation_wire::{
            self as wire, HealthPingMeasurementResult, ObservationResult, OutboundStatus,
        },
    },
    features::observatory::{OutboundSelector, ProbeConnector, ProbeTarget},
    transport::{
        BoxStream,
        tls::{TlsClient, TlsSettings},
    },
};

/// Go `healthping.go` NewHealthPing defaults.
pub const DEFAULT_PING_DESTINATION: &str = "https://connectivitycheck.gstatic.com/generate_204";
pub const DEFAULT_HTTP_METHOD: &str = "HEAD";
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
pub const MIN_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_SAMPLING: usize = 10;
/// Rust-side bound on concurrent probe workers. Go timers are unbounded; the
/// ordinary Rust observer defaults to the same cap.
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;
/// Go `burst.go` RTT sentinels, nanoseconds.
pub const RTT_FAILED: i64 = i64::MAX;
pub const RTT_UNTESTED: i64 = i64::MAX - 1;
pub const RTT_UNQUALIFIED: i64 = i64::MAX - 2;

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADER_FIELDS: usize = 128;
const MAX_INTERIM_RESPONSES: usize = 8;
const NANOS_PER_MILLI: i64 = 1_000_000;

/// Which measurement a probe performs. Go's burst observer only performs the
/// URL HTTP ping; `ConnectOnly` is a native extension reusing the same seam.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BurstProbeType {
    /// Establish the outbound connection to the destination and measure
    /// establishment only; no TLS handshake, no HTTP exchange.
    ConnectOnly,
    /// Go `pingClient.MeasureDelay`: HTTP request through the outbound; a GET
    /// drains the response body before the clock stops. Default, as in Go.
    #[default]
    Url,
}

/// `infra/conf/router_strategy.go` HealthCheckSettings JSON. Durations are Go
/// `duration.Duration` strings; JSON numbers are rejected, as in Go.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthCheckSettings {
    pub destination: String,
    pub connectivity: String,
    /// `None` is Go's missing field (zero duration, default applied later);
    /// an explicit invalid or empty string is a parse error, as in Go.
    pub interval: Option<String>,
    pub sampling: i32,
    pub timeout: Option<String>,
    pub http_method: String,
}

/// `infra/conf/observatory.go` BurstObservatoryConfig JSON.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct BurstObservatoryConfig {
    pub subject_selector: Vec<String>,
    pub ping_config: Option<HealthCheckSettings>,
}

impl BurstObservatoryConfig {
    /// Single JSON entry point the config layer calls.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid burst observatory configuration")
    }

    /// Go BurstObservatoryConfig.Build: pingConfig is mandatory.
    pub fn build(&self) -> Result<BurstSettings> {
        let Some(ping) = self.ping_config.as_ref() else {
            bail!("BurstObservatory requires a valid pingConfig");
        };
        let interval = match ping.interval.as_deref() {
            None => 0,
            Some(text) => crate::router::balancer::parse_duration(text)
                .context("invalid burst pingConfig interval")?,
        };
        let timeout = match ping.timeout.as_deref() {
            None => 0,
            Some(text) => crate::router::balancer::parse_duration(text)
                .context("invalid burst pingConfig timeout")?,
        };
        BurstSettings::from_raw(
            RawPingConfig {
                destination: ping.destination.clone(),
                connectivity: ping.connectivity.clone(),
                interval,
                sampling: ping.sampling,
                timeout,
                http_method: ping.http_method.clone(),
            },
            self.subject_selector.clone(),
        )
    }
}

/// Raw (unclamped) values shared by the JSON and protobuf entry points.
struct RawPingConfig {
    destination: String,
    connectivity: String,
    interval: i64,
    sampling: i32,
    timeout: i64,
    http_method: String,
}

/// Validated runtime settings for the burst observer, after Go
/// `NewHealthPing` clamping.
#[derive(Clone, Debug)]
pub struct BurstSettings {
    pub subject_selector: Vec<String>,
    pub destination: String,
    /// Refresh cadence granularity; at least `MIN_INTERVAL`.
    pub interval: Duration,
    /// Recent samples kept per tag; at least 1.
    pub sampling: usize,
    pub timeout: Duration,
    pub http_method: String,
    pub max_concurrency: usize,
    pub probe_type: BurstProbeType,
    pub tls: TlsSettings,
}

impl BurstSettings {
    fn from_raw(raw: RawPingConfig, subject_selector: Vec<String>) -> Result<Self> {
        ensure!(
            raw.connectivity.trim().is_empty(),
            "burst pingConfig connectivity check is not supported: it requires a direct \
             non-outbound dialer; clear \"connectivity\" to disable the network-down check"
        );
        let mut destination = raw.destination.trim().to_owned();
        if destination.is_empty() {
            destination = DEFAULT_PING_DESTINATION.into();
        }
        // NewHealthPing: 0 -> 1m, below 10s -> 10s (with a warning).
        let interval = if raw.interval == 0 {
            DEFAULT_INTERVAL
        } else if raw.interval < MIN_INTERVAL.as_nanos() as i64 {
            tracing::warn!("burst health check interval is too small, 10s is applied");
            MIN_INTERVAL
        } else {
            Duration::from_nanos(raw.interval as u64)
        };
        let timeout = if raw.timeout <= 0 {
            DEFAULT_TIMEOUT
        } else {
            Duration::from_nanos(raw.timeout as u64)
        };
        let sampling = if raw.sampling <= 0 {
            DEFAULT_SAMPLING
        } else {
            raw.sampling as usize
        };
        let http_method = raw.http_method.trim().to_owned();
        let http_method = if http_method.is_empty() {
            DEFAULT_HTTP_METHOD.into()
        } else {
            http_method
        };
        ensure!(
            valid_http_token(&http_method),
            "invalid burst pingConfig httpMethod {http_method:?}"
        );
        Ok(Self {
            subject_selector,
            destination,
            interval,
            sampling,
            timeout,
            http_method,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            probe_type: BurstProbeType::default(),
            tls: TlsSettings::default(),
        })
    }

    /// Protobuf entry point (`burst.Config`); durations are nanosecond int64s.
    /// A missing ping_config selects every default, as Go's NewHealthPing does
    /// for a nil config.
    pub fn from_wire(config: &wire::burst::Config) -> Result<Self> {
        let raw = match config.ping_config.as_ref() {
            Some(ping) => RawPingConfig {
                destination: ping.destination.clone(),
                connectivity: ping.connectivity.clone(),
                interval: ping.interval,
                sampling: ping.sampling_count,
                timeout: ping.timeout,
                http_method: ping.http_method.clone(),
            },
            None => RawPingConfig {
                destination: String::new(),
                connectivity: String::new(),
                interval: 0,
                sampling: 0,
                timeout: 0,
                http_method: String::new(),
            },
        };
        Self::from_raw(raw, config.subject_selector.clone())
    }

    /// Check URL, TLS settings and runtime bounds without opening a socket.
    pub fn validate(&self) -> Result<()> {
        PreparedPingDestination::new(self).map(|_| ())
    }

    /// Go StartScheduler ticker period: interval * sampling.
    pub fn refresh_interval(&self) -> Duration {
        scaled_duration(self.interval, self.sampling)
    }

    /// Go PutResult sample validity: interval * sampling * 2.
    pub fn validity(&self) -> Duration {
        scaled_duration(self.interval, self.sampling.saturating_mul(2))
    }
}

fn scaled_duration(duration: Duration, factor: usize) -> Duration {
    let nanos = (duration.as_nanos().saturating_mul(factor as u128)).min(u64::MAX as u128);
    Duration::from_nanos(nanos as u64)
}

fn valid_http_token(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Port of Go `HealthPingStats`; durations are nanosecond int64s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthPingStats {
    pub all: usize,
    pub fail: usize,
    pub deviation: i64,
    pub average: i64,
    pub max: i64,
    pub min: i64,
}

#[derive(Clone, Copy)]
struct PingRtt {
    time: Instant,
    value: i64,
}

/// Port of Go `HealthPingRTTS`: a fixed-capacity ring of the most recent RTT
/// samples, with a per-sample validity window.
pub struct HealthPingRtts {
    capacity: usize,
    validity: Duration,
    rtts: Vec<PingRtt>,
    index: isize,
}

impl HealthPingRtts {
    /// Go NewHealthPingResult. A capacity of 0 ignores puts (Go panics on the
    /// first put; the settings path always passes at least 1).
    pub fn new(capacity: usize, validity: Duration) -> Self {
        Self {
            capacity,
            validity,
            rtts: vec![
                PingRtt {
                    time: Instant::now(),
                    value: RTT_UNTESTED,
                };
                capacity
            ],
            index: -1,
        }
    }

    /// Go HealthPingRTTS.Put.
    pub fn put(&mut self, rtt: i64) {
        if self.capacity == 0 {
            return;
        }
        self.index = self.calc_index(1);
        self.rtts[self.index as usize] = PingRtt {
            time: Instant::now(),
            value: rtt,
        };
    }

    fn calc_index(&self, step: isize) -> isize {
        let mut index = self.index + step;
        if index >= self.capacity as isize {
            index %= self.capacity as isize;
        }
        index
    }

    /// Fresh statistics (Go `Get`/`getStatistics`; `GetWithCache` has no Go
    /// caller and is not ported).
    pub fn get(&self) -> HealthPingStats {
        let now = Instant::now();
        let mut fail = 0usize;
        let mut max = 0i64;
        let mut min = RTT_FAILED;
        let mut sum = 0i64;
        let mut count = 0usize;
        let mut valid_rtts = Vec::new();
        for rtt in &self.rtts {
            if rtt.value == RTT_UNTESTED || now.saturating_duration_since(rtt.time) > self.validity
            {
                continue;
            }
            if rtt.value == RTT_FAILED {
                fail += 1;
                continue;
            }
            count += 1;
            sum += rtt.value;
            valid_rtts.push(rtt.value);
            if max < rtt.value {
                max = rtt.value;
            }
            if min > rtt.value {
                min = rtt.value;
            }
        }
        if count == 0 {
            return HealthPingStats {
                all: count + fail,
                fail,
                deviation: 0,
                average: 0,
                max: 0,
                min: 0,
            };
        }
        let average = sum / count as i64;
        let deviation = if count < 2 {
            // Not enough data for a standard deviation; Go assumes half the
            // average so single-round nodes do not always win selection.
            average / 2
        } else {
            let variance = valid_rtts
                .iter()
                .map(|&rtt| {
                    let difference = (rtt - average) as f64;
                    difference * difference
                })
                .sum::<f64>();
            (variance / count as f64).sqrt() as i64
        };
        HealthPingStats {
            all: count + fail,
            fail,
            deviation,
            average,
            max,
            min,
        }
    }
}

/// Per-probe outcome. `Delay(0)` matches Go's "network down" value, which is
/// never recorded; here it cannot occur because the connectivity URL is
/// rejected, so zero-elapsed probes are simply dropped.
enum ProbeOutcome {
    Delay(i64),
    Failed,
    Cancelled,
}

#[derive(Debug)]
pub struct BurstCancelled;

impl fmt::Display for BurstCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("burst observatory check cancelled")
    }
}
impl std::error::Error for BurstCancelled {}

struct PreparedPingDestination {
    target: ProbeTarget,
    authority: String,
    path: String,
    tls: Option<TlsClient>,
}

impl PreparedPingDestination {
    /// URL validation mirrors the ordinary observer: http/https only, no
    /// fragments, userinfo, scoped IPv6 or zero ports, with default ports.
    fn new(settings: &BurstSettings) -> Result<Self> {
        ensure!(
            !settings.timeout.is_zero(),
            "burst ping timeout must be nonzero"
        );
        ensure!(
            !settings.interval.is_zero(),
            "burst ping interval must be nonzero"
        );
        ensure!(
            settings.max_concurrency > 0,
            "burst maximum concurrency must be nonzero"
        );
        ensure!(
            !settings.destination.contains('#'),
            "burst ping destination URL fragments are unsupported"
        );
        let uri: Uri = settings
            .destination
            .parse()
            .context("invalid burst ping destination URL")?;
        let https = match uri.scheme_str().unwrap_or("").to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => bail!("burst ping destination URL must use http or https"),
        };
        let authority = uri
            .authority()
            .context("burst ping destination URL requires a host")?
            .as_str()
            .to_owned();
        ensure!(
            !authority.contains('@'),
            "burst ping destination URL userinfo is unsupported"
        );
        let raw_host = uri
            .host()
            .context("burst ping destination URL requires a host")?;
        let host = raw_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();
        ensure!(
            !host.is_empty() && !host.contains('%'),
            "invalid burst ping host; scoped IP addresses are unsupported"
        );
        let port_text = if authority.starts_with('[') {
            let end = authority
                .find(']')
                .context("invalid burst ping IPv6 authority")?;
            let suffix = &authority[end + 1..];
            if suffix.is_empty() {
                None
            } else {
                Some(
                    suffix
                        .strip_prefix(':')
                        .context("invalid burst ping authority")?,
                )
            }
        } else {
            authority.rsplit_once(':').map(|(_, port)| port)
        };
        let port = if let Some(port) = port_text {
            port.parse::<u16>()
                .context("invalid burst ping destination port")?
        } else if https {
            443
        } else {
            80
        };
        ensure!(port != 0, "burst ping destination port must be nonzero");
        let path = uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        let mut tls_settings = settings.tls.clone();
        let tls = if https {
            ensure!(
                tls_settings.alpn.is_empty() || tls_settings.alpn == ["http/1.1"],
                "burst ping probes require HTTP/1.1 ALPN"
            );
            tls_settings.alpn = vec!["http/1.1".into()];
            tls_settings.server_name(&host)?;
            Some(TlsClient::new(&tls_settings)?)
        } else {
            None
        };
        Ok(Self {
            target: ProbeTarget { host, port, https },
            authority,
            path,
            tls,
        })
    }
}

#[derive(Clone)]
pub struct BurstObserver {
    inner: Arc<Inner>,
}

struct Inner {
    settings: BurstSettings,
    destination: PreparedPingDestination,
    connector: Arc<dyn ProbeConnector>,
    /// Sorted by tag; Go iterates a map (unspecified order).
    results: Mutex<BTreeMap<String, HealthPingRtts>>,
    /// Serializes manual checks and scheduler rounds; concurrency is internal
    /// to one owned round, and a cancelled round releases promptly.
    cycle: AsyncMutex<()>,
    running: AtomicBool,
}

struct RunningGuard<'a>(&'a AtomicBool);
impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl BurstObserver {
    pub fn new(settings: BurstSettings, connector: Arc<dyn ProbeConnector>) -> Result<Self> {
        let destination = PreparedPingDestination::new(&settings)?;
        Ok(Self {
            inner: Arc::new(Inner {
                settings,
                destination,
                connector,
                results: Mutex::new(BTreeMap::new()),
                cycle: AsyncMutex::new(()),
                running: AtomicBool::new(false),
            }),
        })
    }

    /// Go Observer.GetObservation via createResult: only tags with recorded
    /// samples appear; `last_seen_time`/`last_try_time` stay 0 and
    /// `last_error_reason` stays empty, exactly as in Go.
    pub fn snapshot(&self) -> ObservationResult {
        let results = self
            .inner
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = results
            .iter()
            .map(|(tag, rtts)| {
                let stats = rtts.get();
                OutboundStatus {
                    alive: stats.all != stats.fail,
                    delay: stats.average / NANOS_PER_MILLI,
                    last_error_reason: String::new(),
                    outbound_tag: tag.clone(),
                    last_seen_time: 0,
                    last_try_time: 0,
                    health_ping: Some(HealthPingMeasurementResult {
                        all: stats.all as i64,
                        fail: stats.fail as i64,
                        deviation: stats.deviation,
                        average: stats.average,
                        max: stats.max,
                        min: stats.min,
                    }),
                }
            })
            .collect();
        ObservationResult { status }
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Acquire)
    }

    /// Go HealthPing.Check: one immediate round per tag, no jitter, no
    /// cleanup of removed tags.
    pub async fn check(&self, tags: Vec<String>, cancel: &CancellationToken) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let _guard = tokio::select! { biased; _ = cancel.cancelled() => return Err(BurstCancelled.into()), guard = self.inner.cycle.lock() => guard };
        self.do_check(&tags, Duration::ZERO, 1, cancel).await
    }

    /// Go Observer.Start with HealthPing.StartScheduler: an immediate
    /// one-round check, then every `interval * sampling` a fresh sampling
    /// round that cancels any unfinished previous round and cleans up removed
    /// tags. Poll this future under the runtime's own task handle.
    pub async fn run(
        &self,
        selector: Arc<dyn OutboundSelector>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if self.inner.settings.subject_selector.is_empty() {
            return Ok(());
        }
        ensure!(
            self.inner
                .running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "burst observatory scheduler is already running"
        );
        let _running = RunningGuard(&self.inner.running);

        // Go anchors the StartScheduler ticker at startup; the initial fast
        // check runs inside the first period.
        let started = Instant::now();
        let refresh = self.inner.settings.refresh_interval();
        let mut next_tick = started + refresh;

        // Initial fast result. Go logs and skips when selection fails.
        match selector.select(&self.inner.settings.subject_selector).await {
            Ok(tags) => {
                if let Err(error) = self.check(tags, cancel).await {
                    if error.is::<BurstCancelled>() {
                        return Ok(());
                    }
                    return Err(error);
                }
            }
            Err(error) => {
                tracing::warn!("error select outbounds for initial burst health check: {error:#}");
            }
        }

        let mut pending: Option<JoinSetEntry> = None;
        loop {
            if sleep_until_tick(next_tick, cancel).await {
                stop_pending(&mut pending).await;
                return Ok(());
            }
            next_tick += refresh;
            let tags = match selector.select(&self.inner.settings.subject_selector).await {
                Ok(tags) => tags,
                Err(error) => {
                    tracing::warn!(
                        "error select outbounds for scheduled burst health check: {error:#}"
                    );
                    continue;
                }
            };
            stop_pending(&mut pending).await;
            let round_cancel = cancel.child_token();
            let observer = self.clone();
            let entry = JoinSetEntry {
                cancel: round_cancel.clone(),
                task: tokio::spawn(
                    async move { observer.scheduled_round(tags, &round_cancel).await },
                ),
            };
            pending = Some(entry);
        }
    }

    /// One scheduled round: sampling-count jittered probes per tag spread over
    /// the interval, then cleanup. Cancellation still cleans up, as the Go
    /// tick goroutine does (doCheck returns early, Cleanup runs regardless).
    async fn scheduled_round(&self, tags: Vec<String>, cancel: &CancellationToken) {
        let guard = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            guard = self.inner.cycle.lock() => Some(guard),
        };
        if let Some(guard) = guard {
            let _guard = guard;
            let interval = self.inner.settings.interval;
            let sampling = self.inner.settings.sampling;
            if let Err(error) = self.do_check(&tags, interval, sampling, cancel).await
                && !error.is::<BurstCancelled>()
            {
                tracing::warn!("burst observatory health check round failed: {error:#}");
            }
        }
        self.cleanup(&tags);
    }

    /// Go HealthPing.doCheck: `rounds` probes per tag, each delayed by a
    /// uniform random offset in [0, duration) (Go dice.RollInt63n) so the
    /// sampling spreads over the round. Workers are spawned in fire order and
    /// capped at max_concurrency.
    async fn do_check(
        &self,
        tags: &[String],
        duration: Duration,
        rounds: usize,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let count = tags.len().saturating_mul(rounds);
        if count == 0 {
            return Ok(());
        }
        let start = Instant::now();
        let mut items: Vec<(String, Duration)> = Vec::with_capacity(count);
        for tag in tags {
            for _ in 0..rounds {
                items.push((tag.clone(), jitter_offset(duration)));
            }
        }
        items.sort_by_key(|(_, offset)| *offset);
        let mut pending = items.into_iter();
        let mut tasks = JoinSet::new();
        loop {
            while tasks.len() < self.inner.settings.max_concurrency {
                let Some((tag, offset)) = pending.next() else {
                    break;
                };
                let observer = self.clone();
                let cancel = cancel.clone();
                let fire_at = start + offset;
                tasks.spawn(async move {
                    let outcome = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => ProbeOutcome::Cancelled,
                        _ = tokio::time::sleep_until(fire_at) => {
                            observer.measure(&tag, &cancel).await
                        }
                    };
                    (tag, outcome)
                });
            }
            if tasks.is_empty() {
                break;
            }
            let completed = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(BurstCancelled.into());
                }
                completed = tasks.join_next() => completed,
            };
            let (tag, outcome) = completed
                .expect("nonempty probe task set")
                .context("burst observatory probe worker failed")?;
            match outcome {
                // Go drops non-positive values (the network-down sentinel);
                // failures are recorded as rttFailed.
                ProbeOutcome::Delay(rtt) if rtt > 0 => self.put_result(&tag, rtt),
                ProbeOutcome::Failed => self.put_result(&tag, RTT_FAILED),
                ProbeOutcome::Cancelled | ProbeOutcome::Delay(_) => {}
            }
        }
        Ok(())
    }

    /// One measurement; the settings timeout bounds connect, TLS, response
    /// and (for GET) body draining.
    async fn measure(&self, tag: &str, cancel: &CancellationToken) -> ProbeOutcome {
        let start = Instant::now();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return ProbeOutcome::Cancelled,
            result = tokio::time::timeout(self.inner.settings.timeout, self.perform(tag)) => result,
        };
        let destination = &self.inner.settings.destination;
        match result {
            Ok(Ok(())) => {
                ProbeOutcome::Delay(start.elapsed().as_nanos().min(i64::MAX as u128) as i64)
            }
            Ok(Err(error)) => {
                tracing::warn!("error ping {destination} with {tag}: {error:#}");
                ProbeOutcome::Failed
            }
            Err(_) => {
                tracing::warn!("error ping {destination} with {tag}: timed out");
                ProbeOutcome::Failed
            }
        }
    }

    async fn perform(&self, tag: &str) -> Result<()> {
        let mut stream = self
            .inner
            .connector
            .connect(tag, &self.inner.destination.target)
            .await
            .context("cannot dial burst ping remote address")?;
        if self.inner.settings.probe_type == BurstProbeType::ConnectOnly {
            // Dropping the stream closes the fresh probe connection.
            return Ok(());
        }
        if let Some(tls) = &self.inner.destination.tls {
            stream = tls
                .connect(stream, &self.inner.destination.target.host)
                .await?;
        }
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            self.inner.settings.http_method,
            self.inner.destination.path,
            self.inner.destination.authority,
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let drains_body = self.inner.settings.http_method == "GET";
        read_probe_response(&mut stream, drains_body).await
    }

    /// Go HealthPing.PutResult.
    fn put_result(&self, tag: &str, rtt: i64) {
        let mut results = self
            .inner
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sampling = self.inner.settings.sampling;
        let validity = self.inner.settings.validity();
        results
            .entry(tag.to_owned())
            .or_insert_with(|| HealthPingRtts::new(sampling, validity))
            .put(rtt);
    }

    /// Go HealthPing.Cleanup: drop results of tags no longer selected. An
    /// empty tag set clears everything, as in Go.
    fn cleanup(&self, tags: &[String]) {
        self.inner
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|tag, _| tags.iter().any(|current| current == tag));
    }
}

struct JoinSetEntry {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

/// Cancel a pending round and wait for it to finish. The round still runs
/// its cleanup after cancellation, like Go's tick goroutine (doCheck returns
/// early, Cleanup runs regardless), so the task is cancelled, not aborted:
/// every probe select is cancellation-first and bounded by the ping timeout,
/// so the round always exits promptly.
async fn stop_pending(pending: &mut Option<JoinSetEntry>) {
    if let Some(entry) = pending.take() {
        entry.cancel.cancel();
        let _ = entry.task.await;
    }
}

#[tonic::async_trait]
impl ObservationProvider for BurstObserver {
    async fn get_observation(&self) -> std::result::Result<ObservationResult, tonic::Status> {
        Ok(self.snapshot())
    }
}

/// Go dice.RollInt63n over the round duration: uniform [0, duration).
fn jitter_offset(duration: Duration) -> Duration {
    let nanos = duration.as_nanos();
    if nanos == 0 {
        return Duration::ZERO;
    }
    let bound = nanos.min(i64::MAX as u128) as i64;
    Duration::from_nanos(rand::thread_rng().gen_range(0..bound) as u64)
}

async fn sleep_until_tick(at: Instant, cancel: &CancellationToken) -> bool {
    tokio::select! { biased; _ = cancel.cancelled() => true, _ = tokio::time::sleep_until(at) => false }
}

/// Read one final HTTP response. Any valid final status is a successful ping
/// (Go closes the body and returns the elapsed time regardless of status).
/// GET additionally drains the body, like Go's io.Copy(io.Discard, ...).
async fn read_probe_response(stream: &mut BoxStream, drain: bool) -> Result<()> {
    let mut buffer = Vec::new();
    let mut consumed = 0usize;
    let mut interim = 0usize;
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
        let mut response = httparse::Response::new(&mut headers);
        match response
            .parse(&buffer)
            .context("invalid burst probe HTTP response")?
        {
            httparse::Status::Complete(length) => {
                ensure!(
                    length + consumed <= MAX_HEADER_BYTES,
                    "burst probe response headers exceed limit"
                );
                let code = response.code.context("HTTP response lacks status")?;
                ensure!((100..=999).contains(&code), "invalid HTTP status");
                let (content_length, chunked) = validate_framing(response.headers)?;
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
                if drain {
                    if chunked {
                        drain_body(stream, None).await?;
                    } else {
                        drain_body(stream, content_length).await?;
                    }
                }
                return Ok(());
            }
            httparse::Status::Partial => {
                ensure!(
                    buffer.len() + consumed < MAX_HEADER_BYTES,
                    "burst probe response headers exceed limit"
                );
                let mut bytes = [0; 2048];
                let maximum = bytes.len().min(MAX_HEADER_BYTES - buffer.len() - consumed);
                let read = stream.read(&mut bytes[..maximum]).await?;
                ensure!(read != 0, "EOF before complete burst probe HTTP response");
                buffer.extend_from_slice(&bytes[..read]);
            }
        }
    }
}

/// Drain the body: a known Content-Length is read exactly (a short body is an
/// error, as io.Copy would report); an unknown length reads to EOF, which is
/// correct for connection-close framing and conservative for chunked.
async fn drain_body(stream: &mut BoxStream, length: Option<u64>) -> Result<()> {
    let mut remaining = length;
    let mut buffer = [0; 8192];
    loop {
        let target = match remaining {
            Some(0) => return Ok(()),
            Some(left) => buffer.len().min(left as usize),
            None => buffer.len(),
        };
        let read = stream.read(&mut buffer[..target]).await?;
        if read == 0 {
            return match remaining {
                Some(_) => Err(anyhow::anyhow!(
                    "burst probe response body ended before Content-Length"
                )),
                None => Ok(()),
            };
        }
        if let Some(left) = remaining {
            remaining = Some(left - read as u64);
        }
    }
}

fn validate_framing(headers: &[httparse::Header<'_>]) -> Result<(Option<u64>, bool)> {
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
    Ok((length, transfer_encoding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls::{TlsCertificate, TlsServer};
    use std::{net::SocketAddr, sync::atomic::AtomicUsize};
    use tokio::{
        io::duplex,
        net::{TcpListener, TcpStream},
        sync::Notify,
        task::JoinHandle,
    };

    // ===== fixture connectors and servers ================================

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Dials one fixed loopback address for every probe, ignoring the
    /// destination host, and records calls with tokio Instants.
    #[derive(Clone)]
    struct LocalConnector {
        addr: SocketAddr,
        delay: Duration,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        calls: Arc<Mutex<Vec<(String, ProbeTarget, Instant)>>>,
        notify: Arc<Notify>,
    }

    impl LocalConnector {
        fn new(addr: SocketAddr, delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                addr,
                delay,
                active: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
                calls: Arc::new(Mutex::new(Vec::new())),
                notify: Arc::new(Notify::new()),
            })
        }

        async fn calls_at_least(self: &Arc<Self>, count: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let notified = self.notify.notified();
                    if self.calls.lock().unwrap().len() >= count {
                        break;
                    }
                    notified.await;
                }
            })
            .await
            .expect("probe connector was not called");
        }
    }

    #[tonic::async_trait]
    impl ProbeConnector for LocalConnector {
        async fn connect(&self, tag: &str, target: &ProbeTarget) -> Result<BoxStream> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let _active = Active(Arc::clone(&self.active));
            self.calls
                .lock()
                .unwrap()
                .push((tag.into(), target.clone(), Instant::now()));
            self.notify.notify_one();
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            let stream = TcpStream::connect(self.addr)
                .await
                .context("fixture target unreachable")?;
            Ok(Box::new(stream))
        }
    }

    /// Mock connector over tokio duplex streams: no real sockets, so it works
    /// under the paused tokio clock. The server half waits `delay` (mock
    /// time) before replying, which makes every probe's elapsed time exactly
    /// that delay.
    struct DuplexConnector {
        response: Vec<u8>,
        delay: Duration,
        calls: Arc<Mutex<Vec<(String, ProbeTarget, Instant)>>>,
        tasks: Mutex<Vec<JoinHandle<()>>>,
        notify: Arc<Notify>,
    }

    impl DuplexConnector {
        fn new(response: &[u8], delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                response: response.to_vec(),
                delay,
                calls: Arc::new(Mutex::new(Vec::new())),
                tasks: Mutex::new(Vec::new()),
                notify: Arc::new(Notify::new()),
            })
        }

        async fn calls_at_least(self: &Arc<Self>, count: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let notified = self.notify.notified();
                    if self.calls.lock().unwrap().len() >= count {
                        break;
                    }
                    notified.await;
                }
            })
            .await
            .expect("probe connector was not called");
        }
    }

    impl Drop for DuplexConnector {
        fn drop(&mut self) {
            for task in self.tasks.get_mut().unwrap() {
                task.abort();
            }
        }
    }

    #[tonic::async_trait]
    impl ProbeConnector for DuplexConnector {
        async fn connect(&self, tag: &str, target: &ProbeTarget) -> Result<BoxStream> {
            self.calls
                .lock()
                .unwrap()
                .push((tag.into(), target.clone(), Instant::now()));
            self.notify.notify_one();
            let (client, server) = duplex(4096);
            let response = self.response.clone();
            let delay = self.delay;
            let task = tokio::spawn(async move {
                let mut stream: BoxStream = Box::new(server);
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if stream.write_all(&response).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
                let mut closed = [0];
                let _ = stream.read(&mut closed).await;
            });
            self.tasks.lock().unwrap().push(task);
            Ok(Box::new(client))
        }
    }

    /// A connector whose connects never finish, to observe cancellation.
    struct PendingConnector {
        calls: Arc<Mutex<Vec<String>>>,
        notify: Arc<Notify>,
    }

    #[tonic::async_trait]
    impl ProbeConnector for PendingConnector {
        async fn connect(&self, tag: &str, _target: &ProbeTarget) -> Result<BoxStream> {
            self.calls.lock().unwrap().push(tag.into());
            self.notify.notify_one();
            std::future::pending::<Result<BoxStream>>().await
        }
    }

    /// What the loopback echo target replies and when.
    struct Reply {
        headers: &'static str,
        body: &'static [u8],
        /// Real time waited between headers and body.
        delay: Duration,
        /// Drop the connection after replying instead of waiting for the
        /// probe to close first.
        close_after: bool,
    }

    /// Loopback "echo probe target": accepts real TCP (optionally TLS)
    /// connections, records each request, and replies per `Reply`.
    struct EchoServer {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl EchoServer {
        async fn start(reply: Reply, tls: Option<TlsServer>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let request_log = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let tls = tls.clone();
                    let requests = Arc::clone(&request_log);
                    let reply = Reply {
                        headers: reply.headers,
                        body: reply.body,
                        delay: reply.delay,
                        close_after: reply.close_after,
                    };
                    tokio::spawn(async move {
                        let mut stream: BoxStream = if let Some(tls) = tls {
                            let Ok(stream) = tls.accept(Box::new(stream)).await else {
                                return;
                            };
                            stream
                        } else {
                            Box::new(stream)
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
                        if stream.write_all(reply.headers.as_bytes()).await.is_err() {
                            return;
                        }
                        if !reply.delay.is_zero() {
                            tokio::time::sleep(reply.delay).await;
                        }
                        if stream.write_all(reply.body).await.is_err() {
                            return;
                        }
                        let _ = stream.flush().await;
                        if reply.close_after {
                            return;
                        }
                        let mut closed = [0];
                        let _ = stream.read(&mut closed).await;
                    });
                }
            });
            Self {
                addr,
                requests,
                task,
            }
        }
    }

    impl Drop for EchoServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Selector returning a fixed tag list; asserts the selector value.
    struct FixedSelector {
        tags: Vec<String>,
    }
    #[tonic::async_trait]
    impl OutboundSelector for FixedSelector {
        async fn select(&self, selectors: &[String]) -> Result<Vec<String>> {
            assert_eq!(selectors, &["node-".to_owned()]);
            Ok(self.tags.clone())
        }
    }

    /// Selector that fails the first `fail_first` calls, then succeeds.
    struct FlakySelector {
        fail_first: usize,
        calls: AtomicUsize,
        tags: Vec<String>,
    }
    #[tonic::async_trait]
    impl OutboundSelector for FlakySelector {
        async fn select(&self, selectors: &[String]) -> Result<Vec<String>> {
            assert_eq!(selectors, &["node-".to_owned()]);
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call < self.fail_first {
                bail!("fixture selector failed");
            }
            Ok(self.tags.clone())
        }
    }

    /// Selector returning `initial` on the first call and `rest` afterwards.
    struct InitialThenSelector {
        initial: Vec<String>,
        rest: Vec<String>,
        first: AtomicBool,
    }
    #[tonic::async_trait]
    impl OutboundSelector for InitialThenSelector {
        async fn select(&self, _selectors: &[String]) -> Result<Vec<String>> {
            if self.first.swap(false, Ordering::SeqCst) {
                Ok(self.initial.clone())
            } else {
                Ok(self.rest.clone())
            }
        }
    }

    fn direct_settings(destination: &str) -> BurstSettings {
        BurstSettings {
            subject_selector: vec!["node-".into()],
            destination: destination.into(),
            interval: Duration::from_millis(30),
            sampling: 2,
            timeout: Duration::from_secs(2),
            http_method: "HEAD".into(),
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            probe_type: BurstProbeType::Url,
            tls: TlsSettings::default(),
        }
    }

    // ===== Go reference tests ============================================

    #[test]
    fn go_config_defaults_clamps_and_rejections() {
        // Go BurstObservatoryConfig.Build: a missing pingConfig is an error.
        let raw =
            BurstObservatoryConfig::from_value(&serde_json::json!({"subjectSelector": ["a"]}))
                .unwrap();
        assert!(
            raw.build()
                .unwrap_err()
                .to_string()
                .contains("requires a valid pingConfig")
        );

        // Go NewHealthPing defaults with an empty pingConfig object.
        let settings = BurstObservatoryConfig::from_value(&serde_json::json!({
            "subjectSelector": ["proxy-"],
            "pingConfig": {}
        }))
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(settings.subject_selector, ["proxy-"]);
        assert_eq!(settings.destination, DEFAULT_PING_DESTINATION);
        assert_eq!(settings.interval, Duration::from_secs(60));
        assert_eq!(settings.sampling, DEFAULT_SAMPLING);
        assert_eq!(settings.timeout, Duration::from_secs(5));
        assert_eq!(settings.http_method, "HEAD");
        assert_eq!(settings.max_concurrency, DEFAULT_MAX_CONCURRENCY);
        assert_eq!(settings.probe_type, BurstProbeType::Url);
        // Go StartScheduler ticker: interval * sampling; PutResult validity
        // doubles it.
        assert_eq!(settings.refresh_interval(), Duration::from_secs(600));
        assert_eq!(settings.validity(), Duration::from_secs(1200));

        // Clamps: below 10s becomes 10s, non-positive defaults apply.
        let clamped = BurstObservatoryConfig::from_value(&serde_json::json!({
            "pingConfig": {
                "interval": "3s",
                "sampling": -5,
                "timeout": "0s",
                "httpMethod": " get "
            }
        }))
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(clamped.interval, MIN_INTERVAL);
        assert_eq!(clamped.sampling, DEFAULT_SAMPLING);
        assert_eq!(clamped.timeout, Duration::from_secs(5));
        // Go only trims the method; the case is preserved on the wire and
        // only an exact "GET" drains the response body.
        assert_eq!(clamped.http_method, "get");

        let zeroed = BurstObservatoryConfig::from_value(&serde_json::json!({
            "pingConfig": {"interval": "0s", "timeout": "-1s"}
        }))
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(zeroed.interval, DEFAULT_INTERVAL);
        assert_eq!(zeroed.timeout, DEFAULT_TIMEOUT);

        // Protobuf entry point: nanosecond durations, trimmed strings, and a
        // nil ping config selecting every default, as NewHealthPing does.
        let wired = BurstSettings::from_wire(&wire::burst::Config {
            subject_selector: vec!["w".into()],
            ping_config: Some(wire::burst::HealthPingConfig {
                destination: " http://probe.example/x ".into(),
                connectivity: String::new(),
                interval: 3_000_000_000,
                sampling_count: 0,
                timeout: 0,
                http_method: String::new(),
            }),
        })
        .unwrap();
        assert_eq!(wired.subject_selector, ["w"]);
        assert_eq!(wired.destination, "http://probe.example/x");
        assert_eq!(wired.interval, MIN_INTERVAL);
        assert_eq!(wired.sampling, DEFAULT_SAMPLING);
        assert_eq!(wired.timeout, DEFAULT_TIMEOUT);
        assert_eq!(wired.http_method, "HEAD");
        let nil_ping = BurstSettings::from_wire(&wire::burst::Config {
            subject_selector: Vec::new(),
            ping_config: None,
        })
        .unwrap();
        assert_eq!(nil_ping.destination, DEFAULT_PING_DESTINATION);
        assert_eq!(nil_ping.interval, DEFAULT_INTERVAL);

        // Rejections: Go duration strings, the connectivity check (unsupported
        // here, never silently ignored), invalid methods, and bad URLs.
        let bad = [
            serde_json::json!({"pingConfig": {"interval": ""}}),
            serde_json::json!({"pingConfig": {"interval": "abc"}}),
            serde_json::json!({"pingConfig": {"interval": 10}}),
            serde_json::json!({"pingConfig": {"timeout": "5"}}),
            serde_json::json!({"pingConfig": {"sampling": "5"}}),
            serde_json::json!({"pingConfig": {"httpMethod": "GET POST"}}),
            serde_json::json!({"pingConfig": {"connectivity": "https://direct.example/"}}),
            serde_json::json!({"probeInterval": "1m"}),
            serde_json::json!({"subjectSelector": "node-"}),
            serde_json::json!({"pingConfig": null, "subjectSelector": []}),
        ];
        for value in bad {
            let settings = match BurstObservatoryConfig::from_value(&value) {
                Ok(config) => config.build(),
                Err(error) => Err(error),
            };
            assert!(settings.is_err(), "accepted {value}");
        }
        let connectivity = BurstObservatoryConfig::from_value(&serde_json::json!({
            "pingConfig": {"connectivity": "https://direct.example/"}
        }))
        .unwrap()
        .build()
        .unwrap_err()
        .to_string();
        assert!(connectivity.contains("connectivity"), "{connectivity}");
        for url in [
            "ftp://probe.example/",
            "http://user@probe.example/",
            "https://probe.example:0/",
            "https://probe.example/#fragment",
            "http://[fe80::1%25en0]/",
        ] {
            let mut settings = direct_settings(url);
            settings.subject_selector = Vec::new();
            assert!(
                BurstObserver::new(
                    settings,
                    DuplexConnector::new(b"HTTP/1.1 204 No Content\r\n\r\n", Duration::ZERO)
                )
                .is_err(),
                "accepted {url}"
            );
        }
    }

    // Go app/observatory/burst/healthping_result_test.go, first test.
    #[tokio::test]
    async fn rtts_match_go_golden_statistics() {
        let mut rtts = HealthPingRtts::new(4, Duration::from_secs(3600));
        for rtt in [60, 140, 60, 140, 60, 60, 140, 60, 140] {
            rtts.put(rtt);
        }
        assert_eq!(
            rtts.get(),
            HealthPingStats {
                all: 4,
                fail: 0,
                deviation: 40,
                average: 100,
                max: 140,
                min: 60
            }
        );
        rtts.put(RTT_FAILED);
        rtts.put(RTT_FAILED);
        assert_eq!(
            rtts.get(),
            HealthPingStats {
                all: 4,
                fail: 2,
                deviation: 40,
                average: 100,
                max: 140,
                min: 60
            }
        );
        rtts.put(RTT_FAILED);
        rtts.put(RTT_FAILED);
        assert_eq!(
            rtts.get(),
            HealthPingStats {
                all: 4,
                fail: 4,
                deviation: 0,
                average: 0,
                max: 0,
                min: 0
            }
        );
        // Untested sentinels never count.
        let fresh = HealthPingRtts::new(3, Duration::from_secs(3600));
        assert_eq!(
            fresh.get(),
            HealthPingStats {
                all: 0,
                fail: 0,
                deviation: 0,
                average: 0,
                max: 0,
                min: 0
            }
        );
    }

    // Go app/observatory/burst/healthping_result_test.go, outdated test.
    #[tokio::test]
    async fn rtts_ignore_outdated_samples() {
        let mut rtts = HealthPingRtts::new(4, Duration::from_millis(10));
        rtts.put(60);
        rtts.put(140);
        tokio::time::sleep(Duration::from_millis(15)).await;
        rtts.put(60);
        rtts.put(140);
        assert_eq!(
            rtts.get(),
            HealthPingStats {
                all: 2,
                fail: 0,
                deviation: 40,
                average: 100,
                max: 140,
                min: 60
            }
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(
            rtts.get(),
            HealthPingStats {
                all: 0,
                fail: 0,
                deviation: 0,
                average: 0,
                max: 0,
                min: 0
            }
        );
        rtts.put(60);
        // Single sample: Go assumes half the average as deviation.
        assert_eq!(
            rtts.get(),
            HealthPingStats {
                all: 1,
                fail: 0,
                deviation: 30,
                average: 60,
                max: 60,
                min: 60
            }
        );
    }

    // ===== observer tests =================================================

    #[tokio::test]
    async fn healthy_target_records_alive_with_go_record_shape() {
        let server = EchoServer::start(
            Reply {
                headers: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
                body: b"hello",
                delay: Duration::from_millis(15),
                close_after: false,
            },
            None,
        )
        .await;
        let connector = LocalConnector::new(server.addr, Duration::ZERO);
        let settings = BurstSettings {
            http_method: "GET".into(),
            ..direct_settings("http://probe.example/generate_204")
        };
        let observer = BurstObserver::new(settings, connector.clone()).unwrap();
        observer
            .check(vec!["node-a".into()], &CancellationToken::new())
            .await
            .unwrap();
        connector.calls_at_least(1).await;

        let calls = connector.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "node-a");
        assert_eq!(
            calls[0].1,
            ProbeTarget {
                host: "probe.example".into(),
                port: 80,
                https: false
            }
        );
        let request = server.requests.lock().unwrap()[0].clone();
        assert!(request.starts_with(
            "GET /generate_204 HTTP/1.1\r\nHost: probe.example\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        ));

        // Go createResult shape: delay is the average in milliseconds, zero
        // timestamps, empty error reason, nanosecond health ping stats.
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.status.len(), 1);
        let status = &snapshot.status[0];
        assert_eq!(status.outbound_tag, "node-a");
        assert!(status.alive);
        assert!(status.delay >= 15, "delay {}", status.delay);
        assert_eq!(status.last_error_reason, "");
        assert_eq!(status.last_seen_time, 0);
        assert_eq!(status.last_try_time, 0);
        let health = status.health_ping.as_ref().unwrap();
        assert_eq!(health.all, 1);
        assert_eq!(health.fail, 0);
        // The body arrives 15ms after the headers; a GET that did not drain
        // the body would finish before that.
        assert!(health.average >= 15_000_000, "average {}", health.average);
        assert_eq!(health.max, health.min);
        assert_eq!(health.max, health.average);
        // One sample: deviation is half the average (integer nanoseconds).
        assert!(health.average - 2 * health.deviation <= 1);

        // The observatory API surface reads the same snapshot.
        let provider: Arc<dyn ObservationProvider> = Arc::new(observer.clone());
        assert_eq!(provider.get_observation().await.unwrap(), snapshot);
    }

    #[tokio::test]
    async fn head_probe_over_tls_target_records_alive() {
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
        let echo = EchoServer::start(
            Reply {
                headers: "HTTP/1.1 204 No Content\r\n\r\n",
                body: b"",
                delay: Duration::from_millis(10),
                close_after: false,
            },
            Some(server),
        )
        .await;
        let connector = LocalConnector::new(echo.addr, Duration::ZERO);
        for valid in [true, false] {
            let settings = BurstSettings {
                tls: TlsSettings {
                    server_name: if valid {
                        String::new()
                    } else {
                        "wrong.example".into()
                    },
                    disable_system_root: true,
                    certificates: vec![TlsCertificate {
                        certificate: certificate.clone(),
                        usage: "verify".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..direct_settings("https://probe.example/generate_204")
            };
            let observer = BurstObserver::new(settings, connector.clone()).unwrap();
            observer
                .check(vec!["node-tls".into()], &CancellationToken::new())
                .await
                .unwrap();
            let snapshot = observer.snapshot();
            let status = &snapshot.status[0];
            assert_eq!(status.alive, valid, "unexpected aliveness");
            let health = status.health_ping.as_ref().unwrap();
            assert_eq!(health.all, 1);
            assert_eq!(health.fail, if valid { 0 } else { 1 });
        }
        let calls = connector.calls.lock().unwrap();
        assert!(calls.iter().all(|(_, target, _)| target
            == &ProbeTarget {
                host: "probe.example".into(),
                port: 443,
                https: true
            }));
        let request = echo.requests.lock().unwrap()[0].clone();
        assert!(request.starts_with("HEAD /generate_204 HTTP/1.1\r\nHost: probe.example\r\n"));
    }

    #[tokio::test]
    async fn dead_target_refused_port_records_failure() {
        // Reserve a loopback port and free it so connects are refused. Windows
        // may retry such connects for about a second, so the sample validity
        // (interval * sampling * 2) must outlast both attempts.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let connector = LocalConnector::new(addr, Duration::ZERO);
        let settings = BurstSettings {
            interval: Duration::from_secs(60),
            ..direct_settings("http://probe.example/x")
        };
        let observer = BurstObserver::new(settings, connector.clone()).unwrap();
        for _ in 0..2 {
            observer
                .check(vec!["dead".into()], &CancellationToken::new())
                .await
                .unwrap();
        }
        connector.calls_at_least(2).await;
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.status.len(), 1);
        let status = &snapshot.status[0];
        assert_eq!(status.outbound_tag, "dead");
        assert!(!status.alive);
        // Go records failures as rttFailed samples; the record keeps an empty
        // error reason and zero delay.
        assert_eq!(status.delay, 0);
        assert_eq!(status.last_error_reason, "");
        assert_eq!(status.last_seen_time, 0);
        let health = status.health_ping.as_ref().unwrap();
        assert_eq!((health.all, health.fail), (2, 2));
        assert_eq!(
            (health.average, health.max, health.min, health.deviation),
            (0, 0, 0, 0)
        );
    }

    #[tokio::test]
    async fn malformed_and_short_responses_record_failure() {
        let malformed = [
            ("not an HTTP response\r\n\r\n", ""),
            ("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "abc"),
            ("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", ""),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", ""),
        ];
        for (headers, body) in malformed {
            let server = EchoServer::start(
                Reply {
                    headers,
                    body: body.as_bytes(),
                    delay: Duration::ZERO,
                    close_after: true,
                },
                None,
            )
            .await;
            let connector = LocalConnector::new(server.addr, Duration::ZERO);
            let settings = BurstSettings {
                http_method: "GET".into(),
                ..direct_settings("http://probe.example/x")
            };
            let observer = BurstObserver::new(settings, connector.clone()).unwrap();
            observer
                .check(vec!["bad".into()], &CancellationToken::new())
                .await
                .unwrap();
            connector.calls_at_least(1).await;
            let status = &observer.snapshot().status[0];
            assert!(!status.alive, "accepted malformed {headers:?}");
            assert_eq!(status.health_ping.as_ref().unwrap().fail, 1);
        }
    }

    #[tokio::test]
    async fn concurrency_cap_observed_with_counting_connector() {
        let server = EchoServer::start(
            Reply {
                headers: "HTTP/1.1 204 No Content\r\n\r\n",
                body: b"",
                delay: Duration::ZERO,
                close_after: false,
            },
            None,
        )
        .await;
        let connector = LocalConnector::new(server.addr, Duration::from_millis(40));
        let settings = BurstSettings {
            probe_type: BurstProbeType::ConnectOnly,
            max_concurrency: 2,
            // The five 40ms-staggered connects span the default 120ms
            // validity; a long interval keeps every sample current.
            interval: Duration::from_secs(60),
            ..direct_settings("http://probe.example/x")
        };
        let observer = BurstObserver::new(settings, connector.clone()).unwrap();
        observer
            .check(
                (0..5).map(|index| format!("node-{index}")).collect(),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        connector.calls_at_least(5).await;
        assert_eq!(connector.peak.load(Ordering::SeqCst), 2);
        assert_eq!(connector.active.load(Ordering::SeqCst), 0);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.status.len(), 5);
        for status in &snapshot.status {
            assert!(status.alive);
            // The connect-only delay includes the connector's 40ms hold.
            assert!(status.delay >= 40, "delay {}", status.delay);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_refresh_rounds_at_interval_multiples() {
        let connector =
            DuplexConnector::new(b"HTTP/1.1 204 No Content\r\n\r\n", Duration::from_millis(5));
        let mut settings = direct_settings("http://probe.example/generate_204");
        settings.interval = Duration::from_millis(30);
        settings.sampling = 2;
        settings.timeout = Duration::from_secs(1);
        let observer = BurstObserver::new(settings, connector.clone()).unwrap();
        let selector = Arc::new(FixedSelector {
            tags: vec!["node-a".into()],
        });
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_observer = observer.clone();
        let task = tokio::spawn(async move { task_observer.run(selector, &task_cancel).await });

        // Initial round (one probe) plus three refresh rounds of sampling=2.
        connector.calls_at_least(7).await;
        cancel.cancel();
        task.await.unwrap().unwrap();
        assert!(!observer.is_running());

        let calls = connector.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 7);
        let base = calls[0].2;
        for (index, (tag, _, at)) in calls.iter().enumerate() {
            assert_eq!(tag, "node-a");
            let elapsed = at.duration_since(base);
            let (low, high) = match index {
                0 => (0, 1),
                1 | 2 => (60, 90),
                3 | 4 => (120, 150),
                5 | 6 => (180, 210),
                _ => unreachable!(),
            };
            // The paused tokio clock advances in whole milliseconds, so a
            // jittered wake deadline in the final sub-millisecond of the
            // round quantizes up to the round boundary itself; the round
            // window is therefore inclusive at the top.
            assert!(
                elapsed >= Duration::from_millis(low) && elapsed <= Duration::from_millis(high),
                "call {index} at {elapsed:?}"
            );
        }
        // Every probe's elapsed time is exactly the mock 5ms reply delay, so
        // the record values are deterministic.
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.status.len(), 1);
        let status = &snapshot.status[0];
        assert_eq!(status.outbound_tag, "node-a");
        assert!(status.alive);
        assert_eq!(status.delay, 5);
        let health = status.health_ping.as_ref().unwrap();
        assert_eq!((health.all, health.fail), (2, 0));
        assert_eq!(health.average, 5_000_000);
        assert_eq!(health.max, 5_000_000);
        assert_eq!(health.min, 5_000_000);
        assert_eq!(health.deviation, 0);
    }

    #[tokio::test]
    async fn cancelled_check_owns_pending_connector() {
        let connector = Arc::new(PendingConnector {
            calls: Arc::new(Mutex::new(Vec::new())),
            notify: Arc::new(Notify::new()),
        });
        let observer =
            BurstObserver::new(direct_settings("http://probe.example/x"), connector.clone())
                .unwrap();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_observer = observer.clone();
        let task = tokio::spawn(async move {
            task_observer
                .check(vec!["node-a".into()], &task_cancel)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), connector.notify.notified())
            .await
            .expect("probe connector was not called");
        cancel.cancel();
        assert!(task.await.unwrap().unwrap_err().is::<BurstCancelled>());
        assert!(observer.snapshot().status.is_empty());
        assert_eq!(connector.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failing_selector_rounds_are_skipped_but_scheduler_continues() {
        let connector =
            DuplexConnector::new(b"HTTP/1.1 204 No Content\r\n\r\n", Duration::from_millis(2));
        let mut settings = direct_settings("http://probe.example/x");
        settings.interval = Duration::from_millis(10);
        settings.sampling = 1;
        settings.timeout = Duration::from_secs(1);
        let observer = BurstObserver::new(settings, connector.clone()).unwrap();
        let selector = Arc::new(FlakySelector {
            fail_first: 2,
            calls: AtomicUsize::new(0),
            tags: vec!["node-a".into()],
        });
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_observer = observer.clone();
        let task_selector = selector.clone();
        let task =
            tokio::spawn(async move { task_observer.run(task_selector, &task_cancel).await });
        // The initial selection and the first tick fail; later ticks still
        // run and record. Wait for a completed sample, not a started probe.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !observer.snapshot().status.is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("no burst health sample was recorded after selector failures");
        cancel.cancel();
        task.await.unwrap().unwrap();
        assert!(selector.calls.load(Ordering::SeqCst) >= 3);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.status.len(), 1);
        assert_eq!(snapshot.status[0].outbound_tag, "node-a");
        assert!(snapshot.status[0].alive);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduled_cleanup_removes_unselected_tags() {
        let connector =
            DuplexConnector::new(b"HTTP/1.1 204 No Content\r\n\r\n", Duration::from_millis(2));
        let mut settings = direct_settings("http://probe.example/x");
        settings.interval = Duration::from_millis(10);
        settings.sampling = 1;
        settings.timeout = Duration::from_secs(1);
        let observer = BurstObserver::new(settings, connector.clone()).unwrap();
        let selector = Arc::new(InitialThenSelector {
            initial: vec!["node-a".into(), "node-b".into()],
            rest: vec!["node-a".into()],
            first: AtomicBool::new(true),
        });
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_observer = observer.clone();
        let task = tokio::spawn(async move { task_observer.run(selector, &task_cancel).await });
        // Initial round probes both tags; the first scheduled round selects
        // only node-a and cleans node-b up.
        connector.calls_at_least(4).await;
        cancel.cancel();
        task.await.unwrap().unwrap();
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.status.len(), 1);
        assert_eq!(snapshot.status[0].outbound_tag, "node-a");
        assert!(snapshot.status[0].alive);
    }
}
