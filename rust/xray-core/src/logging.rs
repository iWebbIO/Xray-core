//! Xray log configuration, records, and explicitly owned output handlers.
//!
//! Formatting and configuration follow `infra/conf/log.go`, `app/log/log.go`,
//! and `common/log`. A logger is cheap to clone; all clones share its writers
//! and lifecycle. Constructing one does not install a global tracing subscriber.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Duration,
};

use chrono::{DateTime, FixedOffset, Local};
use regex::{Captures, Regex};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{Event, Subscriber, field::Visit, span};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

/// Go's console/file logger uses local time, including six fractional digits.
pub type Timestamp = DateTime<FixedOffset>;

#[cfg(windows)]
pub const LINE_SEPARATOR: &str = "\r\n";
#[cfg(not(windows))]
pub const LINE_SEPARATOR: &str = "\n";

/// The JSON `log` object. Empty fields are intentional: `{}` enables both
/// console streams, unlike an entirely omitted `log` object.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default)]
pub struct LogConfig {
    #[serde(deserialize_with = "null_default")]
    pub access: String,
    #[serde(deserialize_with = "null_default")]
    pub error: String,
    #[serde(deserialize_with = "null_default")]
    pub loglevel: String,
    #[serde(rename = "dnsLog", deserialize_with = "null_default")]
    pub dns_log: bool,
    #[serde(rename = "maskAddress", deserialize_with = "null_default")]
    pub mask_address: String,
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

impl LogConfig {
    pub fn build(&self) -> io::Result<LoggerOptions> {
        let mut options = LoggerOptions {
            access: LogDestination::from_config_path(&self.access),
            error: LogDestination::from_config_path(&self.error),
            level: Severity::from_config(&self.loglevel),
            dns_log: self.dns_log,
            mask: AddressMask::parse(&self.mask_address)?,
        };
        // "none" suppresses access and DNS records as well as general records.
        if self.loglevel.eq_ignore_ascii_case("none") {
            options.access = LogDestination::None;
            options.error = LogDestination::None;
        }
        Ok(options)
    }
}

/// The ordering matches xray.common.log.Severity; lower values are more severe.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Severity {
    Unknown = 0,
    Error = 1,
    #[default]
    Warning = 2,
    Info = 3,
    Debug = 4,
}

impl Severity {
    /// Unknown strings (including "warn") use Xray's warning default.
    pub fn from_config(level: &str) -> Self {
        match level.to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "error" => Self::Error,
            _ => Self::Warning,
        }
    }

    fn from_tracing(level: &tracing::Level) -> Self {
        match *level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warning,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG | tracing::Level::TRACE => Self::Debug,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Error => "Error",
            Self::Warning => "Warning",
            Self::Info => "Info",
            Self::Debug => "Debug",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogDestination {
    None,
    Stdout,
    Stderr,
    File(PathBuf),
}

impl LogDestination {
    /// Only an empty string and literal "none" have special JSON meanings.
    /// In particular, "stdout" and "stderr" are file names in Xray's schema.
    pub fn from_config_path(path: &str) -> Self {
        match path {
            "" => Self::Stdout,
            "none" => Self::None,
            value => Self::File(PathBuf::from(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoggerOptions {
    pub access: LogDestination,
    pub error: LogDestination,
    pub level: Severity,
    pub dns_log: bool,
    pub mask: AddressMask,
}

/// Defaults for an omitted `log` object (`DefaultLogConfig` in the Go source).
impl Default for LoggerOptions {
    fn default() -> Self {
        Self {
            access: LogDestination::None,
            error: LogDestination::Stdout,
            level: Severity::Warning,
            dns_log: false,
            mask: AddressMask::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccessStatus {
    #[default]
    Accepted,
    Rejected,
}

impl fmt::Display for AccessStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessRecord {
    pub from: String,
    pub to: String,
    pub status: AccessStatus,
    pub reason: String,
    pub email: String,
    pub detour: String,
}

impl AccessRecord {
    pub fn accepted(from: impl ToString, to: impl ToString) -> Self {
        Self {
            from: from.to_string(),
            to: to.to_string(),
            ..Self::default()
        }
    }

    pub fn rejected(from: impl ToString, to: impl ToString, reason: impl ToString) -> Self {
        Self {
            status: AccessStatus::Rejected,
            reason: reason.to_string(),
            ..Self::accepted(from, to)
        }
    }
}

impl fmt::Display for AccessRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "from {} {} {}", self.from, self.status, self.to)?;
        if !self.detour.is_empty() {
            write!(formatter, " [{}]", self.detour)?;
        }
        if !self.reason.is_empty() {
            write!(formatter, " {}", self.reason)?;
        }
        if !self.email.is_empty() {
            write!(formatter, " email: {}", self.email)?;
        }
        Ok(())
    }
}

/// Values of `isPickRoute` in app/dispatcher/default.go.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetourKind {
    Default,
    Forced,
    Routed,
}

/// Builds the detour field without the surrounding access-record brackets.
pub fn format_detour(inbound: &str, outbound: &str, kind: DetourKind) -> String {
    if outbound.is_empty() {
        return String::new();
    }
    if inbound.is_empty() {
        return outbound.to_owned();
    }
    let arrow = match kind {
        DetourKind::Default => ">>",
        DetourKind::Forced => "==>",
        DetourKind::Routed => "->",
    };
    format!("{inbound} {arrow} {outbound}")
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnsStatus {
    #[default]
    Queried,
    CacheHit,
    CacheOptimistic,
}

impl fmt::Display for DnsStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Queried => "got answer:",
            Self::CacheHit => "cache HIT:",
            // The spelling is part of the existing wire/file presentation.
            Self::CacheOptimistic => "cache OPTIMISTE:",
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsRecord {
    pub server: String,
    pub domain: String,
    pub result: Vec<IpAddr>,
    pub status: DnsStatus,
    pub elapsed: Duration,
    pub error: Option<String>,
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} {} -> [",
            self.server, self.status, self.domain
        )?;
        for (index, ip) in self.result.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(&format_go_ip(*ip))?;
        }
        formatter.write_str("]")?;
        if !self.elapsed.is_zero() {
            write!(formatter, " {}", format_duration(self.elapsed))?;
        }
        if let Some(error) = &self.error {
            write!(formatter, " <{error}>")?;
        }
        Ok(())
    }
}

fn format_go_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// The positive-duration subset of Go's time.Duration.String formatting.
pub fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos == 0 {
        return "0s".to_owned();
    }
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format!("{}µs", decimal(nanos, 1_000, 3));
    }
    if nanos < 1_000_000_000 {
        return format!("{}ms", decimal(nanos, 1_000_000, 6));
    }
    let seconds = duration.as_secs();
    let hours = seconds / 3_600;
    let minutes = seconds / 60 % 60;
    let second_part = decimal(
        u128::from(seconds % 60) * 1_000_000_000 + u128::from(duration.subsec_nanos()),
        1_000_000_000,
        9,
    );
    if hours > 0 {
        format!("{hours}h{minutes}m{second_part}s")
    } else if minutes > 0 {
        format!("{minutes}m{second_part}s")
    } else {
        format!("{second_part}s")
    }
}

fn decimal(value: u128, divisor: u128, digits: usize) -> String {
    let integer = value / divisor;
    let fraction = value % divisor;
    if fraction == 0 {
        integer.to_string()
    } else {
        let fraction = format!("{fraction:0digits$}");
        format!("{integer}.{}", fraction.trim_end_matches('0'))
    }
}

/// Source-compatible message masking. Masking runs before the timestamp is
/// prefixed and applies to all record fields, including emails and reasons.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressMask {
    enabled: bool,
    ipv4_bits: u8,
    ipv6_bits: i64,
}

impl AddressMask {
    pub fn parse(value: &str) -> io::Result<Self> {
        let (ipv4_bits, ipv6_bits) = match value {
            "" => return Ok(Self::default()),
            "half" => (16, 32),
            "quarter" => (8, 16),
            "full" => (0, 0),
            _ => {
                let mut parts = value.split('+');
                let parse_part = |part: &str| -> io::Result<i64> {
                    if part.is_empty() {
                        return Ok(0);
                    }
                    part.strip_prefix('/')
                        .unwrap_or(part)
                        .parse()
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("Log Mask: {error}"),
                            )
                        })
                };
                // Go deliberately reads only the first two components.
                (
                    parse_part(parts.next().unwrap_or_default())?,
                    parse_part(parts.next().unwrap_or_default())?,
                )
            }
        };
        if !(0..=32).contains(&ipv4_bits) || ipv4_bits % 8 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Log Mask: ipv4 mask must be divisible by 8 and between 0-32",
            ));
        }
        // Go does not range-check IPv6 prefixes. Its nil mask formats as <nil>.
        Ok(Self {
            enabled: true,
            ipv4_bits: ipv4_bits as u8,
            ipv6_bits,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn ipv4_bits(&self) -> u8 {
        self.ipv4_bits
    }

    pub fn ipv6_bits(&self) -> i64 {
        self.ipv6_bits
    }

    pub fn apply(&self, message: &str) -> String {
        if !self.enabled {
            return message.to_owned();
        }
        static IPV4: OnceLock<Regex> = OnceLock::new();
        static IPV6: OnceLock<Regex> = OnceLock::new();
        let ipv4 = IPV4.get_or_init(|| {
            Regex::new(r"([0-9]{1,3}\.){3}[0-9]{1,3}").expect("constant IPv4 expression")
        });
        let ipv6 = IPV6.get_or_init(|| {
            Regex::new(r"(?:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}){2,7}")
                .expect("constant IPv6 expression")
        });
        let message = ipv4.replace_all(message, |captures: &Captures<'_>| {
            let ip = &captures[0];
            match self.ipv4_bits {
                32 => ip.to_owned(),
                0 => "[Masked IPv4]".to_owned(),
                bits => ip
                    .split('.')
                    .enumerate()
                    .map(|(index, part)| {
                        if index < usize::from(bits / 8) {
                            part
                        } else {
                            "*"
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("."),
            }
        });
        ipv6.replace_all(&message, |captures: &Captures<'_>| {
            let ip = &captures[0];
            match self.ipv6_bits {
                128 => ip.to_owned(),
                0 => "Masked IPv6".to_owned(),
                bits => match ip.parse::<Ipv6Addr>() {
                    Ok(ip) if (0..=128).contains(&bits) => {
                        let mask = u128::MAX << (128 - bits as u32);
                        let masked = Ipv6Addr::from(u128::from(ip) & mask);
                        format!("{}/{bits}", format_go_ip(IpAddr::V6(masked)))
                    }
                    Ok(_) => format!("<nil>/{bits}"),
                    Err(_) => ip.to_owned(),
                },
            }
        })
        .into_owned()
    }
}

enum Writer {
    None,
    Stdout,
    Stderr,
    File(File),
}

impl Writer {
    fn open(destination: &LogDestination) -> io::Result<Self> {
        Ok(match destination {
            LogDestination::None => Self::None,
            LogDestination::Stdout => Self::Stdout,
            LogDestination::Stderr => Self::Stderr,
            LogDestination::File(path) => Self::File(open_file(path)?),
        })
    }

    fn write(&mut self, line: &[u8]) -> io::Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Stdout => {
                let stdout = io::stdout();
                let mut writer = stdout.lock();
                writer.write_all(line)?;
                writer.flush()
            }
            Self::Stderr => {
                let stderr = io::stderr();
                let mut writer = stderr.lock();
                writer.write_all(line)?;
                writer.flush()
            }
            Self::File(file) => file.write_all(line),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Stdout => io::stdout().lock().flush(),
            Self::Stderr => io::stderr().lock().flush(),
            Self::File(file) => file.flush(),
        }
    }
}

fn open_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot open log file {}: {error}", path.display()),
        )
    })
}

struct State {
    active: bool,
    access: Writer,
    error: Writer,
    tracing_error: Option<io::Error>,
}

struct Inner {
    options: LoggerOptions,
    state: Mutex<State>,
}

/// Synchronous, serialized writers make completed writes visible immediately
/// and report I/O failures. No background queue or process-global handler is used.
#[derive(Clone)]
pub struct Logger {
    inner: Arc<Inner>,
}

impl Logger {
    pub fn new(config: &LogConfig) -> io::Result<Self> {
        Self::from_options(config.build()?)
    }

    pub fn from_optional_config(config: Option<&LogConfig>) -> io::Result<Self> {
        Self::from_options(match config {
            Some(config) => config.build()?,
            None => LoggerOptions::default(),
        })
    }

    pub fn from_options(options: LoggerOptions) -> io::Result<Self> {
        let access = Writer::open(&options.access)?;
        let error = Writer::open(&options.error)?;
        let logger = Self {
            inner: Arc::new(Inner {
                options,
                state: Mutex::new(State {
                    active: true,
                    access,
                    error,
                    tracing_error: None,
                }),
            }),
        };
        logger.write_general(Severity::Debug, "app/log: Logger started")?;
        Ok(logger)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn options(&self) -> &LoggerOptions {
        &self.inner.options
    }

    pub fn is_active(&self) -> bool {
        self.state().active
    }

    pub fn is_enabled(&self, severity: Severity) -> bool {
        severity <= self.inner.options.level
            && self.inner.options.error != LogDestination::None
            && self.is_active()
    }

    pub fn access_enabled(&self) -> bool {
        self.inner.options.access != LogDestination::None && self.is_active()
    }

    pub fn start(&self) -> io::Result<()> {
        let mut state = self.state();
        if state.active {
            return Ok(());
        }
        self.open_writers(&mut state)
    }

    /// Reopens both outputs under the same lock as writes. If opening fails,
    /// existing outputs remain usable. A successful reopen also starts a closed logger.
    pub fn reopen(&self) -> io::Result<()> {
        self.open_writers(&mut self.state())
    }

    pub fn restart(&self) -> io::Result<()> {
        self.write_general(Severity::Debug, "app/log: Logger closing")?;
        self.reopen()
    }

    fn open_writers(&self, state: &mut State) -> io::Result<()> {
        let access = Writer::open(&self.inner.options.access)?;
        let error = Writer::open(&self.inner.options.error)?;
        state.access.flush()?;
        state.error.flush()?;
        state.access = access;
        state.error = error;
        state.active = true;
        Ok(())
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut state = self.state();
        let access = state.access.flush();
        let error = state.error.flush();
        access.and(error)
    }

    pub fn close(&self) -> io::Result<()> {
        let lifecycle = self.write_general(Severity::Debug, "app/log: Logger closing");
        let mut state = self.state();
        let access = state.access.flush();
        let error = state.error.flush();
        state.active = false;
        state.access = Writer::None;
        state.error = Writer::None;
        lifecycle.and(access).and(error)
    }

    pub fn write_general(&self, severity: Severity, content: impl fmt::Display) -> io::Result<()> {
        self.write_general_at(Local::now().fixed_offset(), severity, content)
    }

    pub fn write_general_at(
        &self,
        timestamp: Timestamp,
        severity: Severity,
        content: impl fmt::Display,
    ) -> io::Result<()> {
        if !self.is_enabled(severity) {
            return Ok(());
        }
        self.write_line(timestamp, &format!("[{severity}] {content}"), false)
    }

    pub fn write_access(&self, record: &AccessRecord) -> io::Result<()> {
        self.write_access_at(Local::now().fixed_offset(), record)
    }

    pub fn write_access_at(&self, timestamp: Timestamp, record: &AccessRecord) -> io::Result<()> {
        if !self.access_enabled() {
            return Ok(());
        }
        self.write_line(timestamp, &record.to_string(), true)
    }

    pub fn write_dns(&self, record: &DnsRecord) -> io::Result<()> {
        self.write_dns_at(Local::now().fixed_offset(), record)
    }

    pub fn write_dns_at(&self, timestamp: Timestamp, record: &DnsRecord) -> io::Result<()> {
        if !self.inner.options.dns_log || !self.access_enabled() {
            return Ok(());
        }
        self.write_line(timestamp, &record.to_string(), true)
    }

    fn write_line(&self, timestamp: Timestamp, message: &str, access: bool) -> io::Result<()> {
        let line = format!(
            "{} {}{LINE_SEPARATOR}",
            timestamp.format("%Y/%m/%d %H:%M:%S%.6f"),
            self.inner.options.mask.apply(message)
        );
        let mut state = self.state();
        if !state.active {
            return Ok(());
        }
        if access {
            state.access.write(line.as_bytes())
        } else {
            state.error.write(line.as_bytes())
        }
    }

    /// Attach the returned layer to a subscriber chosen by the caller.
    pub fn tracing_layer(&self) -> LoggingLayer {
        LoggingLayer {
            logger: self.clone(),
            include_target: true,
        }
    }

    /// `Layer::on_event` cannot return I/O errors; callers can retrieve the latest.
    pub fn take_tracing_error(&self) -> Option<io::Error> {
        self.state().tracing_error.take()
    }
}

/// A bridge for existing Rust tracing calls. Structured event/span fields are
/// retained; a numeric `session_id` receives Xray's `[id]` prefix. This layer
/// filters only its own output, so another subscriber layer keeps its own policy.
#[derive(Clone)]
pub struct LoggingLayer {
    logger: Logger,
    include_target: bool,
}

impl LoggingLayer {
    pub fn with_target(mut self, enabled: bool) -> Self {
        self.include_target = enabled;
        self
    }
}

#[derive(Clone, Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
}

impl<S> Layer<S> for LoggingLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attributes: &span::Attributes<'_>,
        id: &span::Id,
        context: Context<'_, S>,
    ) {
        if let Some(span) = context.span(id) {
            let mut fields = Fields::default();
            attributes.record(&mut fields);
            // Multiple independent logging layers can share a registry.
            let _ = span.extensions_mut().replace(fields);
        }
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, context: Context<'_, S>) {
        if let Some(span) = context.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(fields) = extensions.get_mut::<Fields>() {
                values.record(fields);
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let severity = Severity::from_tracing(event.metadata().level());
        if !self.logger.is_enabled(severity) {
            return;
        }
        let mut fields = Fields::default();
        if let Some(scope) = context.event_scope(event) {
            for span in scope.from_root() {
                if let Some(parent_fields) = span.extensions().get::<Fields>() {
                    fields.0.extend(parent_fields.0.clone());
                }
            }
        }
        event.record(&mut fields);
        let message = fields.0.remove("message").unwrap_or_default();
        let mut content = String::new();
        if let Some(id) = fields
            .0
            .get("session_id")
            .and_then(|value| value.parse::<u32>().ok())
        {
            fields.0.remove("session_id");
            if id != 0 {
                content.push_str(&format!("[{id}] "));
            }
        }
        if self.include_target && !event.metadata().target().is_empty() {
            content.push_str(event.metadata().target());
            content.push_str(": ");
        }
        content.push_str(&message);
        for (name, value) in fields.0 {
            if !content.is_empty() && !content.ends_with(' ') {
                content.push(' ');
            }
            content.push_str(&name);
            content.push('=');
            content.push_str(&value);
        }
        if let Err(error) = self.logger.write_general(severity, content) {
            self.logger.state().tracing_error = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };
    use tracing_subscriber::prelude::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "xray-rust-logging-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn timestamp() -> Timestamp {
        DateTime::parse_from_rfc3339("2026-09-19T12:34:56.123456789+01:00").unwrap()
    }

    fn file_options(directory: &TempDir) -> LoggerOptions {
        LoggerOptions {
            access: LogDestination::File(directory.path("access.log")),
            error: LogDestination::File(directory.path("error.log")),
            ..LoggerOptions::default()
        }
    }

    #[test]
    fn absent_empty_and_none_configurations_are_distinct() {
        assert_eq!(LoggerOptions::default().access, LogDestination::None);
        assert_eq!(
            LogConfig::default().build().unwrap().access,
            LogDestination::Stdout
        );
        let config: LogConfig = serde_json::from_str(
            r#"{"access":null,"dnsLog":null,"loglevel":"NONE","unused":true}"#,
        )
        .unwrap();
        assert_eq!(config.build().unwrap().access, LogDestination::None);
        assert_eq!(config.build().unwrap().error, LogDestination::None);
        assert_eq!(
            LogDestination::from_config_path("stderr"),
            LogDestination::File("stderr".into())
        );
        assert_eq!(
            LogDestination::from_config_path("NONE"),
            LogDestination::File("NONE".into())
        );
        assert_eq!(Severity::from_config("DeBuG"), Severity::Debug);
        assert_eq!(Severity::from_config("trace"), Severity::Warning);
        assert_eq!(Severity::from_config(" info "), Severity::Warning);
    }

    #[test]
    fn access_records_match_source_field_order() {
        let accepted = AccessRecord {
            detour: format_detour("socks", "direct", DetourKind::Routed),
            email: "alice@example.org".to_owned(),
            ..AccessRecord::accepted("127.0.0.1:54321", "tcp:example.org:443")
        };
        assert_eq!(
            accepted.to_string(),
            "from 127.0.0.1:54321 accepted tcp:example.org:443 [socks -> direct] email: alice@example.org"
        );
        let rejected = AccessRecord::rejected("[::1]:54321", "tcp:example.org:443", "invalid user");
        assert_eq!(
            rejected.to_string(),
            "from [::1]:54321 rejected tcp:example.org:443 invalid user"
        );
        assert_eq!(
            format_detour("socks", "direct", DetourKind::Forced),
            "socks ==> direct"
        );
        assert_eq!(
            format_detour("socks", "direct", DetourKind::Default),
            "socks >> direct"
        );
        assert_eq!(format_detour("", "direct", DetourKind::Default), "direct");
        assert_eq!(format_detour("socks", "", DetourKind::Default), "");
    }

    #[test]
    fn dns_records_preserve_status_duration_and_error_spelling() {
        let record = DnsRecord {
            server: "UDP:8.8.8.8:53".to_owned(),
            domain: "example.org.".to_owned(),
            result: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            elapsed: Duration::from_nanos(23_000_456),
            ..DnsRecord::default()
        };
        assert_eq!(
            record.to_string(),
            "UDP:8.8.8.8:53 got answer: example.org. -> [192.0.2.1, 2001:db8::1] 23.000456ms"
        );
        let cached = DnsRecord {
            result: Vec::new(),
            status: DnsStatus::CacheOptimistic,
            elapsed: Duration::ZERO,
            error: Some("lookup failed".to_owned()),
            ..record
        };
        assert_eq!(
            cached.to_string(),
            "UDP:8.8.8.8:53 cache OPTIMISTE: example.org. -> [] <lookup failed>"
        );
        for (nanos, expected) in [
            (0, "0s"),
            (1, "1ns"),
            (1_001, "1.001µs"),
            (1_010_000, "1.01ms"),
            (1_000_000_001, "1.000000001s"),
            (60_000_000_000, "1m0s"),
            (3_600_000_000_000, "1h0m0s"),
            (3_661_250_000_000, "1h1m1.25s"),
        ] {
            assert_eq!(format_duration(Duration::from_nanos(nanos)), expected);
        }
    }

    #[test]
    fn mask_rules_match_go_fixtures_and_quirks() {
        let half = AddressMask::parse("half").unwrap();
        assert_eq!(half.apply("11.45.1.4"), "11.45.*.*");
        assert_eq!(half.apply("11:45:14:19:19:81::"), "11:45::/32");
        assert_eq!(
            AddressMask::parse("/16+/64")
                .unwrap()
                .apply("11:45:14:19:19:81::"),
            "11:45:14:19::/64"
        );
        assert_eq!(
            AddressMask::parse("quarter")
                .unwrap()
                .apply("192.0.2.1 [2001:db8:1234::1]"),
            "192.*.*.* [2001::/16]"
        );
        assert_eq!(
            AddressMask::parse("full").unwrap().apply("192.0.2.1 [::1]"),
            "[Masked IPv4] [Masked IPv6]"
        );
        assert_eq!(
            AddressMask::parse("32+128")
                .unwrap()
                .apply("192.0.2.1 [2001:db8::1]"),
            "192.0.2.1 [2001:db8::1]"
        );
        assert_eq!(
            AddressMask::parse("16+129+ignored")
                .unwrap()
                .apply("2001:db8::1"),
            "<nil>/129"
        );
        assert_eq!(
            AddressMask::parse("16").unwrap().apply("2001:db8::1"),
            "Masked IPv6"
        );
        assert_eq!(half.apply("999.999.999.999"), "999.999.*.*");
        assert_eq!(
            AddressMask::default().apply("127.0.0.1 ::1"),
            "127.0.0.1 ::1"
        );
        for invalid in ["7", "33", "-8", "eight", "16+foo"] {
            assert!(AddressMask::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn file_output_routes_filters_and_masks_before_timestamping() {
        let directory = TempDir::new();
        let logger = Logger::from_options(LoggerOptions {
            dns_log: true,
            mask: AddressMask::parse("half").unwrap(),
            ..file_options(&directory)
        })
        .unwrap();
        logger
            .write_general_at(timestamp(), Severity::Info, "filtered")
            .unwrap();
        logger
            .write_general_at(timestamp(), Severity::Error, "failed at 192.0.2.1")
            .unwrap();
        logger
            .write_access_at(
                timestamp(),
                &AccessRecord::accepted("192.0.2.1:1234", "tcp:example.org:443"),
            )
            .unwrap();
        logger
            .write_dns_at(
                timestamp(),
                &DnsRecord {
                    server: "UDP:8.8.8.8:53".to_owned(),
                    domain: "example.org".to_owned(),
                    ..DnsRecord::default()
                },
            )
            .unwrap();
        assert_eq!(
            fs::read_to_string(directory.path("error.log")).unwrap(),
            format!("2026/09/19 12:34:56.123456 [Error] failed at 192.0.*.*{LINE_SEPARATOR}")
        );
        assert_eq!(
            fs::read_to_string(directory.path("access.log")).unwrap(),
            format!(
                "2026/09/19 12:34:56.123456 from 192.0.*.*:1234 accepted tcp:example.org:443{LINE_SEPARATOR}2026/09/19 12:34:56.123456 UDP:8.8.*.*:53 got answer: example.org -> []{LINE_SEPARATOR}"
            )
        );
        logger.close().unwrap();
    }

    #[test]
    fn dns_switch_does_not_suppress_access_records() {
        let directory = TempDir::new();
        let logger = Logger::from_options(file_options(&directory)).unwrap();
        logger
            .write_dns_at(timestamp(), &DnsRecord::default())
            .unwrap();
        logger
            .write_access_at(timestamp(), &AccessRecord::accepted("a", "b"))
            .unwrap();
        assert!(
            fs::read_to_string(directory.path("access.log"))
                .unwrap()
                .ends_with(&format!("from a accepted b{LINE_SEPARATOR}"))
        );
        logger.close().unwrap();
    }

    #[test]
    fn files_append_and_logger_lifecycle_is_shared() {
        let directory = TempDir::new();
        fs::write(directory.path("error.log"), "previous\n").unwrap();
        let logger = Logger::from_options(file_options(&directory)).unwrap();
        let clone = logger.clone();
        logger
            .write_general_at(timestamp(), Severity::Error, "first")
            .unwrap();
        clone.close().unwrap();
        assert!(!logger.is_active());
        logger
            .write_general_at(timestamp(), Severity::Error, "discarded")
            .unwrap();
        clone.start().unwrap();
        logger.start().unwrap();
        logger
            .write_general_at(timestamp(), Severity::Warning, "second")
            .unwrap();
        logger.close().unwrap();
        let output = fs::read_to_string(directory.path("error.log")).unwrap();
        assert!(output.starts_with("previous\n"));
        assert!(output.contains("[Error] first"));
        assert!(output.contains("[Warning] second"));
        assert!(!output.contains("discarded"));
    }

    #[test]
    fn reopen_switches_rotated_files_and_failed_reopen_keeps_writer() {
        let directory = TempDir::new();
        let logger = Logger::from_options(file_options(&directory)).unwrap();
        logger
            .write_general_at(timestamp(), Severity::Error, "before")
            .unwrap();
        fs::rename(directory.path("error.log"), directory.path("rotated.log")).unwrap();
        logger.reopen().unwrap();
        logger
            .write_general_at(timestamp(), Severity::Error, "after")
            .unwrap();
        assert!(
            fs::read_to_string(directory.path("rotated.log"))
                .unwrap()
                .contains("before")
        );
        assert!(
            !fs::read_to_string(directory.path("rotated.log"))
                .unwrap()
                .contains("after")
        );
        fs::rename(directory.path("error.log"), directory.path("retained.log")).unwrap();
        fs::create_dir(directory.path("error.log")).unwrap();
        assert!(logger.reopen().is_err());
        assert!(logger.is_active());
        logger
            .write_general_at(timestamp(), Severity::Error, "retained")
            .unwrap();
        logger.close().unwrap();
        assert!(
            fs::read_to_string(directory.path("retained.log"))
                .unwrap()
                .contains("retained")
        );
    }

    #[test]
    fn records_from_concurrent_clones_do_not_interleave() {
        let directory = TempDir::new();
        let logger = Logger::from_options(file_options(&directory)).unwrap();
        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let logger = logger.clone();
                thread::spawn(move || {
                    for index in 0..32 {
                        logger
                            .write_general_at(
                                timestamp(),
                                Severity::Warning,
                                format!("worker={worker} record={index}"),
                            )
                            .unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        logger.close().unwrap();
        let output = fs::read_to_string(directory.path("error.log")).unwrap();
        assert_eq!(output.lines().count(), 256);
        for worker in 0..8 {
            for index in 0..32 {
                assert_eq!(output.lines().filter(|line| *line == format!("2026/09/19 12:34:56.123456 [Warning] worker={worker} record={index}")).count(), 1);
            }
        }
    }

    #[test]
    fn tracing_bridge_keeps_span_fields_without_installing_global_state() {
        let directory = TempDir::new();
        let logger = Logger::from_options(file_options(&directory)).unwrap();
        let subscriber = tracing_subscriber::registry().with(logger.tracing_layer());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", session_id = 42u32, inbound = "socks");
            let _entered = span.enter();
            tracing::info!(target: "proxy/socks", "filtered");
            tracing::warn!(target: "proxy/socks", destination = "example.org:443", "relay failed");
        });
        logger.close().unwrap();
        let output = fs::read_to_string(directory.path("error.log")).unwrap();
        assert!(output.contains(
            "[Warning] [42] proxy/socks: relay failed destination=example.org:443 inbound=socks"
        ));
        assert!(!output.contains("filtered"));
        assert!(logger.take_tracing_error().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn new_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TempDir::new();
        let logger = Logger::from_options(file_options(&directory)).unwrap();
        logger.close().unwrap();
        assert_eq!(
            fs::metadata(directory.path("error.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
