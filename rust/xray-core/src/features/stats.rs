//! Thread-safe traffic counters and online-user tracking.
//!
//! Counters use Go-compatible signed atomic arithmetic. Online IPs are exact
//! strings, with one reference per live connection, matching `app/stats`.
//! Registry visitors operate on snapshots so callbacks may reenter the manager.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::policy::{SystemStatsPolicy, UserStatsPolicy};

#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicI64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn value(&self) -> i64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Set the new value and return the previous one (atomic fetch-and-reset).
    pub fn set(&self, new_value: i64) -> i64 {
        self.value.swap(new_value, Ordering::SeqCst)
    }

    /// Add a signed delta and return the new value, wrapping as Go int64 does.
    pub fn add(&self, delta: i64) -> i64 {
        self.value
            .fetch_add(delta, Ordering::SeqCst)
            .wrapping_add(delta)
    }
}

#[derive(Debug)]
struct IpEntry {
    references: usize,
    last_seen: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnlineIpEntry {
    pub ip: String,
    /// Unix time in seconds, updated by each new connection for this IP.
    pub last_seen: i64,
}

#[derive(Debug, Default)]
pub struct OnlineMap {
    entries: Mutex<BTreeMap<String, IpEntry>>,
    count: AtomicUsize,
}

impl OnlineMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_ip(&self, ip: &str) {
        self.add_ip_at(ip, unix_seconds());
    }

    /// Clock-injectable version of `add_ip`, useful for deterministic accounting.
    /// Only the two strings excluded by the source are ignored: `127.0.0.1`
    /// and `[::1]`. Other loopback spellings are deliberately not normalized.
    pub fn add_ip_at(&self, ip: &str, unix_seconds: i64) {
        if ip == "127.0.0.1" || ip == "[::1]" {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = entries.get_mut(ip) {
            entry.references = entry.references.saturating_add(1);
            entry.last_seen = unix_seconds;
        } else {
            entries.insert(
                ip.to_owned(),
                IpEntry {
                    references: 1,
                    last_seen: unix_seconds,
                },
            );
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Release one reference; removing an unknown IP is harmless.
    pub fn remove_ip(&self, ip: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = entries.get_mut(ip) {
            if entry.references > 1 {
                entry.references -= 1;
            } else {
                entries.remove(ip);
                self.count.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// Number of distinct IP strings with at least one live connection.
    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> Vec<OnlineIpEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(|(ip, entry)| OnlineIpEntry {
                ip: ip.clone(),
                last_seen: entry.last_seen,
            })
            .collect()
    }

    /// Visit a snapshot in lexical IP order, stopping when the callback says so.
    pub fn for_each(&self, mut visitor: impl FnMut(&str, i64) -> bool) {
        for entry in self.snapshot() {
            if !visitor(&entry.ip, entry.last_seen) {
                break;
            }
        }
    }

    /// Keep the returned guard alive for the lifetime of one connection.
    pub fn track(self: &Arc<Self>, ip: impl Into<String>) -> OnlineSession {
        self.track_at(ip, unix_seconds())
    }

    pub fn track_at(self: &Arc<Self>, ip: impl Into<String>, unix_seconds: i64) -> OnlineSession {
        let ip = ip.into();
        self.add_ip_at(&ip, unix_seconds);
        OnlineSession {
            map: Arc::clone(self),
            ip: Some(ip),
        }
    }
}

fn unix_seconds() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().min(i64::MAX as u64) as i64,
        Err(error) => {
            let duration = error.duration();
            let seconds = duration
                .as_secs()
                .saturating_add(u64::from(duration.subsec_nanos() != 0));
            -(seconds.min(i64::MAX as u64) as i64)
        }
    }
}

/// Owns exactly one online-map reference. Dropping it releases that reference,
/// including when a connection future is cancelled. It is intentionally not Clone.
#[derive(Debug)]
#[must_use = "keep this guard alive while the connection is online"]
pub struct OnlineSession {
    map: Arc<OnlineMap>,
    ip: Option<String>,
}

impl OnlineSession {
    /// Release early; repeated calls and the later drop have no additional effect.
    pub fn close(&mut self) {
        if let Some(ip) = self.ip.take() {
            self.map.remove_ip(&ip);
        }
    }
}

impl Drop for OnlineSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatsError {
    CounterAlreadyRegistered(String),
    OnlineMapAlreadyRegistered(String),
}

impl fmt::Display for StatsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterAlreadyRegistered(name) => {
                write!(formatter, "Counter {name} already registered.")
            }
            Self::OnlineMapAlreadyRegistered(name) => {
                write!(formatter, "OnlineMap {name} already registered.")
            }
        }
    }
}

impl std::error::Error for StatsError {}

#[derive(Debug, Default)]
struct Registry {
    counters: BTreeMap<String, Arc<Counter>>,
    online_maps: BTreeMap<String, Arc<OnlineMap>>,
}

#[derive(Debug, Default)]
pub struct StatsManager {
    registry: RwLock<Registry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub name: String,
    pub value: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficUserStat {
    pub uplink: i64,
    pub downlink: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserStat {
    pub email: String,
    pub ips: Vec<OnlineIpEntry>,
    pub traffic: Option<TrafficUserStat>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Uplink,
    Downlink,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficScope {
    User,
    Inbound,
    Outbound,
}

impl TrafficScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

pub fn traffic_counter_name(scope: TrafficScope, identity: &str, direction: Direction) -> String {
    format!(
        "{}>>>{identity}>>>traffic>>>{}",
        scope.as_str(),
        direction.as_str()
    )
}

pub fn user_online_name(email: &str) -> String {
    format!("user>>>{email}>>>online")
}

/// Optional counter handles selected by the enabled policy flags.
/// Call the add methods after successful reads/writes with the actual byte count.
#[derive(Clone, Debug, Default)]
pub struct TrafficCounters {
    pub uplink: Option<Arc<Counter>>,
    pub downlink: Option<Arc<Counter>>,
}

impl TrafficCounters {
    pub fn add_uplink(&self, bytes: usize) {
        if let Some(counter) = &self.uplink {
            counter.add(bytes as i64);
        }
    }

    pub fn add_downlink(&self, bytes: usize) {
        if let Some(counter) = &self.downlink {
            counter.add(bytes as i64);
        }
    }
}

#[derive(Debug, Default)]
#[must_use = "keep the online guard alive for the user session"]
pub struct UserSessionStats {
    pub traffic: TrafficCounters,
    pub online: Option<OnlineSession>,
}

impl StatsManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// The actual Go manager accepts any string name, including the empty string.
    pub fn register_counter(&self, name: impl Into<String>) -> Result<Arc<Counter>, StatsError> {
        let name = name.into();
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if registry.counters.contains_key(&name) {
            return Err(StatsError::CounterAlreadyRegistered(name));
        }
        let counter = Arc::new(Counter::new());
        registry.counters.insert(name, Arc::clone(&counter));
        Ok(counter)
    }

    pub fn get_or_register_counter(&self, name: impl Into<String>) -> Arc<Counter> {
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(|error| error.into_inner());
        Arc::clone(registry.counters.entry(name.into()).or_default())
    }

    pub fn get_counter(&self, name: &str) -> Option<Arc<Counter>> {
        self.registry
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .counters
            .get(name)
            .cloned()
    }

    /// Existing connection handles remain valid after unregistering.
    pub fn unregister_counter(&self, name: &str) -> Option<Arc<Counter>> {
        self.registry
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .counters
            .remove(name)
    }

    pub fn visit_counters(&self, mut visitor: impl FnMut(&str, &Arc<Counter>) -> bool) {
        let snapshot = self
            .registry
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .counters
            .clone();
        for (name, counter) in snapshot {
            if !visitor(&name, &counter) {
                break;
            }
        }
    }

    pub fn register_online_map(
        &self,
        name: impl Into<String>,
    ) -> Result<Arc<OnlineMap>, StatsError> {
        let name = name.into();
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if registry.online_maps.contains_key(&name) {
            return Err(StatsError::OnlineMapAlreadyRegistered(name));
        }
        let online_map = Arc::new(OnlineMap::new());
        registry.online_maps.insert(name, Arc::clone(&online_map));
        Ok(online_map)
    }

    pub fn get_or_register_online_map(&self, name: impl Into<String>) -> Arc<OnlineMap> {
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(|error| error.into_inner());
        Arc::clone(registry.online_maps.entry(name.into()).or_default())
    }

    pub fn get_online_map(&self, name: &str) -> Option<Arc<OnlineMap>> {
        self.registry
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .online_maps
            .get(name)
            .cloned()
    }

    pub fn unregister_online_map(&self, name: &str) -> Option<Arc<OnlineMap>> {
        self.registry
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .online_maps
            .remove(name)
    }

    pub fn visit_online_maps(&self, mut visitor: impl FnMut(&str, &Arc<OnlineMap>) -> bool) {
        let snapshot = self
            .registry
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .online_maps
            .clone();
        for (name, online_map) in snapshot {
            if !visitor(&name, &online_map) {
                break;
            }
        }
    }

    /// Return registered map names with online IPs, not stripped email addresses;
    /// this is the behavior of `app/stats.Manager.GetAllOnlineUsers`.
    pub fn get_all_online_users(&self) -> Vec<String> {
        let mut users = Vec::new();
        self.visit_online_maps(|name, map| {
            if map.count() > 0 {
                users.push(name.to_owned());
            }
            true
        });
        users
    }

    pub fn stat(&self, name: &str, reset: bool) -> Option<Stat> {
        self.get_counter(name).map(|counter| Stat {
            name: name.to_owned(),
            value: read_counter(&counter, reset),
        })
    }

    /// Literal substring query, as in StatsService.QueryStats (not a regex).
    /// Each selected counter is read/reset atomically; the set is not transactional.
    pub fn query_stats(&self, pattern: &str, reset: bool) -> Vec<Stat> {
        let mut stats = Vec::new();
        self.visit_counters(|name, counter| {
            if name.contains(pattern) {
                stats.push(Stat {
                    name: name.to_owned(),
                    value: read_counter(counter, reset),
                });
            }
            true
        });
        stats
    }

    pub fn online_ips(&self, name: &str) -> Option<Vec<OnlineIpEntry>> {
        self.get_online_map(name).map(|map| map.snapshot())
    }

    /// Return online users and optional traffic values, matching GetUsersStats.
    /// Only online users' counters are reset, and only if traffic is requested.
    /// The source takes the second `>>>` component as the email, even for an
    /// arbitrary map name. Duplicate emails coalesce; lexical map order makes
    /// the winner deterministic where the Go map iteration order is unspecified.
    pub fn users_stats(&self, include_traffic: bool, reset: bool) -> Vec<UserStat> {
        let mut users = BTreeMap::new();
        self.visit_online_maps(|name, map| {
            let ips = map.snapshot();
            if ips.is_empty() {
                return true;
            }
            let email = name.split(">>>").nth(1).unwrap_or("");
            users.insert(
                email.to_owned(),
                UserStat {
                    email: email.to_owned(),
                    ips,
                    traffic: include_traffic.then(TrafficUserStat::default),
                },
            );
            true
        });
        if include_traffic {
            self.visit_counters(|name, counter| {
                let (without_suffix, uplink) =
                    if let Some(prefix) = name.strip_suffix(">>>traffic>>>uplink") {
                        (prefix, true)
                    } else if let Some(prefix) = name.strip_suffix(">>>traffic>>>downlink") {
                        (prefix, false)
                    } else {
                        return true;
                    };
                // Go slices off len("user>>>") without validating that prefix.
                // get() preserves that behavior but safely skips malformed
                // short names or UTF-8 boundaries that cannot denote an email.
                let Some(email) = without_suffix.get("user>>>".len()..) else {
                    return true;
                };
                if let Some(traffic) = users.get_mut(email).and_then(|user| user.traffic.as_mut()) {
                    let value = read_counter(counter, reset);
                    if uplink {
                        traffic.uplink = value;
                    } else {
                        traffic.downlink = value;
                    }
                }
                true
            });
        }
        users.into_values().collect()
    }

    pub fn user_session(
        &self,
        email: &str,
        source_ip: &str,
        policy: UserStatsPolicy,
    ) -> UserSessionStats {
        if email.is_empty() {
            return UserSessionStats::default();
        }
        UserSessionStats {
            traffic: self.traffic_counters(
                TrafficScope::User,
                email,
                policy.user_uplink,
                policy.user_downlink,
            ),
            online: policy.user_online.then(|| {
                self.get_or_register_online_map(user_online_name(email))
                    .track(source_ip)
            }),
        }
    }

    pub fn inbound_counters(&self, tag: &str, policy: SystemStatsPolicy) -> TrafficCounters {
        self.traffic_counters(
            TrafficScope::Inbound,
            tag,
            policy.inbound_uplink,
            policy.inbound_downlink,
        )
    }

    pub fn outbound_counters(&self, tag: &str, policy: SystemStatsPolicy) -> TrafficCounters {
        self.traffic_counters(
            TrafficScope::Outbound,
            tag,
            policy.outbound_uplink,
            policy.outbound_downlink,
        )
    }

    fn traffic_counters(
        &self,
        scope: TrafficScope,
        identity: &str,
        uplink: bool,
        downlink: bool,
    ) -> TrafficCounters {
        if identity.is_empty() {
            return TrafficCounters::default();
        }
        TrafficCounters {
            uplink: uplink.then(|| {
                self.get_or_register_counter(traffic_counter_name(
                    scope,
                    identity,
                    Direction::Uplink,
                ))
            }),
            downlink: downlink.then(|| {
                self.get_or_register_counter(traffic_counter_name(
                    scope,
                    identity,
                    Direction::Downlink,
                ))
            }),
        }
    }

    /// Drop registry ownership of counters/maps. Outstanding connection handles
    /// survive, as in the source manager's Close implementation.
    pub fn clear(&self) {
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(|error| error.into_inner());
        registry.counters.clear();
        registry.online_maps.clear();
    }
}

fn read_counter(counter: &Counter, reset: bool) -> i64 {
    if reset {
        counter.set(0)
    } else {
        counter.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn source_counter_fixture_and_signed_overflow() {
        // app/stats/counter_test.go uses Add(1), Set(0), Value().
        let counter = Counter::new();
        assert_eq!(counter.add(1), 1);
        assert_eq!(counter.set(0), 1);
        assert_eq!(counter.value(), 0);
        assert_eq!(counter.add(-10), -10);
        assert_eq!(counter.set(i64::MAX), -10);
        assert_eq!(counter.add(1), i64::MIN);
        assert_eq!(counter.add(-1), i64::MAX);
    }

    #[test]
    fn registration_is_unique_and_get_or_register_reuses_handles() {
        let manager = StatsManager::new();
        let counter = manager.register_counter("name").unwrap();
        assert_eq!(
            manager.register_counter("name").unwrap_err(),
            StatsError::CounterAlreadyRegistered("name".into())
        );
        assert!(Arc::ptr_eq(
            &counter,
            &manager.get_or_register_counter("name")
        ));
        let map = manager.register_online_map("name").unwrap();
        assert_eq!(
            manager.register_online_map("name").unwrap_err(),
            StatsError::OnlineMapAlreadyRegistered("name".into())
        );
        assert!(Arc::ptr_eq(
            &map,
            &manager.get_or_register_online_map("name")
        ));
        manager.unregister_counter("name");
        manager.unregister_online_map("name");
        assert!(manager.get_counter("name").is_none());
        assert!(manager.get_online_map("name").is_none());
        assert!(manager.unregister_counter("absent").is_none());
        assert!(manager.register_counter("").is_ok());
    }

    #[test]
    fn concurrent_get_or_register_and_resets_preserve_all_increments() {
        let manager = Arc::new(StatsManager::new());
        let barrier = Arc::new(Barrier::new(9));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let manager = Arc::clone(&manager);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let counter = manager.get_or_register_counter("shared");
                    for _ in 0..2_000 {
                        counter.add(1);
                    }
                    counter
                })
            })
            .collect();
        barrier.wait();
        let counter = manager.get_or_register_counter("shared");
        let mut observed = 0;
        for _ in 0..500 {
            observed += counter.set(0);
        }
        for worker in workers {
            assert!(Arc::ptr_eq(&counter, &worker.join().unwrap()));
        }
        observed += counter.set(0);
        assert_eq!(observed, 16_000);
    }

    #[test]
    fn online_map_counts_unique_ips_and_keeps_latest_connection_timestamp() {
        let map = OnlineMap::new();
        map.add_ip_at("192.0.2.1", 100);
        map.add_ip_at("192.0.2.1", 200);
        map.add_ip_at("2001:db8::1", 150);
        assert_eq!(map.count(), 2);
        map.remove_ip("192.0.2.1");
        assert_eq!(map.count(), 2);
        assert_eq!(
            map.snapshot()[0],
            OnlineIpEntry {
                ip: "192.0.2.1".into(),
                last_seen: 200
            }
        );
        map.remove_ip("192.0.2.1");
        map.remove_ip("192.0.2.1");
        assert_eq!(map.count(), 1);
        map.remove_ip("2001:db8::1");
        assert_eq!(map.count(), 0);
    }

    #[test]
    fn loopback_exclusions_are_exact_source_strings() {
        let map = OnlineMap::new();
        for ip in ["127.0.0.1", "[::1]"] {
            map.add_ip_at(ip, 1);
        }
        assert_eq!(map.count(), 0);
        for ip in ["::1", "127.0.0.2", "[0:0:0:0:0:0:0:1]"] {
            map.add_ip_at(ip, 1);
        }
        assert_eq!(map.count(), 3);
    }

    #[test]
    fn session_guards_release_one_reference_on_close_or_drop() {
        let map = Arc::new(OnlineMap::new());
        let mut first = map.track_at("192.0.2.1", 1);
        let second = map.track_at("192.0.2.1", 2);
        first.close();
        first.close();
        drop(first);
        assert_eq!(map.count(), 1);
        drop(second);
        assert_eq!(map.count(), 0);
        let ignored = map.track("[::1]");
        assert_eq!(map.count(), 0);
        drop(ignored);
        assert_eq!(map.count(), 0);
    }

    #[test]
    fn parallel_sessions_share_a_map_and_release_all_references() {
        let manager = Arc::new(StatsManager::new());
        let started = Arc::new(Barrier::new(9));
        let finish = Arc::new(Barrier::new(9));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let manager = Arc::clone(&manager);
                let started = Arc::clone(&started);
                let finish = Arc::clone(&finish);
                std::thread::spawn(move || {
                    let map = manager.get_or_register_online_map("online");
                    let _guard = map.track("192.0.2.1");
                    started.wait();
                    finish.wait();
                })
            })
            .collect();
        started.wait();
        let map = manager.get_online_map("online").unwrap();
        assert_eq!(map.count(), 1);
        finish.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(map.count(), 0);
    }

    #[test]
    fn queries_use_literal_substrings_and_reset_only_matching_counters() {
        let manager = StatsManager::new();
        manager
            .get_or_register_counter("user>>>a.b>>>traffic>>>uplink")
            .add(12);
        manager
            .get_or_register_counter("user>>>axb>>>traffic>>>uplink")
            .add(34);
        let result = manager.query_stats("a.b", true);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, 12);
        assert_eq!(manager.query_stats("a.b", false)[0].value, 0);
        assert_eq!(manager.query_stats("axb", false)[0].value, 34);
        assert_eq!(manager.query_stats("", false).len(), 2);
        assert!(manager.stat("absent", false).is_none());
    }

    #[test]
    fn registry_and_online_visitors_can_reenter_and_stop() {
        let manager = StatsManager::new();
        manager.get_or_register_counter("a");
        manager.get_or_register_counter("b");
        let mut visited = 0;
        manager.visit_counters(|name, _| {
            manager.unregister_counter(name);
            visited += 1;
            false
        });
        assert_eq!(visited, 1);
        let map = manager.get_or_register_online_map("a");
        map.add_ip_at("192.0.2.1", 1);
        map.for_each(|ip, _| {
            map.remove_ip(ip);
            false
        });
        assert_eq!(map.count(), 0);
        manager.visit_online_maps(|name, _| {
            manager.unregister_online_map(name);
            false
        });
        assert!(manager.get_online_map("a").is_none());
    }

    #[test]
    fn user_stats_reset_only_online_users_when_traffic_requested() {
        let manager = StatsManager::new();
        let enabled = UserStatsPolicy {
            user_uplink: true,
            user_downlink: true,
            user_online: true,
        };
        let active = manager.user_session("active@example.test", "192.0.2.1", enabled);
        active.traffic.add_uplink(100);
        active.traffic.add_downlink(200);
        let offline = manager.user_session("offline@example.test", "192.0.2.2", enabled);
        offline.traffic.add_uplink(300);
        drop(offline);
        let users = manager.users_stats(false, true);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "active@example.test");
        assert_eq!(users[0].traffic, None);
        let users = manager.users_stats(true, true);
        assert_eq!(
            users[0].traffic,
            Some(TrafficUserStat {
                uplink: 100,
                downlink: 200
            })
        );
        assert_eq!(
            manager.users_stats(true, false)[0].traffic,
            Some(TrafficUserStat::default())
        );
        assert_eq!(
            manager.query_stats("offline@example.test>>>traffic>>>uplink", false)[0].value,
            300
        );
        assert_eq!(
            manager.get_all_online_users(),
            vec!["user>>>active@example.test>>>online"]
        );
        drop(active);
        assert!(manager.users_stats(true, false).is_empty());
    }

    #[test]
    fn user_query_uses_source_delimiter_rules_for_arbitrary_names() {
        let manager = StatsManager::new();
        for name in [
            "no-delimiters",
            "custom>>>alice>>>anything",
            "user>>>part>>>rest>>>online",
        ] {
            manager
                .get_or_register_online_map(name)
                .add_ip_at("192.0.2.1", 123);
        }
        manager
            .get_or_register_counter("custom>alice>>>traffic>>>uplink")
            .add(17);
        manager
            .get_or_register_counter("user>>>part>>>rest>>>traffic>>>uplink")
            .add(23);
        // The source would panic on this short counter name. Rust skips it.
        manager
            .get_or_register_counter(">>>traffic>>>uplink")
            .add(99);
        let users = manager.users_stats(true, true);
        assert_eq!(
            users
                .iter()
                .map(|user| user.email.as_str())
                .collect::<Vec<_>>(),
            vec!["", "alice", "part"]
        );
        assert_eq!(users[1].traffic.as_ref().unwrap().uplink, 17);
        assert_eq!(users[2].traffic.as_ref().unwrap().uplink, 0);
        assert_eq!(
            manager
                .stat("user>>>part>>>rest>>>traffic>>>uplink", false)
                .unwrap()
                .value,
            23
        );
        assert_eq!(
            manager.stat(">>>traffic>>>uplink", false).unwrap().value,
            99
        );
    }

    #[test]
    fn policy_flags_control_registration_and_empty_identities_are_ignored() {
        let manager = StatsManager::new();
        let disabled = manager.user_session("a", "192.0.2.1", UserStatsPolicy::default());
        assert!(disabled.online.is_none());
        assert!(disabled.traffic.uplink.is_none());
        let enabled = UserStatsPolicy {
            user_uplink: true,
            user_downlink: true,
            user_online: true,
        };
        let anonymous = manager.user_session("", "192.0.2.1", enabled);
        assert!(anonymous.online.is_none());
        assert!(manager.query_stats("", false).is_empty());
        let policy = SystemStatsPolicy {
            inbound_uplink: true,
            outbound_downlink: true,
            ..Default::default()
        };
        let inbound = manager.inbound_counters("socks", policy);
        let outbound = manager.outbound_counters("direct", policy);
        inbound.add_uplink(17);
        inbound.add_downlink(99);
        outbound.add_downlink(23);
        assert_eq!(
            manager
                .stat("inbound>>>socks>>>traffic>>>uplink", false)
                .unwrap()
                .value,
            17
        );
        assert_eq!(
            manager
                .stat("outbound>>>direct>>>traffic>>>downlink", false)
                .unwrap()
                .value,
            23
        );
        assert!(
            manager
                .stat("inbound>>>socks>>>traffic>>>downlink", false)
                .is_none()
        );
        assert!(manager.inbound_counters("", policy).uplink.is_none());
    }

    #[test]
    fn clearing_registry_does_not_invalidate_live_handles() {
        let manager = StatsManager::new();
        let counter = manager.get_or_register_counter("a");
        let map = manager.get_or_register_online_map("a");
        let guard = map.track("192.0.2.1");
        manager.clear();
        assert!(manager.get_counter("a").is_none());
        assert!(manager.get_online_map("a").is_none());
        assert_eq!(counter.add(2), 2);
        assert_eq!(map.count(), 1);
        drop(guard);
        assert_eq!(map.count(), 0);
    }
}
