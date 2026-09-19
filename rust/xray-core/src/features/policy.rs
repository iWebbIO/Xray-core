//! Session and system policy, including source-compatible timeout/buffer defaults.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

/// JSON `policy` object. A null level entry is ignored, as in `PolicyConfig.Build`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct PolicyConfig {
    #[serde(deserialize_with = "null_default")]
    pub levels: BTreeMap<u32, Option<LevelPolicy>>,
    pub system: Option<SystemPolicyConfig>,
}

/// JSON level policy: timeout units are seconds and `bufferSize` is KiB.
/// `None` inherits a default; `Some(0)` is an explicit zero.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct LevelPolicy {
    pub handshake: Option<u32>,
    pub conn_idle: Option<u32>,
    pub uplink_only: Option<u32>,
    pub downlink_only: Option<u32>,
    #[serde(deserialize_with = "null_default")]
    pub stats_user_uplink: bool,
    #[serde(deserialize_with = "null_default")]
    pub stats_user_downlink: bool,
    #[serde(deserialize_with = "null_default")]
    pub stats_user_online: bool,
    pub buffer_size: Option<i32>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct SystemPolicyConfig {
    #[serde(deserialize_with = "null_default")]
    pub stats_inbound_uplink: bool,
    #[serde(deserialize_with = "null_default")]
    pub stats_inbound_downlink: bool,
    #[serde(deserialize_with = "null_default")]
    pub stats_outbound_uplink: bool,
    #[serde(deserialize_with = "null_default")]
    pub stats_outbound_downlink: bool,
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub handshake: Duration,
    pub connection_idle: Duration,
    /// The downlink has closed; only uplink remains.
    pub uplink_only: Duration,
    /// The uplink has closed; only downlink remains.
    pub downlink_only: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(60),
            connection_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(1),
            downlink_only: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserStatsPolicy {
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemStatsPolicy {
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

/// Raw byte limit, preserving the Go int32 representation. -1 means unlimited;
/// zero disables the connection buffer. Other negative values can arise from
/// source-compatible environment settings or int32 overflow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferPolicy {
    pub per_connection: i32,
}

impl BufferPolicy {
    /// Convert the JSON policy's KiB setting, including Go int32 wraparound.
    pub const fn from_config_kib(value: i32) -> Self {
        Self {
            per_connection: if value < 0 {
                -1
            } else {
                value.wrapping_mul(1024)
            },
        }
    }

    /// Resolve `xray.ray.buffer.size` (MiB), without mutating process environment.
    /// `arch` accepts Rust architecture names and Go names for source fixtures.
    pub fn from_environment_value(value: Option<&str>, arch: &str) -> Self {
        // ParseInt(..., 10, 32) in common/platform rejects whitespace/overflow.
        let value = value.and_then(|value| value.parse::<i32>().ok());
        let per_connection = match value {
            Some(0) => -1,
            None | Some(-17) => match arch {
                "arm" | "mips" | "mipsle" | "mips32r6" => 0,
                "aarch64" | "arm64" | "mips64" | "mips64le" | "mips64r6" => 4 * 1024,
                _ => 512 * 1024,
            },
            Some(value) => value.wrapping_mul(1024 * 1024),
        };
        Self { per_connection }
    }

    pub fn from_environment() -> Self {
        // A present primary name takes precedence, even if its value is invalid.
        let value = std::env::var_os("xray.ray.buffer.size")
            .or_else(|| std::env::var_os("XRAY_RAY_BUFFER_SIZE"));
        Self::from_environment_value(
            value.as_deref().and_then(|value| value.to_str()),
            std::env::consts::ARCH,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    pub timeouts: Timeouts,
    pub stats: UserStatsPolicy,
    pub buffer: BufferPolicy,
}

impl SessionPolicy {
    pub fn with_default_buffer(buffer: BufferPolicy) -> Self {
        Self {
            timeouts: Timeouts::default(),
            stats: UserStatsPolicy::default(),
            buffer,
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::with_default_buffer(BufferPolicy::from_environment())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemPolicy {
    pub stats: SystemStatsPolicy,
    /// Source `ForSystem` leaves this at zero; it does not inherit session buffer.
    pub buffer: BufferPolicy,
}

impl LevelPolicy {
    pub fn resolve(&self, default_buffer: BufferPolicy) -> SessionPolicy {
        let mut session = SessionPolicy::with_default_buffer(default_buffer);
        for (value, target) in [
            (self.handshake, &mut session.timeouts.handshake),
            (self.conn_idle, &mut session.timeouts.connection_idle),
            (self.uplink_only, &mut session.timeouts.uplink_only),
            (self.downlink_only, &mut session.timeouts.downlink_only),
        ] {
            if let Some(value) = value {
                *target = Duration::from_secs(u64::from(value));
            }
        }
        session.stats = UserStatsPolicy {
            user_uplink: self.stats_user_uplink,
            user_downlink: self.stats_user_downlink,
            user_online: self.stats_user_online,
        };
        if let Some(value) = self.buffer_size {
            session.buffer = BufferPolicy::from_config_kib(value);
        }
        session
    }
}

impl From<SystemPolicyConfig> for SystemPolicy {
    fn from(value: SystemPolicyConfig) -> Self {
        Self {
            stats: SystemStatsPolicy {
                inbound_uplink: value.stats_inbound_uplink,
                inbound_downlink: value.stats_inbound_downlink,
                outbound_uplink: value.stats_outbound_uplink,
                outbound_downlink: value.stats_outbound_downlink,
            },
            buffer: BufferPolicy::default(),
        }
    }
}

/// Immutable manager suitable for sharing between connection tasks.
/// Construct from config for `app/policy` semantics, or use `Default` when no
/// policy feature exists (the latter gives level 1 a 600-second idle timeout).
#[derive(Clone, Debug)]
pub struct PolicyManager {
    levels: BTreeMap<u32, SessionPolicy>,
    system: SystemPolicy,
    fallback: SessionPolicy,
}

impl PolicyManager {
    pub fn new(config: &PolicyConfig) -> Self {
        Self::with_default_buffer(config, BufferPolicy::from_environment())
    }

    pub fn with_default_buffer(config: &PolicyConfig, buffer: BufferPolicy) -> Self {
        Self {
            levels: config
                .levels
                .iter()
                .filter_map(|(&level, config)| {
                    config
                        .as_ref()
                        .map(|config| (level, config.resolve(buffer)))
                })
                .collect(),
            system: config.system.map(Into::into).unwrap_or_default(),
            fallback: SessionPolicy::with_default_buffer(buffer),
        }
    }

    /// Stand-in for `features/policy.DefaultManager`, including its level 1 rule.
    pub fn without_config(buffer: BufferPolicy) -> Self {
        let mut manager = Self::with_default_buffer(&PolicyConfig::default(), buffer);
        let mut level_one = manager.fallback;
        level_one.timeouts.connection_idle = Duration::from_secs(600);
        manager.levels.insert(1, level_one);
        manager
    }

    pub fn for_level(&self, level: u32) -> SessionPolicy {
        self.levels.get(&level).copied().unwrap_or(self.fallback)
    }

    pub fn for_system(&self) -> SystemPolicy {
        self.system
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::without_config(BufferPolicy::from_environment())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer() -> BufferPolicy {
        BufferPolicy {
            per_connection: 512 * 1024,
        }
    }

    #[test]
    fn source_manager_fixture_inherits_unspecified_timeouts() {
        // app/policy/manager_test.go: level zero overrides only handshake.
        let config = serde_json::from_str(r#"{"levels":{"0":{"handshake":2}}}"#).unwrap();
        let manager = PolicyManager::with_default_buffer(&config, buffer());
        assert_eq!(
            manager.for_level(0).timeouts.handshake,
            Duration::from_secs(2)
        );
        assert_eq!(
            manager.for_level(0).timeouts.connection_idle,
            Duration::from_secs(300)
        );
        assert_eq!(
            manager.for_level(1),
            SessionPolicy::with_default_buffer(buffer())
        );
    }

    #[test]
    fn source_config_fixture_preserves_explicit_zero_and_null_entries() {
        let config = serde_json::from_str(include_str!("fixtures/policy.json")).unwrap();
        let manager = PolicyManager::with_default_buffer(&config, buffer());
        let zero = manager.for_level(0);
        assert_eq!(zero.timeouts.handshake, Duration::ZERO);
        assert_eq!(zero.timeouts.connection_idle, Duration::from_secs(300));
        assert_eq!(zero.buffer.per_connection, 0);
        assert!(zero.stats.user_online);
        let one = manager.for_level(1);
        assert_eq!(one.timeouts.connection_idle, Duration::from_secs(600));
        assert_eq!(one.timeouts.uplink_only, Duration::from_secs(3));
        assert_eq!(one.timeouts.downlink_only, Duration::from_secs(7));
        assert_eq!(one.buffer.per_connection, -1);
        assert!(one.stats.user_uplink && one.stats.user_downlink);
        assert_eq!(manager.for_level(2), manager.for_level(99));
        assert!(manager.for_system().stats.inbound_uplink);
        assert!(manager.for_system().stats.outbound_downlink);
        assert!(!manager.for_system().stats.inbound_downlink);
        assert_eq!(manager.for_system().buffer.per_connection, 0);
    }

    #[test]
    fn configured_and_absent_policy_have_distinct_level_one_defaults() {
        let absent = PolicyManager::without_config(buffer());
        let configured = PolicyManager::with_default_buffer(&PolicyConfig::default(), buffer());
        assert_eq!(
            absent.for_level(1).timeouts.connection_idle,
            Duration::from_secs(600)
        );
        assert_eq!(
            configured.for_level(1).timeouts.connection_idle,
            Duration::from_secs(300)
        );
        assert_eq!(absent.for_level(0), configured.for_level(0));
    }

    #[test]
    fn buffer_config_uses_kib_and_matches_signed_go_overflow() {
        // First three vectors are infra/conf/policy_test.go.
        for (input, output) in [(0, 0), (-1, -1), (1, 1024), (-100, -1), (i32::MAX, -1024)] {
            assert_eq!(BufferPolicy::from_config_kib(input).per_connection, output);
        }
    }

    #[test]
    fn environment_buffer_uses_mib_and_architecture_defaults() {
        for (value, arch, expected) in [
            (None, "x86_64", 512 * 1024),
            (None, "arm", 0),
            (None, "aarch64", 4 * 1024),
            (Some("-17"), "mips64le", 4 * 1024),
            (Some("0"), "x86_64", -1),
            (Some("2"), "x86_64", 2 * 1024 * 1024),
            (Some("-2"), "x86_64", -2 * 1024 * 1024),
            (Some("2147483648"), "arm", 0),
            (Some(" 1"), "x86_64", 512 * 1024),
            (Some("invalid"), "x86_64", 512 * 1024),
            (Some("2147483647"), "x86_64", -1024 * 1024),
        ] {
            assert_eq!(
                BufferPolicy::from_environment_value(value, arch).per_connection,
                expected
            );
        }
    }

    #[test]
    fn json_null_defaults_and_numeric_ranges_match_source_types() {
        let config: PolicyConfig = serde_json::from_str(r#"{"levels":null}"#).unwrap();
        assert!(config.levels.is_empty());
        let config: PolicyConfig =
            serde_json::from_str(r#"{"levels":{"0":{"statsUserOnline":null,"handshake":null}}}"#)
                .unwrap();
        assert_eq!(config.levels[&0], Some(LevelPolicy::default()));
        for input in [
            r#"{"levels":{"-1":{}}}"#,
            r#"{"levels":{"0":{"handshake":-1}}}"#,
            r#"{"levels":{"0":{"bufferSize":2147483648}}}"#,
        ] {
            assert!(serde_json::from_str::<PolicyConfig>(input).is_err());
        }
    }
}
