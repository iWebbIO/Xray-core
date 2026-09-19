//! Strict ordinary-observatory JSON configuration from `infra/conf/observatory.go`.
//!
//! Only the four fields consumed by the native ordinary observer are accepted.
//! Burst `pingConfig`, sampling, connectivity fallback, and custom TLS/timeout
//! fields are not ordinary-observatory settings and fail deserialization.
//! The parent config must continue to reject top-level `burstObservatory`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    api::observatory::observation_wire, features::observatory::ObservatoryConfig as ProbeConfig,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservatoryConfig {
    pub subject_selector: Vec<String>,
    #[serde(rename = "probeURL")]
    pub probe_url: String,
    /// Go duration syntax, including fractional/compound units; JSON numbers
    /// are not accepted by the pinned duration.Duration.UnmarshalJSON.
    pub probe_interval: String,
    pub enable_concurrency: bool,
}

impl Default for ObservatoryConfig {
    fn default() -> Self {
        Self {
            subject_selector: Vec::new(),
            probe_url: String::new(),
            probe_interval: "0s".into(),
            enable_concurrency: false,
        }
    }
}

/// Validated ordinary observer configuration. Construction performs no dial or
/// DNS lookup; TLS trust and URL errors are reported before listeners start.
#[derive(Clone, Debug)]
pub struct CompiledObservatory {
    pub(crate) probe: ProbeConfig,
}

impl ObservatoryConfig {
    pub fn compile(&self) -> Result<CompiledObservatory> {
        let probe_interval = crate::router::balancer::parse_duration(&self.probe_interval)
            .context("invalid observatory probeInterval")?;
        let probe = ProbeConfig::from_wire(&observation_wire::Config {
            subject_selector: self.subject_selector.clone(),
            probe_url: self.probe_url.clone(),
            probe_interval,
            enable_concurrency: self.enable_concurrency,
        })?;
        probe.validate().context("invalid ordinary observatory")?;
        Ok(CompiledObservatory { probe })
    }
}

impl CompiledObservatory {
    pub fn probe_config(&self) -> &ProbeConfig {
        &self.probe
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn source_defaults_and_compound_duration_compile() {
        let defaults: ObservatoryConfig = serde_json::from_str("{}").unwrap();
        let compiled = defaults.compile().unwrap();
        assert!(compiled.probe.subject_selector.is_empty());
        assert_eq!(compiled.probe.probe_interval, Duration::from_secs(10));
        assert_eq!(compiled.probe.timeout, Duration::from_secs(5));
        assert_eq!(
            compiled.probe.probe_url,
            crate::features::observatory::DEFAULT_PROBE_URL
        );
        let raw: ObservatoryConfig = serde_json::from_value(serde_json::json!({
            "subjectSelector": ["proxy-", ""],
            "probeURL": "http://probe.example/status?x=1",
            "probeInterval": "1m2.5s",
            "enableConcurrency": true
        }))
        .unwrap();
        let compiled = raw.compile().unwrap();
        assert_eq!(compiled.probe.subject_selector, ["proxy-", ""]);
        assert_eq!(compiled.probe.probe_interval, Duration::from_millis(62_500));
        assert!(compiled.probe.enable_concurrency);
        assert_eq!(
            serde_json::to_value(raw).unwrap()["probeURL"],
            "http://probe.example/status?x=1"
        );
    }

    #[test]
    fn rejects_burst_unknown_fields_types_and_invalid_runtime_values() {
        for value in [
            serde_json::json!({"pingConfig": {}}),
            serde_json::json!({"sampling": 5}),
            serde_json::json!({"connectivity": "direct"}),
            serde_json::json!({"timeout": "5s"}),
            serde_json::json!({"tlsSettings": {}}),
            serde_json::json!({"probeInterval": 10}),
            serde_json::json!({"probeInterval": null}),
            serde_json::json!({"subjectSelector": "proxy-"}),
            serde_json::json!({"enableConcurrency": "true"}),
        ] {
            assert!(serde_json::from_value::<ObservatoryConfig>(value).is_err());
        }
        for interval in ["", "5", "1d", "-1ns", "9223372036854775808ns"] {
            let raw = ObservatoryConfig {
                probe_interval: interval.into(),
                ..Default::default()
            };
            assert!(raw.compile().is_err(), "{interval}");
        }
        for url in [
            "ftp://probe.example/",
            "http://user@probe.example/",
            "https://probe.example:0/",
            "https://probe.example/#fragment",
            "http://[fe80::1%25en0]/",
        ] {
            let raw = ObservatoryConfig {
                probe_url: url.into(),
                ..Default::default()
            };
            assert!(raw.compile().is_err(), "{url}");
        }
    }

    #[test]
    fn fractional_microseconds_and_zero_use_source_units() {
        for (input, expected) in [
            ("1.25us", 1_250),
            ("2µs", 2_000),
            ("3μs", 3_000),
            ("0.1ns", 10_000_000_000),
            ("-0", 10_000_000_000),
        ] {
            let raw = ObservatoryConfig {
                probe_url: "http://probe.example/".into(),
                probe_interval: input.into(),
                ..Default::default()
            };
            assert_eq!(
                raw.compile().unwrap().probe.probe_interval,
                Duration::from_nanos(expected),
                "{input}"
            );
        }
    }
}
