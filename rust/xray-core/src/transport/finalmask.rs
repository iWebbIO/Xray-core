//! Native finalmask wire transforms and connection helpers.
//!
//! These modules implement individual masks; installing a mask chain on a
//! transport, configuration conversion, and UDP socket ownership belong to the
//! caller. The Go mask manager's maximum UDP wire packet is 4096 bytes.

pub mod chain;
pub mod custom;
pub mod fragment;
pub mod noise;
pub mod salamander;

use std::io;

use rand::{CryptoRng, Rng, RngCore};

pub const UDP_SIZE: usize = 4096;

/// A nonnegative Go `crypto.RandBetween` range: upper-exclusive unless both
/// endpoints are equal. Reversed endpoints are normalized, as in Go.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleRange {
    pub min: u64,
    pub max: u64,
}

impl SampleRange {
    pub const fn fixed(value: u64) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    pub fn sample<R: Rng + CryptoRng + ?Sized>(self, rng: &mut R) -> u64 {
        let (lo, hi) = (self.min.min(self.max), self.min.max(self.max));
        if hi - lo <= 1 {
            lo
        } else {
            rng.gen_range(lo..hi)
        }
    }

    pub(crate) fn lower(self) -> u64 {
        self.min.min(self.max)
    }
    pub(crate) fn upper(self) -> u64 {
        self.min.max(self.max)
    }
}

/// Matches Go `RandBytesBetween`: inclusive endpoints and byte-modulo mapping.
pub(crate) fn random_bytes<R: RngCore + CryptoRng + ?Sized>(
    out: &mut [u8],
    min: u8,
    max: u8,
    rng: &mut R,
) {
    rng.fill_bytes(out);
    let (lo, hi) = (min.min(max), min.max(max));
    let width = u16::from(hi) - u16::from(lo) + 1;
    if width < 256 {
        for byte in out {
            *byte = lo + (u16::from(*byte) % width) as u8;
        }
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

// ---------------------------------------------------------------------------
// The streamSettings JSON surface (infra/conf/transport_finalmask.go +
// transport_internet.go's quicParams checks)
// ---------------------------------------------------------------------------

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;

/// Go's `Bandwidth` (infra/conf/transport_method.go): a number with an
/// optional decimal-unit suffix, converted to whole bytes per second. Bits
/// become bytes with the same integer division Go's `Bps()` performs.
pub fn parse_bandwidth(value: &str) -> Result<u64> {
    let text = value.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Ok(0);
    }
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let unit = unit.trim();
    let value: f64 = number
        .parse()
        .with_context(|| format!("invalid bandwidth {value:?}"))?;
    let multiplier = match unit {
        "" | "b" | "bps" => 1u64,
        "k" | "kb" | "kbps" => 1_000,
        "m" | "mb" | "mbps" => 1_000_000,
        "g" | "gb" | "gbps" => 1_000_000_000,
        "t" | "tb" | "tbps" => 1_000_000_000_000,
        other => bail!("unsupported unit: {other}"),
    };
    Ok((value * multiplier as f64) as u64 / 8)
}

/// Go's `QuicParamsConfig`: every JSON key with Go's exact spellings. Raw
/// values; `compile()` validates with `StreamConfig.Build`'s rules.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct QuicParamsSettings {
    pub congestion: String,
    pub debug: bool,
    pub bbr_profile: String,
    pub brutal_up: String,
    pub brutal_down: String,
    pub brutal_disable_loss_compensation: bool,
    pub init_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub init_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: i64,
    pub keep_alive_period: i64,
    #[serde(rename = "disablePathMTUDiscovery")]
    pub disable_path_mtu_discovery: bool,
    pub disable_chrome_parrot: bool,
    #[serde(rename = "disableGSO")]
    pub disable_gso: bool,
    pub max_incoming_streams: i64,
    pub disable_stateless_reset: bool,
}

impl QuicParamsSettings {
    pub fn from_value(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid quicParams")
    }

    /// Go `StreamConfig.Build`'s quicParams checks, verbatim, plus the named
    /// rejections for the knobs quinn cannot reproduce.
    pub fn validate(&self) -> Result<&Self> {
        match self.bbr_profile.to_ascii_lowercase().as_str() {
            "" | "conservative" | "standard" | "aggressive" => (),
            _ => bail!("unknown bbr profile"),
        }
        let up = parse_bandwidth(&self.brutal_up)?;
        let down = parse_bandwidth(&self.brutal_down)?;
        if up > 0 && up < 65_536 {
            bail!("BrutalUp must be at least 65536 bytes per second");
        }
        if down > 0 && down < 65_536 {
            bail!("BrutalDown must be at least 65536 bytes per second");
        }
        match self.congestion.to_ascii_lowercase().as_str() {
            "" | "brutal" | "reno" | "bbr" => (),
            "force-brutal" => {
                if up == 0 {
                    bail!("force-brutal requires up");
                }
            }
            congestion => bail!(
                "unknown congestion control: {congestion}, valid values: reno, bbr, brutal, force-brutal"
            ),
        }
        for (name, value) in [
            ("InitStreamReceiveWindow", self.init_stream_receive_window),
            ("MaxStreamReceiveWindow", self.max_stream_receive_window),
            (
                "InitConnectionReceiveWindow",
                self.init_connection_receive_window,
            ),
            (
                "MaxConnectionReceiveWindow",
                self.max_connection_receive_window,
            ),
        ] {
            if value > 0 && value < 16_384 {
                bail!("{name} must be at least 16384");
            }
        }
        if self.max_idle_timeout != 0 && !(4..=120).contains(&self.max_idle_timeout) {
            bail!("MaxIdleTimeout must be between 4 and 120");
        }
        if self.keep_alive_period != 0 && !(2..=60).contains(&self.keep_alive_period) {
            bail!("KeepAlivePeriod must be between 2 and 60");
        }
        if self.max_incoming_streams != 0 && self.max_incoming_streams < 8 {
            bail!("MaxIncomingStreams must be at least 8");
        }
        // Knobs whose pinned behavior quinn cannot reproduce fail by name;
        // their defaults stay as the documented deviations (PARITY_AUDIT.md):
        // quinn never sends stateless resets, always applies GSO where the
        // platform supports it, and never parrots Chrome's QUIC fingerprint.
        ensure!(
            !self.debug,
            "quicParams debug tracing belongs to the unported Hysteria congestion controllers"
        );
        ensure!(
            !self.disable_gso,
            "disableGSO cannot be honored: quinn-udp applies GSO automatically"
        );
        ensure!(
            !self.disable_stateless_reset,
            "disableStatelessReset cannot be honored: quinn never sends stateless resets"
        );
        Ok(self)
    }

    /// Apply Go's zero-value defaults and produce the compiled form.
    pub fn compile(&self) -> Result<QuicParams> {
        self.validate()?;
        // quinn exposes one stream and one connection window; Go's separate
        // init/max values must agree or the distinction is lost. Zero keeps
        // the other value; both zero keep Go's default.
        let window = |name: &str, init: u64, max: u64, default: u64| -> Result<u64> {
            match (init, max) {
                (0, 0) => Ok(default),
                (init, max) if init == max => Ok(init.max(16_384)),
                (value, 0) | (0, value) => Ok(value.max(16_384)),
                _ => bail!(
                    "quinn exposes one {name} receive window; \
                     the init and max values must match"
                ),
            }
        };
        Ok(QuicParams {
            congestion: self.congestion.to_ascii_lowercase(),
            bbr_profile: match self.bbr_profile.to_ascii_lowercase().as_str() {
                "" => "standard".to_owned(),
                profile => profile.to_owned(),
            },
            brutal_up_bps: parse_bandwidth(&self.brutal_up)?,
            brutal_down_bps: parse_bandwidth(&self.brutal_down)?,
            brutal_disable_loss_compensation: self.brutal_disable_loss_compensation,
            stream_receive_window: window(
                "stream",
                self.init_stream_receive_window,
                self.max_stream_receive_window,
                8_388_608,
            )?,
            connection_receive_window: window(
                "connection",
                self.init_connection_receive_window,
                self.max_connection_receive_window,
                8_388_608 * 5 / 2,
            )?,
            max_idle_timeout: if self.max_idle_timeout == 0 {
                Duration::from_secs(30)
            } else {
                Duration::from_secs(self.max_idle_timeout as u64)
            },
            keep_alive_period: if self.keep_alive_period == 0 {
                None
            } else {
                Some(Duration::from_secs(self.keep_alive_period as u64))
            },
            disable_path_mtu_discovery: self.disable_path_mtu_discovery,
            // Accepted as a no-op: quinn never parrots the Chrome QUIC
            // fingerprint, which is exactly what this flag asks for.
            disable_chrome_parrot: self.disable_chrome_parrot,
            max_incoming_streams: if self.max_incoming_streams == 0 {
                1_024
            } else {
                self.max_incoming_streams
            },
        })
    }
}

/// The compiled QUIC parameters one transport binds or dials with.
#[derive(Clone, Debug)]
pub struct QuicParams {
    pub congestion: String,
    pub bbr_profile: String,
    pub brutal_up_bps: u64,
    pub brutal_down_bps: u64,
    pub brutal_disable_loss_compensation: bool,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub max_idle_timeout: Duration,
    pub keep_alive_period: Option<Duration>,
    pub disable_path_mtu_discovery: bool,
    pub disable_chrome_parrot: bool,
    pub max_incoming_streams: i64,
}

impl Default for QuicParams {
    /// Go's `quicParams == nil` defaults: BBR-standard congestion with the
    /// hub/dialer window, timeout and stream-count defaults.
    fn default() -> Self {
        Self {
            congestion: String::new(),
            bbr_profile: "standard".to_owned(),
            brutal_up_bps: 0,
            brutal_down_bps: 0,
            brutal_disable_loss_compensation: false,
            stream_receive_window: 8_388_608,
            connection_receive_window: 8_388_608 * 5 / 2,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_period: None,
            disable_path_mtu_discovery: false,
            disable_chrome_parrot: false,
            max_incoming_streams: 1_024,
        }
    }
}

/// Go's `FinalMask` (the streamSettings `finalmask` object). The mask codecs
/// exist (finalmask::{custom,fragment,noise,salamander}) but the chain install
/// on a socket is not wired into the transports yet, so a non-empty chain
/// fails with a named error instead of silently running unmasked.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalMaskSettings {
    pub tcp: Vec<Value>,
    pub udp: Vec<Value>,
    pub quic_params: Option<QuicParamsSettings>,
}

impl FinalMaskSettings {
    pub fn from_value(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid finalmask")
    }

    pub fn validate(&self) -> Result<&Self> {
        ensure!(
            self.tcp.is_empty() && self.udp.is_empty(),
            "finalmask mask chains are not wired into the transports yet; remove them to run the unmasked transport"
        );
        if let Some(quic) = &self.quic_params {
            quic.validate().context("finalmask quicParams")?;
        }
        Ok(self)
    }

    /// The compiled quicParams, or Go's nil-quicParams defaults.
    pub fn compile(&self) -> Result<QuicParams> {
        self.validate()?;
        match &self.quic_params {
            Some(quic) => quic.compile(),
            None => Ok(QuicParams::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn integer_ranges_are_upper_exclusive_and_bytes_are_inclusive() {
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(SampleRange { min: 1, max: 2 }.sample(&mut rng), 1);
        assert_eq!(SampleRange { min: 2, max: 1 }.sample(&mut rng), 1);
        for _ in 0..100 {
            assert!(SampleRange { min: 3, max: 7 }.sample(&mut rng) < 7);
        }
        let mut bytes = [0; 32];
        random_bytes(&mut bytes, 0x2a, 0x2a, &mut rng);
        assert_eq!(bytes, [0x2a; 32]);
    }

    #[test]
    fn bandwidth_parses_go_spellings() {
        assert_eq!(parse_bandwidth("").unwrap(), 0);
        assert_eq!(parse_bandwidth("100").unwrap(), 12); // 100/8, integer division
        assert_eq!(parse_bandwidth(" 1 MBPS ").unwrap(), 125_000);
        assert_eq!(parse_bandwidth("512kbps").unwrap(), 64_000);
        assert_eq!(parse_bandwidth("1.5mbps").unwrap(), 187_500);
        assert_eq!(parse_bandwidth("2gbps").unwrap(), 250_000_000);
        assert!(parse_bandwidth("1pbps").is_err());
        assert!(parse_bandwidth("fast").is_err());
    }

    #[test]
    fn quic_params_validate_go_rules() {
        // Every congestion spelling and the profile set survive compile.
        for congestion in ["", "brutal", "reno", "bbr"] {
            let compiled = QuicParamsSettings::from_value(&serde_json::json!({
                "congestion": congestion, "bbrProfile": "Aggressive"
            }))
            .unwrap()
            .compile()
            .unwrap();
            assert_eq!(compiled.bbr_profile, "aggressive");
            assert_eq!(compiled.congestion, congestion);
        }
        // force-brutal requires up; unknown spellings fail.
        assert!(
            QuicParamsSettings::from_value(&serde_json::json!({"congestion": "force-brutal"}))
                .unwrap()
                .compile()
                .is_err()
        );
        assert!(
            QuicParamsSettings::from_value(&serde_json::json!({
                "congestion": "force-brutal", "brutalUp": "1mbps"
            }))
            .unwrap()
            .compile()
            .is_ok()
        );
        for bad in [
            serde_json::json!({"congestion": "turbo"}),
            serde_json::json!({"bbrProfile": "turbo"}),
            serde_json::json!({"brutalUp": "8 kbps"}),
            serde_json::json!({"initStreamReceiveWindow": 8192}),
            serde_json::json!({"maxIdleTimeout": 2}),
            serde_json::json!({"keepAlivePeriod": 61}),
            serde_json::json!({"maxIncomingStreams": 4}),
            serde_json::json!({"debug": true}),
            serde_json::json!({"disableGSO": true}),
            serde_json::json!({"disableStatelessReset": true}),
        ] {
            assert!(
                QuicParamsSettings::from_value(&bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{bad} must fail validation"
            );
        }
    }

    #[test]
    fn quic_params_windows_and_defaults() {
        // Matching init/max windows compile to the single quinn window.
        let compiled = QuicParamsSettings::from_value(&serde_json::json!({
            "initStreamReceiveWindow": 16384,
            "maxStreamReceiveWindow": 16384,
            "initConnectionReceiveWindow": 32768,
            "maxConnectionReceiveWindow": 32768,
            "maxIdleTimeout": 60,
            "keepAlivePeriod": 10,
            "maxIncomingStreams": 16,
            "disablePathMTUDiscovery": true,
            "disableChromeParrot": true
        }))
        .unwrap()
        .compile()
        .unwrap();
        assert_eq!(compiled.stream_receive_window, 16_384);
        assert_eq!(compiled.connection_receive_window, 32_768);
        assert_eq!(compiled.max_idle_timeout, Duration::from_secs(60));
        assert_eq!(compiled.keep_alive_period, Some(Duration::from_secs(10)));
        assert_eq!(compiled.max_incoming_streams, 16);
        assert!(compiled.disable_path_mtu_discovery);
        assert!(compiled.disable_chrome_parrot);
        // Divergent init/max fails by name; one-sided values carry over.
        assert!(
            QuicParamsSettings::from_value(&serde_json::json!({
                "initStreamReceiveWindow": 16384, "maxStreamReceiveWindow": 32768
            }))
            .unwrap()
            .compile()
            .is_err()
        );
        let one_sided = QuicParamsSettings::from_value(&serde_json::json!({
            "maxStreamReceiveWindow": 16384, "maxConnectionReceiveWindow": 65536
        }))
        .unwrap()
        .compile()
        .unwrap();
        assert_eq!(one_sided.stream_receive_window, 16_384);
        assert_eq!(one_sided.connection_receive_window, 65_536);
        // The nil-quicParams defaults Go applies.
        let defaults = QuicParams::default();
        assert_eq!(defaults.bbr_profile, "standard");
        assert_eq!(defaults.stream_receive_window, 8_388_608);
        assert_eq!(defaults.connection_receive_window, 8_388_608 * 5 / 2);
        assert_eq!(defaults.max_idle_timeout, Duration::from_secs(30));
        assert_eq!(defaults.max_incoming_streams, 1_024);
    }

    #[test]
    fn finalmask_rejects_mask_chains_and_honors_quic_params() {
        let masks = FinalMaskSettings::from_value(&serde_json::json!({"tcp": [{"type": "noise"}]}))
            .unwrap();
        assert!(masks.validate().is_err());
        let plain = FinalMaskSettings::from_value(&serde_json::json!({
            "tcp": [], "udp": [], "quicParams": {"congestion": "reno"}
        }))
        .unwrap();
        assert_eq!(plain.compile().unwrap().congestion, "reno");
        let empty = FinalMaskSettings::from_value(&serde_json::json!({})).unwrap();
        assert_eq!(
            empty.compile().unwrap().bbr_profile,
            QuicParams::default().bbr_profile
        );
        assert!(FinalMaskSettings::from_value(&serde_json::json!({"unknown": 1})).is_err());
    }
}
