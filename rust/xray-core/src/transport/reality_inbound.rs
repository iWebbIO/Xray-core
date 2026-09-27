// P25 reality_inbound: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]
//! REALITY inbound `streamSettings` wrapper over the native authenticated server.
//!
//! This parses exactly the inbound branch of Go's `REALITYConfig.Build()`
//! (`infra/conf/transport_security.go`): the branch selected when
//! `target`/`dest` is present. `server_config()` turns the parsed policy into a
//! `reality::handshake::server::ServerConfig`, and `accept_stream()` runs the
//! native authenticated TLS 1.3 server on an inbound connection.
//!
//! The wrapper performs no target mirroring or fallback forwarding: on rejection
//! the connection is dropped, and the integrator may instead call
//! `reality::handshake::server::accept_with_target` with its own target stream,
//! using the parsed `dest`/`dest_type`/`xver` fields, to obtain Go's camouflage
//! behavior.

use std::{io, time::Duration};

use anyhow::{Context, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::transport::{
    BoxStream,
    reality::{
        ServerPolicy, decode_short_id,
        handshake::server::{self, ServerConfig, ServerConnectionInfo},
    },
};

/// Every field of Go's `REALITYConfig` JSON. `target`/`dest` are matched here
/// instead of in `Settings` so that an explicit JSON null stays distinguishable
/// from an absent field, as with Go's `json.RawMessage` comparison against nil.
const KNOWN_FIELDS: &[&str] = &[
    "masterKeyLog",
    "show",
    "target",
    "dest",
    "type",
    "xver",
    "serverNames",
    "privateKey",
    "minClientVer",
    "maxClientVer",
    "maxTimeDiff",
    "shortIds",
    "mldsa65Seed",
    "limitFallbackUpload",
    "limitFallbackDownload",
    // Client-only fields; Go's inbound branch parses and silently ignores them.
    "fingerprint",
    "serverName",
    "password",
    "publicKey",
    "shortId",
    "mldsa65Verify",
    "spiderX",
];

/// Go's `LimitFallback`, whose JSON numbers are all zero by default.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct LimitFallback {
    after_bytes: u64,
    bytes_per_sec: u64,
    burst_bytes_per_sec: u64,
}

impl LimitFallback {
    fn is_zero(&self) -> bool {
        self.after_bytes == 0 && self.bytes_per_sec == 0 && self.burst_bytes_per_sec == 0
    }
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    master_key_log: String,
    show: bool,
    r#type: String,
    xver: u64,
    server_names: Vec<String>,
    private_key: String,
    min_client_ver: String,
    max_client_ver: String,
    max_time_diff: u64,
    short_ids: Vec<String>,
    mldsa65_seed: String,
    limit_fallback_upload: LimitFallback,
    limit_fallback_download: LimitFallback,
}

/// The parsed Go REALITY inbound `realitySettings` object.
#[derive(Clone)]
pub struct InboundConfig {
    /// Allowed SNI values, compared byte-exactly like Go's server-name map.
    pub server_names: Vec<String>,
    /// Allowed short IDs, right-padded to eight bytes like Go's hex decoding.
    pub short_ids: Vec<[u8; 8]>,
    private_key: Zeroizing<[u8; 32]>,
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    pub max_time_diff: Duration,
    /// PROXY protocol version for target connections (Go validates 0, 1, 2).
    pub xver: u8,
    /// Parsed fallback destination for `accept_with_target` callers.
    pub dest: String,
    /// Inferred or explicit destination type ("tcp" or "unix" when inferred).
    pub dest_type: String,
}

impl InboundConfig {
    /// Parse the Go REALITY inbound `streamSettings.realitySettings` JSON with
    /// Go's validation rules and error precedence, then reject options the
    /// native server cannot honor. Unsupported but recognized options fail with
    /// a message naming the option; unknown options fail like Go's strict
    /// `denyUnknownFields` would not, but like the rest of this crate does.
    pub fn from_value(value: &Value) -> anyhow::Result<Self> {
        let object = value
            .as_object()
            .context("REALITY inbound settings must be a JSON object")?;
        for key in object.keys() {
            ensure!(
                KNOWN_FIELDS.contains(&key.as_str()),
                "unknown REALITY inbound setting {key:?}"
            );
        }
        let raw: Settings =
            serde_json::from_value(value.clone()).context("invalid REALITY inbound setting")?;

        // Go: `if c.Target != nil { c.Dest = c.Target }`, then the dest branch is
        // selected whenever dest is present. An explicit JSON null unmarshals
        // into Go's uint16 as a no-op, leaving zero, hence "localhost:0".
        let selected = match (object.get("target"), object.get("dest")) {
            (Some(target), _) => Some(target),
            (None, Some(dest)) => Some(dest),
            (None, None) => None,
        };
        let mut dest = String::new();
        let mut dest_type = raw.r#type.clone();
        if let Some(raw_dest) = selected {
            dest = match raw_dest {
                Value::Null => "0".to_string(),
                Value::Number(number) => number
                    .as_u64()
                    .filter(|value| *value <= u16::MAX as u64)
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                Value::String(text) => text.clone(),
                _ => String::new(),
            };
            if dest_type.is_empty() && !dest.is_empty() {
                match dest.as_bytes()[0] {
                    b'@' | b'/' => dest_type = "unix".into(),
                    _ => {
                        if dest.parse::<i64>().is_ok() {
                            dest = format!("localhost:{dest}");
                        }
                        if looks_like_host_port(&dest) {
                            dest_type = "tcp".into();
                        }
                    }
                }
            }
        }
        ensure!(
            !dest_type.is_empty(),
            "please fill in a valid value for \"target\""
        );
        ensure!(
            raw.xver <= 2,
            "invalid PROXY protocol version, \"xver\" only accepts 0, 1, 2"
        );
        ensure!(!raw.server_names.is_empty(), "empty \"serverNames\"");
        ensure!(!raw.private_key.is_empty(), "empty \"privateKey\"");
        let private_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&raw.private_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow!("invalid \"privateKey\": {}", raw.private_key))?;
        let min_client_ver = (!raw.min_client_ver.is_empty())
            .then(|| parse_client_ver("minClientVer", &raw.min_client_ver))
            .transpose()?;
        let max_client_ver = (!raw.max_client_ver.is_empty())
            .then(|| parse_client_ver("maxClientVer", &raw.max_client_ver))
            .transpose()?;
        ensure!(!raw.short_ids.is_empty(), "empty \"shortIds\"");
        let mut short_ids = Vec::with_capacity(raw.short_ids.len());
        for (index, value) in raw.short_ids.iter().enumerate() {
            ensure!(
                value.len() <= 16,
                "too long \"shortIds[{}]\": {}",
                index,
                value
            );
            let short_id = decode_short_id(value)
                .map_err(|_| anyhow!("invalid \"shortIds[{}]\": {}", index, value))?;
            short_ids.push(short_id);
        }
        if !raw.mldsa65_seed.is_empty() {
            ensure!(
                raw.mldsa65_seed != raw.private_key,
                "\"mldsa65Seed\" and \"privateKey\" can not be the same value: {}",
                raw.mldsa65_seed
            );
            let seed = URL_SAFE_NO_PAD
                .decode(&raw.mldsa65_seed)
                .context("invalid \"mldsa65Seed\"")?;
            ensure!(
                seed.len() == 32,
                "invalid \"mldsa65Seed\": {}",
                raw.mldsa65_seed
            );
            // The native REALITY server never signs with ML-DSA-65, so refuse the
            // seed instead of silently dropping the extra certificate proof.
            bail!(
                "\"mldsa65Seed\" is not migrated: the native REALITY server does not sign with ML-DSA-65"
            );
        }
        for name in &raw.server_names {
            let lowered = name.to_ascii_lowercase();
            if lowered.ends_with(".ru")
                || lowered.ends_with(".ir")
                || lowered.ends_with(".cn")
                || lowered.contains("apple")
                || lowered.contains("icloud")
                || lowered.contains("microsoft")
            {
                tracing::warn!(
                    "REALITY: Choosing \"{}\" as the target will increase the likelihood of your server's IP being blocked by the GFW",
                    lowered
                );
            }
        }
        ensure!(
            raw.limit_fallback_upload.is_zero() && raw.limit_fallback_download.is_zero(),
            "\"limitFallbackUpload\"/\"limitFallbackDownload\" are not migrated: this wrapper performs no fallback forwarding"
        );
        ensure!(!raw.show, "\"show\" diagnostics are not migrated");
        ensure!(
            raw.master_key_log.is_empty() || raw.master_key_log == "none",
            "\"masterKeyLog\" key logging is not migrated"
        );
        Ok(Self {
            server_names: raw.server_names,
            short_ids,
            private_key: Zeroizing::new(private_key),
            min_client_ver,
            max_client_ver,
            max_time_diff: Duration::from_millis(raw.max_time_diff),
            xver: raw.xver as u8,
            dest,
            dest_type,
        })
    }

    /// Build the native authenticated server config. Go-valid values the native
    /// server cannot express fail here with a message naming the option.
    pub fn server_config(&self) -> io::Result<ServerConfig> {
        if let (Some(min), Some(max)) = (self.min_client_ver, self.max_client_ver)
            && min > max
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "\"minClientVer\" exceeds \"maxClientVer\": the native REALITY server rejects reversed ranges",
            ));
        }
        if self.server_names.iter().any(|name| {
            name.is_empty()
                || name.len() > 253
                || !name.is_ascii()
                || name.ends_with('.')
                || name.bytes().any(|byte| byte <= 32 || byte >= 127)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid REALITY server policy name",
            ));
        }
        if self.max_time_diff.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "\"maxTimeDiff\" must be nonzero: Go treats zero as disabled, but the native REALITY server requires a timestamp window",
            ));
        }
        Ok(ServerConfig::new(
            *self.private_key,
            ServerPolicy {
                server_names: self.server_names.clone(),
                short_ids: self.short_ids.clone(),
                min_client_version: self.min_client_ver,
                max_client_version: self.max_client_ver,
                max_time_diff: self.max_time_diff,
            },
        ))
    }
}

/// Parse Go's dotted three-byte client version, defaulting missing parts to
/// zero and matching Go's error strings.
fn parse_client_ver(field: &str, value: &str) -> anyhow::Result<[u8; 3]> {
    let mut out = [0u8; 3];
    for (index, part) in value.split('.').enumerate() {
        if index == 3 {
            bail!("invalid \"{field}\": {value}");
        }
        if part.starts_with('+') || part.starts_with('-') {
            bail!("\"{field}[{index}]\" should be less than 256");
        }
        match part.parse::<u32>() {
            Ok(number) if number <= 255 => out[index] = number as u8,
            _ => bail!("\"{field}[{index}]\" should be less than 256"),
        }
    }
    Ok(out)
}

/// Structural `net.SplitHostPort` acceptance test, used only to infer the
/// "tcp" target type exactly as Go does: bracketed IPv6 hosts, named
/// (non-numeric) ports, and empty hosts are accepted; missing or empty ports
/// and unbracketed multi-colon hosts are not.
fn looks_like_host_port(address: &str) -> bool {
    if let Some(rest) = address.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        rest[end + 1..]
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty())
    } else {
        let Some((host, port)) = address.rsplit_once(':') else {
            return false;
        };
        !port.is_empty() && !host.contains(':')
    }
}

/// Run the complete authenticated REALITY server handshake on `stream`.
///
/// On success the returned stream is the decrypted application stream and the
/// connection info is always `Some`. Rejected peers surface as an `io::Error`
/// and the connection is dropped: this wrapper performs none of Go's target
/// mirroring or unauthenticated-traffic forwarding (`accept_with_target`).
pub async fn accept_stream(
    config: &InboundConfig,
    stream: BoxStream,
) -> io::Result<(BoxStream, Option<ServerConnectionInfo>)> {
    let server = config.server_config()?;
    let (stream, info) = server::accept(stream, server).await?;
    Ok((Box::new(stream), Some(info)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

    use crate::transport::reality::handshake::{ClientConfig, client as reality_client};

    fn private_key() -> String {
        URL_SAFE_NO_PAD.encode([7u8; 32])
    }

    fn base() -> Value {
        json!({
            "dest": "example.com:443",
            "serverNames": ["example.test"],
            "privateKey": private_key(),
            "shortIds": ["0101010101010101"],
            "maxTimeDiff": 120000,
        })
    }

    fn parse(value: Value) -> anyhow::Result<InboundConfig> {
        InboundConfig::from_value(&value)
    }

    // The config types intentionally do not implement Debug (they hold private
    // key material), so unwrap_err() cannot be used on their results.
    fn parse_err(value: Value) -> anyhow::Error {
        match parse(value) {
            Ok(_) => panic!("REALITY inbound settings unexpectedly parsed"),
            Err(error) => error,
        }
    }

    fn server_config_err(config: &InboundConfig) -> io::Error {
        match config.server_config() {
            Ok(_) => panic!("REALITY inbound server config unexpectedly built"),
            Err(error) => error,
        }
    }

    #[test]
    fn parse_valid_settings_fields_and_defaults() {
        let config = parse(json!({
            "target": "example.org:8443",
            "serverNames": ["example.test", "a.test"],
            "privateKey": private_key(),
            "minClientVer": "26.3",
            "maxClientVer": "27.0.0",
            "maxTimeDiff": 1500,
            "shortIds": ["0101010101010101", "", "aBcD"],
            "xver": 1,
            "masterKeyLog": "none",
            "limitFallbackUpload": {"afterBytes": 0},
            "fingerprint": "chrome",
            "password": "ignored-by-go-inbound",
        }))
        .unwrap();
        assert_eq!(config.dest, "example.org:8443");
        assert_eq!(config.dest_type, "tcp");
        assert_eq!(config.xver, 1);
        assert_eq!(
            config.server_names,
            ["example.test".to_string(), "a.test".to_string()]
        );
        assert_eq!(
            config.short_ids,
            [[1u8; 8], [0u8; 8], [0xab, 0xcd, 0, 0, 0, 0, 0, 0]]
        );
        assert_eq!(config.min_client_ver, Some([26, 3, 0]));
        assert_eq!(config.max_client_ver, Some([27, 0, 0]));
        assert_eq!(config.max_time_diff, Duration::from_millis(1500));
        // Defaults: no version bounds, zero xver and maxTimeDiff, tcp target.
        // An absent maxTimeDiff stays zero like Go's config copy, where the
        // pinned server reads zero as "clock check disabled".
        let config = parse(json!({
            "dest": "example.com:443",
            "serverNames": ["example.test"],
            "privateKey": private_key(),
            "shortIds": ["0101010101010101"],
        }))
        .unwrap();
        assert_eq!(config.min_client_ver, None);
        assert_eq!(config.max_client_ver, None);
        assert_eq!(config.xver, 0);
        assert_eq!(config.max_time_diff, Duration::ZERO);
        let server = parse(base()).unwrap().server_config().unwrap();
        assert_eq!(server.public_key(), x25519([7; 32], X25519_BASEPOINT_BYTES));
    }

    #[test]
    fn dest_and_target_inference_matches_go() {
        for (value, dest_type, dest) in [
            (json!("443"), "tcp", "localhost:443"),
            (json!(443), "tcp", "localhost:443"),
            (json!("example.com:443"), "tcp", "example.com:443"),
            (json!("example.com:imap"), "tcp", "example.com:imap"),
            (json!("[::1]:443"), "tcp", "[::1]:443"),
            (json!("/run/x.sock"), "unix", "/run/x.sock"),
            (json!("@abstract"), "unix", "@abstract"),
            // Go quirk: net.SplitHostPort accepts any non-empty port, so this
            // string infers "tcp" (use "type": "unix" for unix paths with ports).
            (json!("unix:/run/x.sock"), "tcp", "unix:/run/x.sock"),
            // Go quirk: JSON null unmarshals into uint16 as zero.
            (json!(null), "tcp", "localhost:0"),
            (json!(0), "tcp", "localhost:0"),
        ] {
            let config = parse(json!({
                "dest": value,
                "serverNames": ["a.test"],
                "privateKey": private_key(),
                "shortIds": [""],
                "maxTimeDiff": 1,
            }))
            .unwrap();
            assert_eq!(config.dest_type, dest_type, "{value}");
            assert_eq!(config.dest, dest, "{value}");
        }
        for value in [
            json!("example.com"),
            json!("localhost:"),
            json!("::1:443"),
            json!(65536),
            json!(-1),
            json!(443.5),
            json!(true),
            json!(["a"]),
            json!(""),
        ] {
            let error = parse_err(json!({
                "dest": value,
                "serverNames": ["a.test"],
                "privateKey": private_key(),
                "shortIds": [""],
                "maxTimeDiff": 1,
            }));
            assert!(
                error
                    .to_string()
                    .contains("please fill in a valid value for \"target\""),
                "{value}: {error}"
            );
        }
        // target overrides dest whenever present, even with an explicit null.
        let config = parse(json!({
            "target": "a.test:1",
            "dest": "b.test:2",
            "serverNames": ["a.test"],
            "privateKey": private_key(),
            "shortIds": [""],
            "maxTimeDiff": 1,
        }))
        .unwrap();
        assert_eq!(config.dest, "a.test:1");
        let config = parse(json!({
            "target": null,
            "dest": "b.test:2",
            "serverNames": ["a.test"],
            "privateKey": private_key(),
            "shortIds": [""],
            "maxTimeDiff": 1,
        }))
        .unwrap();
        assert_eq!(config.dest, "localhost:0");
        // An explicit type skips Go's inference, keeping dest unmodified.
        let config = parse(json!({
            "dest": "443",
            "type": "tcp",
            "serverNames": ["a.test"],
            "privateKey": private_key(),
            "shortIds": [""],
            "maxTimeDiff": 1,
        }))
        .unwrap();
        assert_eq!(config.dest, "443");
        assert_eq!(config.dest_type, "tcp");
        let config = parse(json!({
            "dest": true,
            "type": "tcp",
            "serverNames": ["a.test"],
            "privateKey": private_key(),
            "shortIds": [""],
            "maxTimeDiff": 1,
        }))
        .unwrap();
        assert_eq!(config.dest, "");
    }

    #[test]
    fn go_validation_error_matrix() {
        let cases = [
            (json!({}), "please fill in a valid value for \"target\""),
            (
                json!({"serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [""]}),
                "please fill in a valid value for \"target\"",
            ),
            (
                json!({"dest": "a.test:1", "xver": 3}),
                "invalid PROXY protocol version, \"xver\" only accepts 0, 1, 2",
            ),
            (json!({"dest": "a.test:1"}), "empty \"serverNames\""),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"]}),
                "empty \"privateKey\"",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": "!!!"}),
                "invalid \"privateKey\": !!!",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": URL_SAFE_NO_PAD.encode([1u8; 31])}),
                "invalid \"privateKey\"",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key()}),
                "empty \"shortIds\"",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [], "minClientVer": "1.2.3.4"}),
                "invalid \"minClientVer\": 1.2.3.4",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [], "minClientVer": "1.2.300"}),
                "\"minClientVer[2]\" should be less than 256",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [], "minClientVer": "1..2"}),
                "\"minClientVer[1]\" should be less than 256",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [], "maxClientVer": "x"}),
                "\"maxClientVer[0]\" should be less than 256",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": ["010203040506070809"]}),
                "too long \"shortIds[0]\"",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": ["abc"]}),
                "invalid \"shortIds[0]\": abc",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": ["0x"]}),
                "invalid \"shortIds[0]\": 0x",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [""], "mldsa65Seed": private_key()}),
                "\"mldsa65Seed\" and \"privateKey\" can not be the same value",
            ),
            (
                json!({"dest": "a.test:1", "serverNames": ["a.test"], "privateKey": private_key(), "shortIds": [""], "mldsa65Seed": "AAAA"}),
                "invalid \"mldsa65Seed\"",
            ),
        ];
        for (value, message) in cases {
            let error = parse_err(value.clone());
            assert!(
                error.to_string().contains(message),
                "{value}: {error} does not contain {message}"
            );
        }
    }

    #[test]
    fn unsupported_native_options_fail_closed() {
        for (field, setting, message) in [
            ("show", json!(true), "\"show\" diagnostics are not migrated"),
            (
                "masterKeyLog",
                json!("keys.log"),
                "\"masterKeyLog\" key logging is not migrated",
            ),
            (
                "mldsa65Seed",
                json!(URL_SAFE_NO_PAD.encode([8u8; 32])),
                "does not sign with ML-DSA-65",
            ),
            (
                "limitFallbackUpload",
                json!({"bytesPerSec": 100}),
                "fallback forwarding",
            ),
            (
                "limitFallbackDownload",
                json!({"afterBytes": 1}),
                "fallback forwarding",
            ),
            ("unknownField", json!(1), "unknown REALITY inbound setting"),
        ] {
            let mut value = base();
            value[field] = setting;
            let error = parse_err(value);
            assert!(error.to_string().contains(message), "{field}: {error}");
        }
        // Go's inbound branch ignores client-only fields; keep accepting them.
        for field in [
            "fingerprint",
            "serverName",
            "password",
            "publicKey",
            "shortId",
            "mldsa65Verify",
            "spiderX",
        ] {
            let mut value = base();
            value[field] = json!("client-only-value");
            parse(value).unwrap_or_else(|error| panic!("{field}: {error}"));
        }
        let mut all_limits_zero = base();
        all_limits_zero["limitFallbackUpload"] = json!({});
        all_limits_zero["limitFallbackDownload"] = json!({});
        parse(all_limits_zero).unwrap();
    }

    #[test]
    fn server_config_enforces_native_gates() {
        // Go accepts maxTimeDiff 0 (disabled checking); the native server cannot.
        let mut value = base();
        value.as_object_mut().unwrap().remove("maxTimeDiff");
        let config = parse(value).unwrap();
        let error = server_config_err(&config);
        assert!(error.to_string().contains("maxTimeDiff"));
        let mut value = base();
        value["minClientVer"] = json!("28.0.0");
        value["maxClientVer"] = json!("27.0.0");
        let config = parse(value).unwrap();
        let error = server_config_err(&config);
        assert!(error.to_string().contains("reversed ranges"));
        let mut value = base();
        value["serverNames"] = json!(["bad name"]);
        let config = parse(value).unwrap();
        assert!(config.server_config().is_err());
        let mut value = base();
        value["serverNames"] = json!(["trailing.dot."]);
        let config = parse(value).unwrap();
        assert!(config.server_config().is_err());
    }

    fn test_config() -> InboundConfig {
        let mut value = base();
        value["minClientVer"] = json!("26.1.1");
        value["maxClientVer"] = json!("27.0.0");
        parse(value).unwrap()
    }

    fn client_config(config: &InboundConfig, server_name: &str, short_id: [u8; 8]) -> ClientConfig {
        ClientConfig::new(
            server_name.to_owned(),
            config.server_config().unwrap().public_key(),
            short_id,
            [26, 9, 9],
        )
    }

    #[tokio::test]
    async fn accept_stream_relays_echo_payload_for_native_client() {
        let config = test_config();
        let client = client_config(&config, "example.test", [1; 8]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut stream, info) = accept_stream(&config, Box::new(socket)).await.unwrap();
            let info = info.unwrap();
            let mut buffer = vec![0; 64];
            let count = stream.read(&mut buffer).await.unwrap();
            buffer.truncate(count);
            stream.write_all(&buffer).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            (buffer, info)
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut client, _) = reality_client(Box::new(tcp), client).await.unwrap();
            let payload = b"REALITY inbound echo payload";
            client.write_all(payload).await.unwrap();
            client.flush().await.unwrap();
            let mut received = vec![0; payload.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
        })
        .await
        .unwrap();
        let (received, info) = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"REALITY inbound echo payload");
        assert_eq!(info.server_name, "example.test");
        assert_eq!(info.identity.short_id, [1; 8]);
        assert_eq!(info.identity.version, [26, 9, 9]);
    }

    #[tokio::test]
    async fn accept_stream_rejects_short_id_and_server_name_mismatches() {
        for (server_name, short_id) in [
            ("example.test", [9u8; 8]), // wrong short ID
            ("wrong.test", [1u8; 8]),   // wrong server name
        ] {
            let config = test_config();
            let client = client_config(&config, server_name, short_id);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                accept_stream(&config, Box::new(socket)).await
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
                assert!(
                    reality_client(Box::new(tcp), client).await.is_err(),
                    "{server_name} handshake unexpectedly succeeded"
                );
            })
            .await
            .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_err(), "{server_name} server accepted a mismatch");
        }
    }
}
