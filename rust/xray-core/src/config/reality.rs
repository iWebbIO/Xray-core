use crate::transport::reality::{decode_short_id, handshake::ClientConfig};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Settings {
    server_name: String,
    password: String,
    public_key: String,
    short_id: String,
    fingerprint: String,
    mldsa65_verify: String,
    spider_x: String,
    master_key_log: String,
    show: bool,
}

pub(super) fn client(value: Value, http1: bool) -> Result<ClientConfig> {
    let raw: Settings =
        serde_json::from_value(value).context("invalid or unsupported REALITY client settings")?;
    ensure!(
        raw.fingerprint == "native",
        "REALITY requires fingerprint=\"native\"; browser fingerprint emulation is not migrated"
    );
    ensure!(
        raw.spider_x.is_empty(),
        "REALITY spider camouflage is not migrated"
    );
    ensure!(
        raw.master_key_log.is_empty(),
        "REALITY masterKeyLog is not migrated"
    );
    ensure!(!raw.show, "REALITY show diagnostics are not migrated");
    ensure!(
        raw.server_name.len() <= 253
            && raw.server_name.is_ascii()
            && !raw
                .server_name
                .bytes()
                .any(|byte| byte <= 32 || byte >= 127),
        "invalid REALITY serverName"
    );
    let key = if raw.password.is_empty() {
        raw.public_key
    } else {
        raw.password
    };
    let key = URL_SAFE_NO_PAD
        .decode(key)
        .context("invalid REALITY public key base64")?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("REALITY public key must contain 32 bytes"))?;
    let short = decode_short_id(&raw.short_id)
        .map_err(|error| anyhow::anyhow!("invalid REALITY shortId: {error:?}"))?;
    let mut config = ClientConfig::new(raw.server_name, key, short, [26, 9, 9]);
    if !raw.mldsa65_verify.is_empty() {
        let key = URL_SAFE_NO_PAD
            .decode(raw.mldsa65_verify)
            .context("invalid REALITY ML-DSA verification key base64")?;
        ensure!(
            key.len() == 1952,
            "REALITY ML-DSA-65 verification key must contain 1952 bytes"
        );
        config.mldsa65_verify = Some(key);
    }
    if http1 {
        config.alpn = vec![b"http/1.1".to_vec()];
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_fingerprints_and_security_options_fail_closed() {
        let key = URL_SAFE_NO_PAD.encode([7; 32]);
        let base = serde_json::json!({"fingerprint":"native","publicKey":key,"serverName":"example.com","shortId":"0102"});
        let config = client(base.clone(), true).unwrap();
        assert_eq!(config.server_public_key, [7; 32]);
        assert_eq!(config.short_id, [1, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(config.alpn, [b"http/1.1".to_vec()]);
        for (field, value) in [
            ("fingerprint", serde_json::json!("chrome")),
            ("spiderX", serde_json::json!("/")),
            ("show", serde_json::json!(true)),
            ("privateKey", serde_json::json!(key)),
            ("mldsa65Verify", serde_json::json!("AAAA")),
        ] {
            let mut config = base.clone();
            config[field] = value;
            assert!(client(config, false).is_err(), "{field}");
        }
    }
}
