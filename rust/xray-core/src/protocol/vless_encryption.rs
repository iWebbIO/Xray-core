// P03 vless_encryption: agent-owned implementation file.
#![allow(dead_code)]

//! VLESS post-quantum account encryption wire sessions.
//!
//! This is the wire layer the VLESS outbound/inbound handlers use for the
//! `mlkem768x25519plus` account `encryption` / inbound `decryption` settings
//! (`proxy/vless/encryption/{client,server,common}.go` plus the account string
//! parsing in `infra/conf/vless.go`): it parses the dot-separated account
//! parameters (X25519 public keys / ML-KEM-768 public keys for the client,
//! 32-byte X25519 private keys / 64-byte ML-KEM-768 seeds for the server, the
//! XOR mode, ticket lifetime and padding schedule fields), then builds and
//! runs the encrypted session on top of the native 1-RTT hybrid handshake in
//! [`crate::protocol::vless_security::handshake`].
//!
//! The returned [`EncryptedStream`] transparently encrypts and decrypts the
//! inner VLESS request header and body records in both directions; replay of
//! an identical authenticated client hello is rejected by the shared server
//! state (Go's `ServerInstance` session/ticket replay maps onto the
//! handshake's bounded replay history).
//!
//! Go options that this profile does not implement are identified and then
//! rejected with a clear error instead of being silently ignored: XOR
//! disguise modes (`xorpub`, `random`), 0-RTT ticket resumption and nonzero
//! server ticket lifetimes, and configured fragmented padding schedules.

use std::io;

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::protocol::vless_security::handshake::{self, ClientConfig, ServerConfig};

pub use crate::protocol::vless_security::encryption::Algorithm;
pub use crate::protocol::vless_security::handshake::{EncryptedStream, MAX_RELAY_KEYS};

/// Account encryption prefix required by `infra/conf/vless.go`.
pub const ENCRYPTION_PREFIX: &str = "mlkem768x25519plus";

/// Byte offset of the relay/padding fields inside an account text:
/// `len("mlkem768x25519plus") + 1 + len(mode) + 1 + len(seconds) + 1`.
/// All accepted mode names ("native", "xorpub", "random") are six bytes.
const RELAY_FIELDS_OFFSET: usize = 27;

/// Fields shorter than this are padding-schedule parts, not relay keys.
const PADDING_FIELD_LEN: usize = 20;

/// Client relay keys: 32-byte X25519 public keys or 1184-byte ML-KEM-768
/// encapsulation keys (`infra/conf/vless.go` user parsing).
const CLIENT_KEY_LENGTHS: [usize; 2] = [32, 1184];

/// Server relay seeds: 32-byte X25519 private keys or 64-byte ML-KEM-768
/// seeds (`infra/conf/vless.go` settings parsing).
const SERVER_KEY_LENGTHS: [usize; 2] = [32, 64];

fn unsupported(field: &str, text: &str) -> anyhow::Error {
    let scope = if field == "encryption" {
        "users"
    } else {
        "settings"
    };
    anyhow::anyhow!("VLESS {scope}: unsupported \"{field}\": {text}")
}

/// Split an account text into its padding-schedule part and its decoded relay
/// keys, porting the scan and slicing arithmetic of `infra/conf/vless.go`.
/// Short fields accumulate padding characters; longer fields must decode to
/// one of `key_lengths`. `seconds` is the raw third field.
fn split_padding_and_keys<'a>(
    text: &'a str,
    seconds: &str,
    fields_after: &[&'a str],
    key_lengths: &[usize; 2],
    field: &str,
) -> Result<(String, Vec<Vec<u8>>)> {
    let mut padding_chars = 0usize;
    for relay in fields_after {
        if relay.len() < PADDING_FIELD_LEN {
            padding_chars += relay.len() + 1;
            continue;
        }
        // Go ignores the decode error and only inspects the decoded length.
        let decoded = URL_SAFE_NO_PAD.decode(relay).unwrap_or_default();
        if !key_lengths.contains(&decoded.len()) {
            return Err(unsupported(field, text));
        }
    }
    let bytes = text.as_bytes();
    let start = RELAY_FIELDS_OFFSET + seconds.len();
    // s.len() >= 4 guarantees at least one byte after the third dot.
    let remainder = &bytes[start..];
    if padding_chars > remainder.len() {
        // Go panics on this slice; a padding-only account has no relay keys.
        bail!("VLESS {field} has a padding schedule but no relay key");
    }
    let (padding, keys_text) = if padding_chars > 0 {
        (&remainder[..padding_chars - 1], &remainder[padding_chars..])
    } else {
        (&bytes[..0], remainder)
    };
    let padding = String::from_utf8_lossy(padding).into_owned();
    let mut keys = Vec::new();
    for encoded in keys_text.split(|byte| *byte == b'.') {
        let encoded = std::str::from_utf8(encoded).map_err(|_| {
            anyhow::anyhow!("failed to use VLESS {field}: invalid relay key encoding")
        })?;
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            anyhow::anyhow!("failed to use VLESS {field}: invalid relay key base64url")
        })?;
        if !key_lengths.contains(&decoded.len()) {
            bail!(
                "failed to use VLESS {field}: relay key must be a {}-byte or {}-byte key, got {} bytes",
                key_lengths[0],
                key_lengths[1],
                decoded.len()
            );
        }
        keys.push(decoded);
    }
    Ok((padding, keys))
}

/// Port of `ParsePadding` in `proxy/vless/encryption/common.go`. The returned
/// value counts the random padding length groups; the native session profile
/// never applies them (see the module documentation).
fn parse_padding(padding: &str) -> Result<usize> {
    if padding.is_empty() {
        return Ok(0);
    }
    let mut groups = 0usize;
    let mut total_max: i64 = 0;
    for (index, part) in padding.split('.').enumerate() {
        let fields: Vec<&str> = part.split('-').collect();
        if fields.len() < 3 || fields[0].is_empty() || fields[1].is_empty() || fields[2].is_empty()
        {
            bail!("invalid padding lenth/gap parameter: {part}");
        }
        let mut value = [0i64; 3];
        for (slot, raw) in fields.iter().take(3).enumerate() {
            value[slot] = raw
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid padding lenth/gap parameter: {part}"))?;
        }
        if index == 0 && (value[0] < 100 || value[1] < 35 || value[2] < 35) {
            bail!("first padding length must not be smaller than 35");
        }
        if index % 2 == 0 {
            groups += 1;
            total_max += value[1].max(value[2]);
        }
    }
    if total_max > 18 + 65535 {
        bail!("total padding length must not be larger than 65553");
    }
    Ok(groups)
}

/// Reject the Go account options this profile does not implement. Each option
/// is identified first, then named in the error.
fn reject_unsupported_profile(
    field: &str,
    mode: &str,
    xor_mode: u32,
    seconds_nonzero: bool,
    seconds_label: &str,
    padding: &str,
) -> Result<()> {
    if xor_mode > 0 {
        bail!(
            "VLESS {field} XOR mode \"{mode}\" (disguising relay keys with AES-CTR) is not supported by the native session profile"
        );
    }
    if seconds_nonzero {
        bail!(
            "VLESS {field} {seconds_label} (ticket-based session resumption) is not supported by the native 1-RTT session profile"
        );
    }
    let groups = parse_padding(padding)?;
    if groups > 0 {
        bail!(
            "VLESS {field} configured padding schedule \"{padding}\" is not supported by the native session profile"
        );
    }
    Ok(())
}

/// Parsed client account parameters for the `encryption` setting.
struct ClientAccountWire {
    mode: &'static str,
    xor_mode: u32,
    /// Go sets `account.Seconds = 1` for the `0rtt` profile.
    seconds: u32,
    padding: String,
    keys: Vec<Vec<u8>>,
}

/// Parsed inbound settings parameters for the `decryption` setting.
struct ServerAccountWire {
    mode: &'static str,
    xor_mode: u32,
    seconds_from: i64,
    seconds_to: i64,
    padding: String,
    keys: Vec<Vec<u8>>,
}

fn parse_mode(field: &str, text: &str, encoded: &str) -> Result<(&'static str, u32)> {
    match encoded {
        "native" => Ok(("native", 0)),
        "xorpub" => Ok(("xorpub", 1)),
        "random" => Ok(("random", 2)),
        _ => Err(unsupported(field, text)),
    }
}

/// Port of the client `encryption` parsing in `infra/conf/vless.go`.
fn parse_client_wire(encryption: &str) -> Result<ClientAccountWire> {
    let fields: Vec<&str> = encryption.split('.').collect();
    if fields.len() < 4 || fields[0] != ENCRYPTION_PREFIX {
        return Err(unsupported("encryption", encryption));
    }
    let (mode, xor_mode) = parse_mode("encryption", encryption, fields[1])?;
    let seconds = match fields[2] {
        "1rtt" => 0,
        "0rtt" => 1,
        _ => return Err(unsupported("encryption", encryption)),
    };
    let (padding, keys) = split_padding_and_keys(
        encryption,
        fields[2],
        &fields[3..],
        &CLIENT_KEY_LENGTHS,
        "encryption",
    )?;
    Ok(ClientAccountWire {
        mode,
        xor_mode,
        seconds,
        padding,
        keys,
    })
}

/// Port of the inbound `decryption` parsing in `infra/conf/vless.go`.
fn parse_server_wire(decryption: &str) -> Result<ServerAccountWire> {
    let fields: Vec<&str> = decryption.split('.').collect();
    if fields.len() < 4 || fields[0] != ENCRYPTION_PREFIX {
        return Err(unsupported("decryption", decryption));
    }
    let (mode, xor_mode) = parse_mode("decryption", decryption, fields[1])?;
    // seconds: "600s", "300-600s", "0s", "0-0s"; one trailing "s" is trimmed.
    let trimmed = fields[2].strip_suffix('s').unwrap_or(fields[2]);
    let parts: Vec<&str> = trimmed.splitn(2, '-').collect();
    let seconds_from: i64 = parts[0]
        .parse()
        .map_err(|_| unsupported("decryption", decryption))?;
    let seconds_to: i64 = if parts.len() == 2 {
        parts[1]
            .parse()
            .map_err(|_| unsupported("decryption", decryption))?
    } else {
        0
    };
    let (padding, keys) = split_padding_and_keys(
        decryption,
        fields[2],
        &fields[3..],
        &SERVER_KEY_LENGTHS,
        "decryption",
    )?;
    Ok(ServerAccountWire {
        mode,
        xor_mode,
        seconds_from,
        seconds_to,
        padding,
        keys,
    })
}

/// Client-side wire parameters for one VLESS account `encryption` setting.
///
/// Construct one per account (for example through
/// [`ClientEncryption::from_value`]) and reuse it for every connection of
/// that outbound.
pub struct ClientEncryption {
    config: ClientConfig,
    relay_key_count: usize,
}

// Debug without key material: the account text holds the private seeds.
impl std::fmt::Debug for ClientEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientEncryption")
            .field("relay_key_count", &self.relay_key_count)
            .finish_non_exhaustive()
    }
}

impl ClientEncryption {
    /// Parse an account `encryption` text such as
    /// `mlkem768x25519plus.native.1rtt.<base64url-key>[.<base64url-key>...]`
    /// with up to [`MAX_RELAY_KEYS`] relay keys.
    pub fn parse(encryption: &str) -> Result<Self> {
        if encryption.is_empty() || encryption == "none" {
            bail!(
                "VLESS account \"encryption\" is \"{encryption}\"; the encrypted wire session does not apply"
            );
        }
        let wire = parse_client_wire(encryption)?;
        reject_unsupported_profile(
            "encryption",
            wire.mode,
            wire.xor_mode,
            wire.seconds > 0,
            "\"0rtt\"",
            &wire.padding,
        )?;
        let config = ClientConfig::from_public_keys(&wire.keys)
            .map_err(anyhow::Error::from)
            .map_err(|error| error.context("failed to use encryption"))?;
        let relay_key_count = wire.keys.len();
        Ok(Self {
            config,
            relay_key_count,
        })
    }

    /// Single entry point for the config layer: reads the `encryption` field of
    /// a VLESS outbound user JSON object. Sibling fields are handled elsewhere
    /// and are ignored here, mirroring the Go parser. `"none"` and empty
    /// values are valid accounts without encryption; they are rejected here so
    /// the caller keeps a single code path.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let text = value
            .get("encryption")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("VLESS user \"encryption\" must be a string"))?;
        Self::parse(text)
    }

    /// Number of configured relay keys.
    pub fn relay_key_count(&self) -> usize {
        self.relay_key_count
    }

    /// The underlying handshake configuration.
    pub fn into_config(self) -> ClientConfig {
        self.config
    }
}

/// Shared server-side wire state for one inbound `decryption` setting.
///
/// Keep one instance per inbound handler and pass it to every accepted
/// connection: the replay history it shares with
/// [`crate::protocol::vless_security::handshake::server_handshake`] must not
/// be reset per connection.
pub struct ServerDecryption {
    config: ServerConfig,
    relay_key_count: usize,
}

// Debug without key material: the decryption text holds the private seeds.
impl std::fmt::Debug for ServerDecryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerDecryption")
            .field("relay_key_count", &self.relay_key_count)
            .finish_non_exhaustive()
    }
}

impl ServerDecryption {
    /// Parse a `decryption` text such as
    /// `mlkem768x25519plus.native.0-0s.<base64url-seed>[.<base64url-seed>...]`
    /// with up to [`MAX_RELAY_KEYS`] relay seeds (32-byte X25519 private keys
    /// or 64-byte ML-KEM-768 seeds).
    pub fn parse(decryption: &str) -> Result<Self> {
        if decryption.is_empty() {
            bail!("VLESS settings: please add/set \"decryption\":\"none\" to every settings");
        }
        if decryption == "none" {
            bail!(
                "VLESS settings \"decryption\" is \"none\"; the encrypted wire session does not apply"
            );
        }
        let wire = parse_server_wire(decryption)?;
        reject_unsupported_profile(
            "decryption",
            wire.mode,
            wire.xor_mode,
            wire.seconds_from != 0 || wire.seconds_to != 0,
            &format!(
                "ticket lifetime \"{}s\"",
                if wire.seconds_to == 0 || wire.seconds_to == wire.seconds_from {
                    wire.seconds_from.to_string()
                } else {
                    format!("{}-{}", wire.seconds_from, wire.seconds_to)
                }
            ),
            &wire.padding,
        )?;
        let config = ServerConfig::from_private_keys(&wire.keys)
            .map_err(anyhow::Error::from)
            .map_err(|error| error.context("failed to use decryption"))?;
        let relay_key_count = wire.keys.len();
        Ok(Self {
            config,
            relay_key_count,
        })
    }

    /// Single entry point for the config layer: reads the `decryption` field of
    /// a VLESS inbound settings JSON object. Sibling fields (`clients`,
    /// `fallbacks`, ...) are handled elsewhere and are ignored here.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let text = value
            .get("decryption")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "VLESS settings: please add/set \"decryption\":\"none\" to every settings"
                )
            })?;
        Self::parse(text)
    }

    /// The relay chain's public keys, in configuration order. Outbound users
    /// reference them in their `encryption` text.
    pub fn public_keys_bytes(&self) -> Vec<Vec<u8>> {
        self.config.public_keys_bytes()
    }

    /// Number of configured relay seeds.
    pub fn relay_key_count(&self) -> usize {
        self.relay_key_count
    }
}

/// Run the client-side native 1-RTT hybrid handshake over `stream` and return
/// the encrypted session. The VLESS request header and body records written
/// through the returned stream are encrypted; reads decrypt the server's
/// response records. The caller owns connection deadlines.
pub async fn connect<S>(stream: S, client: &ClientEncryption) -> io::Result<EncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake::client_handshake(stream, &client.config).await
}

/// Run the server-side native 1-RTT hybrid handshake over `stream`. A failed
/// exchange must close the connection; there is no plaintext fallback. Share
/// `server` across connections so replayed handshakes are rejected.
pub async fn accept<S>(stream: S, server: &ServerDecryption) -> io::Result<EncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake::server_handshake(stream, &server.config).await
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use anyhow::Result;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };
    use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

    use super::*;
    use crate::address::Destination;
    use crate::protocol::vless;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn server_text(seed: &[u8]) -> String {
        format!("mlkem768x25519plus.native.0-0s.{}", b64(seed))
    }

    fn server_from_seed(seed: &[u8]) -> ServerDecryption {
        ServerDecryption::parse(&server_text(seed)).unwrap()
    }

    fn client_text_for(server: &ServerDecryption) -> String {
        let keys: Vec<String> = server
            .public_keys_bytes()
            .iter()
            .map(|key| b64(key))
            .collect();
        format!("mlkem768x25519plus.native.1rtt.{}", keys.join("."))
    }

    // Known-account fixture keys from the native handshake fixtures: a
    // 32-byte X25519 private key and a 64-byte ML-KEM-768 seed.
    const X25519_SEED: [u8; 32] = [0x11; 32];
    const MLKEM_SEED: [u8; 64] = [0x22; 64];

    #[test]
    fn account_parameters_parse_into_native_configs_and_reject_go_unsupported_options() -> Result<()>
    {
        for seed in [X25519_SEED.as_slice(), MLKEM_SEED.as_slice()] {
            let server = server_from_seed(seed);
            assert_eq!(server.relay_key_count(), 1);
            let public = server.public_keys_bytes();
            if seed.len() == 32 {
                // Fixture key material: the X25519 public key of the seed.
                assert_eq!(public[0], x25519(X25519_SEED, X25519_BASEPOINT_BYTES));
            } else {
                assert_eq!(public[0].len(), 1184);
            }
            let client = ClientEncryption::parse(&client_text_for(&server))?;
            assert_eq!(client.relay_key_count(), 1);

            // Relay chains up to Go's eight keys.
            for count in [2usize, 8] {
                let seeds: Vec<Vec<u8>> = (0..count)
                    .map(|i| vec![0x30 + i as u8; seed.len()])
                    .collect();
                let texts: Vec<String> = seeds.iter().map(|s| b64(s)).collect();
                let chain = ServerDecryption::parse(&format!(
                    "mlkem768x25519plus.native.0s.{}",
                    texts.join(".")
                ))?;
                assert_eq!(chain.relay_key_count(), count);
                let client_chain = ClientEncryption::parse(&format!(
                    "mlkem768x25519plus.native.1rtt.{}",
                    chain
                        .public_keys_bytes()
                        .iter()
                        .map(|key| b64(key))
                        .collect::<Vec<_>>()
                        .join(".")
                ))?;
                assert_eq!(client_chain.relay_key_count(), count);
            }
            let nine_keys: Vec<String> = (0..9)
                .map(|i| {
                    let mut seed_i = seed.to_vec();
                    seed_i[0] = 0x30 + i;
                    b64(&seed_i)
                })
                .collect();
            assert!(
                ServerDecryption::parse(&format!(
                    "mlkem768x25519plus.native.0s.{}",
                    nine_keys.join(".")
                ))
                .is_err()
            );

            // Unsupported account options are identified, then rejected.
            let text = server_text(seed);
            for (label, replaced) in [
                ("xorpub", text.replacen("native", "xorpub", 1)),
                ("random", text.replacen("native", "random", 1)),
            ] {
                let error = ServerDecryption::parse(&replaced).unwrap_err().to_string();
                assert!(error.contains(label), "{error}");
                assert!(error.contains("XOR mode"), "{error}");
            }
            assert!(
                ServerDecryption::parse(&format!("mlkem768x25519plus.native.600s.{}", b64(seed)))
                    .unwrap_err()
                    .to_string()
                    .contains("ticket lifetime")
            );
            assert!(
                ServerDecryption::parse(&format!(
                    "mlkem768x25519plus.native.300-600s.{}",
                    b64(seed)
                ))
                .is_err()
            );
            // Zero ticket lifetimes stay supported.
            ServerDecryption::parse(&format!("mlkem768x25519plus.native.0s.{}", b64(seed)))?;

            let client_account = client_text_for(&server);
            let error = ClientEncryption::parse(&client_account.replacen("1rtt", "0rtt", 1))
                .unwrap_err()
                .to_string();
            assert!(error.contains("0rtt"), "{error}");
            assert!(error.contains("resumption"), "{error}");
            for bad_seconds in ["600s", "300-600s", "1.5rtt"] {
                assert!(
                    ClientEncryption::parse(&format!(
                        "mlkem768x25519plus.native.{bad_seconds}.{}",
                        b64(&public[0])
                    ))
                    .is_err()
                );
            }
            // A server account cannot use the client's rtt seconds field.
            assert!(
                ServerDecryption::parse(&format!("mlkem768x25519plus.native.1rtt.{}", b64(seed)))
                    .is_err()
            );

            // Malformed seeds and relay fields are rejected.
            for length in [0usize, 1, 19, 20, 31, 33, 63, 65, 1183, 1185] {
                let bad = vec![0x41; length];
                if CLIENT_KEY_LENGTHS.contains(&length) {
                    continue;
                }
                assert!(
                    ClientEncryption::parse(&format!(
                        "mlkem768x25519plus.native.1rtt.{}",
                        b64(&bad)
                    ))
                    .is_err(),
                    "client key length {length}"
                );
                if !SERVER_KEY_LENGTHS.contains(&length) {
                    assert!(
                        ServerDecryption::parse(&format!(
                            "mlkem768x25519plus.native.0s.{}",
                            b64(&bad)
                        ))
                        .is_err(),
                        "server key length {length}"
                    );
                }
            }
            // Invalid base64url in a key-sized field, and a structurally
            // invalid ML-KEM-768 public key.
            assert!(
                ClientEncryption::parse(&format!(
                    "mlkem768x25519plus.native.1rtt.{}",
                    "!".repeat(43)
                ))
                .is_err()
            );
            assert!(
                ClientEncryption::parse(&format!(
                    "mlkem768x25519plus.native.1rtt.{}",
                    b64(&[0xff; 1184])
                ))
                .is_err()
            );
            // Missing prefix, missing fields, and padding without relay keys.
            // (An empty field between dots is accepted by Go as an empty
            // padding part, so it is not an error.)
            for broken in [
                format!("{}.native.1rtt.{}", "mlkem768x25519plusX", b64(&public[0])),
                "mlkem768x25519plus.native.1rtt".to_string(),
                "mlkem768x25519plus.native.1rtt.".to_string(),
            ] {
                assert!(ClientEncryption::parse(&broken).is_err(), "{broken}");
                let server_broken = broken.replace("1rtt", "0s");
                assert!(
                    ServerDecryption::parse(&server_broken).is_err(),
                    "{server_broken}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn json_entry_points_accept_known_accounts_and_reject_inactive_ones() -> Result<()> {
        let server = server_from_seed(&X25519_SEED);
        let client_text = client_text_for(&server);
        let client = ClientEncryption::from_value(
            &serde_json::json!({ "id": "uuid", "encryption": client_text, "flow": "" }),
        )?;
        assert_eq!(client.relay_key_count(), 1);
        let server_from_json = ServerDecryption::from_value(&serde_json::json!({
            "decryption": server_text(&X25519_SEED),
            "clients": []
        }))?;
        assert_eq!(server_from_json.relay_key_count(), 1);

        for inactive in ["", "none"] {
            let error =
                ClientEncryption::from_value(&serde_json::json!({ "encryption": inactive }))
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("does not apply"), "{error}");
            let error =
                ServerDecryption::from_value(&serde_json::json!({ "decryption": inactive }))
                    .unwrap_err()
                    .to_string();
            assert!(
                error.contains("does not apply") || error.contains("please add/set"),
                "{error}"
            );
        }
        assert!(ClientEncryption::from_value(&serde_json::json!({ "id": "uuid" })).is_err());
        assert!(ClientEncryption::from_value(&serde_json::json!({ "encryption": 1 })).is_err());
        assert!(ServerDecryption::from_value(&serde_json::json!({})).is_err());
        assert!(
            ServerDecryption::from_value(
                &serde_json::json!({ "decryption": "mlkem768x25519plus.xorpub.0s.KEY" })
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn padding_schedules_are_identified_and_rejected_per_go_rules() -> Result<()> {
        let key = b64(&X25519_SEED);
        // Valid Go padding schedule: identified, then rejected as unsupported.
        let error = ClientEncryption::parse(&format!(
            "mlkem768x25519plus.native.1rtt.100-111-1111.{key}"
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("padding schedule"), "{error}");
        assert!(error.contains("100-111-1111"), "{error}");
        // Go ParsePadding validation errors.
        let error =
            ClientEncryption::parse(&format!("mlkem768x25519plus.native.1rtt.10-11-12.{key}"))
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("first padding length must not be smaller than 35"),
            "{error}"
        );
        let error =
            ServerDecryption::parse(&format!("mlkem768x25519plus.native.0s.100-111-x.{key}"))
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("invalid padding lenth/gap parameter"),
            "{error}"
        );
        let error = ClientEncryption::parse(&format!(
            "mlkem768x25519plus.native.1rtt.100-40000-40000.75-0-1.100-40000-40000.{key}"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("total padding length must not be larger than 65553"),
            "{error}"
        );
        // A padding schedule without any relay key has nothing to protect.
        assert!(ClientEncryption::parse("mlkem768x25519plus.native.1rtt.100-111-1111").is_err());
        Ok(())
    }

    async fn handshake_pair(
        client: &ClientEncryption,
        server: &ServerDecryption,
    ) -> io::Result<(
        EncryptedStream<tokio::io::DuplexStream>,
        EncryptedStream<tokio::io::DuplexStream>,
    )> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_stream, server_stream) =
            tokio::join!(connect(client_io, client), accept(server_io, server),);
        Ok((client_stream?, server_stream?))
    }

    #[tokio::test]
    async fn full_session_round_trip_with_vless_request_header_and_body() -> Result<()> {
        // Known account: 32-byte X25519 and 64-byte ML-KEM-768 seeds, the two
        // static key types Go supports, exercising the default AES-GCM
        // profile an AES-capable client picks.
        for seed in [X25519_SEED.as_slice(), MLKEM_SEED.as_slice()] {
            let server = ServerDecryption::parse(&server_text(seed))?;
            let client = ClientEncryption::parse(&client_text_for(&server))?;
            let (mut client_stream, mut server_stream) =
                timeout(Duration::from_secs(5), handshake_pair(&client, &server)).await??;
            assert_eq!(client_stream.algorithm(), Algorithm::Aes256Gcm);
            assert_eq!(server_stream.algorithm(), Algorithm::Aes256Gcm);

            // The inner VLESS request header and body are encrypted by the
            // session in both directions.
            let account = vless::Account {
                flow: String::new(),
                id: [7; 16],
                email: "known-user".into(),
            };
            let destination = Destination::new("example.com", 443)?;
            timeout(Duration::from_secs(5), async {
                vless::write_request(&mut client_stream, &account, &destination)
                    .await
                    .map_err(io::Error::other)?;
                client_stream.write_all(b"uplink body").await?;
                client_stream.flush().await
            })
            .await??;

            let request = timeout(
                Duration::from_secs(5),
                vless::read_request(&mut server_stream, std::slice::from_ref(&account)),
            )
            .await??;
            assert_eq!(
                request.request.destination.to_string(),
                destination.to_string()
            );
            assert_eq!(request.request.user, "known-user");
            let mut body = vec![0; b"uplink body".len()];
            timeout(Duration::from_secs(5), server_stream.read_exact(&mut body)).await??;
            assert_eq!(body, b"uplink body");

            // Downlink: response header and payload records.
            timeout(Duration::from_secs(5), async {
                vless::write_response(&mut server_stream)
                    .await
                    .map_err(io::Error::other)?;
                server_stream.write_all(b"downlink body").await?;
                server_stream.flush().await
            })
            .await??;
            timeout(
                Duration::from_secs(5),
                vless::read_response(&mut client_stream),
            )
            .await??;
            let mut response = vec![0; b"downlink body".len()];
            timeout(
                Duration::from_secs(5),
                client_stream.read_exact(&mut response),
            )
            .await??;
            assert_eq!(response, b"downlink body");

            // Large payloads chunk into 8192-byte plaintext records.
            let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
            timeout(Duration::from_secs(5), client_stream.write_all(&payload)).await??;
            client_stream.flush().await?;
            let mut received = vec![0; payload.len()];
            timeout(
                Duration::from_secs(5),
                server_stream.read_exact(&mut received),
            )
            .await??;
            assert_eq!(received, payload);
        }
        Ok(())
    }

    #[tokio::test]
    async fn replayed_identical_client_hello_is_rejected() -> Result<()> {
        let server = server_from_seed(&X25519_SEED);
        let client = ClientEncryption::parse(&client_text_for(&server))?;
        // A single-X25519 native client hello with the default 77-byte padding:
        // 16 IV + 32 relay share + 18 length + 1232 hybrid share + 18 + 93
        // padding records.
        const HELLO_LEN: usize = 16 + 32 + 18 + (1184 + 32 + 16) + 18 + (77 + 16);

        // Record one complete hello from a live client.
        let (client_io, mut recorder) = tokio::io::duplex(64 * 1024);
        let client_task = tokio::spawn(async move {
            // Fails once the recorder side is dropped; the hello is what counts.
            let _ = connect(client_io, &client).await;
        });
        let mut hello = vec![0; HELLO_LEN];
        timeout(Duration::from_secs(5), recorder.read_exact(&mut hello)).await??;
        // Nothing else is written before the server hello arrives.
        let mut extra = [0; 1];
        assert!(
            timeout(Duration::from_millis(150), recorder.read(&mut extra))
                .await
                .is_err()
        );
        drop(recorder);
        timeout(Duration::from_secs(5), client_task).await??;

        // First delivery of the identical bytes: accepted.
        let (writer, reader) = tokio::io::duplex(64 * 1024);
        let (mut writer, mut reader) = (writer, reader);
        writer.write_all(&hello).await?;
        writer.flush().await?;
        let first = timeout(Duration::from_secs(5), accept(&mut reader, &server))
            .await
            .unwrap()
            .unwrap();
        drop(first);
        // Replay of the identical authenticated hello: rejected.
        writer.write_all(&hello).await?;
        writer.flush().await?;
        let replay = timeout(Duration::from_secs(5), accept(&mut reader, &server))
            .await
            .unwrap();
        let error = replay.err().unwrap().to_string();
        assert!(error.contains("replay"), "{error}");

        // A fresh, different handshake still succeeds against the same state.
        let client = ClientEncryption::parse(&client_text_for(&server))?;
        let (_client_stream, _server_stream) =
            timeout(Duration::from_secs(5), handshake_pair(&client, &server)).await??;
        Ok(())
    }

    #[tokio::test]
    async fn handshakes_with_unmatched_relay_keys_fail() -> Result<()> {
        let server = server_from_seed(&X25519_SEED);
        let stranger = server_from_seed(&[0x12; 32]);
        let client = ClientEncryption::parse(&client_text_for(&stranger))?;
        let (client_result, server_result) = {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            timeout(Duration::from_secs(5), async {
                tokio::join!(connect(client_io, &client), accept(server_io, &server))
            })
            .await?
        };
        assert!(client_result.is_err());
        assert!(server_result.is_err());
        Ok(())
    }
}
