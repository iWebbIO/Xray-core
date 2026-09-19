//! VMess AEAD authentication IDs and request/response header cryptography.
//!
//! Wire constants and layouts follow `proxy/vmess/aead/{kdf,authid,encrypt}.go`
//! and `proxy/vmess/encoding/{client,server}.go`. The KDF is nested HMAC, not
//! HKDF or repeated ordinary HMAC-SHA256. Randomness and Unix time are supplied
//! by the caller so account selection, replay policy, and I/O remain separate.
//!
//! Opening a request envelope authenticates its contents with the command key;
//! callers must also validate the authentication ID's timestamp and reserve it
//! in a shared replay cache before accepting the session. Header seal functions
//! are one-shot: never reuse an authentication ID/connection nonce pair or a
//! response key/IV pair for a different header.

use std::{collections::HashMap, error::Error, fmt};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
    aes::{
        Aes128,
        cipher::{BlockDecrypt, BlockEncrypt},
    },
};
use md5::{Digest, Md5};
use sha2::Sha256;

pub const AUTH_ID_LEN: usize = 16;
pub const CONNECTION_NONCE_LEN: usize = 8;
pub const AEAD_TAG_LEN: usize = 16;
pub const ENCRYPTED_LENGTH_LEN: usize = 2 + AEAD_TAG_LEN;
pub const REQUEST_HEADER_PREFIX_LEN: usize =
    AUTH_ID_LEN + ENCRYPTED_LENGTH_LEN + CONNECTION_NONCE_LEN;
pub const MAX_HEADER_LEN: usize = u16::MAX as usize;
pub const AUTH_ID_MAX_CLOCK_SKEW: u64 = 120;

const KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const REQUEST_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const REQUEST_LENGTH_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const REQUEST_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const REQUEST_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const RESPONSE_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const RESPONSE_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
const RESPONSE_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const RESPONSE_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidAuthId,
    NegativeTimestamp,
    TimestampOutOfRange,
    ReplayedAuthId,
    ReplayCacheFull,
    HeaderTooLong,
    Truncated { needed: usize, available: usize },
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthId => f.write_str("invalid VMess authentication ID checksum"),
            Self::NegativeTimestamp => f.write_str("negative VMess authentication timestamp"),
            Self::TimestampOutOfRange => {
                f.write_str("VMess authentication timestamp outside window")
            }
            Self::ReplayedAuthId => f.write_str("replayed VMess authentication ID"),
            Self::ReplayCacheFull => f.write_str("VMess authentication replay cache is full"),
            Self::HeaderTooLong => f.write_str("VMess header exceeds 65535 bytes"),
            Self::Truncated { needed, available } => {
                write!(
                    f,
                    "truncated VMess header: need {needed} bytes, have {available}"
                )
            }
            Self::AuthenticationFailed => f.write_str("VMess header authentication failed"),
        }
    }
}

impl Error for CryptoError {}

/// VMess command key: MD5(UUID bytes || protocol-specific UUID string).
pub fn command_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(uuid);
    digest.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    digest.finalize().into()
}

/// VMess's nested-HMAC KDF. Path elements are binary strings, not UTF-8 text.
pub fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let mut levels = Vec::with_capacity(paths.len() + 1);
    levels.push(KDF_ROOT);
    levels.extend_from_slice(paths);
    nested_hash(&levels, &[key])
}

pub fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    first16(kdf(key, paths))
}

// Each path creates HMAC(key=path, hash=previous level). Every level inherits
// SHA-256's 64-byte block size and 32-byte output size. This also handles long
// binary path elements using the previous level to hash the oversized HMAC key.
fn nested_hash(levels: &[&[u8]], data: &[&[u8]]) -> [u8; 32] {
    let Some((key, parent_levels)) = levels.split_last() else {
        let mut hash = Sha256::new();
        for part in data {
            hash.update(part);
        }
        return hash.finalize().into();
    };
    let hashed_key;
    let key = if key.len() > 64 {
        hashed_key = nested_hash(parent_levels, &[key]);
        &hashed_key[..]
    } else {
        key
    };
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (i, &byte) in key.iter().enumerate() {
        inner_pad[i] ^= byte;
        outer_pad[i] ^= byte;
    }
    let mut inner_data = Vec::with_capacity(data.len() + 1);
    inner_data.push(inner_pad.as_slice());
    inner_data.extend_from_slice(data);
    let inner = nested_hash(parent_levels, &inner_data);
    nested_hash(parent_levels, &[&outer_pad, &inner])
}

fn first16(bytes: [u8; 32]) -> [u8; 16] {
    let mut result = [0; 16];
    result.copy_from_slice(&bytes[..16]);
    result
}

fn first12(bytes: [u8; 32]) -> [u8; 12] {
    let mut result = [0; 12];
    result.copy_from_slice(&bytes[..12]);
    result
}

/// Decrypted authentication ID fields, after verifying the IEEE CRC-32.
/// The CRC identifies a likely account; it is not cryptographic authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthId {
    pub timestamp: i64,
    pub random: [u8; 4],
}

/// Construct a deterministic authentication ID using four fresh random bytes.
/// Production callers should use cryptographically secure randomness.
pub fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64, random: [u8; 4]) -> [u8; AUTH_ID_LEN] {
    let mut plaintext = [0; AUTH_ID_LEN];
    plaintext[..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..12].copy_from_slice(&random);
    let checksum = crc32_ieee(&plaintext[..12]);
    plaintext[12..].copy_from_slice(&checksum.to_be_bytes());
    let cipher = Aes128::new(&kdf16(cmd_key, &[AUTH_ID_KEY]).into());
    let mut block = plaintext.into();
    cipher.encrypt_block(&mut block);
    block.into()
}

pub fn decode_auth_id(
    cmd_key: &[u8; 16],
    auth_id: &[u8; AUTH_ID_LEN],
) -> Result<AuthId, CryptoError> {
    let cipher = Aes128::new(&kdf16(cmd_key, &[AUTH_ID_KEY]).into());
    let mut block = (*auth_id).into();
    cipher.decrypt_block(&mut block);
    let plaintext: [u8; 16] = block.into();
    let checksum = u32::from_be_bytes(plaintext[12..16].try_into().unwrap());
    if checksum != crc32_ieee(&plaintext[..12]) {
        return Err(CryptoError::InvalidAuthId);
    }
    Ok(AuthId {
        timestamp: i64::from_be_bytes(plaintext[..8].try_into().unwrap()),
        random: plaintext[8..12].try_into().unwrap(),
    })
}

/// Verify the CRC and inclusive +/-120-second timestamp window. This does not
/// reserve an ID; only reserve it once the entire request is authenticated.
pub fn validate_auth_id(
    cmd_key: &[u8; 16],
    auth_id: &[u8; AUTH_ID_LEN],
    now: i64,
) -> Result<AuthId, CryptoError> {
    let decoded = decode_auth_id(cmd_key, auth_id)?;
    validate_timestamp(decoded.timestamp, now)?;
    Ok(decoded)
}

fn validate_timestamp(timestamp: i64, now: i64) -> Result<(), CryptoError> {
    if timestamp < 0 {
        return Err(CryptoError::NegativeTimestamp);
    }
    if now < 0 || now.abs_diff(timestamp) > AUTH_ID_MAX_CLOCK_SKEW {
        return Err(CryptoError::TimestampOutOfRange);
    }
    Ok(())
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// Bounded, process-local authentication ID history. Share one cache across
/// sessions/accounts under the caller's lock. Entries live until the final
/// second in which their timestamp can pass validation, including future IDs.
/// A full cache rejects new sessions instead of evicting live replay entries.
#[derive(Debug)]
pub struct AuthIdReplayCache {
    expires: HashMap<[u8; AUTH_ID_LEN], i64>,
    max_entries: usize,
}

impl Default for AuthIdReplayCache {
    fn default() -> Self {
        Self::new(65_536)
    }
}

impl AuthIdReplayCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            expires: HashMap::new(),
            max_entries,
        }
    }

    /// `timestamp` must come from validating this ID with its selected account.
    /// Call only after authenticating and decoding the complete request header.
    pub fn check_and_insert(
        &mut self,
        auth_id: [u8; AUTH_ID_LEN],
        timestamp: i64,
        now: i64,
    ) -> Result<(), CryptoError> {
        validate_timestamp(timestamp, now)?;
        self.expires.retain(|_, expires| *expires >= now);
        if self.expires.contains_key(&auth_id) {
            return Err(CryptoError::ReplayedAuthId);
        }
        if self.expires.len() >= self.max_entries {
            return Err(CryptoError::ReplayCacheFull);
        }
        self.expires.insert(
            auth_id,
            timestamp.saturating_add(AUTH_ID_MAX_CLOCK_SKEW as i64),
        );
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.expires.len()
    }

    pub fn is_empty(&self) -> bool {
        self.expires.is_empty()
    }
}

fn seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Aes128Gcm::new(key.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Aes128Gcm::new(key.into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn require_bytes(bytes: &[u8], needed: usize) -> Result<(), CryptoError> {
    if bytes.len() < needed {
        return Err(CryptoError::Truncated {
            needed,
            available: bytes.len(),
        });
    }
    Ok(())
}

fn request_keys(
    cmd_key: &[u8; 16],
    auth_id: &[u8; AUTH_ID_LEN],
    connection_nonce: &[u8; CONNECTION_NONCE_LEN],
    key_label: &[u8],
    iv_label: &[u8],
) -> ([u8; 16], [u8; 12]) {
    (
        kdf16(cmd_key, &[key_label, auth_id, connection_nonce]),
        first12(kdf(cmd_key, &[iv_label, auth_id, connection_nonce])),
    )
}

/// Serialize auth ID || authenticated length || nonce || authenticated payload.
pub fn seal_request_header(
    cmd_key: &[u8; 16],
    payload: &[u8],
    auth_id: &[u8; AUTH_ID_LEN],
    connection_nonce: &[u8; CONNECTION_NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let length = u16::try_from(payload.len()).map_err(|_| CryptoError::HeaderTooLong)?;
    let (length_key, length_iv) = request_keys(
        cmd_key,
        auth_id,
        connection_nonce,
        REQUEST_LENGTH_KEY,
        REQUEST_LENGTH_IV,
    );
    let encrypted_length = seal(&length_key, &length_iv, &length.to_be_bytes(), auth_id)?;
    let (payload_key, payload_iv) = request_keys(
        cmd_key,
        auth_id,
        connection_nonce,
        REQUEST_PAYLOAD_KEY,
        REQUEST_PAYLOAD_IV,
    );
    let encrypted_payload = seal(&payload_key, &payload_iv, payload, auth_id)?;
    let mut result = Vec::with_capacity(REQUEST_HEADER_PREFIX_LEN + payload.len() + AEAD_TAG_LEN);
    result.extend_from_slice(auth_id);
    result.extend_from_slice(&encrypted_length);
    result.extend_from_slice(connection_nonce);
    result.extend_from_slice(&encrypted_payload);
    Ok(result)
}

/// Authenticate the request length before allocating/reading its payload.
pub fn open_request_header_length(
    cmd_key: &[u8; 16],
    auth_id: &[u8; AUTH_ID_LEN],
    encrypted_length: &[u8; ENCRYPTED_LENGTH_LEN],
    connection_nonce: &[u8; CONNECTION_NONCE_LEN],
) -> Result<usize, CryptoError> {
    let (key, iv) = request_keys(
        cmd_key,
        auth_id,
        connection_nonce,
        REQUEST_LENGTH_KEY,
        REQUEST_LENGTH_IV,
    );
    let length = open(&key, &iv, encrypted_length, auth_id)?;
    Ok(usize::from(u16::from_be_bytes([length[0], length[1]])))
}

/// Open a complete request envelope, leaving any following body bytes unread.
/// Returns the plaintext header and the number of envelope bytes consumed.
pub fn open_request_header(
    cmd_key: &[u8; 16],
    wire: &[u8],
) -> Result<(Vec<u8>, usize), CryptoError> {
    require_bytes(wire, REQUEST_HEADER_PREFIX_LEN)?;
    let auth_id: &[u8; AUTH_ID_LEN] = wire[..16].try_into().unwrap();
    let encrypted_length = wire[16..34].try_into().unwrap();
    let connection_nonce = wire[34..42].try_into().unwrap();
    let length = open_request_header_length(cmd_key, auth_id, encrypted_length, connection_nonce)?;
    let consumed = REQUEST_HEADER_PREFIX_LEN + length + AEAD_TAG_LEN;
    require_bytes(wire, consumed)?;
    let (key, iv) = request_keys(
        cmd_key,
        auth_id,
        connection_nonce,
        REQUEST_PAYLOAD_KEY,
        REQUEST_PAYLOAD_IV,
    );
    let plaintext = open(
        &key,
        &iv,
        &wire[REQUEST_HEADER_PREFIX_LEN..consumed],
        auth_id,
    )?;
    Ok((plaintext, consumed))
}

/// Modern VMess AEAD derives each response body secret as SHA-256(request)[..16].
pub fn derive_response_key_iv(
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    (
        first16(Sha256::digest(request_key).into()),
        first16(Sha256::digest(request_iv).into()),
    )
}

fn response_keys(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    key_label: &[u8],
    iv_label: &[u8],
) -> ([u8; 16], [u8; 12]) {
    (
        kdf16(response_key, &[key_label]),
        first12(kdf(response_iv, &[iv_label])),
    )
}

/// Encrypt a response plaintext header with already-derived response secrets.
pub fn seal_response_header(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let length = u16::try_from(payload.len()).map_err(|_| CryptoError::HeaderTooLong)?;
    let (length_key, length_iv) = response_keys(
        response_key,
        response_iv,
        RESPONSE_LENGTH_KEY,
        RESPONSE_LENGTH_IV,
    );
    let mut result = seal(&length_key, &length_iv, &length.to_be_bytes(), &[])?;
    let (payload_key, payload_iv) = response_keys(
        response_key,
        response_iv,
        RESPONSE_PAYLOAD_KEY,
        RESPONSE_PAYLOAD_IV,
    );
    result.extend_from_slice(&seal(&payload_key, &payload_iv, payload, &[])?);
    Ok(result)
}

pub fn open_response_header_length(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    encrypted_length: &[u8; ENCRYPTED_LENGTH_LEN],
) -> Result<usize, CryptoError> {
    let (key, iv) = response_keys(
        response_key,
        response_iv,
        RESPONSE_LENGTH_KEY,
        RESPONSE_LENGTH_IV,
    );
    let length = open(&key, &iv, encrypted_length, &[])?;
    Ok(usize::from(u16::from_be_bytes([length[0], length[1]])))
}

pub fn open_response_header(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    wire: &[u8],
) -> Result<(Vec<u8>, usize), CryptoError> {
    require_bytes(wire, ENCRYPTED_LENGTH_LEN)?;
    let length = open_response_header_length(
        response_key,
        response_iv,
        wire[..ENCRYPTED_LENGTH_LEN].try_into().unwrap(),
    )?;
    let consumed = ENCRYPTED_LENGTH_LEN + length + AEAD_TAG_LEN;
    require_bytes(wire, consumed)?;
    let (key, iv) = response_keys(
        response_key,
        response_iv,
        RESPONSE_PAYLOAD_KEY,
        RESPONSE_PAYLOAD_IV,
    );
    let plaintext = open(&key, &iv, &wire[ENCRYPTED_LENGTH_LEN..consumed], &[])?;
    Ok((plaintext, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed fixtures were independently produced with Python's hashlib/hmac,
    // zlib CRC-32, and cryptography AES/AESGCM from the Go layouts cited above.
    // The nested HMAC oracle builds HMAC objects whose digestmod is the prior
    // HMAC constructor, independently of this module's recursive pad hashing.
    const REQUEST_FIXTURE: &str = concat!(
        "cd513b9d24604cb6c80ab87d5bac470e",
        "850fac187c33eb2bb11fadb899bc75c6a2db",
        "a0a1a2a3a4a5a6a7",
        "a33df3032a3a28af896e201d024cd9e50410ac7eba1134e1cdbdb2"
    );
    const RESPONSE_FIXTURE: &str =
        "936c422a7a3f0c4835561f50648898c4d6e3b210e4a64fdc360d8988702258bf83cb5d83f1f5";

    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn request_key() -> [u8; 16] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn command_key_and_nested_kdf_match_independent_fixtures() {
        let key = request_key();
        assert_eq!(
            command_key(&key).as_slice(),
            hex("8e12bc156ecaf05b7f0a83a21aa77742")
        );
        assert_eq!(
            kdf(&key, &[]).as_slice(),
            hex("ebdb909829820c287b7d7601fe00d5b093f4485a027311c2205e9007d5fc9c16")
        );
        assert_eq!(
            kdf(&key, &[AUTH_ID_KEY]).as_slice(),
            hex("9fa4289c41650861a45b34aeab3879fe4785dce57ab3f68cfb0cc60fca69460a")
        );
        assert_eq!(
            kdf(
                &key,
                &[REQUEST_PAYLOAD_KEY, &key, &[0, 1, 2, 3, 4, 5, 6, 7]]
            )
            .as_slice(),
            hex("8db91c13b5202712aad7b00ea281890acc66245ac48c98961849620ba873c19e")
        );
        let long_path: Vec<u8> = (0..100).collect();
        assert_eq!(
            kdf(&key, &[&long_path, b"next"]).as_slice(),
            hex("87e7025f36d06e78a8d8373fa5396cacfaaaecbda8a56532e02a43003d7405fd")
        );
    }

    #[test]
    fn authentication_id_matches_independent_fixture() {
        let key = request_key();
        let id = create_auth_id(&key, 1_700_000_000, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(id.as_slice(), hex("cd513b9d24604cb6c80ab87d5bac470e"));
        assert_eq!(
            decode_auth_id(&key, &id).unwrap(),
            AuthId {
                timestamp: 1_700_000_000,
                random: [0xde, 0xad, 0xbe, 0xef]
            }
        );
        let mut bad_id = id;
        bad_id[9] ^= 1;
        assert_eq!(
            decode_auth_id(&key, &bad_id),
            Err(CryptoError::InvalidAuthId)
        );
        assert_eq!(
            decode_auth_id(&[0xff; 16], &id),
            Err(CryptoError::InvalidAuthId)
        );
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn timestamps_are_inclusive_and_do_not_overflow() {
        let key = request_key();
        for difference in [-120, 0, 120] {
            let id = create_auth_id(&key, 1_700_000_000 + difference, [0; 4]);
            assert!(validate_auth_id(&key, &id, 1_700_000_000).is_ok());
        }
        for difference in [-121, 121] {
            let id = create_auth_id(&key, 1_700_000_000 + difference, [0; 4]);
            assert_eq!(
                validate_auth_id(&key, &id, 1_700_000_000),
                Err(CryptoError::TimestampOutOfRange)
            );
        }
        for timestamp in [-1, i64::MIN] {
            let id = create_auth_id(&key, timestamp, [0; 4]);
            assert_eq!(
                validate_auth_id(&key, &id, 0),
                Err(CryptoError::NegativeTimestamp)
            );
        }
        assert_eq!(
            validate_timestamp(i64::MAX, 0),
            Err(CryptoError::TimestampOutOfRange)
        );
        assert_eq!(
            validate_timestamp(0, i64::MIN),
            Err(CryptoError::TimestampOutOfRange)
        );
        assert!(validate_timestamp(i64::MAX, i64::MAX).is_ok());
    }

    #[test]
    fn replay_history_retains_future_ids_until_the_final_valid_second() {
        let mut cache = AuthIdReplayCache::new(1);
        let id = [1; 16];
        cache.check_and_insert(id, 1120, 1000).unwrap();
        assert_eq!(
            cache.check_and_insert(id, 1120, 1240),
            Err(CryptoError::ReplayedAuthId)
        );
        assert_eq!(
            cache.check_and_insert([2; 16], 1240, 1240),
            Err(CryptoError::ReplayCacheFull)
        );
        cache.check_and_insert([2; 16], 1241, 1241).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.check_and_insert(id, 1120, 1241),
            Err(CryptoError::TimestampOutOfRange)
        );
        assert_eq!(
            AuthIdReplayCache::new(0).check_and_insert(id, 1, 1),
            Err(CryptoError::ReplayCacheFull)
        );
    }

    #[test]
    fn request_header_matches_independent_wire_fixture_and_leaves_body_unread() {
        let key = request_key();
        let id = create_auth_id(&key, 1_700_000_000, [0xde, 0xad, 0xbe, 0xef]);
        let nonce = std::array::from_fn(|i| 0xa0 + i as u8);
        let sealed = seal_request_header(&key, b"Test Header", &id, &nonce).unwrap();
        assert_eq!(sealed, hex(REQUEST_FIXTURE));
        let mut wire = sealed.clone();
        wire.extend_from_slice(b"body must remain unread");
        assert_eq!(
            open_request_header(&key, &wire).unwrap(),
            (b"Test Header".to_vec(), sealed.len())
        );
        assert_eq!(
            open_request_header_length(&key, &id, sealed[16..34].try_into().unwrap(), &nonce)
                .unwrap(),
            11
        );
    }

    #[test]
    fn request_header_rejects_every_tampered_byte_and_every_truncation() {
        let key = request_key();
        let sealed = hex(REQUEST_FIXTURE);
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert_eq!(
                open_request_header(&key, &tampered),
                Err(CryptoError::AuthenticationFailed),
                "byte {i}"
            );
            assert!(
                matches!(
                    open_request_header(&key, &sealed[..i]),
                    Err(CryptoError::Truncated { .. })
                ),
                "prefix {i}"
            );
        }
        assert_eq!(
            open_request_header(&[9; 16], &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn response_header_matches_independent_fixture_and_checks_all_tags() {
        let request_iv = std::array::from_fn(|i| 16 + i as u8);
        let (key, iv) = derive_response_key_iv(&request_key(), &request_iv);
        assert_eq!(key.as_slice(), hex("be45cb2605bf36bebde684841a28f0fd"));
        assert_eq!(iv.as_slice(), hex("fc2e2c73072bfa2bda03ff9307472deb"));
        let payload = [0x42, 0, 0, 0];
        let sealed = seal_response_header(&key, &iv, &payload).unwrap();
        assert_eq!(sealed, hex(RESPONSE_FIXTURE));
        let mut with_body = sealed.clone();
        with_body.extend_from_slice(&[0; 20]);
        assert_eq!(
            open_response_header(&key, &iv, &with_body).unwrap(),
            (payload.to_vec(), sealed.len())
        );
        assert_eq!(
            open_response_header_length(&key, &iv, sealed[..18].try_into().unwrap()).unwrap(),
            4
        );
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert_eq!(
                open_response_header(&key, &iv, &tampered),
                Err(CryptoError::AuthenticationFailed),
                "byte {i}"
            );
            assert!(
                matches!(
                    open_response_header(&key, &iv, &sealed[..i]),
                    Err(CryptoError::Truncated { .. })
                ),
                "prefix {i}"
            );
        }
    }

    #[test]
    fn header_lengths_support_u16_range_and_reject_overflow() {
        let key = request_key();
        let auth_id = create_auth_id(&key, 1000, [1; 4]);
        for size in [0, MAX_HEADER_LEN] {
            let payload = vec![0x5a; size];
            let request = seal_request_header(&key, &payload, &auth_id, &[2; 8]).unwrap();
            assert_eq!(
                open_request_header(&key, &request).unwrap(),
                (payload.clone(), request.len())
            );
            let response = seal_response_header(&key, &[3; 16], &payload).unwrap();
            assert_eq!(
                open_response_header(&key, &[3; 16], &response).unwrap(),
                (payload, response.len())
            );
        }
        let too_long = vec![0; MAX_HEADER_LEN + 1];
        assert_eq!(
            seal_request_header(&key, &too_long, &auth_id, &[2; 8]),
            Err(CryptoError::HeaderTooLong)
        );
        assert_eq!(
            seal_response_header(&key, &[3; 16], &too_long),
            Err(CryptoError::HeaderTooLong)
        );
    }
}
