//! Native REALITY authentication primitives for the pinned `8cdf7bf9c7f0` protocol.
//!
//! These operate on a complete TLS ClientHello **handshake** message (including
//! its four-byte handshake header, excluding TLS record headers). They do not
//! implement TLS, browser fingerprints, target mirroring, or the REALITY
//! camouflage/fallback transport. In particular, authenticating a ClientHello
//! does not establish a TLS connection or authenticate its Finished message.
//!
//! Source: `transport/internet/reality/reality.go`, and the pinned REALITY
//! dependency's `tls.go` and `handshake_server_tls13.go`. See
//! `rust/notes/REALITY.md` for protocol evidence and integration requirements.

use std::{
    collections::BTreeSet,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

pub const X25519_GROUP: u16 = 0x001d;
pub const X25519_MLKEM768_GROUP: u16 = 0x11ec;
pub const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
pub const AUTH_SESSION_ID_LEN: usize = 32;
const SESSION_ID_START: usize = 39;
const SESSION_ID_END: usize = SESSION_ID_START + AUTH_SESSION_ID_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MalformedClientHello,
    DuplicateExtension,
    InvalidSessionId,
    Tls13Required,
    HybridKeyShareRequired,
    InvalidKeyShareOrder,
    WrongClientPrivateKey,
    InvalidPublicKey,
    AuthenticationFailed,
    ServerNameRejected,
    VersionRejected,
    TimeRejected,
    ShortIdRejected,
    InvalidShortId,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedClientHello => "malformed REALITY TLS ClientHello",
            Self::DuplicateExtension => "duplicate TLS ClientHello extension",
            Self::InvalidSessionId => "REALITY requires a 32-byte TLS session ID",
            Self::Tls13Required => "REALITY requires TLS 1.3",
            Self::HybridKeyShareRequired => "REALITY requires an X25519MLKEM768 key share",
            Self::InvalidKeyShareOrder => {
                "REALITY requires a single hybrid key share before X25519"
            }
            Self::WrongClientPrivateKey => {
                "REALITY private key does not match the advertised key share"
            }
            Self::InvalidPublicKey => "invalid REALITY X25519 public key",
            Self::AuthenticationFailed => "REALITY authentication failed",
            Self::ServerNameRejected => "REALITY server name rejected",
            Self::VersionRejected => "REALITY client version rejected",
            Self::TimeRejected => "REALITY client timestamp rejected",
            Self::ShortIdRejected => "REALITY short ID rejected",
            Self::InvalidShortId => {
                "REALITY short ID must contain at most 16 even-count hexadecimal digits"
            }
        })
    }
}

impl std::error::Error for Error {}

/// Plaintext encrypted into the 32-byte legacy session ID (16 bytes plus tag).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    pub version: [u8; 3],
    /// The current client sends zero. The Go server ignores this byte.
    pub reserved: u8,
    pub unix_seconds: u32,
    pub short_id: [u8; 8],
}

impl ClientIdentity {
    pub const fn new(version: [u8; 3], unix_seconds: u32, short_id: [u8; 8]) -> Self {
        Self {
            version,
            reserved: 0,
            unix_seconds,
            short_id,
        }
    }

    fn encode(self) -> [u8; 16] {
        let mut data = [0; 16];
        data[..3].copy_from_slice(&self.version);
        data[3] = self.reserved;
        data[4..8].copy_from_slice(&self.unix_seconds.to_be_bytes());
        data[8..].copy_from_slice(&self.short_id);
        data
    }

    fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 16 {
            return Err(Error::AuthenticationFailed);
        }
        Ok(Self {
            version: [data[0], data[1], data[2]],
            reserved: data[3],
            unix_seconds: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            short_id: data[8..16]
                .try_into()
                .map_err(|_| Error::AuthenticationFailed)?,
        })
    }
}

/// Decode Xray's short ID representation, including empty and shortened IDs.
/// Short IDs are right-padded with zero bytes, not left-padded.
pub fn decode_short_id(value: &str) -> Result<[u8; 8], Error> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    if value.len() > 16 || !value.len().is_multiple_of(2) {
        return Err(Error::InvalidShortId);
    }
    let mut out = [0; 8];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = digit(pair[0]).ok_or(Error::InvalidShortId)? << 4
            | digit(pair[1]).ok_or(Error::InvalidShortId)?;
    }
    Ok(out)
}

/// Per-connection secret, cleared when dropped and intentionally not `Debug`.
pub struct RealityAuthKey(Zeroizing<[u8; 32]>);

impl RealityAuthKey {
    /// Derive HKDF-SHA256(X25519(private, peer), random[0..20], "REALITY").
    /// The all-zero result is rejected as in Go's X25519 implementation.
    pub fn derive(
        private_key: &[u8; 32],
        peer_public_key: &[u8; 32],
        random: &[u8; 32],
    ) -> Result<Self, Error> {
        let shared = Zeroizing::new(x25519(*private_key, *peer_public_key));
        if bool::from(shared.as_ref().ct_eq(&[0; 32])) {
            return Err(Error::InvalidPublicKey);
        }
        Self::from_shared_secret(&shared, random)
    }

    /// Adapter point for a TLS crypto provider that exposes the additional ECDH
    /// with the REALITY static server key without consuming its ephemeral key.
    pub fn from_shared_secret(shared: &[u8; 32], random: &[u8; 32]) -> Result<Self, Error> {
        if bool::from(shared.ct_eq(&[0; 32])) {
            return Err(Error::InvalidPublicKey);
        }
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&random[..20]), shared)
            .expand(b"REALITY", key.as_mut())
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(Self(key))
    }

    /// Return the encrypted session ID for a TLS pre-transcript callback. The
    /// input's session ID is treated as zeros when constructing authenticated
    /// data. Each handshake must use fresh TLS randomness and ephemeral keys;
    /// do not reuse a key/nonce pair to seal different identities.
    pub fn seal_client_hello(
        &self,
        hello: &[u8],
        identity: ClientIdentity,
    ) -> Result<[u8; 32], Error> {
        let parsed = ClientHello::parse(hello)?;
        let mut aad = hello.to_vec();
        aad[SESSION_ID_START..SESSION_ID_END].fill(0);
        let mut data = Zeroizing::new(identity.encode());
        let cipher =
            Aes256Gcm::new_from_slice(self.0.as_ref()).map_err(|_| Error::AuthenticationFailed)?;
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&parsed.random[20..]), &aad, data.as_mut())
            .map_err(|_| Error::AuthenticationFailed)?;
        let mut out = [0; 32];
        out[..16].copy_from_slice(data.as_ref());
        out[16..].copy_from_slice(&tag);
        Ok(out)
    }

    /// Authenticate and decrypt without changing the input handshake transcript.
    pub fn open_client_hello(&self, hello: &[u8]) -> Result<ClientIdentity, Error> {
        let parsed = ClientHello::parse(hello)?;
        let mut aad = hello.to_vec();
        aad[SESSION_ID_START..SESSION_ID_END].fill(0);
        let mut data = Zeroizing::new([0; 16]);
        data.copy_from_slice(&parsed.session_id[..16]);
        let cipher =
            Aes256Gcm::new_from_slice(self.0.as_ref()).map_err(|_| Error::AuthenticationFailed)?;
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&parsed.random[20..]),
                &aad,
                data.as_mut(),
                aes_gcm::Tag::from_slice(&parsed.session_id[16..]),
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        ClientIdentity::decode(data.as_ref())
    }

    /// REALITY replaces the X.509 Ed25519 signature with this HMAC-SHA512.
    /// This is not the TLS CertificateVerify signature, which must still be
    /// verified by the TLS implementation using this Ed25519 public key.
    pub fn certificate_marker(&self, ed25519_public_key: &[u8; 32]) -> [u8; 64] {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(self.0.as_ref())
            .expect("HMAC accepts keys of every length");
        mac.update(ed25519_public_key);
        mac.finalize().into_bytes().into()
    }

    /// Verify the marker in constant time. Callers must check the certificate
    /// public-key algorithm is Ed25519 before extracting these bytes.
    /// When ML-DSA verification is configured, this result alone is insufficient.
    pub fn verify_certificate_marker(
        &self,
        ed25519_public_key: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(self.0.as_ref())
            .expect("HMAC accepts keys of every length");
        mac.update(ed25519_public_key);
        mac.verify_slice(signature).is_ok()
    }

    /// Message signed by REALITY's optional ML-DSA-65 certificate extension.
    /// It continues the *same* HMAC after the Ed25519 public-key bytes; hashing
    /// the marker itself, or resetting the HMAC, produces an incompatible value.
    /// The hello arguments include handshake headers, without TLS record headers.
    /// This computes the message only; it does not verify an ML-DSA signature.
    pub fn mldsa65_message(
        &self,
        ed25519_public_key: &[u8; 32],
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> [u8; 64] {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(self.0.as_ref())
            .expect("HMAC accepts keys of every length");
        mac.update(ed25519_public_key);
        mac.update(client_hello);
        mac.update(server_hello);
        mac.finalize().into_bytes().into()
    }
}

/// Insert REALITY's encrypted session ID into a prepared ClientHello before TLS
/// hashes or sends it. The private key must correspond to the selected share
/// already advertised in that hello. The function does not create a fingerprint
/// or generate an ML-KEM key pair.
pub fn authenticated_client_hello(
    hello: &mut [u8],
    client_private_key: &[u8; 32],
    server_public_key: &[u8; 32],
    identity: ClientIdentity,
) -> Result<RealityAuthKey, Error> {
    let parsed = ClientHello::parse(hello)?;
    let public_key = x25519(*client_private_key, X25519_BASEPOINT_BYTES);
    if !bool::from(public_key.ct_eq(parsed.auth_public_key)) {
        return Err(Error::WrongClientPrivateKey);
    }
    let key = RealityAuthKey::derive(client_private_key, server_public_key, parsed.random)?;
    let session_id = key.seal_client_hello(hello, identity)?;
    hello[SESSION_ID_START..SESSION_ID_END].copy_from_slice(&session_id);
    Ok(key)
}

/// The authentication policy applied after AES-GCM verification. A zero maximum
/// time difference disables clock checking, matching the Go server. This policy
/// does not add a replay cache: REALITY's TLS Finished is still required.
#[derive(Clone, Debug, Default)]
pub struct ServerPolicy {
    pub server_names: Vec<String>,
    pub short_ids: Vec<[u8; 8]>,
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    pub max_time_diff: Duration,
}

impl ServerPolicy {
    pub fn validate(
        &self,
        server_name: &[u8],
        identity: &ClientIdentity,
        now: SystemTime,
    ) -> Result<(), Error> {
        if !self
            .server_names
            .iter()
            .any(|name| name.as_bytes() == server_name)
        {
            return Err(Error::ServerNameRejected);
        }
        if self
            .min_client_version
            .is_some_and(|min| identity.version < min)
            || self
                .max_client_version
                .is_some_and(|max| identity.version > max)
        {
            return Err(Error::VersionRejected);
        }
        if !self.max_time_diff.is_zero() {
            let client_time = UNIX_EPOCH + Duration::from_secs(u64::from(identity.unix_seconds));
            let difference = match now.duration_since(client_time) {
                Ok(duration) => duration,
                Err(error) => error.duration(),
            };
            if difference > self.max_time_diff {
                return Err(Error::TimeRejected);
            }
        }
        let mut accepted = subtle::Choice::from(0);
        for configured in &self.short_ids {
            accepted |= configured.ct_eq(&identity.short_id);
        }
        if !bool::from(accepted) {
            return Err(Error::ShortIdRejected);
        }
        Ok(())
    }
}

/// Successful *ClientHello* authentication, not a completed TLS handshake.
pub struct AuthenticatedClient {
    pub identity: ClientIdentity,
    pub auth_key: RealityAuthKey,
}

pub fn authenticate_client_hello(
    hello: &[u8],
    server_private_key: &[u8; 32],
    policy: &ServerPolicy,
    now: SystemTime,
) -> Result<AuthenticatedClient, Error> {
    let parsed = ClientHello::parse(hello)?;
    if !policy
        .server_names
        .iter()
        .any(|name| name.as_bytes() == parsed.server_name)
    {
        return Err(Error::ServerNameRejected);
    }
    let auth_key =
        RealityAuthKey::derive(server_private_key, parsed.auth_public_key, parsed.random)?;
    let identity = auth_key.open_client_hello(hello)?;
    policy.validate(parsed.server_name, &identity, now)?;
    Ok(AuthenticatedClient { identity, auth_key })
}

/// A bounded parser for the REALITY authentication fields. A TLS stack must also
/// validate the complete ClientHello semantics. Unknown extensions are kept in
/// the authenticated raw message and are otherwise ignored here.
#[derive(Clone, Copy, Debug)]
pub struct ClientHello<'a> {
    pub random: &'a [u8; 32],
    pub session_id: &'a [u8; 32],
    /// Byte comparison matches Go; no case folding or DNS canonicalization.
    pub server_name: &'a [u8],
    /// X25519, or the X25519 tail of the hybrid share when no standalone share exists.
    pub auth_public_key: &'a [u8; 32],
}

impl<'a> ClientHello<'a> {
    pub fn parse(message: &'a [u8]) -> Result<Self, Error> {
        let mut input = Reader(message);
        if input.u8()? != 1 {
            return Err(Error::MalformedClientHello);
        }
        let length = input.take(3)?;
        let length =
            (usize::from(length[0]) << 16) | (usize::from(length[1]) << 8) | usize::from(length[2]);
        if length != input.0.len() {
            return Err(Error::MalformedClientHello);
        }
        if input.u16()? != 0x0303 {
            return Err(Error::Tls13Required);
        }
        let random = input
            .take(32)?
            .try_into()
            .map_err(|_| Error::MalformedClientHello)?;
        let session_id = input
            .vector8()?
            .try_into()
            .map_err(|_| Error::InvalidSessionId)?;
        let ciphers = input.vector16()?;
        if ciphers.is_empty() || ciphers.len() % 2 != 0 {
            return Err(Error::MalformedClientHello);
        }
        if input.vector8()? != [0] {
            return Err(Error::MalformedClientHello);
        }
        let mut extensions = Reader(input.vector16()?);
        input.end()?;
        let mut seen = BTreeSet::new();
        let mut server_name: &[u8] = &[];
        let mut auth_public_key = None;
        let mut tls13 = false;
        while !extensions.0.is_empty() {
            let kind = extensions.u16()?;
            let mut value = Reader(extensions.vector16()?);
            if !seen.insert(kind) {
                return Err(Error::DuplicateExtension);
            }
            match kind {
                0 => {
                    let mut names = Reader(value.vector16()?);
                    if names.0.is_empty() {
                        return Err(Error::MalformedClientHello);
                    }
                    while !names.0.is_empty() {
                        let name_type = names.u8()?;
                        let name = names.vector16()?;
                        if name.is_empty() {
                            return Err(Error::MalformedClientHello);
                        }
                        if name_type == 0 {
                            if !server_name.is_empty() || name.ends_with(b".") {
                                return Err(Error::MalformedClientHello);
                            }
                            server_name = name;
                        }
                    }
                }
                43 => {
                    let versions = value.vector8()?;
                    if versions.is_empty() || versions.len() % 2 != 0 {
                        return Err(Error::MalformedClientHello);
                    }
                    tls13 = versions.chunks_exact(2).any(|version| version == [3, 4]);
                }
                51 => {
                    auth_public_key = Some(select_auth_key_share(value.vector16()?)?);
                }
                _ => {
                    value.0 = &[];
                }
            }
            value.end()?;
        }
        if !tls13 {
            return Err(Error::Tls13Required);
        }
        Ok(Self {
            random,
            session_id,
            server_name,
            auth_public_key: auth_public_key.ok_or(Error::HybridKeyShareRequired)?,
        })
    }
}

fn select_auth_key_share(bytes: &[u8]) -> Result<&[u8; 32], Error> {
    let mut input = Reader(bytes);
    let mut hybrid = None;
    let mut classical = None;
    let mut selection_complete = false;
    while !input.0.is_empty() {
        let group = input.u16()?;
        let data = input.vector16()?;
        if data.is_empty() {
            return Err(Error::MalformedClientHello);
        }
        // The reference stops selecting after the first correctly sized X25519,
        // but its TLS parser still validates the encoding of all remaining shares.
        if selection_complete {
            continue;
        }
        if group == X25519_MLKEM768_GROUP && data.len() == MLKEM768_PUBLIC_KEY_LEN + 32 {
            if hybrid.is_some() {
                return Err(Error::InvalidKeyShareOrder);
            }
            hybrid = Some(
                data[MLKEM768_PUBLIC_KEY_LEN..]
                    .try_into()
                    .map_err(|_| Error::MalformedClientHello)?,
            );
        } else if group == X25519_GROUP && data.len() == 32 {
            if hybrid.is_none() {
                return Err(Error::InvalidKeyShareOrder);
            }
            classical = Some(data.try_into().map_err(|_| Error::MalformedClientHello)?);
            selection_complete = true;
        }
    }
    hybrid
        .ok_or(Error::HybridKeyShareRequired)
        .map(|hybrid| classical.unwrap_or(hybrid))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err(Error::MalformedClientHello);
        }
        let (out, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn vector8(&mut self) -> Result<&'a [u8], Error> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }
    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
    fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::MalformedClientHello)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SESSION_ID: &str = "161ddad168daf221363144ba2eb8cd580d20b586c293ae5bee3970271ed3b7a5";
    const ED25519_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn key(value: &str) -> [u8; 32] {
        hex(value).try_into().unwrap()
    }
    fn vector(value: &[u8]) -> Vec<u8> {
        let mut out = (value.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(value);
        out
    }
    fn extension(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend(vector(value));
        out
    }
    fn shares(hybrid_key: &[u8; 32], standalone: Option<&[u8; 32]>) -> Vec<u8> {
        // Synthetic ML-KEM bytes are sufficient for the authentication fixture;
        // this is deliberately not presented as an interoperable TLS handshake.
        let mut hybrid = vec![0xa5; MLKEM768_PUBLIC_KEY_LEN];
        hybrid.extend_from_slice(hybrid_key);
        let mut out = extension(X25519_MLKEM768_GROUP, &hybrid);
        if let Some(public) = standalone {
            out.extend(extension(X25519_GROUP, public));
        }
        out
    }
    fn hello_with(shares: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend(0..32);
        body.push(32);
        body.extend([0; 32]);
        body.extend(vector(&[0x13, 1, 0x13, 2, 0x13, 3]));
        body.extend([1, 0]);
        let mut name = vec![0];
        name.extend(vector(b"example.com"));
        let mut extensions = extension(0, &vector(&name));
        extensions.extend(extension(43, &[2, 3, 4]));
        extensions.extend(extension(51, &vector(shares)));
        extensions.extend_from_slice(extra);
        body.extend(vector(&extensions));
        let mut out = vec![1];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend(body);
        out
    }
    fn hello() -> Vec<u8> {
        hello_with(
            &shares(&[0x5a; 32], Some(&key(ALICE_PUBLIC))),
            &extension(0xaaaa, &[0x12, 0x34]),
        )
    }
    fn identity() -> ClientIdentity {
        ClientIdentity::new([26, 3, 27], 1_700_000_000, [1, 2, 3, 4, 5, 6, 7, 8])
    }
    fn policy() -> ServerPolicy {
        ServerPolicy {
            server_names: vec!["example.com".into()],
            short_ids: vec![identity().short_id],
            min_client_version: Some([26, 3, 27]),
            max_client_version: Some([26, 3, 27]),
            max_time_diff: Duration::from_millis(1500),
        }
    }
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(u64::from(identity().unix_seconds))
    }
    fn signed_hello() -> (Vec<u8>, RealityAuthKey) {
        let mut hello = hello();
        let auth = authenticated_client_hello(
            &mut hello,
            &key(ALICE_PRIVATE),
            &key(BOB_PUBLIC),
            identity(),
        )
        .unwrap();
        (hello, auth)
    }

    #[test]
    fn independent_python_cryptography_golden_session_id() {
        // Produced independently with Python cryptography 50.0.1 / OpenSSL:
        // RFC 7748 keys, HKDF-SHA256, AESGCM.encrypt; not a Rust round trip.
        let raw = hello();
        assert_eq!(raw.len(), 1378);
        assert_eq!(
            Sha256::digest(&raw).as_slice(),
            hex("366e34753d8cdd30f91622574ff728c257bc0a4cbd215220d9fc6ae545380198")
        );
        let (signed, auth) = signed_hello();
        assert_eq!(
            auth.0.as_ref(),
            hex("68e5a4d6fbfc0f93477d737fbdd45bd5f81578fbd172327b6db8e963e2ba4a3c")
        );
        assert_eq!(&signed[39..71], hex(SESSION_ID));
        assert_eq!(
            Sha256::digest(&signed).as_slice(),
            hex("6bd2402b7f615b517143ca7d047c425dd1e36a886b2a4ccd0d94134a95345acb")
        );
        let authenticated =
            authenticate_client_hello(&signed, &key(BOB_PRIVATE), &policy(), now()).unwrap();
        assert_eq!(authenticated.identity, identity());
        assert_eq!(authenticated.auth_key.0.as_ref(), auth.0.as_ref());
        assert_eq!(&signed[..39], &raw[..39]);
        assert_eq!(&signed[71..], &raw[71..]);
    }

    #[test]
    fn independently_generated_ciphertext_opens() {
        let mut raw = hello();
        raw[39..71].copy_from_slice(&hex(SESSION_ID));
        let result = authenticate_client_hello(&raw, &key(BOB_PRIVATE), &policy(), now()).unwrap();
        assert_eq!(result.identity, identity());
    }

    #[test]
    fn independent_certificate_and_mldsa_transcript_vectors() {
        let (raw, auth) = signed_hello();
        let public_key = key(ED25519_PUBLIC);
        let expected = hex(
            "b393ce0d664a88657f0d1b8bef84cb8281b3f980e66c4d3bdb40aaf948bc0b67668fb1cff4e8517a58478e0430ac6253bd6f43b58706b8fca5e5fe1a4edc2259",
        );
        assert_eq!(auth.certificate_marker(&public_key).as_slice(), expected);
        assert!(auth.verify_certificate_marker(&public_key, &expected));
        let server_hello = hex(
            "020000760303202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f20161ddad168daf221363144ba2eb8cd580d20b586c293ae5bee3970271ed3b7a5130100002e002b0002030400330024001d0020de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        );
        let expected = hex(
            "f5657daefdf14d3e5e605d4d4917a17d40e2dca83ff862e9f51326449af056ee3d367e523de5f0c21d5a774f9133fa41095bd81c85d52202eda52737b482db0c",
        );
        assert_eq!(
            auth.mldsa65_message(&public_key, &raw, &server_hello)
                .as_slice(),
            expected
        );
        assert_ne!(
            auth.mldsa65_message(&public_key, &raw[4..], &server_hello)
                .as_slice(),
            expected
        );
    }

    #[test]
    fn certificate_marker_rejects_wrong_key_tampering_and_length() {
        let (_, auth) = signed_hello();
        let public_key = key(ED25519_PUBLIC);
        let mut signature = auth.certificate_marker(&public_key);
        assert!(!auth.verify_certificate_marker(&[0; 32], &signature));
        assert!(!auth.verify_certificate_marker(&public_key, &signature[..63]));
        signature[63] ^= 1;
        assert!(!auth.verify_certificate_marker(&public_key, &signature));
    }

    #[test]
    fn tampering_every_client_hello_byte_is_rejected() {
        let (raw, _) = signed_hello();
        for index in 0..raw.len() {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            assert!(
                authenticate_client_hello(&changed, &key(BOB_PRIVATE), &policy(), now()).is_err(),
                "byte {index} escaped authentication"
            );
        }
    }

    #[test]
    fn truncated_and_extra_bytes_never_parse() {
        let raw = hello();
        for length in 0..raw.len() {
            assert!(
                ClientHello::parse(&raw[..length]).is_err(),
                "accepted truncation at {length}"
            );
        }
        let mut extra = raw;
        extra.push(0);
        assert!(ClientHello::parse(&extra).is_err());
    }

    #[test]
    fn required_hybrid_share_precedes_optional_x25519() {
        let public = key(ALICE_PUBLIC);
        let raw = hello_with(&extension(X25519_GROUP, &public), &[]);
        assert_eq!(
            ClientHello::parse(&raw).unwrap_err(),
            Error::InvalidKeyShareOrder
        );
        let mut wrong_order = extension(X25519_GROUP, &public);
        wrong_order.extend(shares(&public, None));
        assert_eq!(
            ClientHello::parse(&hello_with(&wrong_order, &[])).unwrap_err(),
            Error::InvalidKeyShareOrder
        );
        let mut duplicate = shares(&public, None);
        duplicate.extend(shares(&public, None));
        assert_eq!(
            ClientHello::parse(&hello_with(&duplicate, &[])).unwrap_err(),
            Error::InvalidKeyShareOrder
        );
        let raw = hello_with(&shares(&[0x5a; 32], Some(&public)), &[]);
        assert_eq!(ClientHello::parse(&raw).unwrap().auth_public_key, &public);
    }

    #[test]
    fn hybrid_only_uses_its_x25519_tail() {
        let public = key(ALICE_PUBLIC);
        let mut raw = hello_with(&shares(&public, None), &[]);
        let client =
            authenticated_client_hello(&mut raw, &key(ALICE_PRIVATE), &key(BOB_PUBLIC), identity())
                .unwrap();
        let server = authenticate_client_hello(&raw, &key(BOB_PRIVATE), &policy(), now()).unwrap();
        assert_eq!(server.identity, identity());
        assert_eq!(client.0.as_ref(), server.auth_key.0.as_ref());
    }

    #[test]
    fn wrong_private_and_low_order_peer_keys_are_rejected_without_mutation() {
        let mut raw = hello();
        let original = raw.clone();
        assert!(matches!(
            authenticated_client_hello(&mut raw, &key(BOB_PRIVATE), &key(BOB_PUBLIC), identity()),
            Err(Error::WrongClientPrivateKey)
        ));
        assert_eq!(raw, original);
        for low_order in [[0; 32], {
            let mut one = [0; 32];
            one[0] = 1;
            one
        }] {
            assert!(matches!(
                authenticated_client_hello(&mut raw, &key(ALICE_PRIVATE), &low_order, identity()),
                Err(Error::InvalidPublicKey)
            ));
            assert_eq!(raw, original);
        }
    }

    #[test]
    fn duplicate_extensions_and_missing_tls13_are_rejected() {
        let raw = hello_with(
            &shares(&[0x5a; 32], Some(&key(ALICE_PUBLIC))),
            &extension(43, &[2, 3, 4]),
        );
        assert_eq!(
            ClientHello::parse(&raw).unwrap_err(),
            Error::DuplicateExtension
        );
        let mut raw = hello();
        let index = raw
            .windows(7)
            .position(|bytes| bytes == [0, 43, 0, 3, 2, 3, 4])
            .unwrap();
        raw[index + 6] = 3;
        assert_eq!(ClientHello::parse(&raw).unwrap_err(), Error::Tls13Required);
        raw = hello();
        raw[38] = 0;
        assert_eq!(
            ClientHello::parse(&raw).unwrap_err(),
            Error::InvalidSessionId
        );
    }

    #[test]
    fn version_policy_uses_inclusive_three_byte_order() {
        let policy = policy();
        let mut identity = identity();
        policy.validate(b"example.com", &identity, now()).unwrap();
        for version in [[26, 3, 26], [26, 3, 28], [25, 255, 255], [27, 0, 0]] {
            identity.version = version;
            assert_eq!(
                policy.validate(b"example.com", &identity, now()),
                Err(Error::VersionRejected)
            );
        }
    }

    #[test]
    fn timestamp_milliseconds_are_symmetric_and_inclusive() {
        let policy = policy();
        let identity = identity();
        for time in [
            now() + Duration::from_millis(1500),
            now() - Duration::from_millis(1500),
        ] {
            policy.validate(b"example.com", &identity, time).unwrap();
        }
        for time in [
            // Use an offset representable by Windows' SystemTime clock.
            now() + Duration::from_millis(1501),
            now() - Duration::from_millis(1501),
        ] {
            assert_eq!(
                policy.validate(b"example.com", &identity, time),
                Err(Error::TimeRejected)
            );
        }
        let mut policy = policy;
        policy.max_time_diff = Duration::ZERO;
        policy
            .validate(b"example.com", &identity, UNIX_EPOCH)
            .unwrap();
    }

    #[test]
    fn policy_rejects_wrong_server_name_short_id_and_empty_allowlist() {
        let mut policy = policy();
        assert_eq!(
            policy.validate(b"EXAMPLE.COM", &identity(), now()),
            Err(Error::ServerNameRejected)
        );
        policy.short_ids = vec![[0; 8]];
        assert_eq!(
            policy.validate(b"example.com", &identity(), now()),
            Err(Error::ShortIdRejected)
        );
        policy.short_ids.clear();
        assert_eq!(
            policy.validate(b"example.com", &identity(), now()),
            Err(Error::ShortIdRejected)
        );
        policy.short_ids = vec![[0; 8], identity().short_id];
        policy.validate(b"example.com", &identity(), now()).unwrap();
    }

    #[test]
    fn reserved_byte_is_authenticated_but_not_rejected() {
        let mut raw = hello();
        let mut identity = identity();
        identity.reserved = 255;
        authenticated_client_hello(&mut raw, &key(ALICE_PRIVATE), &key(BOB_PUBLIC), identity)
            .unwrap();
        assert_eq!(
            authenticate_client_hello(&raw, &key(BOB_PRIVATE), &policy(), now())
                .unwrap()
                .identity,
            identity
        );
    }

    #[test]
    fn short_ids_follow_go_hex_decode_and_right_padding() {
        assert_eq!(decode_short_id("").unwrap(), [0; 8]);
        assert_eq!(
            decode_short_id("aBcD").unwrap(),
            [0xab, 0xcd, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            decode_short_id("0102030405060708").unwrap(),
            identity().short_id
        );
        for invalid in ["a", "0", "0x12", "12 3", "xyz0", "010203040506070809", "é"] {
            assert_eq!(decode_short_id(invalid), Err(Error::InvalidShortId));
        }
    }
}
pub mod handshake;
