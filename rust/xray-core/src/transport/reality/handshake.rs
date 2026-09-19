//! Strict native TLS 1.3 REALITY client for the pinned Go protocol.
//!
//! This is an explicit native ClientHello profile, not browser fingerprint
//! emulation. It supports fresh X25519MLKEM768 and X25519 handshakes, the three
//! TLS 1.3 cipher suites, REALITY's Ed25519 certificate marker, CertificateVerify,
//! Finished, application records and KeyUpdate. It never accepts public WebPKI
//! certificates as authenticated proxy success. See REALITY_HANDSHAKE.md for
//! interoperability evidence and the still-unsupported camouflage/settings.

mod crypto;
pub mod server;
mod stream;
mod wire;

use std::{
    future::poll_fn,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};
use ml_kem::{Decapsulate, DecapsulationKey, KeyExport, MlKem768};
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use x509_parser::prelude::{FromDer, X509Certificate};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use super::{ClientIdentity, RealityAuthKey, authenticated_client_hello};
use crate::transport::BoxStream;

pub use crypto::CipherSuite;
use crypto::{HandshakeSecrets, RecordCipher, Transcript, verify_finished};
pub use stream::ClientStream;
use wire::{Cursor, HandshakeBuffer, RecordReader};

#[derive(Clone)]
pub struct ClientConfig {
    pub server_name: String,
    pub server_public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub client_version: [u8; 3],
    pub alpn: Vec<Vec<u8>>,
    /// When false, advertise hybrid first and standalone X25519 second.
    pub hybrid_only: bool,
    /// Optional 1952-byte ML-DSA-65 public key. When configured, the first X.509
    /// extension must authenticate both original hello messages as in Go REALITY.
    pub mldsa65_verify: Option<Vec<u8>>,
    pub handshake_timeout: Duration,
    pub max_handshake_bytes: usize,
}

impl ClientConfig {
    pub fn new(
        server_name: String,
        server_public_key: [u8; 32],
        short_id: [u8; 8],
        client_version: [u8; 3],
    ) -> Self {
        Self {
            server_name,
            server_public_key,
            short_id,
            client_version,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            hybrid_only: false,
            mldsa65_verify: None,
            handshake_timeout: Duration::from_secs(15),
            max_handshake_bytes: 1 << 20,
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.server_name.is_empty()
            || self.server_name.len() > 253
            || !self.server_name.is_ascii()
            || self
                .server_name
                .bytes()
                .any(|byte| byte <= 32 || byte >= 127)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY requires a nonempty ASCII server name up to 253 bytes",
            ));
        }
        if self
            .alpn
            .iter()
            .any(|value| value.is_empty() || value.len() > 255)
            || self.alpn.iter().map(|value| value.len() + 1).sum::<usize>() > 65533
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid REALITY ALPN list",
            ));
        }
        if self
            .mldsa65_verify
            .as_ref()
            .is_some_and(|key| !key.is_empty() && key.len() != 1952)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY ML-DSA-65 public key must contain 1952 bytes",
            ));
        }
        if self.handshake_timeout.is_zero() || !(4096..=4 << 20).contains(&self.max_handshake_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid REALITY handshake timeout or memory limit",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub cipher_suite: CipherSuite,
    pub key_exchange_group: u16,
    pub alpn: Option<Vec<u8>>,
}

/// Perform the complete authenticated handshake before returning a usable stream.
/// Cancellation drops the input stream and all ephemeral key material.
pub async fn client(
    stream: BoxStream,
    config: ClientConfig,
) -> io::Result<(ClientStream, ConnectionInfo)> {
    config.validate()?;
    tokio::time::timeout(config.handshake_timeout, connect(stream, &config))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY TLS handshake timed out"))?
}

pub async fn client_boxed(stream: BoxStream, config: ClientConfig) -> io::Result<BoxStream> {
    let (stream, _) = client(stream, config).await?;
    Ok(Box::new(stream))
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct EphemeralKeys {
    hybrid_x25519: Zeroizing<[u8; 32]>,
    standalone_x25519: Zeroizing<[u8; 32]>,
    mlkem: DecapsulationKey<MlKem768>,
}

impl EphemeralKeys {
    fn generate() -> io::Result<Self> {
        let mut hybrid_x25519 = Zeroizing::new([0; 32]);
        let mut standalone_x25519 = Zeroizing::new([0; 32]);
        let mut seed = Zeroizing::new([0; 64]);
        OsRng
            .try_fill_bytes(hybrid_x25519.as_mut())
            .map_err(io::Error::other)?;
        OsRng
            .try_fill_bytes(standalone_x25519.as_mut())
            .map_err(io::Error::other)?;
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(io::Error::other)?;
        let mlkem = DecapsulationKey::<MlKem768>::from_seed((*seed).into());
        Ok(Self {
            hybrid_x25519,
            standalone_x25519,
            mlkem,
        })
    }

    fn hybrid_public(&self) -> Vec<u8> {
        let mut public = self.mlkem.encapsulation_key().to_bytes().to_vec();
        public.extend_from_slice(&x25519(*self.hybrid_x25519, X25519_BASEPOINT_BYTES));
        public
    }

    fn shared_secret(&self, group: u16, share: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let (private, peer) = match (group, share.len()) {
            (0x11ec, 1120) => (&self.hybrid_x25519, &share[1088..]),
            (0x001d, 32) => (&self.standalone_x25519, share),
            _ => return Err(invalid("invalid server key share")),
        };
        let peer = peer
            .try_into()
            .map_err(|_| invalid("invalid X25519 public key length"))?;
        let ecdh = Zeroizing::new(x25519(**private, peer));
        if bool::from(ecdh.as_ref().ct_eq(&[0; 32])) {
            return Err(invalid("server sent a low-order X25519 public key"));
        }
        let mut result = Zeroizing::new(Vec::with_capacity(64));
        if group == 0x11ec {
            let ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(&share[..1088])
                .map_err(|_| invalid("invalid ML-KEM ciphertext length"))?;
            let secret = Zeroizing::new(self.mlkem.decapsulate(&ciphertext));
            result.extend_from_slice(secret.as_slice());
        }
        result.extend_from_slice(ecdh.as_ref());
        Ok(result)
    }
}

async fn connect(
    mut stream: BoxStream,
    config: &ClientConfig,
) -> io::Result<(ClientStream, ConnectionInfo)> {
    let keys = EphemeralKeys::generate()?;
    let mut random = [0; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(io::Error::other)?;
    let standalone = x25519(*keys.standalone_x25519, X25519_BASEPOINT_BYTES);
    let mut hello = wire::client_hello(config, &random, &keys.hybrid_public(), &standalone)?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs() as u32;
    let identity = ClientIdentity::new(config.client_version, seconds, config.short_id);
    let auth_private = if config.hybrid_only {
        &keys.hybrid_x25519
    } else {
        &keys.standalone_x25519
    };
    let auth = authenticated_client_hello(
        &mut hello,
        auth_private,
        &config.server_public_key,
        identity,
    )
    .map_err(io::Error::other)?;
    for (index, fragment) in hello.chunks(16384).enumerate() {
        let mut initial = vec![22, 3, if index == 0 { 1 } else { 3 }];
        initial.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        initial.extend_from_slice(fragment);
        stream.write_all(&initial).await?;
    }
    stream.flush().await?;

    let mut reader = RecordReader::default();
    let mut messages = HandshakeBuffer::new(config.max_handshake_bytes);
    let mut ignored_ccs = 0;
    let server_hello = loop {
        if let Some(message) = messages.take()? {
            break message;
        }
        let record = poll_fn(|cx| reader.poll_read(&mut stream, cx)).await?;
        match record.header[0] {
            22 => {
                if record.payload.len() > 16384 {
                    return Err(invalid("oversized plaintext TLS record"));
                }
                messages.push(&record.payload)?;
            }
            20 if record.payload == [1] && ignored_ccs < 8 => ignored_ccs += 1,
            21 => {
                return Err(invalid(
                    "peer rejected REALITY ClientHello with a TLS alert",
                ));
            }
            _ => return Err(invalid("expected plaintext TLS ServerHello")),
        }
    };
    if !messages.is_empty() {
        return Err(invalid("extra plaintext TLS handshake after ServerHello"));
    }
    let parsed = wire::parse_server_hello(&server_hello, &hello[39..71], config.hybrid_only)?;
    let suite = parsed.suite;
    let group = parsed.group;
    let shared = keys.shared_secret(group, parsed.share)?;
    let mut transcript = Transcript::new(suite);
    transcript.update(&hello);
    transcript.update(&server_hello);
    let secrets = HandshakeSecrets::new(suite, &shared, &transcript.hash())?;
    drop(shared);
    drop(keys);
    let mut read_cipher = RecordCipher::new(suite, secrets.server.clone())?;
    let mut write_cipher = RecordCipher::new(suite, secrets.client.clone())?;
    let mut stage = 0;
    let mut public_key = None;
    let mut alpn = None;
    loop {
        if let Some(message) = messages.take()? {
            match (stage, message[0]) {
                (0, 8) => alpn = wire::encrypted_extensions(&message[4..], &config.alpn)?,
                (1, 11) => {
                    public_key = Some(verify_certificate(
                        &message[4..],
                        &auth,
                        config.mldsa65_verify.as_deref(),
                        &hello,
                        &server_hello,
                    )?)
                }
                (2, 15) => verify_certificate_verify(
                    &message[4..],
                    public_key
                        .as_ref()
                        .ok_or_else(|| invalid("missing REALITY certificate"))?,
                    &transcript.hash(),
                )?,
                (3, 20) => {
                    let finished = suite.finished(&secrets.server, &transcript.hash())?;
                    verify_finished(&finished, &message[4..])?;
                    transcript.update(&message);
                    if !messages.is_empty() {
                        return Err(invalid("server Finished did not end a TLS record"));
                    }
                    break;
                }
                _ => return Err(invalid("unexpected REALITY TLS handshake message or order")),
            }
            transcript.update(&message);
            stage += 1;
            continue;
        }
        let record = poll_fn(|cx| reader.poll_read(&mut stream, cx)).await?;
        if record.header[0] == 20 && record.payload == [1] && ignored_ccs < 8 {
            ignored_ccs += 1;
            continue;
        }
        let (kind, plain) = read_cipher.open(&record.header, record.payload)?;
        if kind != 22 {
            return Err(invalid("expected encrypted REALITY TLS handshake"));
        }
        messages.push(&plain)?;
    }
    let (application_write, application_read) = secrets.application(&transcript.hash())?;
    let client_finished = suite.finished(&secrets.client, &transcript.hash())?;
    let finished_message = wire::handshake(20, &client_finished)?;
    // Middlebox compatibility CCS is not encrypted and is not in the transcript.
    stream.write_all(&[20, 3, 3, 0, 1, 1]).await?;
    stream
        .write_all(&write_cipher.seal(22, &finished_message)?)
        .await?;
    stream.flush().await?;
    Ok((
        ClientStream::new(
            stream,
            application_read,
            application_write,
            config.max_handshake_bytes,
        ),
        ConnectionInfo {
            cipher_suite: suite,
            key_exchange_group: group,
            alpn,
        },
    ))
}

fn verify_certificate(
    body: &[u8],
    auth: &RealityAuthKey,
    mldsa65_key: Option<&[u8]>,
    client_hello: &[u8],
    server_hello: &[u8],
) -> io::Result<VerifyingKey> {
    let mut message = Cursor::new(body);
    if !message.vec8()?.is_empty() {
        return Err(invalid("server certificate request context must be empty"));
    }
    let mut list = Cursor::new(message.vec24()?);
    message.done()?;
    let mut leaf_key = None;
    while !list.rest.is_empty() {
        let der = list.vec24()?;
        let extensions = list.vec16()?;
        let (remaining, cert) = X509Certificate::from_der(der)
            .map_err(|_| invalid("invalid REALITY X.509 certificate"))?;
        if !remaining.is_empty() {
            return Err(invalid("trailing bytes in REALITY certificate"));
        }
        let mut extensions = Cursor::new(extensions);
        let mut seen = std::collections::BTreeSet::new();
        while !extensions.rest.is_empty() {
            let id = extensions.u16()?;
            extensions.vec16()?;
            if !seen.insert(id) {
                return Err(invalid("duplicate TLS certificate extension"));
            }
        }
        if leaf_key.is_none() {
            let spki = cert.public_key();
            if spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
                || spki.algorithm.parameters.is_some()
                || spki.subject_public_key.unused_bits != 0
                || cert.signature_value.unused_bits != 0
            {
                return Err(invalid(
                    "REALITY certificate must contain an Ed25519 public key",
                ));
            }
            let key: [u8; 32] = spki
                .subject_public_key
                .data
                .as_ref()
                .try_into()
                .map_err(|_| invalid("invalid REALITY Ed25519 public key length"))?;
            if !auth.verify_certificate_marker(&key, cert.signature_value.data.as_ref()) {
                return Err(invalid("REALITY certificate marker authentication failed"));
            }
            if let Some(verify_key) = mldsa65_key.filter(|key| !key.is_empty()) {
                let extension = cert.extensions().first().ok_or_else(|| {
                    invalid("REALITY certificate lacks configured ML-DSA-65 signature")
                })?;
                verify_mldsa65(
                    verify_key,
                    extension.value,
                    &auth.mldsa65_message(&key, client_hello, server_hello),
                )?;
            }
            leaf_key = Some(
                VerifyingKey::from_bytes(&key)
                    .map_err(|_| invalid("invalid REALITY Ed25519 public key"))?,
            );
        }
    }
    leaf_key.ok_or_else(|| invalid("REALITY server sent an empty certificate chain"))
}

fn verify_mldsa65(public_key: &[u8], signature: &[u8], message: &[u8]) -> io::Result<()> {
    let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(public_key)
        .map_err(|_| invalid("invalid REALITY ML-DSA-65 public key length"))?;
    let key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded);
    let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature)
        .map_err(|_| invalid("invalid REALITY ML-DSA-65 signature encoding"))?;
    if !key.verify_with_context(message, b"", &signature) {
        return Err(invalid(
            "REALITY ML-DSA-65 certificate authentication failed",
        ));
    }
    Ok(())
}

fn verify_certificate_verify(
    body: &[u8],
    key: &VerifyingKey,
    transcript_hash: &[u8],
) -> io::Result<()> {
    let mut message = Cursor::new(body);
    if message.u16()? != 0x0807 {
        return Err(invalid("REALITY CertificateVerify must use Ed25519"));
    }
    let signature = Signature::from_slice(message.vec16()?)
        .map_err(|_| invalid("invalid REALITY CertificateVerify signature length"))?;
    message.done()?;
    let mut signed = vec![32; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(transcript_hash);
    key.verify_strict(&signed, &signature)
        .map_err(|_| invalid("REALITY CertificateVerify signature authentication failed"))
}

#[cfg(test)]
mod tests;
