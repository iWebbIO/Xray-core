//! Authenticated native REALITY TLS 1.3 server for explicitly configured peers.
//!
//! `accept` is a standalone authenticated endpoint. `accept_with_target` adds
//! bounded target ServerHello/record-size mirroring and rejected-peer forwarding
//! through a caller-supplied target connection. Neither profile resumes sessions,
//! accepts early data, requests client certificates, or signs with ML-DSA.

mod certificate;
mod hello;
mod target;

pub use target::{TargetOutcome, accept_with_target};

use std::{
    future::poll_fn,
    io,
    time::{Duration, SystemTime},
};

use ed25519_dalek::Signer;
use rand::{RngCore, rngs::OsRng};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use super::super::{ClientIdentity, ServerPolicy, authenticate_client_hello};
use super::{
    CipherSuite, ClientStream, ConnectionInfo,
    crypto::{HandshakeSecrets, RecordCipher, Transcript, verify_finished},
    invalid,
    wire::{self, HandshakeBuffer, RecordReader},
};
use crate::transport::BoxStream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyExchangeGroup {
    X25519MlKem768,
    X25519,
}

impl KeyExchangeGroup {
    pub fn id(self) -> u16 {
        match self {
            Self::X25519MlKem768 => 0x11ec,
            Self::X25519 => 0x001d,
        }
    }
}

/// Clone for independent accepted connections; the static key is zeroized on
/// drop. Explicit policy admission is required before any server TLS response.
#[derive(Clone)]
pub struct ServerConfig {
    private_key: Zeroizing<[u8; 32]>,
    pub policy: ServerPolicy,
    pub cipher_suites: Vec<CipherSuite>,
    pub key_exchange_groups: Vec<KeyExchangeGroup>,
    pub alpn: Vec<Vec<u8>>,
    pub handshake_timeout: Duration,
    pub max_handshake_bytes: usize,
}

impl ServerConfig {
    pub fn new(private_key: [u8; 32], policy: ServerPolicy) -> Self {
        Self {
            private_key: Zeroizing::new(private_key),
            policy,
            cipher_suites: vec![
                CipherSuite::Aes128GcmSha256,
                CipherSuite::Aes256GcmSha384,
                CipherSuite::ChaCha20Poly1305Sha256,
            ],
            key_exchange_groups: vec![KeyExchangeGroup::X25519MlKem768, KeyExchangeGroup::X25519],
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            handshake_timeout: Duration::from_secs(15),
            max_handshake_bytes: 1 << 20,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        x25519(*self.private_key, X25519_BASEPOINT_BYTES)
    }

    fn validate(&self) -> io::Result<()> {
        if self.policy.server_names.is_empty()
            || self.policy.short_ids.is_empty()
            || self.policy.max_time_diff.is_zero()
        {
            return Err(invalid(
                "native REALITY server requires SNI, short-ID and nonzero timestamp-window policies",
            ));
        }
        if self.policy.server_names.iter().any(|name| {
            name.is_empty()
                || name.len() > 253
                || !name.is_ascii()
                || name.ends_with('.')
                || name.bytes().any(|b| b <= 32 || b >= 127)
        }) {
            return Err(invalid("invalid REALITY server policy name"));
        }
        if matches!((self.policy.min_client_version,self.policy.max_client_version),(Some(min),Some(max)) if min>max)
        {
            return Err(invalid("REALITY client-version policy range is reversed"));
        }
        if self.cipher_suites.is_empty()
            || self.key_exchange_groups.is_empty()
            || self
                .cipher_suites
                .iter()
                .enumerate()
                .any(|(i, v)| self.cipher_suites[..i].contains(v))
            || self
                .key_exchange_groups
                .iter()
                .enumerate()
                .any(|(i, v)| self.key_exchange_groups[..i].contains(v))
        {
            return Err(invalid(
                "REALITY server requires unique cipher suites and key exchange groups",
            ));
        }
        if self.alpn.iter().any(|v| v.is_empty() || v.len() > 255)
            || self.alpn.iter().map(|v| v.len() + 1).sum::<usize>() > 65533
        {
            return Err(invalid("invalid REALITY server ALPN list"));
        }
        if self.handshake_timeout.is_zero() || !(4096..=4 << 20).contains(&self.max_handshake_bytes)
        {
            return Err(invalid("invalid REALITY server handshake resource limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConnectionInfo {
    pub tls: ConnectionInfo,
    pub identity: ClientIdentity,
    pub server_name: String,
}

/// Complete policy authentication and both TLS Finished checks before exposing
/// application I/O. Error/timeout/cancellation drops the owned input stream.
pub async fn accept(
    stream: BoxStream,
    config: ServerConfig,
) -> io::Result<(ClientStream, ServerConnectionInfo)> {
    config.validate()?;
    tokio::time::timeout(config.handshake_timeout, handshake(stream, &config))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "REALITY server handshake timed out",
            )
        })?
}

pub async fn accept_boxed(stream: BoxStream, config: ServerConfig) -> io::Result<BoxStream> {
    let (stream, _) = accept(stream, config).await?;
    Ok(Box::new(stream))
}

async fn read_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut messages = HandshakeBuffer::new(limit);
    loop {
        // The first ClientHello may use legacy_record_version 0x0301. The shared
        // post-ServerHello record reader expects 0x0303, so use this bounded
        // plaintext reader only for the initial, possibly fragmented message.
        let mut header = [0; 5];
        stream.read_exact(&mut header).await?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != 22
            || header[1] != 3
            || !matches!(header[2], 1 | 3)
            || !(1..=16384).contains(&length)
        {
            return Err(invalid(
                "expected a bounded plaintext TLS ClientHello record",
            ));
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        messages.push(&body)?;
        if let Some(message) = messages.take()? {
            if message[0] != 1 || !messages.is_empty() {
                return Err(invalid("ClientHello must end at a TLS record boundary"));
            }
            return Ok(message);
        }
    }
}

async fn handshake(
    mut stream: BoxStream,
    config: &ServerConfig,
) -> io::Result<(ClientStream, ServerConnectionInfo)> {
    let client_hello = read_client_hello(&mut stream, config.max_handshake_bytes).await?;
    let prepared = prepare(&client_hello, config, None)?;
    finish_handshake(stream, config, prepared).await
}

struct PreparedHandshake {
    flight: Vec<u8>,
    read_cipher: RecordCipher,
    application_read: RecordCipher,
    application_write: RecordCipher,
    expected_finished: Zeroizing<Vec<u8>>,
    info: ServerConnectionInfo,
}

fn prepare(
    client_hello: &[u8],
    config: &ServerConfig,
    target: Option<&target::TargetFlight>,
) -> io::Result<PreparedHandshake> {
    let admitted = authenticate_client_hello(
        &client_hello,
        &config.private_key,
        &config.policy,
        SystemTime::now(),
    )
    .map_err(|e| invalid(e.to_string()))?;
    let offer = hello::Offer::parse(&client_hello)?;
    let selected = match target {
        Some(target) => offer.select_target(config, target.suite, target.group)?,
        None => offer.select(config)?,
    };
    let server_name = std::str::from_utf8(offer.server_name)
        .map_err(|_| invalid("invalid REALITY SNI"))?
        .to_owned();
    let (server_share, shared) = hello::exchange(selected.group, selected.share)?;
    let server_hello = match target {
        Some(target) => target.replace_share(&server_share)?,
        None => {
            let mut random = [0; 32];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(io::Error::other)?;
            hello::server_hello(
                offer.session_id,
                &random,
                selected.suite,
                selected.group,
                &server_share,
            )?
        }
    };
    let mut transcript = Transcript::new(selected.suite);
    transcript.update(&client_hello);
    transcript.update(&server_hello);
    let secrets = HandshakeSecrets::new(selected.suite, &shared, &transcript.hash())?;
    drop(shared);
    let read_cipher = RecordCipher::new(selected.suite, secrets.client.clone())?;
    let mut write_cipher = RecordCipher::new(selected.suite, secrets.server.clone())?;

    // Prepare the entire authenticated server flight before publishing it.
    // Pinned Go's target profile does not negotiate ALPN: its encrypted target
    // extensions are opaque, and c.clientProtocol remains empty.
    let ee = if target.is_some() {
        wire::handshake(8, &[0, 0])?
    } else {
        hello::encrypted_extensions(selected.alpn.as_deref())?
    };
    let (cert, signer) = certificate::create(&server_name, &admitted.auth_key)?;
    let mut messages = Vec::new();
    for message in [ee, cert] {
        transcript.update(&message);
        messages.push(message);
    }
    let mut signed = vec![32; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(&transcript.hash());
    let signature = signer.sign(&signed);
    drop(signer);
    let mut verify = vec![8, 7];
    verify.extend(wire::vector16(&signature.to_bytes())?);
    let verify = wire::handshake(15, &verify)?;
    transcript.update(&verify);
    messages.push(verify);
    let finished = selected
        .suite
        .finished(&secrets.server, &transcript.hash())?;
    let finished = wire::handshake(20, &finished)?;
    transcript.update(&finished);
    messages.push(finished);
    let (application_read, application_write) = secrets.application(&transcript.hash())?;
    let expected_finished = selected
        .suite
        .finished(&secrets.client, &transcript.hash())?;

    let mut first = vec![22, 3, 3];
    first.extend_from_slice(&(server_hello.len() as u16).to_be_bytes());
    first.extend_from_slice(&server_hello);
    // Compatibility CCS is neither encrypted nor part of the transcript.
    first.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    match target {
        Some(target) => first.extend(target.encrypt_flight(&mut write_cipher, &messages)?),
        None => {
            for fragment in messages.concat().chunks(16384) {
                first.extend(write_cipher.seal(22, fragment)?);
            }
        }
    }
    Ok(PreparedHandshake {
        flight: first,
        read_cipher,
        application_read,
        application_write,
        expected_finished,
        info: ServerConnectionInfo {
            tls: ConnectionInfo {
                cipher_suite: selected.suite,
                key_exchange_group: selected.group.id(),
                alpn: selected.alpn,
            },
            identity: admitted.identity,
            server_name,
        },
    })
}

async fn finish_handshake(
    mut stream: BoxStream,
    config: &ServerConfig,
    mut prepared: PreparedHandshake,
) -> io::Result<(ClientStream, ServerConnectionInfo)> {
    stream.write_all(&prepared.flight).await?;
    stream.flush().await?;
    prepared.flight.clear();

    let mut reader = RecordReader::default();
    let mut messages = HandshakeBuffer::new(config.max_handshake_bytes);
    let mut ignored_ccs = 0;
    loop {
        if let Some(message) = messages.take()? {
            if message[0] != 20 || !messages.is_empty() {
                return Err(invalid(
                    "expected client Finished ending at a TLS record boundary",
                ));
            }
            verify_finished(&prepared.expected_finished, &message[4..])
                .map_err(|_| invalid("TLS client Finished authentication failed"))?;
            break;
        }
        let record = poll_fn(|cx| reader.poll_read(&mut stream, cx)).await?;
        if record.header[0] == 20 && record.payload == [1] && ignored_ccs < 8 && messages.is_empty()
        {
            ignored_ccs += 1;
            continue;
        }
        let (kind, plain) = prepared.read_cipher.open(&record.header, record.payload)?;
        if kind != 22 {
            return Err(invalid(
                "expected encrypted client Finished before application data",
            ));
        }
        messages.push(&plain)?;
    }
    Ok((
        ClientStream::new_server(
            stream,
            prepared.application_read,
            prepared.application_write,
            config.max_handshake_bytes,
        ),
        prepared.info,
    ))
}

#[cfg(test)]
mod tests;
