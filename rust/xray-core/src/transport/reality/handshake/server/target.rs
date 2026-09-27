//! Bounded subset of pinned Go REALITY's target-facing server path.
//!
//! The caller supplies an already connected target stream and owns dialing,
//! PROXY protocol, forwarding lifetime, and cancellation. Target TLS plaintext is
//! never trusted as authentication: only the local REALITY policy and Finished
//! checks can produce an authenticated stream.

use std::{
    io,
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{
    BoxStream, CipherSuite, ClientStream, KeyExchangeGroup, PreparedHandshake, RecordCipher,
    ServerConfig, ServerConnectionInfo, authenticate_client_hello, finish_handshake, hello,
    invalid, prepare, read_client_hello, wire,
};

/// Forwarded connections are fully handled and must never enter an authenticated
/// protocol dispatcher. Counts include all bytes consumed during classification.
pub enum TargetOutcome {
    Authenticated {
        stream: Box<ClientStream>,
        info: ServerConnectionInfo,
    },
    Forwarded {
        client_to_target: u64,
        target_to_client: u64,
        reason: String,
    },
}

/// Mirror a supported target flight or transparently forward rejected traffic.
///
/// A single `handshake_timeout` bounds inspection, target observation, and the
/// authenticated handshake. Forwarding after rejection is outside that deadline;
/// the caller must apply its connection lifetime policy and cancellation.
///
/// Supported target flights are TLS 1.3 ServerHello + compatibility CCS followed
/// by either one coalesced encrypted flight (>512 wire bytes), or four encrypted
/// records corresponding to EE/Certificate/CertificateVerify/Finished. Exact
/// ServerHello bytes are kept except for the replacement ephemeral key share.
/// Encrypted record sizes are kept by TLS inner-plaintext zero padding. As in the
/// pinned Go target profile, ALPN is omitted. Target certificates are not copied.
///
/// HRR, PSK, non-TLS/unsupported target flights, disallowed suites/groups, invalid
/// peer admission, over-budget flights, and insufficient padding space fall back
/// before any locally generated TLS flight is sent. After that flight is sent,
/// any failure closes both streams; it can never switch back to forwarding.
/// Post-handshake target probes/ticket-size mimicry and built-in fallback rate
/// limits are not implemented. PROXY headers, if needed, must already be sent by
/// the caller before invoking this function.
pub async fn accept_with_target(
    client: BoxStream,
    target: BoxStream,
    config: ServerConfig,
) -> io::Result<TargetOutcome> {
    config.validate()?;
    let deadline = tokio::time::Instant::now() + config.handshake_timeout;
    let mut connection = TargetConnection {
        client,
        target,
        client_prefix: Vec::new(),
        target_prefix: Vec::new(),
        sent: 0,
        limit: config.max_handshake_bytes,
    };
    let classified = tokio::time::timeout_at(deadline, connection.classify(&config)).await;
    let prepared = match classified {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => return connection.forward(error.to_string()).await,
        Err(_) => {
            return connection
                .forward("target admission/observation timed out".into())
                .await;
        }
    };
    // No fallback is allowed after this point: the transcript and keys now belong
    // to this endpoint. Keep target ownership until Finished verification ends.
    let result = tokio::time::timeout_at(
        deadline,
        finish_handshake(connection.client, &config, prepared),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "REALITY target handshake timed out",
        )
    })?;
    drop(connection.target);
    let (stream, info) = result?;
    Ok(TargetOutcome::Authenticated {
        stream: Box::new(stream),
        info,
    })
}

struct TargetConnection {
    client: BoxStream,
    target: BoxStream,
    client_prefix: Vec<u8>,
    target_prefix: Vec<u8>,
    sent: usize,
    limit: usize,
}

impl TargetConnection {
    async fn classify(&mut self, config: &ServerConfig) -> io::Result<PreparedHandshake> {
        let client_hello = read_client_hello(
            &mut Capture {
                stream: &mut self.client,
                bytes: &mut self.client_prefix,
                limit: self.limit,
            },
            self.limit,
        )
        .await?;
        self.send_prefix().await?;
        // Reject unauthenticated input without waiting for a target TLS flight.
        authenticate_client_hello(
            &client_hello,
            &config.private_key,
            &config.policy,
            std::time::SystemTime::now(),
        )
        .map_err(|error| invalid(error.to_string()))?;
        let offer = hello::Offer::parse(&client_hello)?;
        let flight = TargetFlight::observe(
            &mut Capture {
                stream: &mut self.target,
                bytes: &mut self.target_prefix,
                limit: self.limit,
            },
            offer.session_id,
        )
        .await?;
        prepare(&client_hello, config, Some(&flight))
    }

    async fn send_prefix(&mut self) -> io::Result<()> {
        // Keep the write offset outside the future: an observation deadline may
        // cancel a partial write, after which fallback must not duplicate bytes.
        while self.sent < self.client_prefix.len() {
            let count = self.target.write(&self.client_prefix[self.sent..]).await?;
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.sent += count;
        }
        self.target.flush().await
    }

    async fn forward(self, reason: String) -> io::Result<TargetOutcome> {
        // Replay both prefixes through reads so the normal bidirectional copier
        // can drive them concurrently. Sequentially writing a captured prefix
        // can deadlock when the target and client are both backpressured.
        let already_sent = self.sent as u64;
        let mut client = Replay {
            stream: self.client,
            bytes: self.client_prefix,
            offset: self.sent,
        };
        let mut target = Replay {
            stream: self.target,
            bytes: self.target_prefix,
            offset: 0,
        };
        let (upload, download) = tokio::io::copy_bidirectional(&mut client, &mut target).await?;
        Ok(TargetOutcome::Forwarded {
            client_to_target: already_sent + upload,
            target_to_client: download,
            reason,
        })
    }
}

struct Replay {
    stream: BoxStream,
    bytes: Vec<u8>,
    offset: usize,
}

impl AsyncRead for Replay {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.bytes.len() {
            let count = output.remaining().min(this.bytes.len() - this.offset);
            output.put_slice(&this.bytes[this.offset..this.offset + count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        this.bytes.clear();
        Pin::new(&mut this.stream).poll_read(cx, output)
    }
}

impl AsyncWrite for Replay {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// Keep bytes already consumed by cancelled `read_exact` futures so fallback can
/// replay them. No reader in the observation phase can allocate beyond its cap.
struct Capture<'a> {
    stream: &'a mut BoxStream,
    bytes: &'a mut Vec<u8>,
    limit: usize,
}

impl AsyncRead for Capture<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() > this.limit.saturating_sub(this.bytes.len()) {
            return Poll::Ready(Err(invalid("REALITY predecision capture budget exceeded")));
        }
        let before = output.filled().len();
        match Pin::new(&mut *this.stream).poll_read(cx, output) {
            Poll::Ready(Ok(())) => {
                this.bytes.extend_from_slice(&output.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

pub(super) struct TargetFlight {
    pub(super) suite: CipherSuite,
    pub(super) group: KeyExchangeGroup,
    server_hello: Vec<u8>,
    share: Range<usize>,
    encrypted_lengths: Vec<usize>,
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if header[1..3] != [3, 3] || !(1..=16401).contains(&length) {
        return Err(invalid(
            "target TLS record version or length is unsupported",
        ));
    }
    let mut record = header.to_vec();
    record.resize(5 + length, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

impl TargetFlight {
    async fn observe<S: AsyncRead + Unpin>(stream: &mut S, session_id: &[u8]) -> io::Result<Self> {
        let record = read_record(stream).await?;
        if record[0] != 22 || record.len() > 16389 {
            return Err(invalid(
                "target did not send a bounded plaintext ServerHello",
            ));
        }
        let server_hello = record[5..].to_vec();
        // The shared parser explicitly rejects HRR, selected PSK, unsolicited
        // extensions, wrong session echoes, and malformed/unimplemented shares.
        let parsed = wire::parse_server_hello(&server_hello, session_id, false)?;
        let suite = parsed.suite;
        let group = if parsed.group == 0x11ec {
            KeyExchangeGroup::X25519MlKem768
        } else {
            KeyExchangeGroup::X25519
        };
        let share_len = parsed.share.len();
        let mut body = wire::Cursor::new(&server_hello[4..]);
        body.take(34)?;
        body.vec8()?;
        body.take(3)?;
        let mut extensions = wire::Cursor::new(body.vec16()?);
        let mut share = None;
        while !extensions.rest.is_empty() {
            let id = extensions.u16()?;
            extensions.vec16()?;
            if id == 51 {
                let end = server_hello.len() - extensions.rest.len();
                share = Some(end - share_len..end);
            }
        }
        let share = share.ok_or_else(|| invalid("target ServerHello has no key share"))?;
        let ccs = read_record(stream).await?;
        if ccs != [20, 3, 3, 0, 1, 1] {
            return Err(invalid("target compatibility CCS is unsupported"));
        }
        let first = read_record(stream).await?;
        if first[0] != 23 || first.len() < 22 {
            return Err(invalid("invalid target encrypted handshake record"));
        }
        let mut encrypted_lengths = vec![first.len()];
        if first.len() <= 512 {
            for _ in 0..3 {
                let next = read_record(stream).await?;
                if next[0] != 23 || next.len() < 22 {
                    return Err(invalid("unsupported split target handshake flight"));
                }
                encrypted_lengths.push(next.len());
            }
        }
        Ok(Self {
            suite,
            group,
            server_hello,
            share,
            encrypted_lengths,
        })
    }

    pub(super) fn replace_share(&self, share: &[u8]) -> io::Result<Vec<u8>> {
        if share.len() != self.share.len() {
            return Err(invalid("replacement target key share has the wrong size"));
        }
        let mut hello = self.server_hello.clone();
        hello[self.share.clone()].copy_from_slice(share);
        Ok(hello)
    }

    pub(super) fn encrypt_flight(
        &self,
        cipher: &mut RecordCipher,
        messages: &[Vec<u8>],
    ) -> io::Result<Vec<u8>> {
        let records = if self.encrypted_lengths.len() == 1 {
            vec![messages.concat()]
        } else {
            messages.to_vec()
        };
        if records.len() != self.encrypted_lengths.len() {
            return Err(invalid("unsupported target handshake record layout"));
        }
        // Validate every record before consuming cipher sequence numbers or
        // making the server flight available to the caller.
        let mut paddings = Vec::with_capacity(records.len());
        for (record, size) in records.iter().zip(&self.encrypted_lengths) {
            let padding = size.checked_sub(record.len() + 22).ok_or_else(|| {
                invalid("target handshake record cannot fit the authenticated replacement")
            })?;
            if record.len() + 1 + padding > 16385 {
                return Err(invalid(
                    "target TLS padding exceeds the inner-plaintext limit",
                ));
            }
            paddings.push(padding);
        }
        let mut output = Vec::new();
        for (record, padding) in records.iter().zip(paddings) {
            output.extend(cipher.seal_padded(22, record, padding)?);
        }
        Ok(output)
    }
}
