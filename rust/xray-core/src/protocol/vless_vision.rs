// P04 vless_vision: XTLS Vision (xtls-rprx-vision) stream wrapper.
#![allow(dead_code)]
//! XTLS Vision (`xtls-rprx-vision`) stream wrapper, ported from
//! `proxy/proxy.go` (`XtlsPadding`, `XtlsUnpadding`, `XtlsFilterTls`,
//! `VisionReader`, `VisionWriter`, `ReshapeMultiBuffer`, `IsCompleteRecord`)
//! and the client flow in `proxy/vless/outbound/outbound.go`.
//!
//! The frame codec (UUID once per direction, then
//! `command | content_len u16 | padding_len u16 | content | padding`, body
//! capped at `buf.Size - 21` = 8171) is reused from
//! [`crate::protocol::vless_security::vision`], whose byte layout and padding
//! draw ranges (seed `[900, 500, 900, 256]`) are already ported and tested.
//!
//! This module adds the runtime wrapper around that codec:
//!
//! - the padding-size selection with Go's exact random ranges (long padding
//!   `draw[0..500) + 900 - content` while `content < 900`, short padding
//!   `draw[0..256)` otherwise, clamped to `8171 - content`);
//! - the inner camouflage write: when the client has no early payload within
//!   the 500 ms window, Go inserts an empty-content frame with long padding
//!   "to camouflage VLESS header" (`outbound.go`, `Insert padding with empty
//!   content`). Exposed as [`VisionStream::queue_header_camo`];
//! - TLS filtering (`XtlsFilterTls`) over the plaintext content in both
//!   directions through one shared state, exactly like Go's shared
//!   `TrafficState`;
//! - direct-copy mode switching: when the inner stream turns out to be TLS 1.3
//!   with a splice-eligible cipher, the first complete application-data
//!   record is framed with `CommandPaddingDirect` and both directions continue
//!   as a raw copy of the inner stream. `CommandPaddingEnd` (non-TLS traffic
//!   or TLS without eligible direct copy) ends the padding phase the same way;
//! - a read-side parser that strips padding frames via the strict shared
//!   decoder, then passes subsequent bytes through untouched.
//!
//! Scope and required call order: the adapter wraps the connection body only.
//! The inner VLESS request/response headers are exchanged on the raw transport
//! before wrapping (Go reads/writes them outside the Vision reader/writer), so
//! construct `VisionStream` after the header exchange, then call
//! [`VisionStream::queue_header_camo`] if no early payload is available.

use crate::protocol::vless_security::vision::{
    Command, Decoder, Encoder, GO_BUFFER_SIZE, MAX_FRAME_BODY, PaddingSettings,
    complete_tls_application_records,
};
use crate::transport::BoxStream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `proxy.Tls13SupportedVersions`.
pub const TLS13_SUPPORTED_VERSIONS: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// `proxy.TlsClientHandShakeStart`.
pub const TLS_CLIENT_HANDSHAKE_START: &[u8] = &[0x16, 0x03];
/// `proxy.TlsServerHandShakeStart`.
pub const TLS_SERVER_HANDSHAKE_START: &[u8] = &[0x16, 0x03, 0x03];
/// `proxy.TlsApplicationDataStart`.
pub const TLS_APPLICATION_DATA_START: &[u8] = &[0x17, 0x03, 0x03];
/// `proxy.TlsHandshakeTypeClientHello`.
pub const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// `proxy.TlsHandshakeTypeServerHello`.
pub const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
/// `proxy.NewTrafficState` initial filter budget.
pub const NUMBER_OF_PACKETS_TO_FILTER: i32 = 8;
/// TLS 1.3 cipher suites eligible for the Direct command (all of
/// `Tls13CipherSuiteDic` except `TLS_AES_128_CCM_8_SHA256`, 0x1305).
const TLS13_DIRECT_COPY_CIPHERS: &[u16] = &[0x1301, 0x1302, 0x1303, 0x1304];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// True for the VLESS flow strings that select Vision.
pub fn is_vision_flow(flow: &str) -> bool {
    flow == "xtls-rprx-vision" || flow == "xtls-rprx-vision-udp443"
}

/// The TLS-detection half of `proxy.TrafficState`, shared by the read and write
/// halves of one [`VisionStream`] exactly as Go shares a single state per
/// connection between `VisionReader` and `VisionWriter`.
#[derive(Clone, Debug)]
struct TlsFilter {
    number_of_packet_to_filter: i32,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl Default for TlsFilter {
    fn default() -> Self {
        Self {
            number_of_packet_to_filter: NUMBER_OF_PACKETS_TO_FILTER,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }
}

impl TlsFilter {
    /// Port of `proxy.XtlsFilterTls` for one nonempty data buffer. Like Go,
    /// the budget is spent per buffer and the scan stops conclusively on a
    /// TLS 1.3 marker (eligible cipher enables Direct) or once a tracked
    /// ServerHello ends without one (TLS 1.2: padding ends, no Direct).
    ///
    /// Go panics (`buf.Buffer.BytesRange`) on a ServerHello whose session-id
    /// length runs past the buffer; here the cipher simply stays 0, which can
    /// only downgrade Direct to End, never enable it spuriously.
    fn observe(&mut self, data: &[u8]) {
        if self.number_of_packet_to_filter <= 0 {
            return;
        }
        self.number_of_packet_to_filter -= 1;
        if data.len() >= 6 {
            let head = &data[..6];
            if head[..3] == *TLS_SERVER_HANDSHAKE_START
                && head[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
            {
                self.remaining_server_hello = (((data[3] as i32) << 8) | data[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if data.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = data[43] as usize;
                    if let Some(cipher) = data.get(44 + session_id_len..46 + session_id_len) {
                        self.cipher = ((cipher[0] as u16) << 8) | cipher[1] as u16;
                    }
                }
            } else if head[..2] == *TLS_CLIENT_HANDSHAKE_START
                && head[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
            {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(data.len());
            self.remaining_server_hello -= data.len() as i32;
            if data[..end]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|window| window == TLS13_SUPPORTED_VERSIONS)
            {
                if TLS13_DIRECT_COPY_CIPHERS.contains(&self.cipher) {
                    self.enable_xtls = true;
                }
                self.number_of_packet_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                // TLS 1.2 or older: keep padding, never switch to Direct.
                self.number_of_packet_to_filter = 0;
            }
        }
    }
}

/// Port of `proxy.ReshapeMultiBuffer`: split the write into `buf.Size` (8192)
/// source buffers, then split any buffer of length >= `buf.Size - 21` (8171)
/// at the last TLS application-data header when it lands in `[21, 8171]`,
/// otherwise at `buf.Size / 2`, so framed bodies fit the 8171-byte cap.
fn reshape_write(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut bounds = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let end = (offset + GO_BUFFER_SIZE).min(buf.len());
        if end - offset >= MAX_FRAME_BODY {
            let piece = &buf[offset..end];
            let split = match piece
                .windows(TLS_APPLICATION_DATA_START.len())
                .rposition(|window| window == TLS_APPLICATION_DATA_START)
            {
                Some(index) if (21..=MAX_FRAME_BODY).contains(&index) => index,
                _ => GO_BUFFER_SIZE / 2,
            };
            if split > 0 {
                bounds.push((offset, offset + split));
            }
            bounds.push((offset + split, end));
        } else {
            bounds.push((offset, end));
        }
        offset = end;
    }
    bounds
}

/// The Vision stream adapter: a tokio `AsyncRead + AsyncWrite` wrapper over a
/// [`BoxStream`], usable by both the client and the server side of a VLESS
/// connection whose account flow selects `xtls-rprx-vision`.
pub struct VisionStream {
    inner: BoxStream,
    settings: PaddingSettings,
    encoder: Encoder,
    decoder: Decoder,
    filter: TlsFilter,
    /// `IsPadding`: false once this direction has emitted End/Direct.
    write_padding: bool,
    /// `WithinPaddingBuffers` + the End/Direct reader transitions: false once
    /// the peer's padding phase ended; reads become a direct copy.
    read_padding: bool,
    /// Framed bytes not yet accepted by the inner stream.
    write_pending: Vec<u8>,
    write_pos: usize,
    /// Length of a caller buffer already framed into `write_pending` but not
    /// yet fully drained; a `poll_write` that returned `Pending` must be
    /// retried with the same buffer, which this remembers.
    write_staged: Option<usize>,
    /// Decoded content (and, after End/Direct, raw passthrough bytes) not yet
    /// handed to the reader.
    read_leftover: Vec<u8>,
    read_pos: usize,
    /// Whether any framed bytes arrived; EOF before the first frame is clean,
    /// EOF mid-frame is `UnexpectedEof`.
    read_started: bool,
    /// A decoder failure is sticky: later reads fail immediately instead of
    /// waiting for inner bytes that may never arrive.
    read_failed: bool,
    read_scratch: Vec<u8>,
}

impl VisionStream {
    fn build(inner: BoxStream, uuid: [u8; 16], settings: PaddingSettings) -> Self {
        Self {
            encoder: Encoder::new(uuid),
            decoder: Decoder::new(uuid),
            inner,
            settings,
            filter: TlsFilter::default(),
            write_padding: true,
            read_padding: true,
            write_pending: Vec::new(),
            write_pos: 0,
            write_staged: None,
            read_leftover: Vec::new(),
            read_pos: 0,
            read_started: false,
            read_failed: false,
            read_scratch: vec![0; GO_BUFFER_SIZE],
        }
    }

    /// Wraps the body of a Vision connection with the default Go padding seed
    /// `[900, 500, 900, 256]`.
    pub fn new(inner: BoxStream, uuid: [u8; 16]) -> Self {
        Self::build(inner, uuid, PaddingSettings::default())
    }

    /// Client-side constructor. Identical to [`VisionStream::new`]: both peers
    /// frame their uplink and unframe their downlink symmetrically. The inner
    /// VLESS request header must already be on the wire before wrapping.
    pub fn client(inner: BoxStream, uuid: [u8; 16]) -> Self {
        Self::new(inner, uuid)
    }

    /// Server-side constructor. The inner VLESS request header must already
    /// have been consumed and the response header sent before wrapping.
    pub fn server(inner: BoxStream, uuid: [u8; 16]) -> Self {
        Self::new(inner, uuid)
    }

    /// Wraps with an explicit padding seed (Go's account `Testseed`).
    pub fn with_settings(inner: BoxStream, uuid: [u8; 16], settings: PaddingSettings) -> Self {
        Self::build(inner, uuid, settings)
    }

    /// The inner camouflage write (`Insert padding with empty content to
    /// camouflage VLESS header`, `proxy/vless/outbound/outbound.go`): an
    /// empty-content `CommandPaddingContinue` frame with long padding
    /// (`draw[0..500) + 900`), queued before the first payload frame when the
    /// client has no early data to send with the header.
    pub fn queue_header_camo(&mut self) -> io::Result<()> {
        if !self.write_padding {
            return Err(invalid("Vision padding phase already ended"));
        }
        if self.write_pos < self.write_pending.len() {
            return Err(invalid(
                "Vision camouflage frame must precede the first payload frame",
            ));
        }
        let frame = self
            .encoder
            .encode(&[], Command::Continue, true, self.settings)?;
        self.write_pending.extend_from_slice(&frame);
        Ok(())
    }

    /// Whether this direction still frames writes with padding
    /// (`TrafficState.{Inbound,Outbound}State.IsPadding`).
    pub fn padding_phase(&self) -> bool {
        self.write_padding
    }

    /// Whether reads still expect padding frames; false once the peer sent
    /// End/Direct or the phase was never entered.
    pub fn read_padding_phase(&self) -> bool {
        self.read_padding
    }

    /// Unwraps the underlying stream.
    pub fn into_inner(self) -> BoxStream {
        self.inner
    }

    /// Port of `VisionWriter.WriteMultiBuffer`'s padding section for one
    /// write: filter the plaintext, reshape it, then frame each piece with
    /// the Go command and long/short padding selection.
    fn frame_write(&mut self, buf: &[u8]) -> io::Result<()> {
        // Go filters the plaintext multibuffer before padding, on both the
        // reader (after unpadding) and writer (before padding), through one
        // shared state.
        if self.filter.number_of_packet_to_filter > 0 {
            self.filter.observe(buf);
        }
        if buf.is_empty() {
            return Ok(());
        }
        let is_complete = complete_tls_application_records(buf);
        let bounds = reshape_write(buf);
        let last = bounds.len() - 1;
        let mut long_padding = self.filter.is_tls;
        let mut raw_tail = buf.len();
        for (index, (start, end)) in bounds.iter().copied().enumerate() {
            let piece = &buf[start..end];
            if self.filter.is_tls
                && piece.len() >= 6
                && piece.starts_with(TLS_APPLICATION_DATA_START)
                && is_complete
            {
                // Complete TLS application data: padding ends here. Go also
                // arms the writer's direct-copy switch whenever EnableXtls is
                // set; both paths continue as raw writes, which
                // `write_padding = false` already provides.
                let command = if index == last {
                    if self.filter.enable_xtls {
                        Command::Direct
                    } else {
                        Command::End
                    }
                } else {
                    Command::Continue
                };
                self.encode_piece(piece, command, true)?;
                self.write_padding = false;
                long_padding = false;
                continue;
            }
            if !self.filter.is_tls12_or_above && self.filter.number_of_packet_to_filter <= 1 {
                // For compatibility with earlier vision receivers, finish
                // padding one packet early; the rest of the write goes raw,
                // exactly like Go's `break` leaves the remaining multibuffer
                // entries unframed.
                self.write_padding = false;
                self.encode_piece(piece, Command::End, long_padding)?;
                raw_tail = end;
                break;
            }
            let command = if index == last && !self.write_padding {
                if self.filter.enable_xtls {
                    Command::Direct
                } else {
                    Command::End
                }
            } else {
                Command::Continue
            };
            self.encode_piece(piece, command, long_padding)?;
        }
        if raw_tail < buf.len() {
            self.write_pending.extend_from_slice(&buf[raw_tail..]);
        }
        Ok(())
    }

    /// `proxy.XtlsPadding` for one piece, reusing the shared codec's
    /// random-range padding draw.
    fn encode_piece(&mut self, content: &[u8], command: Command, long: bool) -> io::Result<()> {
        let frame = self.encoder.encode(content, command, long, self.settings)?;
        self.write_pending.extend_from_slice(&frame);
        Ok(())
    }
}

/// Copies buffered bytes into the caller's `ReadBuf`; returns whether anything
/// was served.
fn serve_leftover(leftover: &mut Vec<u8>, pos: &mut usize, buf: &mut ReadBuf<'_>) -> bool {
    if *pos >= leftover.len() {
        leftover.clear();
        *pos = 0;
        return false;
    }
    let take = buf.remaining().min(leftover.len() - *pos);
    let start = *pos;
    buf.put_slice(&leftover[start..start + take]);
    *pos += take;
    if *pos >= leftover.len() {
        leftover.clear();
        *pos = 0;
    }
    take > 0
}

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if serve_leftover(&mut this.read_leftover, &mut this.read_pos, buf) {
            return Poll::Ready(Ok(()));
        }
        if !this.read_padding {
            // Direct copy: bytes after the padding phase (and anything the peer
            // sent raw after End) pass through untouched.
            return Pin::new(&mut *this.inner).poll_read(cx, buf);
        }
        if this.read_failed {
            return Poll::Ready(Err(invalid("Vision decoder is poisoned")));
        }
        let VisionStream {
            inner,
            decoder,
            filter,
            read_leftover,
            read_padding,
            read_started,
            read_failed,
            read_scratch,
            read_pos,
            ..
        } = this;
        loop {
            if read_scratch.len() != GO_BUFFER_SIZE {
                read_scratch.resize(GO_BUFFER_SIZE, 0);
            }
            let mut scratch = ReadBuf::new(read_scratch.as_mut_slice());
            match Pin::new(&mut **inner).poll_read(cx, &mut scratch) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let data = scratch.filled();
                    if data.is_empty() {
                        // EOF from the inner stream.
                        if !*read_started {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(match decoder.finish() {
                            // Clean end: the peer closed at a frame boundary
                            // (Go propagates io.EOF as a normal termination).
                            Ok(()) => Ok(()),
                            Err(_) => Err(io::ErrorKind::UnexpectedEof.into()),
                        });
                    }
                    *read_started = true;
                    let chunk = match decoder.push(data) {
                        Ok(chunk) => chunk,
                        // Malformed frame (UUID mismatch, unknown command,
                        // oversized body): the decoder is poisoned; surface
                        // the exact error and fail future reads too.
                        Err(error) => {
                            *read_failed = true;
                            return Poll::Ready(Err(error));
                        }
                    };
                    read_leftover.extend_from_slice(&chunk.content);
                    if !chunk.content.is_empty() {
                        filter.observe(&chunk.content);
                    }
                    if let Some(command) = chunk.transition {
                        // End or Direct: padding phase over. Bytes the peer
                        // sent after the frame belong to the raw layer; Go
                        // merges its buffered `input`/`rawInput` here.
                        tracing::debug!(?command, "Vision padding phase ended");
                        *read_padding = false;
                        let consumed = chunk.consumed;
                        read_leftover.extend_from_slice(&data[consumed..]);
                        break;
                    }
                    if !read_leftover.is_empty() {
                        break;
                    }
                }
            }
        }
        if read_leftover.is_empty() {
            return Pin::new(&mut **inner).poll_read(cx, buf);
        }
        serve_leftover(read_leftover, read_pos, buf);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let len = buf.len();
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        if this.write_staged.is_none() {
            if !this.write_padding {
                // Direct copy after End/Direct: raw passthrough.
                return Pin::new(&mut *this.inner).poll_write(cx, buf);
            }
            match this.frame_write(buf) {
                Ok(()) => this.write_staged = Some(len),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        let VisionStream {
            inner,
            write_pending,
            write_pos,
            write_staged,
            ..
        } = this;
        loop {
            if *write_pos >= write_pending.len() {
                write_pending.clear();
                *write_pos = 0;
                // Either this call just framed `buf`, or a previous call
                // returned Pending and the caller retried with the same
                // buffer (the AsyncWrite contract); in both cases the bytes
                // are now fully accepted.
                *write_staged = None;
                return Poll::Ready(Ok(len));
            }
            match Pin::new(&mut **inner).poll_write(cx, &write_pending[*write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Vision inner stream accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => *write_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let VisionStream {
            inner,
            write_pending,
            write_pos,
            ..
        } = this;
        loop {
            if *write_pos >= write_pending.len() {
                write_pending.clear();
                *write_pos = 0;
                break;
            }
            match Pin::new(&mut **inner).poll_write(cx, &write_pending[*write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Vision inner stream accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => *write_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                // The staged marker is deliberately kept: a flush that
                // drains the buffer does not discharge a pending retry of
                // the same caller buffer.
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut **inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn test_uuid() -> [u8; 16] {
        std::array::from_fn(|index| index as u8 * 3)
    }

    /// A buffer the Go filter recognizes as a TLS ClientHello
    /// (`16 03 .. 01`).
    fn client_hello() -> Vec<u8> {
        let mut buffer = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01];
        buffer.extend_from_slice(&[0x0a; 32]);
        buffer
    }

    /// A complete TLS ServerHello record: TLS 1.3 supported-versions
    /// extension, cipher 0x1301, session id length 0, >= 79 bytes so the Go
    /// cipher probe (offset 43 + session id) engages.
    fn server_hello() -> Vec<u8> {
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0x11; 32]); // random
        hello.push(0); // session id length
        hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.push(0); // compression
        let mut extensions = TLS13_SUPPORTED_VERSIONS.to_vec();
        extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x18]); // dummy ext 23
        extensions.extend_from_slice(&[0x33; 24]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut handshake = vec![0x02];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// One complete TLS application-data record.
    fn application_data(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![0x17, 0x03, 0x03];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    /// Reads one full Vision frame from the raw peer; `first` consumes the
    /// UUID prefix that appears once per direction.
    async fn read_frame(peer: &mut DuplexStream, first: bool) -> (u8, Vec<u8>, usize) {
        if first {
            let mut uuid = [0u8; 16];
            peer.read_exact(&mut uuid).await.unwrap();
            assert_eq!(uuid, test_uuid());
        }
        let mut head = [0u8; 5];
        peer.read_exact(&mut head).await.unwrap();
        let command = head[0];
        let content_len = u16::from_be_bytes([head[1], head[2]]) as usize;
        let padding_len = u16::from_be_bytes([head[3], head[4]]) as usize;
        assert!(content_len + padding_len <= MAX_FRAME_BODY);
        let mut body = vec![0u8; content_len + padding_len];
        peer.read_exact(&mut body).await.unwrap();
        (command, body[..content_len].to_vec(), padding_len)
    }

    #[test]
    fn go_padding_constants_and_bounds() {
        let settings = PaddingSettings::default();
        // Go's testseed: [900, 500, 900, 256].
        assert_eq!(
            (
                settings.long_threshold,
                settings.long_range,
                settings.long_base,
                settings.short_range
            ),
            (900, 500, 900, 256)
        );
        // Long padding: draw[0..500) + 900 - content, while content < 900.
        for content in [0usize, 100, 899] {
            for draw in 0..settings.long_range {
                let length = settings.length_for_draw(content, true, draw).unwrap();
                assert!(
                    (900 - content..=1399 - content).contains(&length),
                    "long padding out of Go range: content={content} length={length}"
                );
            }
        }
        // At or above the threshold (and always for short padding) the draw is
        // uniform in [0, 256).
        for content in [900usize, 1000, 899] {
            for draw in 0..settings.short_range {
                let length = settings.length_for_draw(content, false, draw).unwrap();
                assert!(length < 256);
            }
        }
        for draw in 0..settings.short_range {
            let length = settings.length_for_draw(900, true, draw).unwrap();
            assert!(length < 256);
        }
        // The 8171-byte body cap clamps padding to zero at full content.
        for draw in 0..settings.short_range {
            assert_eq!(
                settings
                    .length_for_draw(MAX_FRAME_BODY, false, draw)
                    .unwrap(),
                0
            );
        }
        // The runtime draw respects the same bounds.
        for _ in 0..100 {
            let length = settings.random_length(0, true).unwrap();
            assert!((900..1400).contains(&length));
            let length = settings.random_length(0, false).unwrap();
            assert!(length < 256);
        }
    }

    #[tokio::test]
    async fn wire_layout_uuid_once_and_short_padding() {
        let (client_io, mut peer) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), test_uuid());
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();

        let (command, content, padding_len) = read_frame(&mut peer, true).await;
        assert_eq!(command, 0);
        assert_eq!(content, b"hello");
        // Not TLS: long_padding = IsTLS = false, so the short range applies.
        assert!(padding_len < 256, "short padding range violated");

        client.write_all(b"again").await.unwrap();
        client.flush().await.unwrap();
        let (command, content, padding_len) = read_frame(&mut peer, false).await;
        assert_eq!(command, 0);
        assert_eq!(content, b"again");
        assert!(padding_len < 256);
    }

    #[tokio::test]
    async fn camouflage_frame_long_padding_bounds() {
        let (client_io, mut peer) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), test_uuid());
        client.queue_header_camo().unwrap();
        client.write_all(b"data").await.unwrap();
        client.flush().await.unwrap();

        // Empty content, long padding: draw[0..500) + 900.
        let (command, content, padding_len) = read_frame(&mut peer, true).await;
        assert_eq!(command, 0);
        assert!(content.is_empty());
        assert!(
            (900..1400).contains(&padding_len),
            "camouflage padding out of Go range: {padding_len}"
        );
        // The camouflage frame consumed the one-shot UUID prefix.
        let (command, content, _) = read_frame(&mut peer, false).await;
        assert_eq!(command, 0);
        assert_eq!(content, b"data");
    }

    #[tokio::test]
    async fn early_finish_end_for_non_tls_traffic() {
        let (client_io, mut peer) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), test_uuid());
        // Non-TLS writes burn the 8-buffer filter budget; the 7th write sees
        // NumberOfPacketToFilter <= 1 and finishes padding one packet early
        // (CommandPaddingEnd), then the writer continues raw.
        for index in 0..7u8 {
            client.write_all(&[b'a', b'0' + index]).await.unwrap();
            client.flush().await.unwrap();
            let (command, content, _) = read_frame(&mut peer, index == 0).await;
            assert_eq!(command, u8::from(index == 6), "frame {index} command");
            assert_eq!(content, vec![b'a', b'0' + index]);
        }
        assert!(!client.padding_phase());
        client.write_all(b"raw tail").await.unwrap();
        client.flush().await.unwrap();
        let mut raw = [0u8; 8];
        peer.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw tail");
    }

    #[tokio::test]
    async fn client_server_pair_echo_with_direct_copy_switch() {
        let uuid = test_uuid();
        let (client_io, server_io) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), uuid);
        let server = VisionStream::server(Box::new(server_io), uuid);

        let hello = client_hello();
        let server_hello_record = server_hello();
        let payload = b"vision direct copy payload";
        let appdata = application_data(payload);
        let raw_tail = b"raw tail after direct copy";

        // A real TLS stack delivers each record in its own write; one mixed
        // write keeps Vision in padding mode because Go's IsCompleteRecord —
        // and this port — checks the entire written buffer.
        let sizes = [
            hello.len(),
            server_hello_record.len(),
            appdata.len(),
            raw_tail.len(),
        ];
        let echo = tokio::spawn(async move {
            let mut server = server;
            for size in sizes {
                let mut buffer = vec![0u8; size];
                tokio::time::timeout(TIMEOUT, server.read_exact(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                tokio::time::timeout(TIMEOUT, server.write_all(&buffer))
                    .await
                    .unwrap()
                    .unwrap();
                tokio::time::timeout(TIMEOUT, server.flush())
                    .await
                    .unwrap()
                    .unwrap();
            }
        });

        // Uplink: client hello marks the flow as TLS for the shared filter.
        tokio::time::timeout(TIMEOUT, client.write_all(&hello))
            .await
            .unwrap()
            .unwrap();
        // The inner ServerHello (TLS 1.3, cipher 0x1301) enables Direct in the
        // shared state.
        tokio::time::timeout(TIMEOUT, client.write_all(&server_hello_record))
            .await
            .unwrap()
            .unwrap();
        // First complete application-data record: framed with Direct.
        tokio::time::timeout(TIMEOUT, client.write_all(&appdata))
            .await
            .unwrap()
            .unwrap();
        assert!(
            !client.padding_phase(),
            "Direct must end the uplink padding phase"
        );
        // Everything after the Direct frame is a raw copy.
        tokio::time::timeout(TIMEOUT, client.write_all(raw_tail))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(TIMEOUT, client.flush())
            .await
            .unwrap()
            .unwrap();
        assert!(is_vision_flow("xtls-rprx-vision"));
        assert!(is_vision_flow("xtls-rprx-vision-udp443"));
        assert!(!is_vision_flow(""));

        tokio::time::timeout(TIMEOUT, client.shutdown())
            .await
            .unwrap()
            .unwrap();
        let mut echoed = Vec::new();
        tokio::time::timeout(TIMEOUT, client.read_to_end(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&hello);
        expected.extend_from_slice(&server_hello_record);
        expected.extend_from_slice(&appdata);
        expected.extend_from_slice(raw_tail);
        assert_eq!(echoed, expected);
        assert!(
            !client.read_padding_phase(),
            "Direct must switch the downlink to direct copy"
        );
        tokio::time::timeout(TIMEOUT, echo).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_frames_rejected() {
        let uuid = test_uuid();

        // Wrong UUID prefix.
        let (client_io, mut peer) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), uuid);
        peer.write_all(&[0u8; 16]).await.unwrap();
        peer.write_all(&[0x00, 0x00, 0x01, 0x00, 0x01, b'x', b'y'])
            .await
            .unwrap();
        peer.flush().await.unwrap();
        let mut buffer = [0u8; 8];
        let error = tokio::time::timeout(TIMEOUT, client.read(&mut buffer))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("UUID prefix mismatch"));
        // The decoder is poisoned: later reads fail as well.
        assert!(client.read(&mut buffer).await.is_err());

        // Unknown padding command.
        let (client_io, mut peer) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), uuid);
        peer.write_all(&uuid).await.unwrap();
        peer.write_all(&[0x03, 0x00, 0x01, 0x00, 0x01, b'x', b'y'])
            .await
            .unwrap();
        peer.flush().await.unwrap();
        let error = tokio::time::timeout(TIMEOUT, client.read(&mut buffer))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unknown Vision padding command"));

        // Frame body beyond the 8171-byte source buffer limit.
        let (client_io, mut peer) = duplex(1 << 16);
        let mut client = VisionStream::client(Box::new(client_io), uuid);
        peer.write_all(&uuid).await.unwrap();
        peer.write_all(&[0x00, 0x20, 0x00, 0x00, 0x01])
            .await
            .unwrap();
        peer.flush().await.unwrap();
        let error = tokio::time::timeout(TIMEOUT, client.read(&mut buffer))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds source buffer limit"));
    }
}
