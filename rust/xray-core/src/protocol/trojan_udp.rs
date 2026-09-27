// P05 trojan_udp: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]

//! Trojan UDP-over-stream relaying, ported from `proxy/trojan/protocol.go`
//! (`PacketWriter`/`PacketReader`), `proxy/trojan/client.go` (`Process` with
//! `Network_UDP`) and `proxy/trojan/server.go` (`handleUDPPayload`).
//!
//! # Wire format (the complete, documented frame set)
//!
//! A UDP association is a Trojan request whose command byte is 3 (the request
//! header itself — hash, CRLF, command, SOCKS address, CRLF — is parsed by
//! [`crate::protocol::trojan`]); every byte after the header is a sequence of
//! frames and nothing else:
//!
//! ```text
//! SOCKS address (ATYP | host | port) | length: u16be | CRLF | payload[length]
//! ```
//!
//! * The address is written/read with [`Destination::write_socks`]/[`Destination::read_socks`].
//! * `length` is a 2-byte big-endian payload length; the largest value the
//!   reader accepts is [`MAX_PAYLOAD`] (`maxLength` in the Go source). Larger
//!   lengths are rejected with an "oversize payload" error.
//! * A zero-length frame (`length == 0`) is the association close signal: it
//!   still carries an address and CRLF on the wire, but carries no datagram
//!   and ends the association in the direction it was received.
//!
//! Anything else on the stream is rejected: unknown address families, invalid
//! CRLF delimiters, truncated frames and oversize lengths all produce errors
//! naming the problem. Deliberate deltas from the Go source (documented
//! requirements of this port, see notes in the batch spec):
//!
//! * Go's `PacketReader` yields an empty `MultiBuffer` for a zero-length
//!   frame, which the server loop simply skips. Here the zero-length frame is
//!   the explicit close signal per the Trojan UDP specification.
//! * Go reads the frame CRLF without checking its bytes; this port validates
//!   them so corrupted frames are rejected instead of silently tolerated.
//! * Go's writer casts the length to `uint16` unchecked; this port refuses to
//!   encode payloads above [`MAX_PAYLOAD`].

use std::io::Cursor;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::address::Destination;

/// Largest UDP payload a Trojan frame may carry (`maxLength` in Go).
pub const MAX_PAYLOAD: usize = 8192;

const CRLF: [u8; 2] = *b"\r\n";

/// One UDP datagram as it crosses the association.
///
/// Client frames target the request destination (Go `PacketWriter.Target`),
/// server response frames carry the remote UDP source as their destination
/// (Go sets `udpPayload.UDP = &packet.Source`). An empty `payload` encodes the
/// zero-length close frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFrame {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

impl UdpFrame {
    pub fn new(destination: Destination, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            destination,
            payload: payload.into(),
        }
    }

    /// True when this frame is the zero-length association close signal.
    pub fn is_close(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Read one UDP frame from the stream.
///
/// Returns `Ok(None)` when the association is over: either the peer sent the
/// zero-length close frame (which is consumed, along with its address and
/// CRLF) or the stream ended cleanly at a frame boundary (Go treats `io.EOF`
/// at this point as a normal end of the association). Any truncated or
/// malformed frame is an error.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<UdpFrame>> {
    // Distinguish a clean EOF at a frame boundary (graceful close) from a
    // truncated frame (error) by hand-reading the first address byte, then
    // feeding it back through the shared SOCKS address codec.
    let mut family = [0u8; 1];
    let read = reader
        .read(&mut family)
        .await
        .context("failed to read frame address")?;
    if read == 0 {
        return Ok(None);
    }
    let mut reader = Cursor::new(family).chain(reader);

    let destination = Destination::read_socks(&mut reader)
        .await
        .context("failed to read frame address")?;
    let length = reader
        .read_u16()
        .await
        .context("failed to read payload length")? as usize;
    if length > MAX_PAYLOAD {
        bail!("oversize payload: {length} bytes exceeds the Trojan UDP maximum {MAX_PAYLOAD}");
    }
    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .await
        .context("failed to read crlf")?;
    ensure!(crlf == CRLF, "invalid Trojan UDP frame CRLF delimiter");
    if length == 0 {
        // Zero-length frame: the association close signal. Its address and
        // CRLF are consumed; nothing (not even an empty datagram) is emitted.
        return Ok(None);
    }
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed to read payload")?;
    Ok(Some(UdpFrame {
        destination,
        payload,
    }))
}

/// Write one UDP frame to the stream.
///
/// An empty `frame.payload` writes the zero-length close frame. Payloads
/// larger than [`MAX_PAYLOAD`] are rejected up front: the wire length is a
/// `u16` and the peer's reader refuses anything above 8192.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &UdpFrame) -> Result<()> {
    ensure!(
        frame.payload.len() <= MAX_PAYLOAD,
        "oversize payload: {} bytes exceeds the Trojan UDP maximum {MAX_PAYLOAD}",
        frame.payload.len()
    );
    let mut buffer = Vec::with_capacity(frame.payload.len() + 320);
    frame
        .destination
        .write_socks(&mut buffer)
        .await
        .context("write frame address")?;
    buffer.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
    buffer.extend_from_slice(&CRLF);
    buffer.extend_from_slice(&frame.payload);
    writer
        .write_all(&buffer)
        .await
        .context("write Trojan UDP frame")?;
    Ok(())
}

/// Relay one direction: map a datagram queue to frames on the stream
/// (Go client `postRequest` draining `link.Reader` into the `PacketWriter`,
/// or the server's response callback writing `PacketWriter`).
///
/// Frames are written until every sender drops `queue`; the zero-length close
/// frame addressed to `request_destination` (the destination from the request
/// header, Go `PacketWriter.Target`) is then emitted to close the association
/// before returning.
pub async fn pump_queue_to_frames<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_destination: &Destination,
    mut queue: mpsc::Receiver<UdpFrame>,
) -> Result<()> {
    while let Some(frame) = queue.recv().await {
        write_frame(writer, &frame).await?;
    }
    write_frame(
        writer,
        &UdpFrame {
            destination: request_destination.clone(),
            payload: Vec::new(),
        },
    )
    .await
}

/// Relay the other direction: map incoming frames to a datagram queue
/// (Go server `requestDone` loop, or the client `getResponse` copy).
///
/// Each decoded frame is forwarded to `sink` until the association ends —
/// zero-length close frame or clean stream EOF — which returns `Ok(())`
/// (Go: `io.EOF` ends the relay without error). If the sink is dropped the
/// association is torn down silently, leaving the stream positioned after the
/// last consumed frame.
pub async fn pump_frames_to_queue<R: AsyncRead + Unpin>(
    reader: &mut R,
    sink: mpsc::Sender<UdpFrame>,
) -> Result<()> {
    while let Some(frame) = read_frame(reader).await? {
        if sink.send(frame).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PAYLOAD: &[u8] = b"abcd";

    fn close_wire(destination: &Destination) -> UdpFrame {
        UdpFrame::new(destination.clone(), Vec::new())
    }

    #[tokio::test]
    async fn frame_wire_matches_go_format_and_round_trips() {
        let cases = [
            (
                vec![
                    0x01, 127, 0, 0, 1, // ATYP 1, 127.0.0.1
                    0x01, 0xbb, // port 443
                ],
                Destination::new("127.0.0.1", 443).unwrap(),
            ),
            (
                [
                    vec![0x03, 0x0b],
                    b"example.com".to_vec(),
                    vec![0x00, 0x35], // port 53
                ]
                .concat(),
                Destination::new("example.com", 53).unwrap(),
            ),
            (
                [
                    vec![0x04],
                    vec![0u8; 15],
                    vec![1], // ::1
                    vec![0x00, 0x35],
                ]
                .concat(),
                Destination::new("::1", 53).unwrap(),
            ),
        ];
        for (address, destination) in cases {
            let mut golden = address;
            golden.extend_from_slice(&[
                0x00, 0x04, // 2-byte big-endian payload length
                b'\r', b'\n',
            ]);
            golden.extend_from_slice(PAYLOAD);

            let frame = UdpFrame::new(destination.clone(), PAYLOAD);
            let mut wire = Vec::new();
            write_frame(&mut wire, &frame).await.unwrap();
            assert_eq!(wire, golden, "encoded bytes for {destination}");

            let decoded = read_frame(&mut golden.as_slice())
                .await
                .unwrap()
                .expect("datagram frame");
            assert_eq!(decoded, frame);
        }
    }

    #[tokio::test]
    async fn zero_length_frame_is_the_close_signal() {
        let destination = Destination::new("127.0.0.1", 443).unwrap();
        let golden = [
            0x01, 127, 0, 0, 1, 0x01, 0xbb, 0x00, 0x00, // length 0
            b'\r', b'\n',
        ];

        let mut wire = Vec::new();
        write_frame(&mut wire, &close_wire(&destination))
            .await
            .unwrap();
        assert_eq!(wire, golden);
        assert!(close_wire(&destination).is_close());

        // The close frame is consumed but does not read past its own bytes
        // (`&[u8]` readers advance, so the remaining slice is observable).
        let mut reader: &[u8] = &[golden.as_slice(), b"REST"].concat();
        assert!(read_frame(&mut reader).await.unwrap().is_none());
        assert_eq!(reader, b"REST");

        // Clean EOF at a frame boundary is also an association end.
        assert!(read_frame(&mut &[][..]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn pump_queue_to_frames_writes_frames_then_close() {
        let destination = Destination::new("127.0.0.1", 443).unwrap();
        let (tx, rx) = mpsc::channel(4);
        tx.send(UdpFrame::new(destination.clone(), PAYLOAD))
            .await
            .unwrap();
        drop(tx);

        let mut wire = Vec::new();
        pump_queue_to_frames(&mut wire, &destination, rx)
            .await
            .unwrap();
        let expected = [
            vec![0x01, 127, 0, 0, 1, 0x01, 0xbb, 0x00, 0x04, b'\r', b'\n'],
            PAYLOAD.to_vec(),
            vec![0x01, 127, 0, 0, 1, 0x01, 0xbb, 0x00, 0x00, b'\r', b'\n'],
        ]
        .concat();
        assert_eq!(wire, expected);
    }

    #[tokio::test]
    async fn pump_frames_to_queue_ends_on_close_frame_clean_eof_and_sink_close() {
        let destination = Destination::new("127.0.0.1", 443).unwrap();
        let frame = [
            vec![0x01, 127, 0, 0, 1, 0x01, 0xbb, 0x00, 0x04, b'\r', b'\n'],
            PAYLOAD.to_vec(),
        ]
        .concat();
        let close = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb, 0x00, 0x00, b'\r', b'\n'];

        // Close frame ends the association; trailing bytes stay unconsumed.
        let mut input: &[u8] = &[frame.as_slice(), close.as_slice(), b"trailing"].concat();
        let (tx, mut rx) = mpsc::channel(8);
        pump_frames_to_queue(&mut input, tx).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.destination, destination);
        assert_eq!(received.payload, PAYLOAD);
        assert!(rx.recv().await.is_none());
        assert_eq!(input, b"trailing");

        // Clean EOF without a close frame is a graceful end too (Go: io.EOF).
        let mut input: &[u8] = &frame;
        let (tx, mut rx) = mpsc::channel(8);
        pump_frames_to_queue(&mut input, tx).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().payload, PAYLOAD);
        assert!(rx.recv().await.is_none());

        // A dropped sink tears the association down without error.
        let mut input: &[u8] = &[frame.as_slice(), close.as_slice()].concat();
        let (tx, rx) = mpsc::channel(8);
        drop(rx);
        pump_frames_to_queue(&mut input, tx).await.unwrap();
        assert_eq!(input, close);
    }

    #[tokio::test]
    async fn client_server_relay_echoes_a_datagram_end_to_end() {
        let target = Destination::new("8.8.8.8", 53).unwrap();
        let query = UdpFrame::new(target.clone(), b"hello query".to_vec());
        let answer_payload = b"hello answer".to_vec();

        let (client_conn, server_conn) = tokio::io::duplex(256);
        let (mut client_read, mut client_write) = tokio::io::split(client_conn);
        let (mut server_read, mut server_write) = tokio::io::split(server_conn);

        let (client_out_tx, client_out_rx) = mpsc::channel::<UdpFrame>(8);
        let (client_in_tx, mut client_in_rx) = mpsc::channel::<UdpFrame>(8);
        let (server_in_tx, mut server_in_rx) = mpsc::channel::<UdpFrame>(8);
        let (server_out_tx, server_out_rx) = mpsc::channel::<UdpFrame>(8);

        // Client: postRequest drains the datagram queue into request frames;
        // getResponse copies response frames back into the datagram queue.
        // Server: requestDone reads request frames; dispatcher responses are
        // written back with the remote source as the frame destination.
        let flow = async {
            client_out_tx.send(query.clone()).await.unwrap();
            let request = server_in_rx.recv().await.unwrap();
            assert_eq!(request, query);
            server_out_tx
                .send(UdpFrame::new(
                    request.destination.clone(),
                    answer_payload.clone(),
                ))
                .await
                .unwrap();
            let answer = client_in_rx.recv().await.unwrap();
            assert_eq!(answer.destination, target);
            assert_eq!(answer.payload, b"hello answer");

            // Closing the client's datagram queue emits the close frame and
            // ends the server's read side; dropping the server's response
            // queue then ends the client's read side.
            drop(client_out_tx);
            assert!(server_in_rx.recv().await.is_none());
            drop(server_out_tx);
            assert!(client_in_rx.recv().await.is_none());
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(Duration::from_secs(5), async {
            let (flow, client_out, client_in, server_reader, server_writer) = tokio::join!(
                flow,
                pump_queue_to_frames(&mut client_write, &target, client_out_rx),
                pump_frames_to_queue(&mut client_read, client_in_tx),
                pump_frames_to_queue(&mut server_read, server_in_tx),
                pump_queue_to_frames(&mut server_write, &target, server_out_rx),
            );
            flow.unwrap();
            client_out.unwrap();
            client_in.unwrap();
            server_reader.unwrap();
            server_writer.unwrap();
        })
        .await
        .expect("Trojan UDP relay echo timed out");
    }

    #[tokio::test]
    async fn rejects_oversize_malformed_and_truncated_frames() {
        let destination = Destination::new("127.0.0.1", 443).unwrap();
        let mut frame = Vec::new();
        write_frame(&mut frame, &UdpFrame::new(destination.clone(), PAYLOAD))
            .await
            .unwrap();

        // Oversize length field (8193 > maxLength): rejected like Go's
        // "oversize payload" before the CRLF or payload is consumed. The
        // length field sits at indices 7..9 (1 ATYP + 4 IPv4 + 2 port).
        let mut oversize = frame.clone();
        oversize[7] = 0x20;
        oversize[8] = 0x01;
        let error = read_frame(&mut oversize.as_slice()).await.err().unwrap();
        assert!(
            format!("{error:#}").contains("oversize payload"),
            "{error:#}"
        );

        // 8192 is the inclusive maximum and must decode.
        let boundary = vec![0xa5u8; MAX_PAYLOAD];
        let mut wire = Vec::new();
        write_frame(
            &mut wire,
            &UdpFrame::new(destination.clone(), boundary.clone()),
        )
        .await
        .unwrap();
        let decoded = read_frame(&mut wire.as_slice()).await.unwrap().unwrap();
        assert_eq!(decoded.payload.len(), MAX_PAYLOAD);
        assert_eq!(decoded.payload, boundary);

        // Encoding a payload above the maximum is rejected up front.
        let mut too_big = Vec::new();
        let error = write_frame(
            &mut too_big,
            &UdpFrame::new(destination.clone(), vec![0u8; MAX_PAYLOAD + 1]),
        )
        .await
        .err()
        .unwrap();
        assert!(
            format!("{error:#}").contains("oversize payload"),
            "{error:#}"
        );

        // Unknown address family is beyond the documented frame set.
        let mut bad_family = frame.clone();
        bad_family[0] = 0x02;
        let error = read_frame(&mut bad_family.as_slice()).await.err().unwrap();
        assert!(
            format!("{error:#}").contains("unsupported address family 2"),
            "{error:#}"
        );

        // Corrupted CRLF delimiter is rejected.
        let mut bad_crlf = frame.clone();
        bad_crlf[10] = b'!';
        let error = read_frame(&mut bad_crlf.as_slice()).await.err().unwrap();
        assert!(format!("{error:#}").contains("CRLF delimiter"), "{error:#}");

        // Every truncation after the first byte is an error; only a fully
        // empty stream is a clean close.
        for length in 1..frame.len() {
            assert!(
                read_frame(&mut &frame[..length]).await.is_err(),
                "accepted a frame truncated to {length} bytes"
            );
        }
        assert!(read_frame(&mut &frame[..0][..]).await.unwrap().is_none());
    }
}
