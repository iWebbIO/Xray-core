//! CONTRACT (fixed by the integrator): the Trojan UDP-over-TCP association.
//!
//! OWNER: wiring batch agent A-UDP. After `trojan::read_request` accepts
//! command 3, every byte on the connection is a sequence of
//! `trojan_udp::UdpFrame`s and nothing else (the component's module doc).
//! Pump frames from the client into `dispatcher.udp` (the
//! `udp::UdpDispatcher`, one dispatch per frame destination, SOCKS-style
//! sessions) and pump replies back as frames through
//! `trojan_udp::pump_queue_to_frames`/`pump_frames_to_queue`, honoring the
//! dispatcher's limits and the connection cancellation token. The request's
//! own destination is the close-frame target, exactly like Go's
//! `PacketWriter.Target`.

use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::protocol::Request;
use crate::transport::BoxStream;

pub(super) async fn serve(
    stream: BoxStream,
    request: Request,
    dispatcher: &Dispatcher,
    tag: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let _ = (stream, request, dispatcher, tag, cancel);
    anyhow::bail!("Trojan UDP relay is not wired yet")
}
