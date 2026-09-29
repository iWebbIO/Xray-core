//! The hysteria runtime wiring: the QUIC listener task one hysteria inbound
//! spawns (proxy/hysteria's server over transport/internet/hysteria's hub),
//! the dispatch seam that routes every authenticated stream and UDP session
//! through the runtime dispatcher, and the outbound pool that keeps one
//! shared authenticated QUIC session per hysteria outbound (Go's
//! clientManager cache).

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

use super::{
    Dispatcher, accounting::CountedStream, sniffing::SniffingRequest, udp, udp::DispatchAction,
};
use crate::{
    address::Destination,
    config::{Inbound, Outbound},
    protocol::{
        self,
        hysteria_runtime::{
            HysteriaDispatch, HysteriaDispatchFuture, HysteriaOutbound, TcpDispatch, UdpDispatch,
        },
    },
    transport::{
        BoxStream,
        hysteria_endpoint::{HysteriaClientDialer, HysteriaEndpointListener},
    },
};

/// One connected relay socket toward an admitted UDP endpoint, with a pump
/// that returns remote replies to the session loop (plain_udp's Peer shape;
/// hysteria replies are bare payloads, so no client identity rides along).
struct RelayPeer {
    socket: Arc<UdpSocket>,
    stop: CancellationToken,
}

impl RelayPeer {
    fn new(replies: mpsc::Sender<Vec<u8>>) -> Self {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind a hysteria relay socket");
        socket
            .set_nonblocking(true)
            .expect("non-blocking hysteria relay socket");
        let socket = Arc::new(UdpSocket::from_std(socket).expect("register relay socket"));
        let stop = CancellationToken::new();
        let pump_socket = Arc::clone(&socket);
        let pump_replies = replies.clone();
        let pump_stop = stop.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = pump_stop.cancelled() => return,
                    received = timeout(Duration::from_secs(300), pump_socket.recv_from(&mut buffer)) => received,
                };
                match received {
                    Ok(Ok((size, _))) => {
                        if pump_replies.send(buffer[..size].to_vec()).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
            }
        });
        Self { socket, stop }
    }
}

impl Drop for RelayPeer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// The runtime's dispatch seam over one hysteria inbound: TCP streams run the
/// same post-handshake dispatch as every other inbound (routing, sniffing,
/// stats, relay), UDP sessions dispatch each datagram through the UDP routing
/// dispatcher exactly like the legacy Shadowsocks and dokodemo listeners.
struct RuntimeSeam {
    dispatcher: Arc<Dispatcher>,
    inbound: Arc<Inbound>,
    tag: Arc<str>,
    /// The QUIC endpoint's own address (the bound-side half of the relay).
    bound: SocketAddr,
    cancel: CancellationToken,
    sniff: Option<Arc<SniffingRequest>>,
}

impl HysteriaDispatch for RuntimeSeam {
    fn dispatch_stream(&self, connection: TcpDispatch) -> HysteriaDispatchFuture {
        let TcpDispatch {
            destination,
            source,
            user,
            stream,
        } = connection;
        let dispatcher = Arc::clone(&self.dispatcher);
        let inbound = Arc::clone(&self.inbound);
        let tag = Arc::clone(&self.tag);
        let bound = self.bound;
        let cancel = self.cancel.clone();
        let sniff = self.sniff.clone();
        Box::pin(async move {
            let request = protocol::Request {
                level: user.as_ref().map_or(0, |user| user.level),
                destination,
                user: user.map(|user| user.email).unwrap_or_default(),
                initial_payload: Vec::new(),
                reply: protocol::Reply::None,
            };
            let stream = match &dispatcher.stats {
                Some(stats) => CountedStream::wrap(
                    stream,
                    stats.inbound_counters(&tag, dispatcher.policy.for_system().stats),
                    true,
                ),
                None => stream,
            };
            super::dispatch_request(
                stream,
                source,
                bound,
                &inbound,
                &tag,
                &dispatcher,
                &cancel,
                request,
                None,
                sniff.as_ref().cloned(),
            )
            .await
        })
    }

    fn dispatch_udp(&self, session: UdpDispatch) -> HysteriaDispatchFuture {
        let UdpDispatch {
            source,
            user,
            packets,
            responses,
            ..
        } = session;
        let dispatcher = Arc::clone(&self.dispatcher);
        let tag = Arc::clone(&self.tag);
        Box::pin(async move {
            let udp = dispatcher
                .udp
                .as_ref()
                .context("hysteria UDP dispatcher unavailable")?
                .clone();
            let user_tag: Arc<str> = Arc::from(user.map(|user| user.email).unwrap_or_default());
            // The bounded reply queue mirrors plain_udp's listener loop; the
            // session's own idle timeout (hysteriaSettings) governs its
            // lifetime inside the endpoint.
            let (replies_tx, mut replies_rx) = mpsc::channel::<Vec<u8>>(64);
            let mut peers: HashMap<SocketAddr, RelayPeer> = HashMap::new();
            let mut xudp_pumps = JoinSet::new();
            let stop = CancellationToken::new();
            let mut packets = packets;
            let result = loop {
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => break Ok(()),
                    reply = replies_rx.recv() => {
                        let Some(reply) = reply else { continue };
                        tokio::select! {
                            _ = stop.cancelled() => break Ok(()),
                            sent = responses.send(reply) => {
                                if sent.is_err() {
                                    break Ok(());
                                }
                            }
                        }
                    }
                    completed = xudp_pumps.join_next(), if !xudp_pumps.is_empty() => {
                        if completed.is_some() {
                            // The lease closed; its replies already flowed.
                        }
                    }
                    packet = packets.recv() => {
                        let Some((destination, payload)) = packet else { break Ok(()) };
                        let action = udp
                            .dispatch(udp::DispatchContext {
                                destination: destination.clone(),
                                source,
                                inbound_tag: Arc::clone(&tag),
                                user: Arc::clone(&user_tag),
                                network: "udp",
                            })
                            .await;
                        let action = match action {
                            Ok(action) => action,
                            Err(error) => {
                                tracing::debug!(%error, "hysteria UDP dispatch failed");
                                continue;
                            }
                        };
                        match action {
                            DispatchAction::Drop => continue,
                            DispatchAction::Direct(target)
                            | DispatchAction::TrackedDirect { target, .. } => {
                                if !udp::valid_endpoint(target) {
                                    continue;
                                }
                                let peer = peers
                                    .entry(target)
                                    .or_insert_with(|| RelayPeer::new(replies_tx.clone()));
                                let _ = peer.socket.send_to(&payload, target).await;
                            }
                            DispatchAction::Xudp { lease } => {
                                // One pump per lease feeds the session's
                                // replies; the packet rides the carrier.
                                let sender = responses.clone();
                                let pump_stop = stop.clone();
                                let send_lease = lease.clone();
                                xudp_pumps.spawn(async move {
                                    loop {
                                        let reply = tokio::select! {
                                            biased;
                                            _ = pump_stop.cancelled() => return,
                                            reply = send_lease.recv() => reply,
                                        };
                                        let Some((_target, payload)) = reply else { return };
                                        if sender.send(payload).await.is_err() {
                                            return;
                                        }
                                    }
                                });
                                let target = crate::mux::Target::from_destination(
                                    crate::mux::Network::Udp,
                                    &destination,
                                );
                                let _ = lease.send(target, &payload).await;
                            }
                        }
                    }
                }
            };
            stop.cancel();
            peers.clear();
            xudp_pumps.abort_all();
            result
        })
    }
}

/// Bind one hysteria inbound's QUIC listener from the compiled config pieces
/// (Go's hub.Listen): the TLS server config from tlsSettings, the users and
/// hysteriaSettings pieces, and the quicParams congestion/tuning. Every
/// piece was already validated at config parse; this only assembles.
pub(super) fn bind_inbound(
    raw: &crate::config::InboundConfig,
    users: &[crate::protocol::hysteria_runtime::HysteriaUser],
    port: u16,
) -> Result<HysteriaEndpointListener> {
    let transport_settings =
        crate::transport::hysteria_endpoint::HysteriaTransportSettings::from_value(
            raw.stream_settings
                .hysteria_settings
                .as_ref()
                .context("the hysteria inbound requires hysteriaSettings")?,
        )
        .context("hysteriaSettings")?;
    transport_settings.validate().context("hysteriaSettings")?;
    let tls: crate::transport::tls::TlsSettings = serde_json::from_value(
        raw.stream_settings
            .tls_settings
            .clone()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .context("tlsSettings")?;
    let server_tls = tls
        .build_server_config()
        .context("hysteria inbound tlsSettings")?;
    let quic = raw.stream_settings.quic_params()?;
    let options = crate::transport::hysteria_endpoint::HysteriaServerOptions {
        users: users.to_vec(),
        auth: transport_settings.auth.clone(),
        masquerade: transport_settings.masquerade.compile()?,
        udp_idle_timeout: transport_settings.udp_idle_timeout(),
        receive_bytes_per_second: quic.brutal_down_bps,
        congestion: crate::config::congestion_or_reject(&quic)?,
        quic,
    };
    let address = SocketAddr::new(raw.listen, port);
    HysteriaEndpointListener::bind(address, (*server_tls).clone(), options)
        .with_context(|| format!("bind the hysteria QUIC listener on {address}"))
}

/// Serve one bound hysteria inbound: accept QUIC connections until the
/// runtime stops, running every connection's streams and UDP sessions through
/// the seam.
pub(super) async fn serve(
    listener: HysteriaEndpointListener,
    inbound: Inbound,
    tag: Arc<str>,
    sniff: Option<Arc<SniffingRequest>>,
    dispatcher: Arc<Dispatcher>,
    cancel: CancellationToken,
) -> Result<()> {
    let bound = listener.local_addr();
    let seam = Arc::new(RuntimeSeam {
        dispatcher,
        inbound: Arc::new(inbound),
        tag,
        bound,
        cancel: cancel.clone(),
        sniff,
    });
    let inbound_server = Arc::new(crate::protocol::hysteria_runtime::HysteriaInbound::new(
        seam,
    ));
    crate::protocol::hysteria_runtime::serve_until(inbound_server, listener, &cancel).await
}

// ---------------------------------------------------------------------------
// The outbound pool
// ---------------------------------------------------------------------------

/// One shared authenticated QUIC session per hysteria outbound (Go's
/// clientManager cache keyed by the outbound's dialer).
pub(super) struct HysteriaPool {
    entries: Vec<(usize, Arc<HysteriaOutbound>)>,
}

impl HysteriaPool {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Seed from the compiled outbounds (the dialer Arc identity keys the
    /// pool; establish passes the same Arc from the same list).
    pub(super) fn seed(&mut self, outbound: &Outbound) {
        if let Outbound::Hysteria { dialer } = outbound {
            self.entries.push((
                Arc::as_ptr(dialer) as usize,
                Arc::new(HysteriaOutbound::new(dialer.as_ref().clone())),
            ));
        }
    }

    /// Open one proxy stream on the outbound's shared authenticated session.
    pub(super) async fn connect(
        &self,
        dialer: &Arc<HysteriaClientDialer>,
        target: &Destination,
    ) -> Result<(BoxStream, SocketAddr)> {
        let key = Arc::as_ptr(dialer) as usize;
        let outbound = self
            .entries
            .iter()
            .find(|(existing, _)| *existing == key)
            .map(|(_, outbound)| Arc::clone(outbound))
            .context("the hysteria outbound pool was not seeded for this dialer")?;
        let stream = outbound.open_stream(target).await?;
        // Go reports the QUIC endpoint's address; the masque outbound uses
        // the unspecified endpoint the same way.
        Ok((Box::new(stream), SocketAddr::from(([0, 0, 0, 0], 0))))
    }
}
