//! Optional native TCP stack and Linux TUN adapter.
//!
//! `run_packets` permits unprivileged use of the actual userspace TCP stack.
//! `run_native` creates an owned Linux interface; it never changes system DNS,
//! installs routes, shells out, or bypasses the caller's outbound dispatcher.
//! Dropping/cancelling either runtime drops all pumps and the stack together.

use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::{
    TunConfig,
    packet::{self, ICMPV4, ICMPV6, TCP, UDP},
    session::{SessionKey, UdpSessions},
};

pub enum TunEvent {
    /// Tokio AsyncRead + AsyncWrite + Unpin + Send. Box into the dispatcher's
    /// stream abstraction. `source` is the client and `destination` the target.
    Tcp {
        stream: TcpStream,
        source: SocketAddr,
        destination: SocketAddr,
    },
    Udp {
        session: SessionKey,
        is_new: bool,
        destination: SocketAddr,
        payload: Vec<u8>,
    },
    UdpClosed(SessionKey),
}

pub struct Dispatcher {
    pub events: mpsc::Receiver<TunEvent>,
    pub udp: UdpReplies,
}

pub struct Endpoint {
    events: mpsc::Sender<TunEvent>,
    commands: mpsc::Receiver<UdpCommand>,
}

enum UdpCommand {
    Reply {
        session: SessionKey,
        remote: SocketAddr,
        payload: Vec<u8>,
        result: oneshot::Sender<io::Result<()>>,
    },
    Close(SessionKey),
}

#[derive(Clone)]
pub struct UdpReplies {
    commands: mpsc::Sender<UdpCommand>,
}

impl UdpReplies {
    /// Success means the raw reply entered the bounded device output queue.
    /// The runtime's return value reports later device I/O failure. The remote
    /// need not be the original destination (Go's full-cone UDP behavior).
    pub async fn send(
        &self,
        session: SessionKey,
        remote: SocketAddr,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let (result, response) = oneshot::channel();
        self.commands
            .send(UdpCommand::Reply {
                session,
                remote,
                payload,
                result,
            })
            .await
            .map_err(|_| closed("TUN UDP command channel"))?;
        response
            .await
            .map_err(|_| closed("TUN UDP reply acknowledgement"))?
    }

    pub async fn close(&self, session: SessionKey) -> io::Result<()> {
        self.commands
            .send(UdpCommand::Close(session))
            .await
            .map_err(|_| closed("TUN UDP command channel"))
    }
}

pub fn channels(capacity: usize) -> io::Result<(Endpoint, Dispatcher)> {
    if capacity == 0 || capacity > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN channel capacity is outside Tokio's supported range",
        ));
    }
    let (events, receiver) = mpsc::channel(capacity);
    let (commands, command_receiver) = mpsc::channel(capacity);
    Ok((
        Endpoint {
            events,
            commands: command_receiver,
        },
        Dispatcher {
            events: receiver,
            udp: UdpReplies { commands },
        },
    ))
}

fn closed(channel: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, channel)
}

struct Datagram {
    source: SocketAddr,
    destination: SocketAddr,
    payload: Vec<u8>,
}

/// Run the actual TCP stack and native UDP/ICMP handlers over bounded raw-packet
/// channels. All packet channel messages are a single complete L3 IP packet.
///
/// No background task survives this future. A closed ingress/egress/dispatcher
/// is an error; explicit cancellation is successful shutdown. The dispatcher
/// must close its TCP/UDP sessions when this future returns or events close.
pub async fn run_packets(
    config: TunConfig,
    mut ingress: mpsc::Receiver<Vec<u8>>,
    egress: mpsc::Sender<Vec<u8>>,
    endpoint: Endpoint,
    shutdown: CancellationToken,
) -> io::Result<()> {
    config.validate_native()?;
    if shutdown.is_cancelled() {
        return Ok(());
    }
    let (stack, runner, _, listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(false)
        .enable_icmp(false)
        .mtu(usize::from(config.mtu))
        .stack_buffer_size(config.event_capacity)
        .tcp_buffer_size(config.event_capacity)
        .build()?;
    let runner = runner.ok_or_else(|| io::Error::other("TCP stack runner was not created"))?;
    let mut listener =
        listener.ok_or_else(|| io::Error::other("TCP stack listener was not created"))?;
    let (mut stack_input, mut stack_output) = stack.split();
    let (udp_input, udp_output) = mpsc::channel(config.event_capacity);
    let udp_events = endpoint.events.clone();
    let icmp_output = egress.clone();
    let stack_egress = egress.clone();
    let mtu = usize::from(config.mtu);

    let read_packets = async move {
        while let Some(bytes) = ingress.recv().await {
            let parsed = match packet::parse_ip(&bytes) {
                Ok(packet) if bytes.len() <= mtu && packet.hop_limit != 0 => packet,
                Ok(_) => {
                    tracing::debug!("drop TUN packet with zero hop limit or over MTU");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%error, "drop unsupported or malformed TUN packet");
                    continue;
                }
            };
            match parsed.protocol {
                TCP => {
                    if let Err(error) = packet::validate_tcp(&parsed) {
                        tracing::debug!(%error, "drop malformed TUN TCP packet");
                        continue;
                    }
                    stack_input.send(bytes).await?;
                }
                UDP => match packet::parse_udp(&parsed) {
                    Ok(packet) => {
                        let datagram = Datagram {
                            source: packet.source,
                            destination: packet.destination,
                            payload: packet.payload.to_vec(),
                        };
                        // Like Go's per-association queue, congestion drops UDP
                        // instead of indefinitely stopping all packet ingress.
                        match udp_input.try_send(datagram) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                tracing::debug!("drop TUN UDP packet: queue full")
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                return Err(closed("TUN UDP input channel"));
                            }
                        }
                    }
                    Err(error) => tracing::debug!(%error, "drop malformed TUN UDP packet"),
                },
                ICMPV4 | ICMPV6 => match packet::build_echo_reply(&parsed) {
                    Ok(reply) => icmp_output
                        .send(reply)
                        .await
                        .map_err(|_| closed("TUN ICMP output channel"))?,
                    Err(error) => {
                        tracing::debug!(%error, "drop non-echo or malformed TUN ICMP packet")
                    }
                },
                protocol => tracing::debug!(protocol, "drop unsupported TUN IP protocol"),
            }
        }
        Err(closed("TUN packet ingress closed"))
    };
    let write_packets = async move {
        while let Some(packet) = stack_output.next().await {
            let packet = packet?;
            if packet.len() > mtu {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TCP stack generated packet above MTU",
                ));
            }
            stack_egress
                .send(packet)
                .await
                .map_err(|_| closed("TUN packet egress closed"))?;
        }
        Err(closed("TUN TCP stack output closed"))
    };
    let tcp_events = async move {
        while let Some((stream, source, destination)) = listener.next().await {
            endpoint
                .events
                .send(TunEvent::Tcp {
                    stream,
                    source,
                    destination,
                })
                .await
                .map_err(|_| closed("TUN dispatcher closed"))?;
        }
        Err(closed("TUN TCP listener closed"))
    };
    let udp_service = run_udp(&config, udp_output, egress, udp_events, endpoint.commands);

    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(()),
        result = runner => result.and_then(|()| Err(closed("TUN TCP runner stopped"))),
        result = read_packets => result,
        result = write_packets => result,
        result = tcp_events => result,
        result = udp_service => result,
    }
}

async fn run_udp(
    config: &TunConfig,
    mut packets: mpsc::Receiver<Datagram>,
    output: mpsc::Sender<Vec<u8>>,
    events: mpsc::Sender<TunEvent>,
    mut commands: mpsc::Receiver<UdpCommand>,
) -> io::Result<()> {
    let mut sessions = UdpSessions::new(config.max_udp_sessions, config.udp_idle_timeout)?;
    let mut timer = tokio::time::interval(config.udp_idle_timeout.min(Duration::from_secs(1)));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = timer.tick() => {
                for session in sessions.expire(Instant::now()) {
                    events.send(TunEvent::UdpClosed(session)).await.map_err(|_| closed("TUN dispatcher closed"))?;
                }
            }
            packet = packets.recv() => {
                let Some(packet) = packet else { return Err(closed("TUN UDP ingress closed")); };
                let now = Instant::now();
                for session in sessions.expire(now) {
                    events.send(TunEvent::UdpClosed(session)).await.map_err(|_| closed("TUN dispatcher closed"))?;
                }
                let (session, is_new) = match sessions.register(packet.source, now) {
                    Ok(session) => session,
                    Err(error) => { tracing::debug!(%error, "drop TUN UDP packet at session limit"); continue; }
                };
                let event = TunEvent::Udp { session, is_new, destination: packet.destination, payload: packet.payload };
                match events.try_send(event) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        if is_new { sessions.remove(session); }
                        tracing::debug!("drop TUN UDP packet: dispatcher queue full");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return Err(closed("TUN dispatcher closed")),
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { return Err(closed("TUN UDP commands closed")); };
                match command {
                    UdpCommand::Close(session) => {
                        if sessions.remove(session) { events.send(TunEvent::UdpClosed(session)).await.map_err(|_| closed("TUN dispatcher closed"))?; }
                    }
                    UdpCommand::Reply { session, remote, payload, result } => {
                        let reply = packet::build_udp(remote, session.source, &payload).and_then(|packet| {
                            if packet.len() > usize::from(config.mtu) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN UDP reply exceeds MTU; fragmentation is unsupported")); }
                            sessions.accept_reply(session, remote, Instant::now())?;
                            Ok(packet)
                        });
                        let reply = match reply {
                            Ok(packet) => output.send(packet).await.map_err(|_| closed("TUN UDP packet output closed")),
                            Err(error) => Err(error),
                        };
                        let _ = result.send(reply);
                    }
                }
            }
        }
    }
}

/// Create and serve a Linux L3 TUN. The returned future owns the descriptor.
/// Creation requires the OS capabilities normally needed to create a TUN.
#[cfg(target_os = "linux")]
pub async fn run_native(
    config: TunConfig,
    endpoint: Endpoint,
    shutdown: CancellationToken,
) -> io::Result<()> {
    config.validate_native()?;
    if shutdown.is_cancelled() {
        return Ok(());
    }
    for key in ["xray.tun.fd", "XRAY_TUN_FD"] {
        if std::env::var_os(key).is_some_and(|value| !value.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native Rust TUN inherited descriptors are not implemented",
            ));
        }
    }
    let existing = std::path::Path::new("/sys/class/net").join(&config.name);
    if existing.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "refusing to reconfigure an existing TUN interface",
        ));
    }
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(&config.name)
        .mtu(config.mtu)
        .layer(tun_rs::Layer::L3)
        .enable(false)
        .offload(false)
        .multi_queue(false);
    for address in &config.gateway {
        builder = match address.address() {
            std::net::IpAddr::V4(ip) => builder.ipv4(ip, address.prefix_len(), None),
            std::net::IpAddr::V6(ip) => builder.ipv6(ip, address.prefix_len()),
        };
    }
    let device = builder.build_async()?;
    let (packet_input, ingress) = mpsc::channel(config.event_capacity);
    let (egress, mut packet_output) = mpsc::channel::<Vec<u8>>(config.event_capacity);
    // An owned, nonpersistent interface disappears when its descriptor closes,
    // including stack/setup failures and cancellation of this entire future.
    device.enabled(true)?;
    let reader = async {
        let mut buffer = vec![0; packet::MAX_IP_PACKET];
        loop {
            let count = device.recv(&mut buffer).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN device returned EOF",
                ));
            }
            packet_input
                .send(buffer[..count].to_vec())
                .await
                .map_err(|_| closed("TUN ingress pump closed"))?;
        }
    };
    let writer = async {
        while let Some(packet) = packet_output.recv().await {
            let count = device.send(&packet).await?;
            if count != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUN device wrote a partial packet",
                ));
            }
        }
        Err(closed("TUN egress pump closed"))
    };
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(()),
        result = run_packets(config, ingress, egress, endpoint, shutdown.clone()) => result,
        result = reader => result,
        result = writer => result,
    };
    let cleanup = device.enabled(false);
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), cleanup) => cleanup,
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run_native(
    config: TunConfig,
    _endpoint: Endpoint,
    _shutdown: CancellationToken,
) -> io::Result<()> {
    config.validate_native()?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native Rust TUN device startup is implemented only for Linux",
    ))
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
