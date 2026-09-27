// P01 masque_proxy: port of the Go MASQUE outbound proxy (proxy/masque).
#![allow(dead_code)]

//! MASQUE outbound proxy over a CONNECT-IP tunnel (RFC 9484), ported from
//! `proxy/masque/client.go`, `proxy/masque/config.proto` and
//! `infra/conf/masque.go`.
//!
//! Go drives a userspace TCP/IP stack (WireGuard's `tun` + netstack) on top of
//! the raw-IP tunnel connection and dials TCP/UDP through it. This port keeps
//! the proxy semantics — one shared tunnel per outbound with cached
//! establishment failures ([`Client`]), a CONNECT-IP request context per
//! target ([`RequestCtx`]), TCP relay over an opened tunnel stream and UDP
//! relay via RFC 9484 DATAGRAM capsules — and hides the tunnel plumbing behind
//! the [`ConnectIpSession`] trait, which the MASQUE transport
//! (`crate::transport::masque_connectip`) implements. Capsule frames cross
//! the trait boundary as raw bytes and are built/parsed here with the shared
//! capsule codec ([`capsule::encode`] / [`capsule::decode`]).
//!
//! Deliberate deltas from Go (documented requirements of this port):
//!
//! * Go runs a netstack over IP packets; here the transport exposes per-target
//!   streams and datagram capsules directly, so ICMP errors, address-assignment
//!   withdrawal checks and `PacketTooBigError` handling live in the transport.
//! * Policy-manager timeouts (handshake / idle / uplink / downlink) are applied
//!   by the runtime around [`Client::process_tcp`] / [`Client::process_udp`],
//!   not by this module.

use std::{
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
};

use crate::{
    address::Destination,
    transport::{
        BoxStream,
        masque_connectip::capsule::{self, Capsule},
    },
};

/// Remote DNS servers used when the configuration leaves `remoteDNS` empty
/// (`proxy/masque/client.go` `NewClient`).
pub const DEFAULT_REMOTE_DNS: [&str; 4] = [
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
];

/// Tunnel establishment deadline (Go `establishTimeout`).
pub const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a failed establishment is remembered before dialing again (Go
/// `retryInterval`).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Largest UDP payload a DATAGRAM capsule may carry: IPv4's 65,535-byte packet
/// minus IP and UDP headers (Go `wireguard.MAX_DATAGRAM_SIZE`).
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// Extra room for capsule headers (varint type, varint length, context id).
const CAPSULE_HEADER_ROOM: usize = 64;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// MASQUE outbound settings (`infra/conf/masque.go` `MasqueClientConfig`).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub address: Option<String>,
    pub port: u16,
    #[serde(rename = "remoteDNS")]
    pub remote_dns: Vec<String>,
}

impl Settings {
    /// Parses and validates the outbound `settings` JSON object.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let settings: Self = serde_json::from_value(value.clone())?;
        settings.validate()?;
        Ok(settings)
    }

    /// `MasqueClientConfig.Build` checks: `address` and `port` must be set and
    /// every `remoteDNS` entry must be an IP literal (Go `netip.ParseAddr`).
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.address.as_deref().is_some_and(|a| !a.is_empty()),
            "MASQUE: \"address\" is not set"
        );
        ensure!(self.port != 0, "MASQUE: \"port\" is not set");
        for s in &self.remote_dns {
            ensure!(
                s.parse::<IpAddr>().is_ok(),
                "MASQUE: invalid \"remoteDNS\" {s:?}: must be an IP literal"
            );
        }
        Ok(())
    }

    /// Effective remote DNS server list: the configured one, or Go's defaults
    /// (`NewClient`) when it is empty.
    pub fn remote_dns_addrs(&self) -> Result<Vec<IpAddr>> {
        if self.remote_dns.is_empty() {
            return Ok(DEFAULT_REMOTE_DNS
                .iter()
                .map(|s| {
                    s.parse::<IpAddr>()
                        .expect("default remote DNS servers are IP literals")
                })
                .collect());
        }
        self.remote_dns
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .with_context(|| format!("MASQUE: invalid \"remoteDNS\" {s:?}"))
            })
            .collect()
    }

    /// The configured server endpoint (`xray.proxy.masque.ClientConfig.server`).
    pub fn server_destination(&self) -> Result<Destination> {
        Destination::new(self.address.as_deref().unwrap_or_default(), self.port)
    }
}

/// Go `NewClient`'s stream settings checks, run by the runtime on the
/// outbound's streamSettings before wiring this proxy: MASQUE requires the
/// masque transport secured with TLS.
pub fn check_stream_settings(transport: &str, security: &str) -> Result<()> {
    ensure!(
        transport.eq_ignore_ascii_case("masque"),
        "not masque transport"
    );
    ensure!(
        security.eq_ignore_ascii_case("tls"),
        "MASQUE requires \"security\": \"tls\""
    );
    Ok(())
}

pub type OpenStreamFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;
pub type SendDatagramFuture<'a> = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
pub type RecvDatagramFuture<'a> = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

/// One established CONNECT-IP tunnel, implemented by the MASQUE transport.
///
/// All methods take `&self`: the tunnel is shared by every connection of the
/// outbound (Go reuses one tunnel for all `Process` calls), so the
/// implementation multiplexes internally. `recv_datagram` must be
/// cancel-safe: it only fills `out` with complete capsule frames.
pub trait ConnectIpSession: Send + Sync {
    /// Opens a bidirectional tunnel stream toward the TCP `target` and returns
    /// it (Go dials through the netstack; here the transport maps the target
    /// onto a CONNECT-IP stream/context).
    fn open_stream(&self, target: &Destination) -> OpenStreamFuture;
    /// Writes one capsule frame — as produced by [`capsule::encode`] — onto
    /// the tunnel.
    fn send_datagram<'a>(&'a self, capsule: &'a [u8]) -> SendDatagramFuture<'a>;
    /// Reads the next capsule frame into `out` and returns its length.
    fn recv_datagram<'a>(&'a self, out: &'a mut [u8]) -> RecvDatagramFuture<'a>;
    /// Closes the tunnel (Go `tunnel.close`).
    fn close(&self);
}

/// The CONNECT-IP request context for one proxied target (RFC 9484): the
/// target plus the context id its packets travel under. Context 0 belongs to
/// the tunnel control stream, so target contexts start at 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestCtx {
    pub destination: Destination,
    pub context_id: u32,
}

/// A MASQUE proxy session over an established tunnel (Go `tunnel`): allocates
/// per-target request contexts and relays TCP streams and UDP datagrams.
///
/// Cheap to clone: every clone shares the same underlying
/// [`ConnectIpSession`].
#[derive(Clone)]
pub struct Session {
    tunnel: Arc<dyn ConnectIpSession>,
    remote_dns: Arc<[IpAddr]>,
    next_context_id: Arc<AtomicU32>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("remote_dns", &self.remote_dns)
            .field(
                "next_context_id",
                &self.next_context_id.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn new(tunnel: Arc<dyn ConnectIpSession>, remote_dns: Vec<IpAddr>) -> Self {
        Self {
            tunnel,
            remote_dns: remote_dns.into(),
            next_context_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Remote DNS servers reachable through the tunnel.
    pub fn remote_dns(&self) -> &[IpAddr] {
        &self.remote_dns
    }

    /// Allocates the CONNECT-IP request context for `target`. Successive
    /// targets get successive context ids (1, 2, ...).
    pub fn request_context(&self, target: &Destination) -> RequestCtx {
        RequestCtx {
            destination: target.clone(),
            context_id: self.next_context_id.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Closes the tunnel.
    pub fn close(&self) {
        self.tunnel.close();
    }

    /// Relays a TCP target (Go `Process`, `net.Network_TCP` branch): opens a
    /// tunnel stream and copies bytes in both directions until either side
    /// reaches EOF. Dropping the returned stream (which happens when this
    /// returns) closes the tunnel connection, like Go's `defer conn.Close()`.
    pub async fn relay_tcp<D: AsyncRead + AsyncWrite + Unpin>(
        &self,
        target: &Destination,
        downstream: &mut D,
    ) -> io::Result<(u64, u64)> {
        let mut stream = self.tunnel.open_stream(target).await.map_err(|e| {
            io::Error::new(e.kind(), format!("failed to create TCP connection: {e}"))
        })?;
        tokio::io::copy_bidirectional(downstream, &mut stream).await
    }

    /// Sends one UDP payload toward the request context's target, wrapped in
    /// an RFC 9484 DATAGRAM capsule.
    pub async fn udp_send(&self, ctx: &RequestCtx, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(invalid(
                "UDP payload exceeds the datagram capsule size limit",
            ));
        }
        let capsule = Capsule::Datagram {
            context_id: ctx.context_id,
            payload: payload.to_vec(),
        };
        let mut frame = Vec::with_capacity(payload.len() + CAPSULE_HEADER_ROOM);
        capsule::encode(&capsule, &mut frame);
        self.tunnel.send_datagram(&frame).await
    }

    /// Reads and decodes the next capsule frame.
    async fn recv_capsule(&self, frame: &mut [u8]) -> io::Result<Capsule> {
        let n = self.tunnel.recv_datagram(frame).await?;
        let (capsule, consumed) = capsule::decode(&frame[..n])?;
        if consumed != n {
            return Err(invalid("capsule frame has trailing bytes"));
        }
        Ok(capsule)
    }

    /// Receives the next UDP payload for `ctx`. Datagrams of other contexts and
    /// tunnel control capsules (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT, unknown
    /// RFC 9484 types) are skipped — Go's netstack routes them by IP — and a
    /// CLOSE capsule ends the tunnel.
    pub async fn udp_recv(&self, ctx: &RequestCtx) -> io::Result<Vec<u8>> {
        let mut frame = vec![0u8; MAX_UDP_PAYLOAD + CAPSULE_HEADER_ROOM];
        loop {
            match self.recv_capsule(&mut frame).await? {
                Capsule::Datagram {
                    context_id,
                    payload,
                } if context_id == ctx.context_id => {
                    return Ok(payload);
                }
                Capsule::Close => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "MASQUE: CONNECT-IP tunnel closed",
                    ));
                }
                other => {
                    tracing::debug!(capsule = ?other, "MASQUE: capsule for another context skipped");
                }
            }
        }
    }

    /// Full UDP relay for one request context (Go `Process`,
    /// `net.Network_UDP` branch): payloads from `outbound` are
    /// capsule-encoded onto the tunnel; datagrams received for the context are
    /// decoded to `inbound`. When `outbound` closes, the relay keeps draining
    /// the tunnel (Go keeps the response copy running) until `inbound` is
    /// dropped or the tunnel closes.
    pub async fn relay_udp(
        &self,
        ctx: &RequestCtx,
        mut outbound: mpsc::Receiver<Vec<u8>>,
        inbound: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<()> {
        let mut frame = vec![0u8; MAX_UDP_PAYLOAD + CAPSULE_HEADER_ROOM];
        loop {
            tokio::select! {
                maybe = outbound.recv() => {
                    let Some(payload) = maybe else {
                        return self.drain_udp(ctx, inbound).await;
                    };
                    self.udp_send(ctx, &payload).await?;
                }
                result = self.tunnel.recv_datagram(&mut frame) => {
                    let n = result?;
                    if !self.forward_capsule(ctx, &frame[..n], &inbound).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Uplink-only drain after the outbound side closed (Go keeps the response
    /// copy running until the tunnel ends or the link writer is closed).
    async fn drain_udp(&self, ctx: &RequestCtx, inbound: mpsc::Sender<Vec<u8>>) -> io::Result<()> {
        let mut frame = vec![0u8; MAX_UDP_PAYLOAD + CAPSULE_HEADER_ROOM];
        loop {
            tokio::select! {
                _ = inbound.closed() => return Ok(()),
                result = self.tunnel.recv_datagram(&mut frame) => {
                    let n = result?;
                    if !self.forward_capsule(ctx, &frame[..n], &inbound).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Decodes one capsule frame and forwards datagrams of `ctx`'s context to
    /// the inbound sink. Returns `false` when the sink is gone (the
    /// association is over), errors when the tunnel closed.
    async fn forward_capsule(
        &self,
        ctx: &RequestCtx,
        frame: &[u8],
        inbound: &mpsc::Sender<Vec<u8>>,
    ) -> io::Result<bool> {
        let (capsule, consumed) = capsule::decode(frame)?;
        if consumed != frame.len() {
            return Err(invalid("capsule frame has trailing bytes"));
        }
        match capsule {
            Capsule::Datagram {
                context_id,
                payload,
            } if context_id == ctx.context_id => {
                if inbound.send(payload).await.is_err() {
                    return Ok(false);
                }
            }
            Capsule::Close => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "MASQUE: CONNECT-IP tunnel closed",
                ));
            }
            other => {
                tracing::debug!(capsule = ?other, "MASQUE: capsule for another context skipped");
            }
        }
        Ok(true)
    }
}

/// Future returned by the tunnel-establishment factory.
pub type EstablishFuture = Pin<Box<dyn Future<Output = io::Result<Session>> + Send>>;
/// Factory establishing a CONNECT-IP tunnel toward the configured server (Go
/// `Client.establish`: dial the server, run the extended CONNECT handshake,
/// build the tunnel). It receives the effective remote DNS list — Go's
/// `newTunnel` filters it against the assigned address families.
pub type Establish = Arc<dyn Fn(&[IpAddr]) -> EstablishFuture + Send + Sync>;

#[derive(Default)]
struct ClientState {
    session: Option<Session>,
    last_err: Option<(io::Error, tokio::time::Instant)>,
    closed: bool,
}

/// The MASQUE outbound proxy (Go `Client`): owns the settings and the shared
/// tunnel, reuses a live tunnel across connections, remembers establishment
/// failures for [`RETRY_INTERVAL`] and re-dials afterwards.
pub struct Client {
    settings: Settings,
    remote_dns: Vec<IpAddr>,
    establish: Establish,
    state: Mutex<ClientState>,
}

impl Client {
    /// Go `NewClient`. The runtime must already have verified the outbound's
    /// stream settings with [`check_stream_settings`].
    pub fn new(settings: Settings, establish: Establish) -> Result<Self> {
        settings.validate()?;
        let remote_dns = settings.remote_dns_addrs()?;
        Ok(Self {
            settings,
            remote_dns,
            establish,
            state: Mutex::new(ClientState::default()),
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn remote_dns(&self) -> &[IpAddr] {
        &self.remote_dns
    }

    /// Go `getTunnel`: return the live tunnel or establish a new one. A failed
    /// establishment is remembered for [`RETRY_INTERVAL`]; dialing is bounded
    /// by [`ESTABLISH_TIMEOUT`].
    pub async fn get_tunnel(&self) -> io::Result<Session> {
        let mut state = self.state.lock().await;
        if state.closed {
            return Err(io::Error::other("closed"));
        }
        if let Some(session) = &state.session {
            return Ok(session.clone());
        }
        if let Some((err, at)) = &state.last_err
            && at.elapsed() < RETRY_INTERVAL
        {
            return Err(io::Error::new(err.kind(), err.to_string()));
        }
        let session =
            match tokio::time::timeout(ESTABLISH_TIMEOUT, (self.establish)(&self.remote_dns)).await
            {
                Ok(result) => match result {
                    Ok(session) => session,
                    Err(error) => {
                        state.last_err = Some((
                            io::Error::new(error.kind(), error.to_string()),
                            tokio::time::Instant::now(),
                        ));
                        return Err(error);
                    }
                },
                Err(_) => {
                    let error = io::Error::new(
                        io::ErrorKind::TimedOut,
                        "MASQUE: CONNECT-IP tunnel establishment timed out",
                    );
                    state.last_err = Some((
                        io::Error::new(error.kind(), error.to_string()),
                        tokio::time::Instant::now(),
                    ));
                    return Err(error);
                }
            };
        state.last_err = None;
        state.session = Some(session.clone());
        Ok(session)
    }

    /// Drops the cached tunnel so the next use dials a new one. Go replaces a
    /// tunnel whose relay loops exited; here the runtime calls this when the
    /// transport reports the tunnel dead.
    pub async fn invalidate(&self) {
        let mut state = self.state.lock().await;
        if let Some(session) = state.session.take() {
            session.close();
        }
    }

    /// Go `Client.Close`.
    pub async fn close(&self) {
        let mut state = self.state.lock().await;
        state.closed = true;
        if let Some(session) = state.session.take() {
            session.close();
        }
        state.last_err = None;
    }

    /// Go `Process`, TCP branch: reuse or establish the tunnel, open a stream
    /// toward `target` and relay until either side reaches EOF.
    pub async fn process_tcp<D: AsyncRead + AsyncWrite + Unpin>(
        &self,
        target: &Destination,
        downstream: &mut D,
    ) -> io::Result<()> {
        let session = self.get_tunnel().await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to establish CONNECT-IP tunnel: {e}"),
            )
        })?;
        session
            .relay_tcp(target, downstream)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("connection ends: {e}")))?;
        Ok(())
    }

    /// Go `Process`, UDP branch: relay one target's datagrams over the tunnel
    /// as RFC 9484 DATAGRAM capsules.
    pub async fn process_udp(
        &self,
        target: &Destination,
        outbound: mpsc::Receiver<Vec<u8>>,
        inbound: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<()> {
        let session = self.get_tunnel().await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to establish CONNECT-IP tunnel: {e}"),
            )
        })?;
        let ctx = session.request_context(target);
        session
            .relay_udp(&ctx, outbound, inbound)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("connection ends: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        io,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicBool, AtomicUsize},
        },
        task::{Context as TaskContext, Poll},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, ReadBuf, duplex},
        sync::mpsc,
        time::{Duration, timeout},
    };

    const T: Duration = Duration::from_secs(5);

    fn target() -> Destination {
        Destination::new("93.184.216.34", 443).unwrap()
    }

    /// In-process tunnel stream that echoes every byte it receives.
    struct EchoStream {
        pending: VecDeque<u8>,
        closed: bool,
        waker: StdMutex<Option<std::task::Waker>>,
    }

    impl EchoStream {
        fn new() -> Self {
            Self {
                pending: VecDeque::new(),
                closed: false,
                waker: StdMutex::new(None),
            }
        }
    }

    impl AsyncRead for EchoStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending.is_empty() {
                if self.closed {
                    // A shut-down echo stream reports EOF so
                    // copy_bidirectional can finish after the peer drops.
                    return Poll::Ready(Ok(()));
                }
                // Register the waker: poll_write must wake the relay loop, or
                // copy_bidirectional sleeps forever on this unnotified read.
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let mut remaining = buf.remaining();
            while remaining > 0 {
                let (front, _) = self.pending.as_slices();
                if front.is_empty() {
                    break;
                }
                let take = remaining.min(front.len());
                buf.put_slice(&front[..take]);
                self.pending.drain(..take);
                remaining -= take;
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for EchoStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "echo stream closed",
                )));
            }
            self.pending.extend(buf);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            self.closed = true;
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
            Poll::Ready(Ok(()))
        }
    }

    /// In-process [`ConnectIpSession`]: hands out preloaded streams, records
    /// sent capsule frames and serves `recv` from a queue (optionally echoing
    /// everything that is sent).
    #[derive(Clone, Default)]
    struct FakeSession {
        inner: Arc<FakeInner>,
    }

    #[derive(Default)]
    struct FakeInner {
        streams: StdMutex<VecDeque<BoxStream>>,
        inbox: StdMutex<VecDeque<Vec<u8>>>,
        sent: StdMutex<Vec<Vec<u8>>>,
        echo: AtomicBool,
        closed: AtomicBool,
    }

    impl FakeSession {
        fn with_stream(stream: BoxStream) -> Self {
            let fake = Self::default();
            fake.inner.streams.lock().unwrap().push_back(stream);
            fake
        }

        fn echoing() -> Self {
            let fake = Self::default();
            fake.inner.echo.store(true, Ordering::SeqCst);
            fake
        }

        fn queue_frame(&self, frame: Vec<u8>) {
            self.inner.inbox.lock().unwrap().push_back(frame);
        }

        fn sent_frames(&self) -> Vec<Vec<u8>> {
            self.inner.sent.lock().unwrap().clone()
        }

        fn encoded(capsule: &Capsule) -> Vec<u8> {
            let mut out = Vec::new();
            capsule::encode(capsule, &mut out);
            out
        }
    }

    impl ConnectIpSession for FakeSession {
        fn open_stream(&self, _target: &Destination) -> OpenStreamFuture {
            let stream = self.inner.streams.lock().unwrap().pop_front();
            Box::pin(async move { stream.ok_or_else(|| io::Error::other("no stream available")) })
        }

        fn send_datagram<'a>(&'a self, frame: &'a [u8]) -> SendDatagramFuture<'a> {
            Box::pin(async move {
                self.inner.sent.lock().unwrap().push(frame.to_vec());
                if self.inner.echo.load(Ordering::SeqCst) {
                    self.inner.inbox.lock().unwrap().push_back(frame.to_vec());
                }
                Ok(())
            })
        }

        fn recv_datagram<'a>(&'a self, out: &'a mut [u8]) -> RecvDatagramFuture<'a> {
            Box::pin(async move {
                loop {
                    if self.inner.closed.load(Ordering::SeqCst) {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "fake tunnel closed",
                        ));
                    }
                    if let Some(frame) = self.inner.inbox.lock().unwrap().pop_front() {
                        if frame.len() > out.len() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "capsule frame exceeds buffer",
                            ));
                        }
                        out[..frame.len()].copy_from_slice(&frame);
                        return Ok(frame.len());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
        }

        fn close(&self) {
            self.inner.closed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn settings_parse_and_defaults() {
        let value = json!({
            "address": "masque.example.com",
            "port": 443,
            "remoteDNS": ["1.1.1.1", "2606:4700:4700::1111"],
        });
        let settings = Settings::from_value(&value).unwrap();
        assert_eq!(settings.address.as_deref(), Some("masque.example.com"));
        assert_eq!(settings.port, 443);
        assert_eq!(settings.remote_dns, ["1.1.1.1", "2606:4700:4700::1111"]);
        let dns: Vec<IpAddr> = settings.remote_dns_addrs().unwrap().into_iter().collect();
        assert_eq!(
            dns,
            [
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(
            settings.server_destination().unwrap(),
            Destination::new("masque.example.com", 443).unwrap()
        );

        // Go NewClient's defaults when remoteDNS is absent.
        let empty =
            Settings::from_value(&json!({"address": "a.example.com", "port": 443})).unwrap();
        assert_eq!(
            empty.remote_dns_addrs().unwrap(),
            DEFAULT_REMOTE_DNS
                .iter()
                .map(|s| s.parse::<IpAddr>().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            DEFAULT_REMOTE_DNS,
            [
                "1.1.1.1",
                "1.0.0.1",
                "2606:4700:4700::1111",
                "2606:4700:4700::1001"
            ]
        );
    }

    #[test]
    fn settings_rejects_missing_fields_and_invalid_dns() {
        let err = Settings::from_value(&json!({"port": 443})).unwrap_err();
        assert!(err.to_string().contains("address"), "{err}");

        let err = Settings::from_value(&json!({"address": "example.com", "port": 0})).unwrap_err();
        assert!(err.to_string().contains("port"), "{err}");

        let err = Settings::from_value(&json!({"address": "example.com"})).unwrap_err();
        assert!(err.to_string().contains("port"), "{err}");

        for bad in ["dns.example.com", "1.2.3", ""] {
            let err = Settings::from_value(&json!({
                "address": "example.com",
                "port": 443,
                "remoteDNS": [bad],
            }))
            .unwrap_err();
            assert!(err.to_string().contains("remoteDNS"), "{err}");
        }

        let err = Settings::from_value(&json!({
            "address": "example.com",
            "port": 443,
            "unknownField": 1,
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn stream_settings_checks_match_go() {
        check_stream_settings("masque", "tls").unwrap();
        assert_eq!(
            check_stream_settings("tcp", "tls").unwrap_err().to_string(),
            "not masque transport"
        );
        assert_eq!(
            check_stream_settings("masque", "none")
                .unwrap_err()
                .to_string(),
            "MASQUE requires \"security\": \"tls\""
        );
    }

    #[tokio::test]
    async fn tcp_relay_echoes_through_fake_tunnel_stream() {
        let (mut peer, mut downstream) = duplex(4096);
        let fake = FakeSession::with_stream(Box::new(EchoStream::new()));
        let session = Session::new(Arc::new(fake), vec![]);
        let target = target();

        let relay =
            tokio::spawn(
                async move { timeout(T, session.relay_tcp(&target, &mut downstream)).await },
            );

        peer.write_all(b"ping over masque").await.unwrap();
        let mut echoed = [0u8; 16];
        timeout(T, peer.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"ping over masque");

        // Dropping the downstream peer ends the relay (EOF propagation).
        drop(peer);
        let (up, down) = relay.await.unwrap().unwrap().unwrap();
        assert!(up >= 16 && down >= 16);
    }

    #[tokio::test]
    async fn client_process_tcp_relays_through_established_tunnel() {
        let settings =
            Settings::from_value(&json!({"address": "example.com", "port": 443})).unwrap();
        let fake = FakeSession::with_stream(Box::new(EchoStream::new()));
        let session = Session::new(Arc::new(fake), vec![]);
        let establish: Establish = {
            let session = session.clone();
            Arc::new(move |_dns: &[IpAddr]| {
                let session = session.clone();
                Box::pin(async move { Ok(session) })
            })
        };
        let client = Client::new(settings, establish).unwrap();

        let (mut peer, mut downstream) = duplex(4096);
        let target = target();
        let relay =
            tokio::spawn(
                async move { timeout(T, client.process_tcp(&target, &mut downstream)).await },
            );

        peer.write_all(b"via client").await.unwrap();
        let mut echoed = [0u8; 10];
        timeout(T, peer.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"via client");

        drop(peer);
        relay.await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_datagrams_round_trip_through_capsules() {
        let fake = FakeSession::echoing();
        let session = Session::new(Arc::new(fake.clone()), vec!["1.1.1.1".parse().unwrap()]);
        assert_eq!(
            session.remote_dns(),
            &["1.1.1.1".parse::<IpAddr>().unwrap()]
        );

        // Context 0 is the control context; targets get 1, 2, ...
        let ctx = session.request_context(&target());
        assert_eq!(ctx.context_id, 1);
        assert_eq!(ctx.destination, target());
        assert_eq!(session.request_context(&target()).context_id, 2);

        timeout(T, session.udp_send(&ctx, b"hello"))
            .await
            .unwrap()
            .unwrap();
        // The frame on the wire is a DATAGRAM capsule carrying the context.
        let frames = fake.sent_frames();
        assert_eq!(frames.len(), 1);
        let (capsule, consumed) = capsule::decode(&frames[0]).unwrap();
        assert_eq!(consumed, frames[0].len());
        assert_eq!(
            capsule,
            Capsule::Datagram {
                context_id: 1,
                payload: b"hello".to_vec(),
            }
        );

        let back = timeout(T, session.udp_recv(&ctx)).await.unwrap().unwrap();
        assert_eq!(back, b"hello");

        // Oversize payloads are rejected instead of silently truncated.
        let big = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert!(
            timeout(T, session.udp_send(&ctx, &big))
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn udp_recv_skips_other_contexts_and_control_capsules() {
        let fake = FakeSession::default();
        fake.queue_frame(FakeSession::encoded(&Capsule::Datagram {
            context_id: 7,
            payload: b"other".to_vec(),
        }));
        fake.queue_frame(FakeSession::encoded(&Capsule::AddressAssigned {
            ipv4: vec![],
            ipv6: vec![],
        }));
        fake.queue_frame(FakeSession::encoded(&Capsule::Unknown {
            kind: 99,
            payload: vec![1],
        }));
        fake.queue_frame(FakeSession::encoded(&Capsule::Datagram {
            context_id: 3,
            payload: b"mine".to_vec(),
        }));

        let session = Session::new(Arc::new(fake.clone()), vec![]);
        let ctx = RequestCtx {
            destination: target(),
            context_id: 3,
        };
        let got = timeout(T, session.udp_recv(&ctx)).await.unwrap().unwrap();
        assert_eq!(got, b"mine");

        // A CLOSE capsule tears the tunnel down.
        fake.queue_frame(FakeSession::encoded(&Capsule::Close));
        let err = timeout(T, session.udp_recv(&ctx))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn udp_relay_round_trips_and_drains_after_outbound_closes() {
        let fake = FakeSession::echoing();
        let session = Session::new(Arc::new(fake), vec![]);
        let ctx = session.request_context(&target());
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(8);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(8);

        let relay = tokio::spawn({
            // The relay owns clones; the test keeps its own handles.
            let session = session.clone();
            let ctx = ctx.clone();
            async move { timeout(T, session.relay_udp(&ctx, out_rx, in_tx)).await }
        });

        for payload in ["first".as_bytes().to_vec(), "second".as_bytes().to_vec()] {
            out_tx.send(payload).await.unwrap();
        }
        // Every outbound payload is echoed back through the capsule codec.
        for expected in ["first", "second"] {
            let got = timeout(T, in_rx.recv()).await.unwrap().unwrap();
            assert_eq!(got, expected.as_bytes());
        }

        // Closing the outbound side enters the drain phase; dropping the sink
        // (or a CLOSE capsule) ends it.
        drop(out_tx);
        drop(in_rx);
        relay.await.unwrap().unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn client_reuses_tunnel_and_caches_failures() {
        let settings =
            Settings::from_value(&json!({"address": "example.com", "port": 443})).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(true));
        let establish: Establish = {
            let (attempts, fail) = (attempts.clone(), fail.clone());
            Arc::new(move |_dns: &[IpAddr]| {
                let (attempts, fail) = (attempts.clone(), fail.clone());
                Box::pin(async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    if fail.load(Ordering::SeqCst) {
                        Err(io::Error::other("dial failed"))
                    } else {
                        Ok(Session::new(Arc::new(FakeSession::default()), vec![]))
                    }
                })
            })
        };
        let client = Client::new(settings, establish).unwrap();

        // A failed establishment is remembered: the immediate retry does not
        // dial again (Go retryInterval).
        assert!(client.get_tunnel().await.is_err());
        assert!(client.get_tunnel().await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        // After the retry interval the dial is repeated, succeeds, and the
        // live tunnel is then reused without dialing.
        tokio::time::advance(RETRY_INTERVAL).await;
        fail.store(false, Ordering::SeqCst);
        client.get_tunnel().await.unwrap();
        client.get_tunnel().await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // Go Client.Close.
        client.close().await;
        assert!(client.get_tunnel().await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn client_establishment_times_out() {
        let settings = Settings::from_value(&json!({
            "address": "example.com",
            "port": 443,
            "remoteDNS": ["1.1.1.1"],
        }))
        .unwrap();
        let establish: Establish =
            Arc::new(|_dns: &[IpAddr]| Box::pin(std::future::pending::<io::Result<Session>>()));
        let client = Arc::new(Client::new(settings, establish).unwrap());

        let handle = tokio::spawn({
            let client = client.clone();
            async move { client.get_tunnel().await }
        });
        tokio::time::advance(ESTABLISH_TIMEOUT).await;
        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
