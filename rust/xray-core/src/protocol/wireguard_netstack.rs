// P12 wg_netstack: userspace TCP/IP netstack for the WireGuard proxy, replacing Go's gVisor netstack (proxy/wireguard/netstack.go).
#![allow(dead_code)]
//! Userspace TCP/IP termination for the native WireGuard engine.
//!
//! [`Netstack`] is a self-contained smoltcp-backed TCP/IP stack fed with raw IP
//! packets: [`Netstack::write_ip`] receives decrypted packets from the WireGuard
//! engine and [`Netstack::read_ip`] produces packets that must be encrypted and
//! sent to the peer. [`Netstack::dial_tcp`] opens an active TCP connection and
//! [`Netstack::listen_tcp`] accepts incoming ones; both halves bridge smoltcp
//! sockets to tokio [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`].
//!
//! UDP datagrams are routed through the `netstack-smoltcp` crate's packet-level
//! [`netstack_smoltcp::udp::UdpSocket`] halves and respect the configured MTU
//! (oversized datagrams are rejected, fragmentation is unsupported, like Go's
//! netstack which never fragments inside the tunnel).
//!
//! [`WgNet`] glues a [`Netstack`] to the existing packet engine
//! (`crate::protocol::wireguard::WireGuardDevice`) and an endpoint-agnostic UDP
//! transport trait, so the same adapter serves a real socket, a test loopback
//! wire, or any future dispatcher-proxied transport.

/// The TCP/IP stack and the WireGuard adapter need the `netstack-smoltcp`
/// dependency, which is only available with the `native-tun` feature (the
/// workspace default).
#[cfg(feature = "native-tun")]
mod imp {
    use std::{
        collections::HashMap,
        future::Future,
        io,
        net::{IpAddr, SocketAddr},
        pin::Pin,
        sync::{
            Arc, Mutex as StdMutex, MutexGuard,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    use anyhow::Result as AnyhowResult;
    use futures_util::{
        SinkExt, StreamExt,
        stream::{SplitSink, SplitStream},
    };
    use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder, smoltcp};
    use smoltcp::{
        iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
        phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
        socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
        storage::RingBuffer,
        time::{Duration, Instant},
        wire::{
            HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address,
            Ipv6Address,
        },
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::{Notify, mpsc, mpsc::Permit, oneshot},
    };
    use tracing::{debug, warn};

    use crate::protocol::wireguard::{DeviceConfig, PacketAction, WireGuardDevice};

    /// Per-socket TCP window in bytes. Matches the historical `netstack-smoltcp`
    /// default (`0x3FFF * 20`, about 320 KiB), which is what the Go gVisor
    /// netstack's default buffers roughly provide as well.
    const TCP_WINDOW: usize = 0x3FFF * 20;
    /// Smallest legal IPv4 MTU (RFC 791); anything smaller cannot carry a TCP
    /// header and is rejected at construction.
    const MIN_MTU: usize = 68;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn closed(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, message)
    }

    fn lock_control(control: &StdMutex<StreamControl>) -> MutexGuard<'_, StreamControl> {
        control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // ---------------------------------------------------------------------------
    // Public types
    // ---------------------------------------------------------------------------

    /// A userspace TCP/IP netstack over which the WireGuard engine moves raw IP
    /// packets. Cheap to clone: all clones share one stack and its runners.
    #[derive(Clone)]
    pub struct Netstack {
        inner: Arc<NetstackInner>,
    }

    /// A bridged smoltcp TCP socket implementing tokio read/write traits.
    pub struct NetTcpStream {
        local: SocketAddr,
        remote: SocketAddr,
        notify: Arc<Notify>,
        control: Arc<StdMutex<StreamControl>>,
    }

    /// A listening TCP endpoint inside the netstack.
    pub struct NetTcpListener {
        bind: SocketAddr,
        accept: mpsc::UnboundedReceiver<NetTcpStream>,
    }

    /// One UDP datagram that crossed the netstack.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UdpDatagram {
        pub payload: Vec<u8>,
        pub source: SocketAddr,
        pub destination: SocketAddr,
    }

    // ---------------------------------------------------------------------------
    // Shared per-connection control block (runner <-> socket halves)
    // ---------------------------------------------------------------------------

    /// State of one half of the bridged socket, mirroring netstack-smoltcp.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Half {
        /// Open for business.
        Normal,
        /// The user called shutdown; the runner must drain and close.
        Close,
        /// The runner has sent (or is sending) the FIN.
        Closing,
        /// Fully closed; reads return EOF and writes return errors.
        Closed,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ConnectState {
        Connecting,
        Established,
        Failed(String),
    }

    struct StreamControl {
        send_buf: RingBuffer<'static, u8>,
        send_waker: Option<Waker>,
        recv_buf: RingBuffer<'static, u8>,
        recv_waker: Option<Waker>,
        recv_state: Half,
        send_state: Half,
        conn: ConnectState,
        conn_waker: Option<Waker>,
    }

    impl StreamControl {
        fn new(window: usize) -> Self {
            Self {
                send_buf: RingBuffer::new(vec![0u8; window]),
                send_waker: None,
                recv_buf: RingBuffer::new(vec![0u8; window]),
                recv_waker: None,
                recv_state: Half::Normal,
                send_state: Half::Normal,
                conn: ConnectState::Connecting,
                conn_waker: None,
            }
        }
    }

    /// Waits until the runner reports the dial handshake outcome.
    struct ConnectWait {
        control: Arc<StdMutex<StreamControl>>,
    }

    impl Future for ConnectWait {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut control = lock_control(&self.control);
            match control.conn.clone() {
                ConnectState::Established => Poll::Ready(Ok(())),
                ConnectState::Failed(message) => {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)))
                }
                ConnectState::Connecting => {
                    control.conn_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    // ---------------------------------------------------------------------------
    // NetTcpStream / NetTcpListener IO
    // ---------------------------------------------------------------------------

    impl NetTcpStream {
        pub fn local_addr(&self) -> SocketAddr {
            self.local
        }

        pub fn remote_addr(&self) -> SocketAddr {
            self.remote
        }
    }

    impl Drop for NetTcpStream {
        fn drop(&mut self) {
            let mut control = lock_control(&self.control);
            if matches!(control.recv_state, Half::Normal) {
                control.recv_state = Half::Close;
            }
            if matches!(control.send_state, Half::Normal) {
                control.send_state = Half::Close;
            }
            self.notify.notify_one();
        }
    }

    impl AsyncRead for NetTcpStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut control = lock_control(&self.control);
            if control.recv_buf.is_empty() {
                if matches!(control.recv_state, Half::Closed) {
                    return Poll::Ready(Ok(()));
                }
                if let Some(old) = control.recv_waker.replace(cx.waker().clone())
                    && !old.will_wake(cx.waker())
                {
                    old.wake();
                }
                return Poll::Pending;
            }
            let recv_buf = buf.initialize_unfilled();
            let count = control.recv_buf.dequeue_slice(recv_buf);
            buf.advance(count);
            if count > 0 {
                self.notify.notify_one();
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for NetTcpStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut control = lock_control(&self.control);
            if !matches!(control.send_state, Half::Normal) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if control.send_buf.is_full() {
                if let Some(old) = control.send_waker.replace(cx.waker().clone())
                    && !old.will_wake(cx.waker())
                {
                    old.wake();
                }
                return Poll::Pending;
            }
            let count = control.send_buf.enqueue_slice(buf);
            if count > 0 {
                self.notify.notify_one();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut control = lock_control(&self.control);
            if matches!(control.send_state, Half::Closed) {
                return Poll::Ready(Ok(()));
            }
            if matches!(control.send_state, Half::Normal) {
                control.send_state = Half::Close;
            }
            if let Some(old) = control.send_waker.replace(cx.waker().clone())
                && !old.will_wake(cx.waker())
            {
                old.wake();
            }
            self.notify.notify_one();
            Poll::Pending
        }
    }

    impl NetTcpListener {
        /// The address this listener was bound to inside the netstack.
        pub fn bind_addr(&self) -> SocketAddr {
            self.bind
        }

        /// Waits for the next inbound TCP connection; the returned address is
        /// the connection's remote (source) endpoint.
        pub async fn accept(&mut self) -> io::Result<(NetTcpStream, SocketAddr)> {
            match self.accept.recv().await {
                Some(stream) => {
                    let remote = stream.remote_addr();
                    Ok((stream, remote))
                }
                None => Err(closed("WireGuard netstack listener closed")),
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Netstack: channel plumbing and public IP-packet API
    // ---------------------------------------------------------------------------

    enum TcpCommand {
        Dial {
            bind: SocketAddr,
            remote: SocketAddr,
            reply: oneshot::Sender<io::Result<(SocketAddr, Arc<StdMutex<StreamControl>>)>>,
        },
        Listen {
            bind: SocketAddr,
            accept: mpsc::UnboundedSender<NetTcpStream>,
            reply: oneshot::Sender<io::Result<()>>,
        },
    }

    struct NetstackInner {
        mtu: usize,
        notify: Arc<Notify>,
        tcp_ingress_avail: Arc<AtomicBool>,
        cmd_tx: mpsc::Sender<TcpCommand>,
        cmd_rx: StdMutex<Option<mpsc::Receiver<TcpCommand>>>,
        tcp_in_tx: mpsc::Sender<Vec<u8>>,
        tcp_in_rx: StdMutex<Option<mpsc::Receiver<Vec<u8>>>>,
        other_tx: mpsc::Sender<Vec<u8>>,
        other_rx: StdMutex<Option<mpsc::Receiver<Vec<u8>>>>,
        udp_in_tx: mpsc::Sender<netstack_smoltcp::udp::UdpMsg>,
        udp_in_rx: StdMutex<Option<mpsc::Receiver<netstack_smoltcp::udp::UdpMsg>>>,
        egress_tx: mpsc::Sender<Vec<u8>>,
        egress_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        udp_out_tx: mpsc::Sender<UdpDatagram>,
        udp_out_rx: tokio::sync::Mutex<mpsc::Receiver<UdpDatagram>>,
        started: tokio::sync::Mutex<bool>,
    }

    impl Netstack {
        /// Build an empty netstack. The smoltcp runner and the UDP bridge tasks
        /// are started lazily on the first asynchronous call so that `new` stays
        /// usable outside a tokio runtime.
        pub fn new(mtu: usize) -> io::Result<Self> {
            if !(MIN_MTU..=65_535).contains(&mtu) {
                return Err(invalid(
                    "WireGuard netstack MTU must be between 68 and 65535 bytes",
                ));
            }
            let (egress_tx, egress_rx) = mpsc::channel(1024);
            let (cmd_tx, cmd_rx) = mpsc::channel(64);
            let (tcp_in_tx, tcp_in_rx) = mpsc::channel(1024);
            let (other_tx, other_rx) = mpsc::channel(1024);
            let (udp_in_tx, udp_in_rx) = mpsc::channel(256);
            let (udp_out_tx, udp_out_rx) = mpsc::channel(256);
            Ok(Self {
                inner: Arc::new(NetstackInner {
                    mtu,
                    notify: Arc::new(Notify::new()),
                    tcp_ingress_avail: Arc::new(AtomicBool::new(false)),
                    cmd_tx,
                    cmd_rx: StdMutex::new(Some(cmd_rx)),
                    tcp_in_tx,
                    tcp_in_rx: StdMutex::new(Some(tcp_in_rx)),
                    other_tx,
                    other_rx: StdMutex::new(Some(other_rx)),
                    udp_in_tx,
                    udp_in_rx: StdMutex::new(Some(udp_in_rx)),
                    egress_tx,
                    egress_rx: tokio::sync::Mutex::new(egress_rx),
                    udp_out_tx,
                    udp_out_rx: tokio::sync::Mutex::new(udp_out_rx),
                    started: tokio::sync::Mutex::new(false),
                }),
            })
        }

        pub fn mtu(&self) -> usize {
            self.inner.mtu
        }

        /// Feed one decrypted inbound IP packet into the stack. Mirrors
        /// `netTun.Write` in proxy/wireguard/netstack.go: the version nibble
        /// must be 4 or 6 (Go answers `EAFNOSUPPORT` otherwise) and the packet
        /// is dispatched to the TCP runner or the UDP bridge.
        pub fn write_ip(&self, packet: &[u8]) -> io::Result<()> {
            let is_tcp = classify_ip(packet)?;
            let channel = if is_tcp {
                &self.inner.tcp_in_tx
            } else {
                &self.inner.other_tx
            };
            match channel.try_send(packet.to_vec()) {
                Ok(()) => {
                    if is_tcp {
                        self.inner.tcp_ingress_avail.store(true, Ordering::Release);
                        self.inner.notify.notify_one();
                    }
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "WireGuard netstack ingress queue is full",
                )),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(closed("WireGuard netstack ingress channel is closed"))
                }
            }
        }

        /// Read the next outbound IP packet produced by the stack (to be
        /// encrypted and forwarded through the tunnel). One packet per call,
        /// like `netTun.Read`.
        pub async fn read_ip(&self, out: &mut [u8]) -> io::Result<usize> {
            self.ensure_started().await?;
            let packet = self
                .inner
                .egress_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| closed("WireGuard netstack egress channel is closed"))?;
            if packet.len() > out.len() {
                return Err(invalid(
                    "read_ip buffer is smaller than the produced IP packet",
                ));
            }
            out[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        /// Open an active TCP connection from `bind` to `remote`. `bind` may
        /// carry port 0 (an ephemeral port is chosen) or the unspecified
        /// address (smoltcp picks a source from the routing table). The call
        /// completes once the three-way handshake succeeds, like Go's
        /// `gonet.DialContextTCP`.
        pub async fn dial_tcp(
            &self,
            bind: SocketAddr,
            remote: SocketAddr,
        ) -> io::Result<NetTcpStream> {
            self.ensure_started().await?;
            if remote.port() == 0 {
                return Err(invalid("the remote port must be nonzero"));
            }
            if remote.ip().is_unspecified() {
                return Err(invalid("the remote address must not be unspecified"));
            }
            if bind.is_ipv4() != remote.is_ipv4() {
                return Err(invalid("the local and remote address families differ"));
            }
            let (reply, response) = oneshot::channel();
            self.inner
                .cmd_tx
                .send(TcpCommand::Dial {
                    bind,
                    remote,
                    reply,
                })
                .await
                .map_err(|_| closed("WireGuard netstack command channel is closed"))?;
            self.inner.notify.notify_one();
            let (local, control) = response
                .await
                .map_err(|_| closed("WireGuard netstack dial response channel is closed"))??;
            ConnectWait {
                control: control.clone(),
            }
            .await?;
            Ok(NetTcpStream {
                local,
                remote,
                notify: self.inner.notify.clone(),
                control,
            })
        }

        /// Accept inbound TCP connections addressed to `bind` inside the
        /// netstack. One listener per bind address; a second registration
        /// fails with `AddrInUse`.
        pub async fn listen_tcp(&self, bind: SocketAddr) -> io::Result<NetTcpListener> {
            self.ensure_started().await?;
            if bind.port() == 0 {
                return Err(invalid("the listen port must be nonzero"));
            }
            let (accept_tx, accept_rx) = mpsc::unbounded_channel();
            let (reply, response) = oneshot::channel();
            self.inner
                .cmd_tx
                .send(TcpCommand::Listen {
                    bind,
                    accept: accept_tx,
                    reply,
                })
                .await
                .map_err(|_| closed("WireGuard netstack command channel is closed"))?;
            self.inner.notify.notify_one();
            response
                .await
                .map_err(|_| closed("WireGuard netstack listen response channel is closed"))??;
            Ok(NetTcpListener {
                bind,
                accept: accept_rx,
            })
        }

        /// Send one UDP datagram through the netstack. The complete IP packet
        /// must fit the configured MTU; larger datagrams are rejected because
        /// neither Go's netstack nor this port fragments inside the tunnel.
        pub async fn udp_send(
            &self,
            source: SocketAddr,
            destination: SocketAddr,
            payload: &[u8],
        ) -> io::Result<()> {
            self.ensure_started().await?;
            if source.is_ipv4() != destination.is_ipv4() {
                return Err(invalid(
                    "the source and destination address families differ",
                ));
            }
            if payload.is_empty() {
                return Err(invalid("UDP datagrams must carry a payload"));
            }
            let headers = if destination.is_ipv4() { 28 } else { 48 };
            if payload.len() + headers > self.inner.mtu {
                return Err(invalid(
                    "UDP datagram exceeds the WireGuard netstack MTU; fragmentation is unsupported",
                ));
            }
            self.inner
                .udp_in_tx
                .send((payload.to_vec(), source, destination))
                .await
                .map_err(|_| closed("WireGuard netstack UDP channel is closed"))
        }

        /// Receive the next inbound UDP datagram crossing the netstack.
        pub async fn udp_recv(&self) -> io::Result<UdpDatagram> {
            self.ensure_started().await?;
            self.inner
                .udp_out_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| closed("WireGuard netstack UDP channel is closed"))
        }

        async fn ensure_started(&self) -> io::Result<()> {
            let mut started = self.inner.started.lock().await;
            if *started {
                return Ok(());
            }
            // UDP is handled entirely by netstack-smoltcp's packet-level socket:
            // inbound frames are parsed into datagrams and outbound datagrams
            // are rebuilt into IP packets with correct checksums.
            let (stack, _, udp_socket, _) = StackBuilder::default()
                .enable_udp(true)
                .enable_tcp(false)
                .mtu(self.inner.mtu)
                .stack_buffer_size(1024)
                .build()?;
            let udp_socket = udp_socket
                .ok_or_else(|| io::Error::other("the netstack UDP socket was not created"))?;
            let (udp_read, udp_write) = udp_socket.split();
            let (stack_in, stack_out) = stack.split::<AnyIpPktFrame>();

            let other_rx = self
                .inner
                .other_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or_else(|| io::Error::other("the UDP bridge was already started"))?;
            let udp_in_rx = self
                .inner
                .udp_in_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or_else(|| io::Error::other("the UDP bridge was already started"))?;
            tokio::spawn(run_udp_bridge(
                other_rx,
                stack_in,
                stack_out,
                udp_read,
                udp_write,
                udp_in_rx,
                self.inner.egress_tx.clone(),
                self.inner.udp_out_tx.clone(),
            ));

            let cmd_rx = self
                .inner
                .cmd_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or_else(|| io::Error::other("the TCP stack was already started"))?;
            let tcp_in_rx = self
                .inner
                .tcp_in_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or_else(|| io::Error::other("the TCP stack was already started"))?;
            let notify = self.inner.notify.clone();
            let ingress_avail = self.inner.tcp_ingress_avail.clone();
            let egress_tx = self.inner.egress_tx.clone();
            let mtu = self.inner.mtu;
            tokio::spawn(async move {
                if let Err(error) =
                    run_tcp_stack(mtu, notify, ingress_avail, cmd_rx, tcp_in_rx, egress_tx).await
                {
                    warn!(%error, "WireGuard netstack TCP stack stopped");
                }
            });
            *started = true;
            Ok(())
        }
    }

    fn classify_ip(packet: &[u8]) -> io::Result<bool> {
        let Some((&version, _)) = packet.split_first() else {
            return Err(invalid("IP packets must not be empty"));
        };
        match version >> 4 {
            4 => {
                if packet.len() < 20 {
                    Err(invalid("IPv4 packet is shorter than its header"))
                } else {
                    Ok(packet[9] == 6)
                }
            }
            6 => {
                if packet.len() < 40 {
                    Err(invalid("IPv6 packet is shorter than its header"))
                } else {
                    Ok(packet[6] == 6)
                }
            }
            other => Err(io::Error::other(format!(
                "unsupported IP packet version {other}"
            ))),
        }
    }

    // ---------------------------------------------------------------------------
    // UDP bridge over netstack-smoltcp
    // ---------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn run_udp_bridge(
        mut other_rx: mpsc::Receiver<Vec<u8>>,
        mut stack_in: SplitSink<Stack, AnyIpPktFrame>,
        mut stack_out: SplitStream<Stack>,
        mut udp_read: netstack_smoltcp::udp::ReadHalf,
        mut udp_write: netstack_smoltcp::udp::WriteHalf,
        mut udp_in_rx: mpsc::Receiver<netstack_smoltcp::udp::UdpMsg>,
        egress_tx: mpsc::Sender<Vec<u8>>,
        udp_out_tx: mpsc::Sender<UdpDatagram>,
    ) {
        loop {
            tokio::select! {
                packet = other_rx.recv() => {
                    let Some(packet) = packet else { return };
                    if let Err(error) = stack_in.send(packet).await {
                        warn!(%error, "WireGuard netstack UDP input failed");
                        return;
                    }
                }
                frame = stack_out.next() => {
                    match frame {
                        Some(Ok(packet)) => {
                            if egress_tx.send(packet).await.is_err() {
                                return;
                            }
                        }
                        Some(Err(error)) => {
                            warn!(%error, "WireGuard netstack UDP output failed");
                        }
                        None => return,
                    }
                }
                datagram = udp_read.next() => {
                    let Some((payload, source, destination)) = datagram else { return };
                    let message = UdpDatagram {
                        payload,
                        source,
                        destination,
                    };
                    if udp_out_tx.send(message).await.is_err() {
                        return;
                    }
                }
                message = udp_in_rx.recv() => {
                    let Some(message) = message else { return };
                    if let Err(error) = udp_write.send(message).await {
                        warn!(%error, "WireGuard netstack UDP write failed");
                        return;
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------------
    // The smoltcp TCP stack runner (dial + listen)
    // ---------------------------------------------------------------------------

    enum Slot {
        Listen {
            bind: SocketAddr,
            accept: mpsc::UnboundedSender<NetTcpStream>,
        },
        Connecting {
            local: SocketAddr,
            remote: SocketAddr,
            control: Arc<StdMutex<StreamControl>>,
            established: bool,
        },
        Stream {
            local: SocketAddr,
            remote: SocketAddr,
            control: Arc<StdMutex<StreamControl>>,
        },
    }

    impl Slot {
        fn local_port(&self) -> Option<u16> {
            match self {
                Slot::Listen { bind, .. } => Some(bind.port()),
                Slot::Connecting { local, .. } | Slot::Stream { local, .. } => Some(local.port()),
            }
        }
    }

    /// The loopback L3 device smoltcp drives: bounded ingress/egress channels
    /// with availability signalling so the runner parks instead of spinning.
    struct IpDevice {
        ingress: mpsc::Receiver<Vec<u8>>,
        ingress_avail: Arc<AtomicBool>,
        egress: mpsc::Sender<Vec<u8>>,
        mtu: usize,
    }

    struct IpRxToken {
        buffer: Vec<u8>,
    }

    impl RxToken for IpRxToken {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.buffer[..])
        }
    }

    struct IpTxToken<'a> {
        permit: Permit<'a, Vec<u8>>,
    }

    impl TxToken for IpTxToken<'_> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut buffer = vec![0u8; len];
            let result = f(&mut buffer);
            self.permit.send(buffer);
            result
        }
    }

    impl Device for IpDevice {
        type RxToken<'a> = IpRxToken;
        type TxToken<'a> = IpTxToken<'a>;

        fn receive(
            &mut self,
            _timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            // Reserve egress capacity first: when the egress queue is full the
            // packet must stay queued instead of being dropped (the runner
            // re-polls once the reader drains the queue).
            let Ok(permit) = self.egress.try_reserve() else {
                return None;
            };
            match self.ingress.try_recv() {
                Ok(buffer) => Some((IpRxToken { buffer }, IpTxToken { permit })),
                Err(_) => {
                    self.ingress_avail.store(false, Ordering::Release);
                    None
                }
            }
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
            self.egress
                .try_reserve()
                .ok()
                .map(|permit| IpTxToken { permit })
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut capabilities = DeviceCapabilities::default();
            capabilities.medium = Medium::Ip;
            capabilities.max_transmission_unit = self.mtu;
            capabilities
        }
    }

    struct TcpStack {
        notify: Arc<Notify>,
        device: IpDevice,
        iface: Interface,
        socket_set: SocketSet<'static>,
        sockets: HashMap<SocketHandle, Slot>,
        ephemeral: u16,
        window: usize,
    }

    impl TcpStack {
        fn new(
            mtu: usize,
            notify: Arc<Notify>,
            ingress: mpsc::Receiver<Vec<u8>>,
            ingress_avail: Arc<AtomicBool>,
            egress: mpsc::Sender<Vec<u8>>,
        ) -> io::Result<Self> {
            let mut device = IpDevice {
                ingress,
                ingress_avail,
                egress,
                mtu,
            };
            let mut config = InterfaceConfig::new(HardwareAddress::Ip);
            config.random_seed = rand::random::<u64>();
            let mut iface = Interface::new(config, &mut device, Instant::now());
            // Same any-IP setup as netstack-smoltcp / the Go netstack: accept
            // packets for arbitrary tunnel addresses with default routes.
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                    .expect("iface IPv4 address");
                addrs
                    .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                    .expect("iface IPv6 address");
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
                .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))?;
            iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
                .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))?;
            iface.set_any_ip(true);
            Ok(Self {
                notify,
                device,
                iface,
                socket_set: SocketSet::new(vec![]),
                sockets: HashMap::new(),
                ephemeral: 32_767,
                window: TCP_WINDOW,
            })
        }

        fn alloc_port(&mut self) -> io::Result<u16> {
            for _ in 0..(u16::MAX - 32_768) {
                self.ephemeral = self.ephemeral.wrapping_add(1);
                if self.ephemeral < 32_768 {
                    self.ephemeral = 32_768;
                }
                let candidate = self.ephemeral;
                if !self
                    .sockets
                    .values()
                    .any(|slot| slot.local_port() == Some(candidate))
                {
                    return Ok(candidate);
                }
            }
            Err(io::Error::other(
                "WireGuard netstack ephemeral ports exhausted",
            ))
        }

        fn apply(&mut self, cmd: TcpCommand) {
            match cmd {
                TcpCommand::Listen {
                    bind,
                    accept,
                    reply,
                } => {
                    let result = if self.sockets.values().any(
                        |slot| matches!(slot, Slot::Listen { bind: existing, .. } if *existing == bind),
                    ) {
                        Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "the netstack is already listening on this address",
                        ))
                    } else {
                        let mut socket = new_tcp_socket(self.window);
                        match socket.listen(listen_endpoint(bind)) {
                            Ok(()) => {
                                let handle = self.socket_set.add(socket);
                                self.sockets
                                    .insert(handle, Slot::Listen { bind, accept });
                                Ok(())
                            }
                            Err(error) => Err(io::Error::other(format!(
                                "WireGuard netstack listen failed: {error:?}"
                            ))),
                        }
                    };
                    let _ = reply.send(result);
                }
                TcpCommand::Dial {
                    bind,
                    remote,
                    reply,
                } => {
                    let _ = reply.send(self.dial(bind, remote));
                }
            }
        }

        fn dial(
            &mut self,
            bind: SocketAddr,
            remote: SocketAddr,
        ) -> io::Result<(SocketAddr, Arc<StdMutex<StreamControl>>)> {
            let local_port = if bind.port() == 0 {
                self.alloc_port()?
            } else {
                bind.port()
            };
            let local = IpListenEndpoint {
                addr: (!bind.ip().is_unspecified()).then(|| IpAddress::from(bind.ip())),
                port: local_port,
            };
            let mut socket = new_tcp_socket(self.window);
            socket
                .connect(self.iface.context(), ip_endpoint(remote), local)
                .map_err(|error| {
                    io::Error::other(format!("WireGuard netstack TCP connect failed: {error:?}"))
                })?;
            let used = socket
                .local_endpoint()
                .map(endpoint_socket_addr)
                .unwrap_or_else(|| SocketAddr::new(bind.ip(), local_port));
            let control = Arc::new(StdMutex::new(StreamControl::new(self.window)));
            let handle = self.socket_set.add(socket);
            self.sockets.insert(
                handle,
                Slot::Connecting {
                    local: used,
                    remote,
                    control: control.clone(),
                    established: false,
                },
            );
            Ok((used, control))
        }

        /// One service pass: promote handshakes, pump ring buffers, close
        /// finished sockets. Directly modeled on netstack-smoltcp's socket
        /// servicing with the same half-close semantics.
        fn service(&mut self) {
            let mut pending: Vec<(TcpSocket<'static>, Slot)> = Vec::new();
            let mut remove: Vec<SocketHandle> = Vec::new();

            for (handle, slot) in self.sockets.iter_mut() {
                let socket = self.socket_set.get_mut::<TcpSocket>(*handle);
                match slot {
                    Slot::Listen { bind, accept } => {
                        let bind = *bind;
                        let accept = accept.clone();
                        if accept.is_closed() {
                            remove.push(*handle);
                            continue;
                        }
                        if socket.state() != TcpState::Listen {
                            // The socket got tied to a remote: hand the
                            // connection to the listener and respawn a fresh
                            // listening socket for the next inbound SYN.
                            let local = socket
                                .local_endpoint()
                                .map(endpoint_socket_addr)
                                .unwrap_or(bind);
                            let remote = socket
                                .remote_endpoint()
                                .map(endpoint_socket_addr)
                                .unwrap_or(bind);
                            let control = Arc::new(StdMutex::new(StreamControl::new(self.window)));
                            let stream = NetTcpStream {
                                local,
                                remote,
                                notify: self.notify.clone(),
                                control: control.clone(),
                            };
                            if accept.send(stream).is_ok() {
                                *slot = Slot::Stream {
                                    local,
                                    remote,
                                    control,
                                };
                            } else {
                                remove.push(*handle);
                            }
                            let mut listener = new_tcp_socket(self.window);
                            if listener.listen(listen_endpoint(bind)).is_ok() {
                                pending.push((listener, Slot::Listen { bind, accept }));
                            }
                        }
                    }
                    Slot::Connecting {
                        local,
                        remote,
                        control,
                        established,
                    } => {
                        let local = *local;
                        let remote = *remote;
                        let established = *established;
                        match socket.state() {
                            TcpState::Established => {
                                if !established {
                                    {
                                        let mut guard = lock_control(control);
                                        guard.conn = ConnectState::Established;
                                        if let Some(waker) = guard.conn_waker.take() {
                                            waker.wake();
                                        }
                                    }
                                    let control = control.clone();
                                    *slot = Slot::Stream {
                                        local,
                                        remote,
                                        control,
                                    };
                                }
                            }
                            TcpState::Closed => {
                                let mut guard = lock_control(control);
                                guard.conn = ConnectState::Failed(
                                    "the TCP connection closed before the handshake completed"
                                        .to_owned(),
                                );
                                if let Some(waker) = guard.conn_waker.take() {
                                    waker.wake();
                                }
                                remove.push(*handle);
                            }
                            _ => {}
                        }
                    }
                    Slot::Stream { control, .. } => {
                        let mut guard = lock_control(control);
                        if socket.state() == TcpState::Closed {
                            remove.push(*handle);
                            guard.send_state = Half::Closed;
                            guard.recv_state = Half::Closed;
                            if let Some(waker) = guard.send_waker.take() {
                                waker.wake();
                            }
                            if let Some(waker) = guard.recv_waker.take() {
                                waker.wake();
                            }
                            continue;
                        }
                        // SHUT_WR: only close once the send buffer has been
                        // fully drained into the smoltcp socket, otherwise the
                        // remaining bytes are lost.
                        if matches!(guard.send_state, Half::Close) && guard.send_buf.is_empty() {
                            socket.close();
                            guard.send_state = Half::Closing;
                        }
                        // tokio shutdown resolves once OUR FIN is queued: the
                        // socket only reaches Closed after the peer's FIN too,
                        // which the caller must not have to wait for.
                        if matches!(guard.send_state, Half::Closing)
                            && matches!(
                                socket.state(),
                                TcpState::FinWait1
                                    | TcpState::FinWait2
                                    | TcpState::Closing
                                    | TcpState::TimeWait
                                    | TcpState::LastAck
                                    | TcpState::Closed
                            )
                        {
                            guard.send_state = Half::Closed;
                            if let Some(waker) = guard.send_waker.take() {
                                waker.wake();
                            }
                        }

                        let mut wake_recv = false;
                        while socket.can_recv() && !guard.recv_buf.is_full() {
                            match socket.recv(|buffer| (guard.recv_buf.enqueue_slice(buffer), ())) {
                                Ok(()) => wake_recv = true,
                                Err(error) => {
                                    debug!("netstack TCP recv error: {error:?}");
                                    socket.abort();
                                    if matches!(guard.recv_state, Half::Normal) {
                                        guard.recv_state = Half::Closed;
                                    }
                                    wake_recv = true;
                                    break;
                                }
                            }
                        }
                        // Outside the pre-established states a dead remote
                        // read half means EOF for the local reader.
                        if matches!(guard.recv_state, Half::Normal)
                            && !socket.may_recv()
                            && !matches!(
                                socket.state(),
                                TcpState::Listen
                                    | TcpState::SynReceived
                                    | TcpState::Established
                                    | TcpState::FinWait1
                                    | TcpState::FinWait2
                            )
                        {
                            guard.recv_state = Half::Closed;
                            wake_recv = true;
                        }
                        if wake_recv && let Some(waker) = guard.recv_waker.take() {
                            waker.wake();
                        }

                        let mut wake_send = false;
                        while socket.can_send() && !guard.send_buf.is_empty() {
                            match socket.send(|buffer| (guard.send_buf.dequeue_slice(buffer), ())) {
                                Ok(()) => wake_send = true,
                                Err(error) => {
                                    debug!("netstack TCP send error: {error:?}");
                                    socket.abort();
                                    if matches!(guard.send_state, Half::Normal) {
                                        guard.send_state = Half::Closed;
                                    }
                                    wake_send = true;
                                    break;
                                }
                            }
                        }
                        if wake_send && let Some(waker) = guard.send_waker.take() {
                            waker.wake();
                        }
                    }
                }
            }

            for (socket, slot) in pending {
                let handle = self.socket_set.add(socket);
                self.sockets.insert(handle, slot);
            }
            for handle in remove {
                self.sockets.remove(&handle);
                self.socket_set.remove(handle);
            }
        }

        async fn run(mut self, mut cmd_rx: mpsc::Receiver<TcpCommand>) -> io::Result<()> {
            loop {
                // The command channel is the stack's lifeline: when every
                // Netstack clone is gone there is nothing left to serve.
                match cmd_rx.try_recv() {
                    Ok(cmd) => self.apply(cmd),
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
                }
                while let Ok(cmd) = cmd_rx.try_recv() {
                    self.apply(cmd);
                }

                let before_poll = Instant::now();
                let _ = self
                    .iface
                    .poll(before_poll, &mut self.device, &mut self.socket_set);
                self.service();

                if self.device.ingress_avail.load(Ordering::Acquire) {
                    // Cooperative yield keeps the command arm of this loop
                    // responsive while ingress is flowing.
                    tokio::task::yield_now().await;
                } else {
                    let next = self
                        .iface
                        .poll_delay(Instant::now(), &self.socket_set)
                        .unwrap_or(Duration::from_millis(5));
                    if next != Duration::ZERO {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from(next),
                            self.notify.notified(),
                        )
                        .await;
                    } else {
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }

    async fn run_tcp_stack(
        mtu: usize,
        notify: Arc<Notify>,
        ingress_avail: Arc<AtomicBool>,
        cmd_rx: mpsc::Receiver<TcpCommand>,
        tcp_in_rx: mpsc::Receiver<Vec<u8>>,
        egress_tx: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<()> {
        let stack = TcpStack::new(mtu, notify, tcp_in_rx, ingress_avail, egress_tx)?;
        stack.run(cmd_rx).await
    }

    /// Fresh TCP socket with the historical netstack-smoltcp keepalive and
    /// idle-timeout settings (28 s / 7200 s).
    fn new_tcp_socket(window: usize) -> TcpSocket<'static> {
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; window]),
            TcpSocketBuffer::new(vec![0u8; window]),
        );
        socket.set_keep_alive(Some(Duration::from_secs(28)));
        socket.set_timeout(Some(Duration::from_secs(7200)));
        socket
    }

    fn ip_endpoint(address: SocketAddr) -> IpEndpoint {
        IpEndpoint {
            addr: IpAddress::from(address.ip()),
            port: address.port(),
        }
    }

    fn listen_endpoint(bind: SocketAddr) -> IpListenEndpoint {
        IpListenEndpoint {
            addr: (!bind.ip().is_unspecified()).then(|| IpAddress::from(bind.ip())),
            port: bind.port(),
        }
    }

    fn endpoint_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
        SocketAddr::new(IpAddr::from(endpoint.addr), endpoint.port)
    }

    // ---------------------------------------------------------------------------
    // WgNet: netstack + WireGuard engine + endpoint-agnostic UDP transport
    // ---------------------------------------------------------------------------

    /// Endpoint-agnostic transport for encrypted WireGuard datagrams. The
    /// adapter works over any implementation: a bound UDP socket, a proxied
    /// socket from the dispatcher, or an in-memory wire in tests.
    //
    // The async receiver is intentionally not object-safe: consumers are
    // generic over T, never dyn, so the desugared associated-Future bound
    // carries the needed Send bound itself.
    #[allow(async_fn_in_trait)]
    pub trait WgUdpTransport: Send + Sync + 'static {
        /// Queue one encrypted datagram to a WireGuard endpoint. Async like
        /// Go's blocking `PacketConn.WriteTo`: a real socket waits for
        /// writability instead of failing the whole engine on WouldBlock.
        async fn send_datagram(&self, endpoint: SocketAddr, datagram: &[u8]) -> io::Result<()>;

        /// Wait for the next datagram and its source endpoint.
        async fn recv_datagram(&self) -> io::Result<(SocketAddr, Vec<u8>)>;
    }

    /// The full userspace WireGuard proxy adapter: decrypts tunnel packets
    /// into [`Netstack`], encrypts netstack output back into the tunnel, and
    /// runs the engine's timers. All pumps live inside [`WgNet::run`]; dropping
    /// the returned future stops them.
    pub struct WgNet<T: WgUdpTransport> {
        netstack: Netstack,
        device: StdMutex<WireGuardDevice>,
        transport: T,
    }

    impl<T: WgUdpTransport> WgNet<T> {
        /// Build the adapter from a validated device configuration.
        pub fn new(config: DeviceConfig, transport: T) -> AnyhowResult<Self> {
            let mtu = config.mtu;
            let device = WireGuardDevice::new(config)?;
            Ok(Self {
                netstack: Netstack::new(mtu)?,
                device: StdMutex::new(device),
                transport,
            })
        }

        pub fn netstack(&self) -> &Netstack {
            &self.netstack
        }

        /// Run until a pump fails. Handshake initiation is automatic: the
        /// engine queues outbound packets and emits the Noise handshake as
        /// soon as the first packet needs a session.
        pub async fn run(&self) -> AnyhowResult<()> {
            let outbound = async {
                let mut buffer = vec![0u8; self.netstack.mtu()];
                loop {
                    let count = self.netstack.read_ip(&mut buffer).await?;
                    let actions = {
                        let mut device = lock_device(&self.device);
                        device.encapsulate(&buffer[..count])
                    };
                    match actions {
                        Ok(actions) => {
                            for action in actions {
                                self.deliver(action).await?;
                            }
                        }
                        Err(error) => {
                            warn!(%error, "WireGuard outbound packet rejected");
                        }
                    }
                }
            };

            let inbound = async {
                loop {
                    let (source, datagram) = self.transport.recv_datagram().await?;
                    let actions = {
                        let mut device = lock_device(&self.device);
                        device.decapsulate(source, &datagram)
                    };
                    match actions {
                        Ok(actions) => {
                            for action in actions {
                                self.deliver(action).await?;
                            }
                        }
                        Err(error) => {
                            warn!(%error, "WireGuard inbound datagram rejected");
                        }
                    }
                }
            };

            let timers = async {
                let mut timer = tokio::time::interval(std::time::Duration::from_millis(250));
                loop {
                    timer.tick().await;
                    let events = {
                        let mut device = lock_device(&self.device);
                        device.update_timers()
                    };
                    for (peer, error) in events.errors {
                        warn!(peer, %error, "WireGuard timer error");
                    }
                    for action in events.actions {
                        self.deliver(action).await?;
                    }
                }
            };

            tokio::select! {
                result = outbound => result,
                result = inbound => result,
                result = timers => result,
            }
        }

        async fn deliver(&self, action: PacketAction) -> io::Result<()> {
            match action {
                PacketAction::Network {
                    endpoint, packet, ..
                } => self.transport.send_datagram(endpoint, &packet).await,
                PacketAction::Tunnel { packet, .. } => match self.netstack.write_ip(&packet) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        // Congested ingress drops like a network device, which
                        // is also how the bounded queues in Go's device behave.
                        debug!("WireGuard netstack dropped a packet: ingress full");
                        Ok(())
                    }
                    Err(error) => Err(error),
                },
            }
        }
    }

    fn lock_device(device: &StdMutex<WireGuardDevice>) -> MutexGuard<'_, WireGuardDevice> {
        device
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // ---------------------------------------------------------------------------
    // Real-socket UDP transport (proxy/wireguard bind.go)
    // ---------------------------------------------------------------------------

    /// One bound UDP socket serving every peer endpoint, like Go's
    /// `net.PacketConn` in proxy/wireguard/bind.go: datagrams are sent with
    /// `send_to` to the engine-chosen endpoint, so authenticated endpoint
    /// roaming (the engine's `set_peer_endpoint` on verified traffic) keeps
    /// working without rebinding. Reserved-byte marking is the engine's job
    /// (`mark_reserved` on send, clearing on receive), not the transport's.
    pub struct WgUdpSocket {
        socket: tokio::net::UdpSocket,
    }

    impl WgUdpSocket {
        /// Bind the transport socket. `bind` is usually the unspecified
        /// address with port 0 (the OS picks the port, like Go's
        /// `internet.DialSystem` UDP bind); a concrete address is accepted for
        /// callers that must control it. Must be called inside a tokio runtime
        /// because the socket is registered with its reactor.
        pub fn bind(bind: SocketAddr) -> io::Result<Self> {
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.set_nonblocking(true)?;
            Ok(Self {
                socket: tokio::net::UdpSocket::from_std(socket)?,
            })
        }

        /// The bound local address of the underlying socket.
        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }
    }

    impl WgUdpTransport for WgUdpSocket {
        async fn send_datagram(&self, endpoint: SocketAddr, datagram: &[u8]) -> io::Result<()> {
            // A UDP datagram is atomic: the count is either the whole buffer
            // or the call fails, exactly like Go's `PacketConn.WriteTo`. The
            // reactor-integrated send waits for writability when the socket
            // is momentarily not ready, instead of surfacing WouldBlock.
            self.socket.send_to(datagram, endpoint).await?;
            Ok(())
        }

        async fn recv_datagram(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
            let mut buffer = vec![0u8; 65_535];
            let (count, source) = self.socket.recv_from(&mut buffer).await?;
            buffer.truncate(count);
            Ok((source, buffer))
        }
    }
}

#[cfg(feature = "native-tun")]
pub use imp::{
    NetTcpListener, NetTcpStream, Netstack, UdpDatagram, WgNet, WgUdpSocket, WgUdpTransport,
};

// -----------------------------------------------------------------------------
// Tests: two in-memory WgNet instances cross-wired over a loopback datagram
// channel perform a full userspace TCP echo through the netstack.
// -----------------------------------------------------------------------------
#[cfg(all(test, feature = "native-tun"))]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use super::{NetTcpStream, Netstack, WgNet, WgUdpTransport};
    use crate::protocol::wireguard::{DEFAULT_MTU, Role, WireGuardConfig, WireGuardPeerConfig};
    use tokio::time::timeout;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
    };

    // Key fixtures from protocol/wireguard/tests.rs, which took them from
    // testing/scenarios/wireguard_test.go.
    const SERVER_PRIVATE: &str = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=";
    const SERVER_PUBLIC: &str = "MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=";
    const CLIENT_PRIVATE: &str = "CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=";
    const CLIENT_PUBLIC: &str = "osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=";

    fn transport_address_client() -> SocketAddr {
        "127.0.0.1:51001".parse().unwrap()
    }

    fn transport_address_server() -> SocketAddr {
        "127.0.0.1:51002".parse().unwrap()
    }

    fn client_tunnel(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn server_tunnel(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port)
    }

    fn pump_error(pump: &'static str, result: anyhow::Result<()>) -> anyhow::Error {
        match result {
            Ok(()) => anyhow::anyhow!("the {pump} pump stopped unexpectedly"),
            Err(error) => error,
        }
    }

    /// In-memory cross-wire: datagrams sent to the remote endpoint are queued
    /// for the peer with the sender's address as source.
    struct LoopbackWire {
        local: SocketAddr,
        remote: SocketAddr,
        out: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        incoming: tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    }

    impl LoopbackWire {
        fn pair() -> (Self, Self) {
            let (tx_client, rx_server) = mpsc::channel(1024);
            let (tx_server, rx_client) = mpsc::channel(1024);
            (
                Self {
                    local: transport_address_client(),
                    remote: transport_address_server(),
                    out: tx_client,
                    incoming: tokio::sync::Mutex::new(rx_client),
                },
                Self {
                    local: transport_address_server(),
                    remote: transport_address_client(),
                    out: tx_server,
                    incoming: tokio::sync::Mutex::new(rx_server),
                },
            )
        }
    }

    impl WgUdpTransport for LoopbackWire {
        async fn send_datagram(&self, endpoint: SocketAddr, datagram: &[u8]) -> io::Result<()> {
            if endpoint != self.remote {
                return Err(io::Error::other(format!(
                    "the loopback wire only reaches {}",
                    self.remote
                )));
            }
            self.out
                .try_send((self.local, datagram.to_vec()))
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        io::Error::new(io::ErrorKind::WouldBlock, "the loopback wire is congested")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "the loopback wire is closed")
                    }
                })
        }

        async fn recv_datagram(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
            self.incoming.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "the loopback wire is closed")
            })
        }
    }

    fn settings(
        secret: &str,
        peer_public: &str,
        endpoint: &str,
        allowed_ips: &[&str],
    ) -> WireGuardConfig {
        WireGuardConfig {
            secret_key: secret.to_owned(),
            peers: vec![WireGuardPeerConfig {
                public_key: peer_public.to_owned(),
                endpoint: endpoint.to_owned(),
                allowed_ips: Some(
                    allowed_ips
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn net_pair() -> (WgNet<LoopbackWire>, WgNet<LoopbackWire>) {
        let (wire_client, wire_server) = LoopbackWire::pair();
        let client = WgNet::new(
            settings(
                CLIENT_PRIVATE,
                SERVER_PUBLIC,
                &transport_address_server().to_string(),
                &["0.0.0.0/0", "::/0"],
            )
            .build(Role::Client)
            .unwrap(),
            wire_client,
        )
        .unwrap();
        let server = WgNet::new(
            settings(
                SERVER_PRIVATE,
                CLIENT_PUBLIC,
                "",
                &["10.0.0.1/32", "fd00::/128"],
            )
            .build(Role::Server)
            .unwrap(),
            wire_server,
        )
        .unwrap();
        (client, server)
    }

    fn tunnel_v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn client_bind(port: u16) -> SocketAddr {
        SocketAddr::new(tunnel_v4(10, 0, 0, 1), port)
    }

    fn server_bind(port: u16) -> SocketAddr {
        SocketAddr::new(tunnel_v4(10, 0, 0, 2), port)
    }

    async fn echo_once(conn: NetTcpStream) -> u64 {
        let (mut reader, mut writer) = tokio::io::split(conn);
        tokio::io::copy(&mut reader, &mut writer)
            .await
            .expect("echo copy")
    }

    #[tokio::test]
    async fn netstack_validates_mtu_and_endpoints() {
        assert!(Netstack::new(0).is_err());
        assert!(Netstack::new(67).is_err());
        assert!(Netstack::new(65_536).is_err());
        let netstack = Netstack::new(DEFAULT_MTU).unwrap();
        assert_eq!(netstack.mtu(), DEFAULT_MTU);

        // Malformed inbound IP packets are rejected like netTun.Write answers
        // EAFNOSUPPORT for unknown versions.
        assert_eq!(
            netstack.write_ip(&[0x55, 0x00]).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            netstack.write_ip(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            netstack.write_ip(&[0x45, 0x00]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let zero = server_bind(0);
        let error = netstack
            .listen_tcp(zero)
            .await
            .err()
            .expect("listen on port zero must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = netstack
            .dial_tcp(client_bind(40001), server_bind(0))
            .await
            .err()
            .expect("dial to port zero must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = netstack
            .udp_send(
                client_bind(53),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
                b"x",
            )
            .await
            .expect_err("UDP send across address families must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn netstack_rejects_duplicate_listeners() {
        let netstack = Netstack::new(DEFAULT_MTU).unwrap();
        let bind = server_bind(40002);
        let first = netstack.listen_tcp(bind).await.unwrap();
        assert_eq!(first.bind_addr(), bind);
        let error = netstack
            .listen_tcp(bind)
            .await
            .err()
            .expect("duplicate listen must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn wireguard_tcp_echo_through_userspace_netstack() {
        let (client, server) = net_pair();
        assert_eq!(client.netstack().mtu(), DEFAULT_MTU);
        let work = async {
            let bind = server_bind(40002);
            let mut listener = server.netstack().listen_tcp(bind).await?;
            let dialer = client_bind(40001);
            let mut stream = client.netstack().dial_tcp(dialer, bind).await?;
            assert_eq!(stream.local_addr(), dialer);
            assert_eq!(stream.remote_addr(), bind);
            let (conn, remote) = listener.accept().await?;
            assert_eq!(remote, dialer);
            assert_eq!(conn.local_addr(), bind);
            let echo = tokio::spawn(echo_once(conn));
            // Larger than the MTU so the echo exercises segmentation.
            let payload: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
            stream.write_all(&payload).await?;
            let mut echoed = vec![0u8; payload.len()];
            stream.read_exact(&mut echoed).await?;
            assert_eq!(echoed, payload);
            drop(stream);
            let copied = timeout(Duration::from_secs(2), echo)
                .await
                .expect("echo finished")
                .expect("echo task alive");
            assert_eq!(copied as usize, payload.len());
            anyhow::Ok(())
        };
        timeout(Duration::from_secs(5), async {
            tokio::select! {
                error = client.run() => Err(pump_error("client", error)),
                error = server.run() => Err(pump_error("server", error)),
                result = work => result,
            }
        })
        .await
        .expect("echo test finished within the deadline")
        .unwrap();
    }

    #[tokio::test]
    async fn wireguard_concurrent_tcp_streams() {
        const STREAMS: usize = 3;
        const PAYLOAD: usize = 4096;
        let (client, server) = net_pair();
        let work = async {
            let bind = server_bind(40002);
            let mut listener = server.netstack().listen_tcp(bind).await?;
            let mut dialers = Vec::new();
            for index in 0..STREAMS {
                let local = client_bind(40_010 + index as u16);
                dialers.push(client.netstack().dial_tcp(local, bind).await?);
            }
            let mut echo_tasks = Vec::new();
            for _ in 0..STREAMS {
                let (conn, _) = listener.accept().await?;
                echo_tasks.push(tokio::spawn(echo_once(conn)));
            }
            let mut tasks = Vec::new();
            for (index, mut stream) in dialers.into_iter().enumerate() {
                tasks.push(tokio::spawn(async move {
                    let payload = vec![0x5a + index as u8; PAYLOAD];
                    stream.write_all(&payload).await?;
                    let mut echoed = vec![0u8; PAYLOAD];
                    stream.read_exact(&mut echoed).await?;
                    assert_eq!(echoed, payload);
                    anyhow::Ok(())
                }));
            }
            for task in tasks {
                timeout(Duration::from_secs(5), task)
                    .await
                    .expect("stream finished")
                    .expect("stream task alive")?;
            }
            for task in echo_tasks {
                let copied = timeout(Duration::from_secs(5), task)
                    .await
                    .expect("echo finished")
                    .expect("echo task alive");
                assert_eq!(copied as usize, PAYLOAD);
            }
            anyhow::Ok(())
        };
        timeout(Duration::from_secs(10), async {
            tokio::select! {
                error = client.run() => Err(pump_error("client", error)),
                error = server.run() => Err(pump_error("server", error)),
                result = work => result,
            }
        })
        .await
        .expect("concurrent test finished within the deadline")
        .unwrap();
    }

    #[tokio::test]
    async fn wireguard_tcp_half_close() {
        let (client, server) = net_pair();
        let work = async {
            let bind = server_bind(40002);
            let mut listener = server.netstack().listen_tcp(bind).await?;
            let mut dialer = client.netstack().dial_tcp(client_bind(40001), bind).await?;
            let (mut conn, _) = listener.accept().await?;
            dialer.write_all(b"hello half-close").await?;
            dialer.shutdown().await?;

            let mut received = Vec::new();
            conn.read_to_end(&mut received).await?;
            assert_eq!(received, b"hello half-close");

            conn.write_all(b"final word").await?;
            conn.shutdown().await?;
            let mut replied = Vec::new();
            dialer.read_to_end(&mut replied).await?;
            assert_eq!(replied, b"final word");
            anyhow::Ok(())
        };
        timeout(Duration::from_secs(5), async {
            tokio::select! {
                error = client.run() => Err(pump_error("client", error)),
                error = server.run() => Err(pump_error("server", error)),
                result = work => result,
            }
        })
        .await
        .expect("half-close test finished within the deadline")
        .unwrap();
    }

    #[tokio::test]
    async fn wireguard_udp_datagrams_respect_mtu() {
        let (client, server) = net_pair();
        let work = async {
            let mtu = client.netstack().mtu();
            // IPv4 + UDP headers are 28 bytes.
            let max_payload = mtu - 28;
            let payload: Vec<u8> = (0..max_payload).map(|index| (index % 256) as u8).collect();
            client
                .netstack()
                .udp_send(client_bind(53), server_bind(53), &payload)
                .await?;
            let datagram = server.netstack().udp_recv().await?;
            assert_eq!(datagram.payload, payload);
            assert_eq!(datagram.source, client_bind(53));
            assert_eq!(datagram.destination, server_bind(53));

            server
                .netstack()
                .udp_send(server_bind(53), client_bind(53), b"pong")
                .await?;
            let reply = client.netstack().udp_recv().await?;
            assert_eq!(reply.payload, b"pong");
            assert_eq!(reply.source, server_bind(53));

            let oversized = vec![0u8; max_payload + 1];
            let error = client
                .netstack()
                .udp_send(client_bind(53), server_bind(53), &oversized)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            anyhow::Ok(())
        };
        timeout(Duration::from_secs(5), async {
            tokio::select! {
                error = client.run() => Err(pump_error("client", error)),
                error = server.run() => Err(pump_error("server", error)),
                result = work => result,
            }
        })
        .await
        .expect("UDP test finished within the deadline")
        .unwrap();
    }
}
