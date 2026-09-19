//! Native Mux.Cool carriers, sessions and XUDP framing.
//!
//! A carrier is an already authenticated proxy stream to `v1.mux.cool:9527`.
//! This module does not bypass the enclosing proxy's authentication/routing.
//! The dispatcher explicitly receives each accepted target and its metadata.

pub mod wire;
pub mod xudp;

use crate::{
    address::{Address, Destination},
    transport::BoxStream,
};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;
pub use wire::{Frame, Host, MetadataMode, Network, Status, Target};
pub use xudp::{GlobalId, Packet};

pub const MUX_DOMAIN: &str = "v1.mux.cool";
pub const MUX_PORT: u16 = 9527;

impl Target {
    pub fn from_destination(network: Network, destination: &Destination) -> Self {
        Self {
            network,
            host: match &destination.address {
                Address::Ip(ip) => Host::Ip(*ip),
                Address::Domain(domain) => Host::Domain(domain.clone()),
            },
            port: destination.port,
        }
    }
    pub fn destination(&self) -> Destination {
        Destination {
            address: match &self.host {
                Host::Ip(ip) => Address::Ip(*ip),
                Host::Domain(domain) => Address::Domain(domain.clone()),
            },
            port: self.port,
        }
    }
}

/// Exact XUDP keyed BLAKE3 identity: the first eight keyed digest bytes of
/// inbound.Source.String(), only for cone UDP and the four source-supported
/// inbound names. The runtime owns/reloads its random 32-byte base key.
pub fn xudp_global_id(
    base_key: &[u8; 32],
    cone: bool,
    inbound_name: &str,
    source: &Target,
) -> GlobalId {
    if !cone
        || source.network != Network::Udp
        || !matches!(
            inbound_name,
            "dokodemo-door" | "socks" | "shadowsocks" | "tun"
        )
    {
        return [0; 8];
    }
    let host = match &source.host {
        Host::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(domain) => domain.clone(),
    };
    let digest = blake3::keyed_hash(base_key, format!("udp:{host}:{}", source.port).as_bytes());
    digest.as_bytes()[..8].try_into().expect("eight bytes")
}

/// Read exactly one frame. EOF between frames returns None; truncated frames
/// are errors. Cancellation must close the carrier; session receive operations
/// are separately cancellation safe because this runs in a dedicated reader.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    mode: MetadataMode,
) -> io::Result<Option<Frame>> {
    let mut prefix = [0; 2];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..]).await?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if !(4..=wire::MAX_METADATA).contains(&length) {
        return Err(invalid("Mux.Cool metadata length must be 4..512"));
    }
    let mut bytes = vec![0; length + 2];
    bytes[..2].copy_from_slice(&prefix);
    reader.read_exact(&mut bytes[2..]).await?;
    if bytes[5] & wire::OPTION_DATA != 0 {
        let size = reader.read_u16().await?;
        bytes.extend_from_slice(&size.to_be_bytes());
        let start = bytes.len();
        bytes.resize(start + usize::from(size), 0);
        reader.read_exact(&mut bytes[start..]).await?;
    }
    let (frame, _) =
        wire::decode(&bytes, mode)?.ok_or_else(|| invalid("incomplete Mux.Cool frame"))?;
    Ok(Some(frame))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> io::Result<()> {
    writer.write_all(&frame.encode()?).await?;
    writer.flush().await
}

pub async fn read_xudp_packet<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Packet>> {
    loop {
        let Some(frame) = read_frame(reader, MetadataMode::Ordinary).await? else {
            return Ok(None);
        };
        match xudp::decode_reply(frame)? {
            xudp::Reply::Packet(packet) => return Ok(Some(packet)),
            xudp::Reply::Ignore => {}
            xudp::Reply::End => return Ok(None),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GlobalIdPolicy {
    /// Prevent accidental success without cross-carrier association reuse.
    #[default]
    Reject,
    /// Dispatcher consumes Session.global_id using AssociationRegistry and
    /// replaces/detaches prior response routing. This is an explicit contract.
    Dispatch,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub max_concurrency: usize,
    pub max_connections: usize,
    pub queue_capacity: usize,
    pub metadata_mode: MetadataMode,
    pub global_ids: GlobalIdPolicy,
    pub allowed_network: Option<Network>,
    /// None uses Go's 16s client / 60s server idle interval. Zero is invalid.
    pub idle_interval: Option<Duration>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_concurrency: 0,
            max_connections: 65_535,
            queue_capacity: 32,
            metadata_mode: MetadataMode::Ordinary,
            global_ids: GlobalIdPolicy::Reject,
            allowed_network: None,
            idle_interval: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    pub source: Option<Target>,
    pub local: Option<Target>,
    pub global_id: Option<GlobalId>,
    /// Required with nonzero XUDP global IDs, as in the Go server's initial
    /// packet test. Ordinary sessions may open without a first payload.
    pub initial_data: Option<Vec<u8>>,
}

type Failure = (io::ErrorKind, String);
fn from_failure(failure: &Failure) -> io::Error {
    io::Error::new(failure.0, failure.1.clone())
}

struct Shared {
    commands: mpsc::Sender<Command>,
    closes: mpsc::UnboundedSender<u16>,
    cancel: CancellationToken,
    active: AtomicUsize,
    total: AtomicUsize,
    failure: Mutex<Option<Failure>>,
    max_concurrency: usize,
    max_connections: usize,
}

impl Shared {
    fn error(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(from_failure)
    }
    fn fail(&self, error: io::Error) {
        let mut failure = self.failure.lock().unwrap_or_else(|p| p.into_inner());
        if failure.is_none() {
            *failure = Some((error.kind(), error.to_string()));
        }
        drop(failure);
        self.cancel.cancel();
    }
}

#[derive(Clone)]
pub struct Connection {
    shared: Arc<Shared>,
}

impl Connection {
    pub fn client(stream: BoxStream, options: Options) -> io::Result<Self> {
        let (connection, _) = start(stream, Role::Client, options)?;
        Ok(connection)
    }
    pub fn server(
        stream: BoxStream,
        options: Options,
    ) -> io::Result<(Self, mpsc::Receiver<Session>)> {
        start(stream, Role::Server, options)
    }
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }
    pub fn total_connections(&self) -> usize {
        self.shared.total.load(Ordering::Acquire)
    }
    pub fn is_closed(&self) -> bool {
        self.shared.cancel.is_cancelled()
    }
    pub fn is_full(&self) -> bool {
        self.is_closed()
            || self.total_connections() >= self.shared.max_connections
            || (self.shared.max_concurrency > 0
                && self.active_connections() >= self.shared.max_concurrency)
    }
    pub fn close(&self) {
        self.shared.cancel.cancel();
    }
    pub async fn closed(&self) -> io::Result<()> {
        self.shared.cancel.cancelled().await;
        match self.shared.error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub async fn open(&self, target: Target, options: OpenOptions) -> io::Result<Session> {
        if self.is_closed() {
            return Err(self.shared.error().unwrap_or_else(closed));
        }
        let (reply, receive) = oneshot::channel();
        self.shared
            .commands
            .send(Command::Open {
                target,
                options,
                reply,
            })
            .await
            .map_err(|_| closed())?;
        receive
            .await
            .map_err(|_| self.shared.error().unwrap_or_else(closed))?
    }
}

struct SessionState {
    closed: AtomicBool,
    failure: Mutex<Option<Failure>>,
}

pub struct Session {
    pub id: u16,
    pub target: Target,
    pub source: Option<Target>,
    pub local: Option<Target>,
    pub global_id: Option<GlobalId>,
    sender: SessionSender,
    receiver: SessionReceiver,
}

impl Session {
    pub fn sender(&self) -> SessionSender {
        self.sender.clone()
    }
    pub fn split(self) -> (SessionSender, SessionReceiver) {
        (self.sender, self.receiver)
    }
    pub async fn send(&self, payload: &[u8], target: Option<Target>) -> io::Result<()> {
        self.sender.send(payload, target).await
    }
    pub async fn recv(&mut self) -> io::Result<Option<Packet>> {
        self.receiver.recv().await
    }
    pub async fn close(&self, error: bool) -> io::Result<()> {
        self.sender.close(error).await
    }
    /// TCP byte adapter. Mux End closes both directions (there is no wire
    /// half-close), matching Go session lifecycle. UDP must use packet methods.
    pub fn into_stream(self) -> io::Result<BoxStream> {
        if self.target.network != Network::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP Mux sessions require packet I/O",
            ));
        }
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let (sender, mut receiver) = self.split();
        let failure = Arc::new(Mutex::new(None));
        let task_failure = Arc::clone(&failure);
        let task = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(remote);
            let upload = async {
                let mut buffer = [0; wire::STREAM_CHUNK];
                loop {
                    let size = reader.read(&mut buffer).await?;
                    if size == 0 {
                        return Ok::<(), io::Error>(());
                    }
                    sender.send(&buffer[..size], None).await?;
                }
            };
            let download = async {
                while let Some(packet) = receiver.recv().await? {
                    writer.write_all(&packet.payload).await?;
                }
                writer.shutdown().await
            };
            let result = tokio::select! { result = upload => result, result = download => result };
            if let Err(error) = &result {
                // Prefer the actual peer/carrier failure over a secondary
                // BrokenPipe from a concurrently cancelled upload.
                let error = sender
                    .failure()
                    .unwrap_or_else(|| io::Error::new(error.kind(), error.to_string()));
                *task_failure.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some((error.kind(), error.to_string()));
            }
            // Publish errors before closing the duplex halves so a woken read
            // observes the error instead of mistaking the close for clean EOF.
            drop(reader);
            drop(writer);
            let _ = sender.close(result.is_err()).await;
        });
        Ok(Box::new(SessionByteStream {
            inner: local,
            failure,
            task,
        }))
    }
}

struct SessionByteStream {
    inner: DuplexStream,
    failure: Arc<Mutex<Option<Failure>>>,
    task: tokio::task::JoinHandle<()>,
}

impl SessionByteStream {
    fn failure(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(from_failure)
    }
}

impl AsyncRead for SessionByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => {
                Poll::Ready(self.failure().map_or(Ok(()), Err))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.failure().unwrap_or(error))),
            other => other,
        }
    }
}

impl AsyncWrite for SessionByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.failure() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.failure() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.failure() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for SessionByteStream {
    fn drop(&mut self) {
        // Cancels blocked queue/network operations and drops SessionReceiver,
        // whose lifecycle channel requests End without needing queue capacity.
        self.task.abort();
    }
}

#[derive(Clone)]
pub struct SessionSender {
    id: u16,
    network: Network,
    shared: Arc<Shared>,
    state: Arc<SessionState>,
}

impl SessionSender {
    fn failure(&self) -> Option<io::Error> {
        self.state
            .failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(from_failure)
            .or_else(|| self.shared.error())
    }
    pub async fn send(&self, payload: &[u8], target: Option<Target>) -> io::Result<()> {
        if self.state.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        if target
            .as_ref()
            .is_some_and(|target| self.network != Network::Udp || target.network != Network::Udp)
        {
            return Err(invalid("per-packet targets require a UDP Mux session"));
        }
        let limit = if self.network == Network::Udp {
            wire::MAX_PACKET
        } else {
            wire::STREAM_CHUNK
        };
        if self.network == Network::Udp && payload.len() > limit {
            return Err(invalid("Mux UDP packet exceeds 8192 bytes"));
        }
        if payload.is_empty() {
            return self.send_chunk(Vec::new(), target).await;
        }
        for chunk in payload.chunks(limit) {
            self.send_chunk(chunk.to_vec(), target.clone()).await?;
        }
        Ok(())
    }
    async fn send_chunk(&self, payload: Vec<u8>, target: Option<Target>) -> io::Result<()> {
        let (reply, receive) = oneshot::channel();
        self.shared
            .commands
            .send(Command::Send {
                id: self.id,
                payload,
                target,
                reply,
            })
            .await
            .map_err(|_| closed())?;
        receive
            .await
            .map_err(|_| self.shared.error().unwrap_or_else(closed))?
    }
    pub async fn close(&self, error: bool) -> io::Result<()> {
        if self.state.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let (reply, receive) = oneshot::channel();
        self.shared
            .commands
            .send(Command::Close {
                id: self.id,
                error,
                reply,
            })
            .await
            .map_err(|_| closed())?;
        receive.await.map_err(|_| closed())?
    }
}

pub struct SessionReceiver {
    id: u16,
    incoming: mpsc::Receiver<Packet>,
    shared: Arc<Shared>,
    state: Arc<SessionState>,
}

impl SessionReceiver {
    pub async fn recv(&mut self) -> io::Result<Option<Packet>> {
        if let Some(packet) = self.incoming.recv().await {
            return Ok(Some(packet));
        }
        if let Some(error) = self
            .state
            .failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(from_failure)
        {
            return Err(error);
        }
        match self.shared.error() {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }
}

impl Drop for SessionReceiver {
    fn drop(&mut self) {
        let _ = self.shared.closes.send(self.id);
    }
}

enum Command {
    Open {
        target: Target,
        options: OpenOptions,
        reply: oneshot::Sender<io::Result<Session>>,
    },
    Send {
        id: u16,
        payload: Vec<u8>,
        target: Option<Target>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Close {
        id: u16,
        error: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
}
struct Entry {
    target: Target,
    incoming: mpsc::Sender<Packet>,
    state: Arc<SessionState>,
}

fn session(frame: &Frame, shared: &Arc<Shared>, capacity: usize) -> io::Result<(Session, Entry)> {
    let target = frame
        .target
        .clone()
        .ok_or_else(|| invalid("session lacks target"))?;
    let (incoming, receiver) = mpsc::channel(capacity);
    let state = Arc::new(SessionState {
        closed: AtomicBool::new(false),
        failure: Mutex::new(None),
    });
    let sender = SessionSender {
        id: frame.session_id,
        network: target.network,
        shared: Arc::clone(shared),
        state: Arc::clone(&state),
    };
    let receiver = SessionReceiver {
        id: frame.session_id,
        incoming: receiver,
        shared: Arc::clone(shared),
        state: Arc::clone(&state),
    };
    let result = Session {
        id: frame.session_id,
        target: target.clone(),
        source: frame.source.clone(),
        local: frame.local.clone(),
        global_id: frame.global_id.filter(|id| *id != [0; 8]),
        sender,
        receiver,
    };
    Ok((
        result,
        Entry {
            target,
            incoming,
            state,
        },
    ))
}

fn remove_session(sessions: &mut HashMap<u16, Entry>, id: u16, error: bool, shared: &Shared) {
    if let Some(entry) = sessions.remove(&id) {
        entry.state.closed.store(true, Ordering::Release);
        if error {
            *entry
                .state
                .failure
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some((
                io::ErrorKind::ConnectionReset,
                "Mux peer ended session with error".into(),
            ));
        }
        shared.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn start(
    stream: BoxStream,
    role: Role,
    options: Options,
) -> io::Result<(Connection, mpsc::Receiver<Session>)> {
    if options.queue_capacity == 0
        || options.queue_capacity > 4096
        || options.max_connections > 65535
        || options.idle_interval.is_some_and(|d| d.is_zero())
    {
        return Err(invalid("invalid Mux carrier limits"));
    }
    let max_connections = if options.max_connections == 0 {
        65535
    } else {
        options.max_connections
    };
    let (commands, command_rx) = mpsc::channel(options.queue_capacity);
    let (closes, close_rx) = mpsc::unbounded_channel();
    let (accepted, accept_rx) = mpsc::channel(options.queue_capacity);
    let shared = Arc::new(Shared {
        commands,
        closes,
        cancel: CancellationToken::new(),
        active: AtomicUsize::new(0),
        total: AtomicUsize::new(0),
        failure: Mutex::new(None),
        max_concurrency: options.max_concurrency,
        max_connections,
    });
    let worker_shared = Arc::clone(&shared);
    tokio::spawn(async move {
        let result = run_carrier(
            stream,
            role,
            options,
            Arc::clone(&worker_shared),
            command_rx,
            close_rx,
            accepted,
        )
        .await;
        if let Err(error) = result {
            worker_shared.fail(error);
        } else {
            worker_shared.cancel.cancel();
        }
    });
    Ok((Connection { shared }, accept_rx))
}

async fn run_carrier(
    stream: BoxStream,
    role: Role,
    options: Options,
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<Command>,
    mut closes: mpsc::UnboundedReceiver<u16>,
    accepted: mpsc::Sender<Session>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frames, mut frame_rx) = mpsc::channel(options.queue_capacity);
    let (outgoing, mut output_rx) = mpsc::channel::<Frame>(options.queue_capacity);
    let reader_cancel = shared.cancel.clone();
    let mode = options.metadata_mode;
    let reader_task = tokio::spawn(async move {
        loop {
            let result = tokio::select! { _ = reader_cancel.cancelled() => return, result = read_frame(&mut reader, mode) => result };
            let terminal = !matches!(&result, Ok(Some(_)));
            if frames.send(result).await.is_err() || terminal {
                return;
            }
        }
    });
    let writer_shared = Arc::clone(&shared);
    let writer_task = tokio::spawn(async move {
        loop {
            let frame = tokio::select! { _ = writer_shared.cancel.cancelled() => break, frame = output_rx.recv() => frame };
            let Some(frame) = frame else {
                break;
            };
            let result = tokio::select! { _ = writer_shared.cancel.cancelled() => break, result = write_frame(&mut writer, &frame) => result };
            if let Err(error) = result {
                writer_shared.fail(error);
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    let mut sessions = HashMap::new();
    let interval = options
        .idle_interval
        .unwrap_or(Duration::from_secs(if role == Role::Client {
            16
        } else {
            60
        }));
    let mut idle = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut previous_count = 0;
    let mut previous_active = 0;
    let result: io::Result<()> = async {
        loop {
            tokio::select! {
                _ = shared.cancel.cancelled() => return Ok(()),
                _ = idle.tick() => {
                    let total = shared.total.load(Ordering::Acquire);
                    if sessions.is_empty() && previous_active == 0 && total == previous_count { return Ok(()); }
                    previous_count = total;
                    previous_active = sessions.len();
                }
                Some(id) = closes.recv() => {
                    if sessions.contains_key(&id) { remove_session(&mut sessions, id, false, &shared); enqueue(&outgoing, Frame::control(id, Status::End), &shared).await?; }
                }
                Some(command) = commands.recv() => {
                    match command {
                        Command::Open { target, options: open, reply } => {
                            if role != Role::Client { let _ = reply.send(Err(io::Error::new(io::ErrorKind::Unsupported, "Mux server cannot initiate New sessions"))); continue; }
                            let total = shared.total.load(Ordering::Acquire);
                            if total >= shared.max_connections || (shared.max_concurrency > 0 && sessions.len() >= shared.max_concurrency) { let _ = reply.send(Err(io::Error::new(io::ErrorKind::WouldBlock, "Mux carrier is full"))); continue; }
                            let mut frame = Frame::new((total + 1) as u16, target, open.initial_data);
                            frame.source = open.source; frame.local = open.local; frame.global_id = open.global_id;
                            if let Err(error) = validate_new(&frame, &options, false).and_then(|_| frame.encode().map(|_| ())) { let _ = reply.send(Err(error)); continue; }
                            let (session, entry) = session(&frame, &shared, options.queue_capacity)?;
                            let id = frame.session_id;
                            enqueue(&outgoing, frame, &shared).await?;
                            sessions.insert(id, entry); shared.active.fetch_add(1, Ordering::AcqRel); shared.total.fetch_add(1, Ordering::AcqRel);
                            if reply.send(Ok(session)).is_err() { remove_session(&mut sessions, id, false, &shared); enqueue(&outgoing, Frame::control(id, Status::End), &shared).await?; }
                        }
                        Command::Send { id, payload, target, reply } => {
                            if !sessions.contains_key(&id) { let _ = reply.send(Err(closed())); continue; }
                            let mut frame = Frame::control(id, Status::Keep); frame.target = target; frame.payload = Some(payload);
                            let result = enqueue(&outgoing, frame, &shared).await;
                            let terminal = result.is_err(); let _ = reply.send(result); if terminal { return Err(closed()); }
                        }
                        Command::Close { id, error, reply } => {
                            let result = if sessions.contains_key(&id) { remove_session(&mut sessions, id, error, &shared); let mut frame = Frame::control(id, Status::End); if error { frame.options = wire::OPTION_ERROR; } enqueue(&outgoing, frame, &shared).await } else { Ok(()) };
                            let terminal = result.is_err(); let _ = reply.send(result); if terminal { return Err(closed()); }
                        }
                    }
                }
                received = frame_rx.recv() => {
                    let frame = match received { Some(Ok(Some(frame))) => frame, Some(Err(error)) => return Err(error), _ => return Ok(()) };
                    let id = frame.session_id;
                    match frame.status {
                        Status::KeepAlive => {},
                        Status::New if role == Role::Client => {}, // Go client discards unsolicited New data.
                        Status::New => {
                            validate_new(&frame, &options, true)?;
                            if sessions.contains_key(&id) { return Err(invalid("duplicate active Mux session ID")); }
                            if shared.max_concurrency > 0 && sessions.len() >= shared.max_concurrency {
                                let mut end = Frame::control(id, Status::End); end.options = wire::OPTION_ERROR; enqueue(&outgoing, end, &shared).await?; continue;
                            }
                            let (session, entry) = session(&frame, &shared, options.queue_capacity)?;
                            let incoming = entry.incoming.clone();
                            sessions.insert(id, entry); shared.active.fetch_add(1, Ordering::AcqRel); shared.total.fetch_add(1, Ordering::AcqRel);
                            tokio::select! { _ = shared.cancel.cancelled() => return Ok(()), result = accepted.send(session) => { result.map_err(|_| closed())?; } }
                            if let Some(payload) = frame.payload { let packet = Packet { target: frame.target.filter(|target| target.network == Network::Udp), payload }; if !deliver(&incoming, packet, &shared).await? { remove_session(&mut sessions, id, false, &shared); enqueue(&outgoing, Frame::control(id, Status::End), &shared).await?; } }
                        }
                        Status::Keep => {
                            let Some(payload) = frame.payload else { continue; };
                            let Some(entry) = sessions.get(&id) else { enqueue(&outgoing, Frame::control(id, Status::End), &shared).await?; continue; };
                            if entry.target.network == Network::Udp && payload.len() > wire::MAX_PACKET { return Err(invalid("Mux UDP packet exceeds 8192 bytes")); }
                            if entry.target.network == Network::Tcp && frame.target.is_some() { return Err(invalid("UDP endpoint on TCP Mux session")); }
                            let incoming = entry.incoming.clone();
                            if !deliver(&incoming, Packet { target: frame.target, payload }, &shared).await? { remove_session(&mut sessions, id, false, &shared); enqueue(&outgoing, Frame::control(id, Status::End), &shared).await?; }
                        }
                        Status::End => remove_session(&mut sessions, id, frame.options & wire::OPTION_ERROR != 0, &shared),
                    }
                }
            }
        }
    }.await;
    for entry in sessions.values() {
        entry.state.closed.store(true, Ordering::Release);
    }
    shared.active.store(0, Ordering::Release);
    if let Err(error) = &result {
        shared.fail(io::Error::new(error.kind(), error.to_string()));
    } else {
        shared.cancel.cancel();
    }
    reader_task.abort();
    writer_task.abort();
    let _ = reader_task.await;
    let _ = writer_task.await;
    result
}

fn validate_new(frame: &Frame, options: &Options, incoming: bool) -> io::Result<()> {
    let target = frame
        .target
        .as_ref()
        .ok_or_else(|| invalid("New Mux frame requires a target"))?;
    if options
        .allowed_network
        .is_some_and(|network| network != target.network)
    {
        return Err(invalid("Mux target network is not permitted"));
    }
    if target.network == Network::Udp
        && frame
            .payload
            .as_ref()
            .is_some_and(|p| p.len() > wire::MAX_PACKET)
    {
        return Err(invalid("Mux UDP packet exceeds 8192 bytes"));
    }
    if incoming
        && frame.global_id.is_some_and(|id| id != [0; 8])
        && options.global_ids == GlobalIdPolicy::Reject
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "XUDP global ID requires an association-aware dispatcher",
        ));
    }
    Ok(())
}

async fn enqueue(output: &mpsc::Sender<Frame>, frame: Frame, shared: &Shared) -> io::Result<()> {
    tokio::select! { _ = shared.cancel.cancelled() => Err(closed()), result = output.send(frame) => result.map_err(|_| closed()) }
}
async fn deliver(
    output: &mpsc::Sender<Packet>,
    packet: Packet,
    shared: &Shared,
) -> io::Result<bool> {
    tokio::select! { _ = shared.cancel.cancelled() => Err(closed()), result = output.send(packet) => Ok(result.is_ok()) }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Mux session/carrier is closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(network: Network) -> Target {
        Target::new(network, "example.com", 443).unwrap()
    }
    #[tokio::test]
    async fn concurrent_sessions_are_isolated_and_end_releases_capacity() {
        let (a, b) = tokio::io::duplex(65536);
        let client = Connection::client(
            Box::new(a),
            Options {
                max_concurrency: 2,
                ..Options::default()
            },
        )
        .unwrap();
        let (server, mut incoming) = Connection::server(Box::new(b), Options::default()).unwrap();
        let mut first = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap();
        let mut second = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap();
        assert!(
            client
                .open(target(Network::Tcp), OpenOptions::default())
                .await
                .is_err()
        );
        let mut remote_first = incoming.recv().await.unwrap();
        let mut remote_second = incoming.recv().await.unwrap();
        first.send(b"one", None).await.unwrap();
        second.send(b"two", None).await.unwrap();
        assert_eq!(remote_first.recv().await.unwrap().unwrap().payload, b"one");
        assert_eq!(remote_second.recv().await.unwrap().unwrap().payload, b"two");
        remote_second.send(b"TWO", None).await.unwrap();
        remote_first.send(b"ONE", None).await.unwrap();
        assert_eq!(first.recv().await.unwrap().unwrap().payload, b"ONE");
        assert_eq!(second.recv().await.unwrap().unwrap().payload, b"TWO");
        first.close(false).await.unwrap();
        assert!(remote_first.recv().await.unwrap().is_none());
        let third = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(third.id, 3);
        client.close();
        server.close();
    }
    #[tokio::test]
    async fn udp_preserves_packet_boundaries_and_per_packet_targets() {
        let (a, b) = tokio::io::duplex(65536);
        let client = Connection::client(Box::new(a), Options::default()).unwrap();
        let (server, mut incoming) = Connection::server(Box::new(b), Options::default()).unwrap();
        let session = client
            .open(
                target(Network::Udp),
                OpenOptions {
                    initial_data: Some(b"first".to_vec()),
                    ..OpenOptions::default()
                },
            )
            .await
            .unwrap();
        let mut remote = incoming.recv().await.unwrap();
        assert_eq!(remote.recv().await.unwrap().unwrap().payload, b"first");
        let other = Target::new(Network::Udp, "8.8.8.8", 53).unwrap();
        session.send(b"second", Some(other.clone())).await.unwrap();
        let packet = remote.recv().await.unwrap().unwrap();
        assert_eq!(packet.target, Some(other));
        assert_eq!(packet.payload, b"second");
        assert!(session.send(&vec![0; 8193], None).await.is_err());
        client.close();
        server.close();
    }
    #[tokio::test]
    async fn native_tcp_adapter_relays_raw_bytes() {
        let (a, b) = tokio::io::duplex(65536);
        let client = Connection::client(Box::new(a), Options::default()).unwrap();
        let (server, mut incoming) = Connection::server(Box::new(b), Options::default()).unwrap();
        let mut local = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap()
            .into_stream()
            .unwrap();
        let mut remote = incoming.recv().await.unwrap().into_stream().unwrap();
        let payload = vec![0x97; 20_000];
        local.write_all(&payload).await.unwrap();
        let mut read = vec![0; payload.len()];
        remote.read_exact(&mut read).await.unwrap();
        assert_eq!(read, payload);
        remote.write_all(b"ok").await.unwrap();
        let mut reply = [0; 2];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        client.close();
        server.close();
    }

    #[tokio::test]
    async fn tcp_adapter_preserves_peer_error_and_graceful_end() {
        for error in [false, true] {
            let (a, b) = tokio::io::duplex(4096);
            let client = Connection::client(Box::new(a), Options::default()).unwrap();
            let (server, mut incoming) =
                Connection::server(Box::new(b), Options::default()).unwrap();
            let mut stream = client
                .open(target(Network::Tcp), OpenOptions::default())
                .await
                .unwrap()
                .into_stream()
                .unwrap();
            let remote = incoming.recv().await.unwrap();
            remote.close(error).await.unwrap();
            let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0]))
                .await
                .unwrap();
            if error {
                assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
                assert_eq!(
                    stream.write(b"late").await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
            } else {
                assert_eq!(read.unwrap(), 0);
            }
            client.close();
            server.close();
        }
    }

    #[tokio::test]
    async fn tcp_adapter_reports_invalid_carrier_frame_and_drop_releases_session() {
        let (a, mut raw) = tokio::io::duplex(4096);
        let client = Connection::client(Box::new(a), Options::default()).unwrap();
        let mut stream = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap()
            .into_stream()
            .unwrap();
        read_frame(&mut raw, MetadataMode::Ordinary)
            .await
            .unwrap()
            .unwrap();
        raw.write_all(&[0, 4, 0, 1, 99, 0]).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(stream);
        client.close();

        // No peer reads: the writer is blocked on the small carrier. Dropping
        // the adapter must still cancel its pump and remove the local session.
        let (a, _unread) = tokio::io::duplex(8);
        let client = Connection::client(Box::new(a), Options::default()).unwrap();
        let stream = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap()
            .into_stream()
            .unwrap();
        drop(stream);
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.active_connections() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        client.close();
    }
    #[tokio::test]
    async fn unknown_session_data_gets_end_and_bad_frames_close_carrier() {
        let (mut raw, b) = tokio::io::duplex(4096);
        let (server, _incoming) = Connection::server(Box::new(b), Options::default()).unwrap();
        let mut frame = Frame::control(42, Status::Keep);
        frame.payload = Some(vec![1]);
        write_frame(&mut raw, &frame).await.unwrap();
        let reply = read_frame(&mut raw, MetadataMode::Ordinary)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((reply.session_id, reply.status), (42, Status::End));
        raw.write_all(&[0, 4, 0, 1, 99, 0]).await.unwrap();
        assert!(server.closed().await.is_err());
    }
    #[tokio::test]
    async fn session_id_budget_does_not_wrap_and_drop_sends_end() {
        let (a, b) = tokio::io::duplex(4096);
        let client = Connection::client(
            Box::new(a),
            Options {
                max_connections: 1,
                ..Options::default()
            },
        )
        .unwrap();
        let (server, mut incoming) = Connection::server(Box::new(b), Options::default()).unwrap();
        let session = client
            .open(target(Network::Tcp), OpenOptions::default())
            .await
            .unwrap();
        let mut remote = incoming.recv().await.unwrap();
        drop(session);
        assert!(remote.recv().await.unwrap().is_none());
        assert!(
            client
                .open(target(Network::Tcp), OpenOptions::default())
                .await
                .is_err()
        );
        client.close();
        server.close();
    }
    #[test]
    fn xudp_id_matches_keyed_hash_and_source_eligibility() {
        let source = Target::new(Network::Udp, "2001:db8::1", 12345).unwrap();
        let key = [7; 32];
        let expected = blake3::keyed_hash(&key, b"udp:[2001:db8::1]:12345");
        assert_eq!(
            xudp_global_id(&key, true, "socks", &source),
            expected.as_bytes()[..8]
        );
        assert_eq!(xudp_global_id(&key, false, "socks", &source), [0; 8]);
        assert_eq!(xudp_global_id(&key, true, "http", &source), [0; 8]);
    }
}
