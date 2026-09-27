// P15 mux_session: Go common/mux client.go/server.go/session.go scheduling over a BoxStream.
#![allow(dead_code)]
//! Mux.Cool session scheduling: `ClientSession` and `ServerSession` over a
//! `BoxStream`, porting Go's `common/mux/{client,server,session,writer,reader}.go`.
//!
//! Go behavior carried over exactly:
//! - Session IDs are `uint16`, allocated as `m.count++; s.ID = m.count`: strictly
//!   monotonic, never reused, and the budget is the *total* (`MaxConnection`),
//!   not the active count (`MaxConcurrency` bounds active streams only).
//! - Credit-based flow control uses Go's window constant
//!   `pipe.WithSizeLimit(64 * 1024)` from `client.go`'s `DialingWorkerFactory`:
//!   a stream may not have more than `window` bytes queued-but-unwritten on the
//!   carrier, and stream data is chunked at Go's `8 * 1024` (`writer.go`)
//!   per frame.
//! - Receiving `End` closes the stream in both directions (Go has no wire
//!   half-close); `OptionError` becomes `ConnectionReset`. Data already in
//!   flight is delivered before EOF.
//! - Dropping a stream handle sends `End` (Go `fetchInput`'s
//!   `defer writer.Close()`), so an abrupt cancel never corrupts other streams.
//! - Each stream's writes are serialized (Go runs one `fetchInput` goroutine
//!   per session), so concurrent writers on one stream cannot interleave
//!   their 8 KiB chunks.
//! - The server admits peer-opened streams unconditionally (Go
//!   `SessionManager.Add` checks nothing but manager closure):
//!   `max_concurrency` and `max_connections` bound client-initiated opens
//!   only, exactly like Go's `ClientStrategy`; a slow `accept` backpressures
//!   the carrier through the bounded queue instead.
//! - A graceful session close drains every queued frame to the wire before
//!   shutting the carrier stream down.
//! - Unsolicited `New` on a client is discarded, `Keep` data for an unknown
//!   session is answered with `End`, and a malformed frame fails the carrier.

use crate::{
    mux::wire::{self, Frame, MetadataMode, Network, OPTION_ERROR, STREAM_CHUNK, Status, Target},
    transport::BoxStream,
};
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

/// Go's pipe window: `pipe.WithSizeLimit(64 * 1024)` in common/mux/client.go.
pub const WINDOW: usize = 64 * 1024;
/// Go's `uint16` session IDs start at 1, so 65,535 IDs exist per carrier.
pub const MAX_CONNECTIONS: usize = 65_535;
/// Bounded frame/command queue depth for the carrier.
pub const QUEUE_CAPACITY: usize = 32;
/// Upper bound on how long a graceful close waits for its drain.
pub const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Go `ClientStrategy.MaxConcurrency`: active-stream bound on client
    /// opens. 0 = unlimited. Go's server `SessionManager.Add` admits
    /// peer-opened streams unconditionally, so this never gates acceptance.
    pub max_concurrency: usize,
    /// Go `ClientStrategy.MaxConnection`: total-stream budget (IDs are never
    /// reused, so this only grows). 0 = the full u16 ID space.
    pub max_connections: usize,
    /// Per-stream send window in bytes. Go's default is 64 KiB (pipe limit).
    pub window: usize,
    /// Bounded queue depth for commands, frames and accepted streams.
    pub queue_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 0,
            max_connections: 0,
            window: WINDOW,
            queue_capacity: QUEUE_CAPACITY,
        }
    }
}

impl SessionConfig {
    fn validated(&self) -> io::Result<(usize, usize)> {
        if self.window == 0 || self.window > 1 << 20 {
            return Err(invalid("Mux window must be within 1..=1048576 bytes"));
        }
        if self.queue_capacity == 0 || self.queue_capacity > 4096 {
            return Err(invalid("Mux queue capacity must be within 1..=4096"));
        }
        let max_connections = if self.max_connections == 0 {
            MAX_CONNECTIONS
        } else {
            self.max_connections
        };
        if max_connections > MAX_CONNECTIONS {
            return Err(invalid(
                "Mux connection budget exceeds the u16 session ID space",
            ));
        }
        Ok((max_connections, self.window))
    }
}

type Failure = (io::ErrorKind, String);

fn from_failure(failure: &Failure) -> io::Error {
    io::Error::new(failure.0, failure.1.clone())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Mux stream or carrier is closed")
}

/// Per-stream send credit, replenished by the carrier writer once a chunk has
/// been fully written to the wire. Chunks never exceed the window, so
/// `acquire` always makes progress.
struct Credit {
    available: Mutex<usize>,
    notify: Notify,
}

impl Credit {
    fn new(window: usize) -> Self {
        Self {
            available: Mutex::new(window),
            notify: Notify::new(),
        }
    }
    async fn acquire(self: &Arc<Self>, bytes: usize) -> CreditPermit {
        loop {
            {
                let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
                if *available >= bytes {
                    *available -= bytes;
                    break;
                }
            }
            self.notify.notified().await;
        }
        CreditPermit {
            credit: Arc::clone(self),
            bytes,
        }
    }
    fn release(&self, bytes: usize) {
        let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
        *available = available.saturating_add(bytes);
        drop(available);
        self.notify.notify_one();
    }
}

/// RAII grant of `bytes` of window credit. Dropping it returns the credit, so
/// every path (rejected command, failed write, cancelled write future,
/// completed write) replenishes exactly once.
struct CreditPermit {
    credit: Arc<Credit>,
    bytes: usize,
}

impl Drop for CreditPermit {
    fn drop(&mut self) {
        self.credit.release(self.bytes);
    }
}

struct StreamState {
    closed: AtomicBool,
    failure: Mutex<Option<Failure>>,
}

enum Item {
    Data(Vec<u8>),
    Eof(Option<Failure>),
}

enum Command {
    Open {
        target: Target,
        reply: oneshot::Sender<io::Result<MuxStream>>,
    },
    Send {
        id: u16,
        payload: Vec<u8>,
        permit: Option<CreditPermit>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Close {
        id: u16,
        error: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
}

struct Queued {
    frame: Frame,
    permit: Option<CreditPermit>,
}

struct Entry {
    incoming: mpsc::Sender<Item>,
    state: Arc<StreamState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Client,
    Server,
}

struct Core {
    commands: mpsc::Sender<Command>,
    lifecycle: mpsc::UnboundedSender<u16>,
    cancel: CancellationToken,
    active: AtomicUsize,
    total: AtomicUsize,
    failure: Mutex<Option<Failure>>,
    max_concurrency: usize,
    max_connections: usize,
    window: usize,
    writer_finished: AtomicBool,
    writer_done: Notify,
}

impl Core {
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

/// A single muxed stream. Writes are chunked at Go's 8 KiB frame size, bounded
/// by the per-stream credit window; reads deliver in-order chunks and `None`
/// on EOF (peer `End`, carrier shutdown or a local close).
pub struct MuxStream {
    pub id: u16,
    pub target: Target,
    core: Arc<Core>,
    state: Arc<StreamState>,
    credit: Arc<Credit>,
    /// Serializes whole `write` calls: Go pumps a session with a single
    /// `fetchInput` goroutine, so two concurrent writers on one stream must
    /// not interleave their 8 KiB chunks.
    write_lock: Arc<AsyncMutex<()>>,
    incoming: mpsc::Receiver<Item>,
}

impl MuxStream {
    fn failure(&self) -> Option<io::Error> {
        self.state
            .failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(from_failure)
            .or_else(|| self.core.error())
    }

    /// Writes `payload` as one or more `Keep` frames, blocking whenever the
    /// stream's window of not-yet-written bytes is exhausted (Go's pipe
    /// backpressure). Returns once every chunk is queued on the carrier.
    /// Whole calls are serialized, mirroring Go's single `fetchInput`
    /// goroutine per session, so concurrent writers cannot interleave.
    pub async fn write(&self, payload: &[u8]) -> io::Result<()> {
        if self.state.closed.load(Ordering::Acquire) {
            return Err(closed());
        }
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if self.target.network != Network::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Mux UDP streams require packet semantics",
            ));
        }
        let _serialized = self.write_lock.lock().await;
        if payload.is_empty() {
            // Go's Writer.WriteMultiBuffer with an empty buffer sends a
            // meta-only Keep frame.
            return self.send_chunk(Vec::new(), None).await;
        }
        let chunk = STREAM_CHUNK.min(self.core.window);
        for part in payload.chunks(chunk) {
            let permit = self.credit.acquire(part.len()).await;
            self.send_chunk(part.to_vec(), Some(permit)).await?;
        }
        Ok(())
    }

    async fn send_chunk(&self, payload: Vec<u8>, permit: Option<CreditPermit>) -> io::Result<()> {
        let (reply, receive) = oneshot::channel();
        self.core
            .commands
            .send(Command::Send {
                id: self.id,
                payload,
                permit,
                reply,
            })
            .await
            .map_err(|_| self.failure().unwrap_or_else(closed))?;
        receive
            .await
            .map_err(|_| self.failure().unwrap_or_else(closed))?
    }

    /// Reads the next in-order data chunk, or `None` on EOF. Buffered data is
    /// delivered before EOF; an error is reported only after it drains.
    pub async fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.incoming.recv().await {
            Some(Item::Data(data)) => Ok(Some(data)),
            Some(Item::Eof(Some(failure))) => Err(from_failure(&failure)),
            Some(Item::Eof(None)) => Ok(None),
            None => match self.failure() {
                Some(error) => Err(error),
                None => Ok(None),
            },
        }
    }

    /// Closes the stream, sending `End` (with `OptionError` when `error`).
    /// Receiving `End` closes both directions, matching Go: there is no wire
    /// half-close, and the peer drains in-flight data before EOF.
    pub async fn close(&self, error: bool) -> io::Result<()> {
        if self.state.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let (reply, receive) = oneshot::channel();
        self.core
            .commands
            .send(Command::Close {
                id: self.id,
                error,
                reply,
            })
            .await
            .map_err(|_| self.failure().unwrap_or_else(closed))?;
        receive.await.map_err(|_| closed())?
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        // Go fetchInput's `defer writer.Close()`: an abruptly cancelled stream
        // still notifies the peer with End, leaving other streams intact.
        let _ = self.core.lifecycle.send(self.id);
    }
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("id", &self.id)
            .field("target", &self.target)
            .finish()
    }
}

fn make_stream(id: u16, target: &Target, core: &Arc<Core>, capacity: usize) -> (MuxStream, Entry) {
    let (incoming, receiver) = mpsc::channel(capacity);
    let state = Arc::new(StreamState {
        closed: AtomicBool::new(false),
        failure: Mutex::new(None),
    });
    (
        MuxStream {
            id,
            target: target.clone(),
            core: Arc::clone(core),
            state: Arc::clone(&state),
            credit: Arc::new(Credit::new(core.window)),
            write_lock: Arc::new(AsyncMutex::new(())),
            incoming: receiver,
        },
        Entry { incoming, state },
    )
}

/// Go's ClientWorker over one carrier stream: opens streams with strictly
/// increasing IDs and demultiplexes the downlink.
pub struct ClientSession {
    core: Arc<Core>,
}

impl ClientSession {
    pub fn new(stream: BoxStream, config: SessionConfig) -> io::Result<Self> {
        let (core, _) = start(stream, Role::Client, config)?;
        Ok(Self { core })
    }

    /// Opens a stream to `target`. The ID is `count + 1`, monotonically
    /// increasing and never reused (Go `SessionManager.Allocate`).
    pub async fn open(&self, target: Target) -> io::Result<MuxStream> {
        if self.core.cancel.is_cancelled() {
            return Err(self.core.error().unwrap_or_else(closed));
        }
        let (reply, receive) = oneshot::channel();
        self.core
            .commands
            .send(Command::Open { target, reply })
            .await
            .map_err(|_| self.core.error().unwrap_or_else(closed))?;
        receive
            .await
            .map_err(|_| self.core.error().unwrap_or_else(closed))?
    }

    /// Go `ClientWorker.IsFull`: closing (total budget exhausted), closed, or
    /// at the active concurrency limit.
    pub fn is_full(&self) -> bool {
        self.is_closed()
            || self.core.total.load(Ordering::Acquire) >= self.core.max_connections
            || (self.core.max_concurrency > 0
                && self.core.active.load(Ordering::Acquire) >= self.core.max_concurrency)
    }

    /// Go `SessionManager.Size`: currently active streams.
    pub fn active_streams(&self) -> usize {
        self.core.active.load(Ordering::Acquire)
    }

    /// Go `SessionManager.Count` / `TotalConnections`: ever-allocated streams.
    pub fn total_streams(&self) -> usize {
        self.core.total.load(Ordering::Acquire)
    }

    pub fn is_closed(&self) -> bool {
        self.core.cancel.is_cancelled()
    }

    /// Graceful close: drain every queued frame to the wire (bounded by
    /// `CLOSE_DRAIN_TIMEOUT`), then shut the carrier stream down.
    pub async fn close(&self) -> io::Result<()> {
        close_core(&self.core).await
    }
}

/// Go's ServerWorker over one carrier stream: accepts streams opened by the
/// client and demultiplexes the uplink.
pub struct ServerSession {
    core: Arc<Core>,
    incoming: mpsc::Receiver<MuxStream>,
}

impl ServerSession {
    pub fn new(stream: BoxStream, config: SessionConfig) -> io::Result<Self> {
        let (core, incoming) = start(stream, Role::Server, config)?;
        Ok(Self { core, incoming })
    }

    /// Waits for the next client-opened stream. `None` means the carrier
    /// reached EOF or was closed; an error means the carrier failed (e.g. a
    /// malformed frame).
    pub async fn accept(&mut self) -> io::Result<Option<MuxStream>> {
        match self.incoming.recv().await {
            Some(stream) => Ok(Some(stream)),
            None => match self.core.error() {
                Some(error) => Err(error),
                None => Ok(None),
            },
        }
    }

    /// Go `ServerWorker.ActiveConnections`.
    pub fn active_streams(&self) -> usize {
        self.core.active.load(Ordering::Acquire)
    }

    pub fn total_streams(&self) -> usize {
        self.core.total.load(Ordering::Acquire)
    }

    pub fn is_closed(&self) -> bool {
        self.core.cancel.is_cancelled()
    }

    /// Graceful close, same drain-then-close as the client.
    pub async fn close(&self) -> io::Result<()> {
        close_core(&self.core).await
    }
}

fn start(
    stream: BoxStream,
    role: Role,
    config: SessionConfig,
) -> io::Result<(Arc<Core>, mpsc::Receiver<MuxStream>)> {
    let (max_connections, window) = config.validated()?;
    let (commands, command_rx) = mpsc::channel(config.queue_capacity);
    let (lifecycle, lifecycle_rx) = mpsc::unbounded_channel();
    let (frames, frame_rx) = mpsc::channel(config.queue_capacity);
    let (outgoing, outgoing_rx) = mpsc::channel(config.queue_capacity);
    let (accepted, accepted_rx) = mpsc::channel(config.queue_capacity);
    let core = Arc::new(Core {
        commands,
        lifecycle,
        cancel: CancellationToken::new(),
        active: AtomicUsize::new(0),
        total: AtomicUsize::new(0),
        failure: Mutex::new(None),
        max_concurrency: config.max_concurrency,
        max_connections,
        window,
        writer_finished: AtomicBool::new(false),
        writer_done: Notify::new(),
    });

    let (mut reader, mut writer) = tokio::io::split(stream);

    let reader_core = Arc::clone(&core);
    let reader_frames = frames;
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        loop {
            let result = tokio::select! {
                _ = reader_core.cancel.cancelled() => return,
                result = read_frame(&mut reader, &mut buffer) => result,
            };
            let terminal = !matches!(&result, Ok(Some(_)));
            if reader_frames.send(result).await.is_err() || terminal {
                return;
            }
        }
    });

    let writer_core = Arc::clone(&core);
    tokio::spawn(async move {
        let mut outgoing_rx = outgoing_rx;
        loop {
            let queued: Queued = tokio::select! {
                _ = writer_core.cancel.cancelled() => break,
                queued = outgoing_rx.recv() => match queued {
                    Some(queued) => queued,
                    None => break,
                },
            };
            if let Err(error) = write_frame(&mut writer, &queued.frame).await {
                writer_core.fail(error);
                break;
            }
            drop(queued.permit);
        }
        // Drain frames already queued before the close: a graceful session
        // close flushes pending stream data, like Go's writers pushing their
        // final frames through the same carrier pipe.
        while let Ok(queued) = outgoing_rx.try_recv() {
            if let Err(error) = write_frame(&mut writer, &queued.frame).await {
                writer_core.fail(error);
                break;
            }
            drop(queued.permit);
        }
        let _ = writer.shutdown().await;
        writer_core.writer_finished.store(true, Ordering::Release);
        writer_core.writer_done.notify_one();
    });

    let coord_core = Arc::clone(&core);
    tokio::spawn(async move {
        let result = coordinate(
            Arc::clone(&coord_core),
            role,
            command_rx,
            lifecycle_rx,
            frame_rx,
            outgoing,
            accepted,
            window,
        )
        .await;
        if let Err(error) = result
            && !coord_core.cancel.is_cancelled()
        {
            coord_core.fail(io::Error::new(error.kind(), error.to_string()));
        } else {
            coord_core.cancel.cancel();
        }
    });

    Ok((core, accepted_rx))
}

async fn close_core(core: &Arc<Core>) -> io::Result<()> {
    core.cancel.cancel();
    let deadline = tokio::time::Instant::now() + CLOSE_DRAIN_TIMEOUT;
    let drained = loop {
        if core.writer_finished.load(Ordering::Acquire) {
            break true;
        }
        let notified = core.writer_done.notified();
        if core.writer_finished.load(Ordering::Acquire) {
            break true;
        }
        match tokio::time::timeout_at(deadline, notified).await {
            Ok(()) => continue,
            Err(_) => break false,
        }
    };
    if !drained {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Mux close drain timed out",
        ));
    }
    match core.error() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn coordinate(
    core: Arc<Core>,
    role: Role,
    mut commands: mpsc::Receiver<Command>,
    mut lifecycle: mpsc::UnboundedReceiver<u16>,
    mut frames: mpsc::Receiver<io::Result<Option<Frame>>>,
    outgoing: mpsc::Sender<Queued>,
    accepted: mpsc::Sender<MuxStream>,
    window: usize,
) -> io::Result<()> {
    let mut sessions: HashMap<u16, Entry> = HashMap::new();
    // Go's u16 session-ID counter for locally opened streams.
    let mut count: u16 = 0;
    let chunk = STREAM_CHUNK.min(window);
    // The receive buffer holds about one window of undelivered chunks, which
    // mirrors Go's bounded session pipes: a slow reader backpressures the
    // carrier instead of buffering unboundedly.
    let receive_capacity = (window / chunk).max(1);

    let result: io::Result<()> = async {
        loop {
            tokio::select! {
                _ = core.cancel.cancelled() => return Ok(()),
                received = commands.recv() => {
                    let Some(command) = received else { return Ok(()) };
                    match command {
                        Command::Open { target, reply } => {
                            let result = open_stream(
                                &core, role, &mut sessions, &mut count, &target,
                                receive_capacity, &outgoing,
                            ).await;
                            let _ = reply.send(result);
                        }
                        Command::Send { id, payload, permit, reply } => {
                            if !sessions.contains_key(&id) {
                                // Write to a closed session fails like Go's
                                // closed pipe; the permit drops, releasing credit.
                                let _ = reply.send(Err(closed()));
                                continue;
                            }
                            let mut frame = Frame::control(id, Status::Keep);
                            if !payload.is_empty() {
                                frame.payload = Some(payload);
                            }
                            let result = enqueue(&outgoing, Queued { frame, permit }, &core).await;
                            let fatal = result.is_err();
                            let _ = reply.send(result);
                            if fatal {
                                return Err(closed());
                            }
                        }
                        Command::Close { id, error, reply } => {
                            let result = drop_stream(&mut sessions, &core, id, error, &outgoing).await;
                            let fatal = result.is_err();
                            let _ = reply.send(result);
                            if fatal { return Err(closed()); }
                        }
                    }
                }
                Some(id) = lifecycle.recv() => {
                    // A stream handle was dropped without an explicit close.
                    drop_stream(&mut sessions, &core, id, false, &outgoing).await?;
                }
                received = frames.recv() => {
                    let frame = match received {
                        Some(Ok(Some(frame))) => frame,
                        Some(Ok(None)) => return Ok(()),
                        Some(Err(error)) => return Err(error),
                        None => return Ok(()),
                    };
                    handle_frame(
                        &core, role, &mut sessions, frame, receive_capacity,
                        &outgoing, &accepted,
                    ).await?;
                }
            }
        }
    }
    .await;

    // Go SessionManager.Close: every remaining stream is interrupted; already
    // buffered data stays readable and then yields EOF.
    for entry in sessions.values() {
        entry.state.closed.store(true, Ordering::Release);
        let _ = entry.incoming.try_send(Item::Eof(None));
    }
    core.active.store(0, Ordering::Release);
    result
}

#[allow(clippy::too_many_arguments)]
async fn open_stream(
    core: &Arc<Core>,
    role: Role,
    sessions: &mut HashMap<u16, Entry>,
    count: &mut u16,
    target: &Target,
    receive_capacity: usize,
    outgoing: &mpsc::Sender<Queued>,
) -> io::Result<MuxStream> {
    if role == Role::Server {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only a Mux client initiates streams",
        ));
    }
    if target.network != Network::Tcp {
        // Go dispatches UDP through TransferTypePacket with XUDP; this
        // scheduler ports the stream (TCP) transfer type only.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Mux UDP/XUDP packet sessions are not supported by this scheduler",
        ));
    }
    if usize::from(*count) >= core.max_connections
        || (core.max_concurrency > 0 && sessions.len() >= core.max_concurrency)
    {
        // Go Allocate returns nil when closed, at the concurrency limit or at
        // the total connection budget.
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Mux session budget or concurrency limit reached",
        ));
    }
    let id = *count + 1;
    let frame = Frame::new(id, target.clone(), None);
    // Validate encoding before burning the ID on a malformed target.
    frame.encode()?;
    let (stream, entry) = make_stream(id, target, core, receive_capacity);
    enqueue(
        outgoing,
        Queued {
            frame,
            permit: None,
        },
        core,
    )
    .await?;
    sessions.insert(id, entry);
    core.active.fetch_add(1, Ordering::AcqRel);
    core.total.fetch_add(1, Ordering::AcqRel);
    *count = id;
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame(
    core: &Arc<Core>,
    role: Role,
    sessions: &mut HashMap<u16, Entry>,
    frame: Frame,
    receive_capacity: usize,
    outgoing: &mpsc::Sender<Queued>,
    accepted: &mpsc::Sender<MuxStream>,
) -> io::Result<()> {
    let id = frame.session_id;
    match frame.status {
        Status::KeepAlive => Ok(()),
        // Go's client handleStatusNew discards unsolicited New data.
        Status::New if role == Role::Client => Ok(()),
        Status::New => {
            let Some(target) = frame.target.clone() else {
                return Err(invalid("New Mux frame lacks a target"));
            };
            if sessions.contains_key(&id) {
                // Deliberate difference: Go's map overwrites the live session;
                // we fail the carrier instead of leaking the old stream.
                return Err(invalid("duplicate active Mux session ID"));
            }
            if target.network != Network::Tcp {
                let mut end = Frame::control(id, Status::End);
                end.options = OPTION_ERROR;
                let _ = enqueue(
                    outgoing,
                    Queued {
                        frame: end,
                        permit: None,
                    },
                    core,
                )
                .await;
                return Ok(());
            }
            // Go's SessionManager.Add gates nothing but manager closure: the
            // server admits peer-opened streams unconditionally (the strategy
            // bounds client opens only). A slow accept backpressures through
            // the bounded accepted-streams queue below.
            let (stream, entry) = make_stream(id, &target, core, receive_capacity);
            sessions.insert(id, entry);
            core.active.fetch_add(1, Ordering::AcqRel);
            core.total.fetch_add(1, Ordering::AcqRel);
            tokio::select! {
                _ = core.cancel.cancelled() => return Ok(()),
                result = accepted.send(stream) => {
                    result.map_err(|_| closed())?;
                }
            }
            if let Some(payload) = frame.payload {
                let Some(entry) = sessions.get(&id) else {
                    return Ok(());
                };
                let incoming = entry.incoming.clone();
                if !deliver(&incoming, Item::Data(payload), core).await? {
                    drop_stream(sessions, core, id, false, outgoing).await?;
                }
            }
            Ok(())
        }
        Status::Keep => {
            let Some(payload) = frame.payload else {
                return Ok(());
            };
            let Some(entry) = sessions.get(&id) else {
                // Go notifies the remote peer to close this session.
                let end = Frame::control(id, Status::End);
                enqueue(
                    outgoing,
                    Queued {
                        frame: end,
                        permit: None,
                    },
                    core,
                )
                .await?;
                return Ok(());
            };
            let incoming = entry.incoming.clone();
            if !deliver(&incoming, Item::Data(payload), core).await? {
                drop_stream(sessions, core, id, false, outgoing).await?;
            }
            Ok(())
        }
        Status::End => {
            if let Some(entry) = sessions.remove(&id) {
                entry.state.closed.store(true, Ordering::Release);
                let failure = if frame.options & OPTION_ERROR != 0 {
                    let failure = (
                        io::ErrorKind::ConnectionReset,
                        "Mux peer ended stream with error".to_string(),
                    );
                    *entry
                        .state
                        .failure
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = Some(failure.clone());
                    Some(failure)
                } else {
                    None
                };
                let _ = entry.incoming.try_send(Item::Eof(failure));
                core.active.fetch_sub(1, Ordering::AcqRel);
            }
            Ok(())
        }
    }
}

async fn drop_stream(
    sessions: &mut HashMap<u16, Entry>,
    core: &Arc<Core>,
    id: u16,
    error: bool,
    outgoing: &mpsc::Sender<Queued>,
) -> io::Result<()> {
    if let Some(entry) = sessions.remove(&id) {
        entry.state.closed.store(true, Ordering::Release);
        if error {
            *entry
                .state
                .failure
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some((
                io::ErrorKind::ConnectionReset,
                "Mux stream closed with error".to_string(),
            ));
        }
        core.active.fetch_sub(1, Ordering::AcqRel);
        let mut frame = Frame::control(id, Status::End);
        if error {
            frame.options = OPTION_ERROR;
        }
        enqueue(
            outgoing,
            Queued {
                frame,
                permit: None,
            },
            core,
        )
        .await?;
    }
    Ok(())
}

async fn deliver(incoming: &mpsc::Sender<Item>, item: Item, core: &Arc<Core>) -> io::Result<bool> {
    tokio::select! {
        _ = core.cancel.cancelled() => Err(closed()),
        result = incoming.send(item) => Ok(result.is_ok()),
    }
}

async fn enqueue(
    outgoing: &mpsc::Sender<Queued>,
    queued: Queued,
    core: &Arc<Core>,
) -> io::Result<()> {
    tokio::select! {
        _ = core.cancel.cancelled() => Err(closed()),
        result = outgoing.send(queued) => result.map_err(|_| closed()),
    }
}

/// Reads exactly one frame, accumulating partial bytes. `Ok(None)` is a clean
/// EOF between frames; a truncated frame is an error.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<Frame>> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((frame, consumed)) = wire::decode(buffer, MetadataMode::Ordinary)? {
            buffer.drain(..consumed);
            return Ok(Some(frame));
        }
        let size = reader.read(&mut chunk).await?;
        if size == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Mux.Cool frame",
            ));
        }
        buffer.extend_from_slice(&chunk[..size]);
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> io::Result<()> {
    writer.write_all(&frame.encode()?).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    const WAIT: Duration = Duration::from_secs(5);

    fn tcp_target() -> Target {
        Target::new(Network::Tcp, "127.0.0.1", 8080).unwrap()
    }

    #[test]
    fn go_window_and_budget_constants() {
        // Go's exact constants: pipe.WithSizeLimit(64 * 1024), 8 KiB stream
        // chunks (writer.go), and the u16 session-ID space.
        assert_eq!(SessionConfig::default().window, 64 * 1024);
        assert_eq!(STREAM_CHUNK, 8 * 1024);
        assert_eq!(MAX_CONNECTIONS, 65_535);
        assert_eq!(SessionConfig::default().queue_capacity, 32);
        assert_eq!(SessionConfig::default().max_concurrency, 0);
        assert!(
            SessionConfig {
                window: 0,
                ..SessionConfig::default()
            }
            .validated()
            .is_err()
        );
    }

    #[tokio::test]
    async fn concurrent_streams_echo_in_parallel() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let client = ClientSession::new(Box::new(client_side), SessionConfig::default()).unwrap();
        let mut server =
            ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();

        let mut streams = Vec::new();
        for i in 0..4u16 {
            let stream = timeout(WAIT, client.open(tcp_target()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stream.id, i + 1); // monotonically increasing, 1-based
            streams.push(stream);
        }
        assert_eq!(client.active_streams(), 4);
        assert_eq!(client.total_streams(), 4);

        let mut echo_tasks = Vec::new();
        for _ in 0..4 {
            let mut stream = timeout(WAIT, server.accept())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            // Go's `go handle(ctx, s, ...)`: one spawned task per stream.
            echo_tasks.push(tokio::spawn(async move {
                while let Some(data) = timeout(WAIT, stream.read()).await.unwrap().unwrap() {
                    let reply: Vec<u8> = data.iter().map(|b| !*b).collect();
                    timeout(WAIT, stream.write(&reply)).await.unwrap().unwrap();
                }
            }));
        }
        assert_eq!(server.active_streams(), 4);

        let mut client_tasks = Vec::new();
        for (i, mut stream) in streams.into_iter().enumerate() {
            let payload: Vec<u8> = (0..1000 + i * 7000).map(|j| (j % 251) as u8).collect();
            let expected: Vec<u8> = payload.iter().map(|b| !*b).collect();
            client_tasks.push(tokio::spawn(async move {
                timeout(WAIT, stream.write(&payload))
                    .await
                    .unwrap()
                    .unwrap();
                let mut seen = Vec::new();
                while seen.len() < expected.len() {
                    let chunk = timeout(WAIT, stream.read())
                        .await
                        .unwrap()
                        .unwrap()
                        .expect("stream EOF before echo completed");
                    seen.extend_from_slice(&chunk);
                }
                assert_eq!(seen, expected);
            }));
        }
        for task in client_tasks {
            timeout(WAIT, task).await.unwrap().unwrap();
        }

        client.close().await.unwrap();
        server.close().await.unwrap();
        for task in echo_tasks {
            timeout(WAIT, task).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn small_window_applies_flow_control_backpressure() {
        // Small window and deliberately shallow queues: with the server
        // application reading nothing, the whole chain (client credit window
        // 4096 + outgoing queue + duplex + server frame queue + receive queue)
        // absorbs well under 64 KiB, far below the 128 KiB payload, so the
        // client's write must block on exhausted credit no matter the timing.
        let config = SessionConfig {
            window: 4096,
            queue_capacity: 2,
            ..SessionConfig::default()
        };
        let (client_side, server_side) = tokio::io::duplex(8 * 1024);
        let client = ClientSession::new(Box::new(client_side), config).unwrap();
        let mut server = ServerSession::new(Box::new(server_side), config).unwrap();

        let stream = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        let mut remote = timeout(WAIT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let payload: Vec<u8> = (0..128 * 1024).map(|j| (j % 199) as u8).collect();
        let writer = tokio::spawn({
            let stream = stream;
            let payload = payload.clone();
            async move { stream.write(&payload).await }
        });

        // The remote reads nothing for a while: the write must be blocked,
        // because nothing in the chain can absorb 128 KiB.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!writer.is_finished());

        let mut seen = Vec::new();
        while seen.len() < payload.len() {
            let chunk = timeout(WAIT, remote.read())
                .await
                .unwrap()
                .unwrap()
                .expect("stream EOF before all data arrived");
            assert!(chunk.len() <= 4096, "chunks respect the small window bound");
            seen.extend_from_slice(&chunk);
        }
        assert_eq!(seen, payload);
        timeout(WAIT, writer).await.unwrap().unwrap().unwrap();

        client.close().await.unwrap();
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn half_close_delivers_data_then_eof_and_closes_both_ways() {
        let (client_side, server_side) = tokio::io::duplex(16 * 1024);
        let client = ClientSession::new(Box::new(client_side), SessionConfig::default()).unwrap();
        let mut server =
            ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();

        // Client half: local writes finish, End is sent, the peer drains all
        // in-flight data before EOF (Go has no wire half-close, so End also
        // invalidates the peer's write side, like Go's closed pipe).
        let stream = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        stream.write(b"hello").await.unwrap();
        stream.write(b" world").await.unwrap();
        stream.close(false).await.unwrap();
        let mut remote = timeout(WAIT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = timeout(WAIT, remote.read()).await.unwrap().unwrap() {
            collected.extend_from_slice(&chunk);
        }
        assert_eq!(collected, b"hello world");
        assert!(
            timeout(WAIT, remote.write(b"late")).await.unwrap().is_err(),
            "peer writes must fail after End, as with Go's closed session pipe"
        );

        // Server half: the server finishing sends End and the client drains
        // remaining data before EOF.
        let mut second = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        let second_remote = timeout(WAIT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        second_remote.write(b"reply").await.unwrap();
        second_remote.close(false).await.unwrap();
        let mut echoed = Vec::new();
        while let Some(chunk) = timeout(WAIT, second.read()).await.unwrap().unwrap() {
            echoed.extend_from_slice(&chunk);
        }
        assert_eq!(echoed, b"reply");
        assert!(second.write(b"late").await.is_err());

        client.close().await.unwrap();
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn abrupt_stream_cancel_leaves_other_streams_intact() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let client = ClientSession::new(Box::new(client_side), SessionConfig::default()).unwrap();
        let mut server =
            ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();

        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(
                timeout(WAIT, client.open(tcp_target()))
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let mut remotes = Vec::new();
        for _ in 0..3 {
            remotes.push(
                timeout(WAIT, server.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
            );
        }
        let mut echo_tasks = Vec::new();
        for remote in remotes.drain(..) {
            echo_tasks.push(tokio::spawn(async move {
                let mut remote = remote;
                while let Some(data) = timeout(WAIT, remote.read()).await.unwrap().unwrap() {
                    let reply: Vec<u8> = data.iter().map(|b| b ^ 0x5a).collect();
                    // The cancelled stream's peer-side writes fail once its End
                    // arrives (Go's closed session pipe); that is expected.
                    if timeout(WAIT, remote.write(&reply)).await.unwrap().is_err() {
                        break;
                    }
                }
            }));
        }

        // Abruptly cancel stream 2 mid-conversation: Drop sends End (Go's
        // deferred writer.Close), so its peer drains then sees EOF, while
        // streams 1 and 3 keep echoing untouched.
        let cancelled = streams.remove(1);
        let cancel_task = tokio::spawn(async move {
            cancelled.write(&vec![0x42; 20_000]).await.unwrap();
            drop(cancelled); // abrupt cancel without an explicit close
        });

        let mut verify_tasks = Vec::new();
        for mut stream in streams {
            verify_tasks.push(tokio::spawn(async move {
                let payload: Vec<u8> = (0..12_000).map(|j| (j % 253) as u8).collect();
                let expected: Vec<u8> = payload.iter().map(|b| b ^ 0x5a).collect();
                stream.write(&payload).await.unwrap();
                let mut seen = Vec::new();
                while seen.len() < expected.len() {
                    let chunk = timeout(WAIT, stream.read())
                        .await
                        .unwrap()
                        .unwrap()
                        .expect("sibling stream must survive the cancel");
                    seen.extend_from_slice(&chunk);
                }
                assert_eq!(seen, expected);
            }));
        }
        for task in verify_tasks {
            timeout(WAIT, task).await.unwrap().unwrap();
        }
        timeout(WAIT, cancel_task).await.unwrap().unwrap();

        client.close().await.unwrap();
        server.close().await.unwrap();
        for task in echo_tasks {
            timeout(WAIT, task).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn session_close_drains_pending_frames_before_shutdown() {
        let (client_side, server_side) = tokio::io::duplex(16 * 1024);
        let client = ClientSession::new(Box::new(client_side), SessionConfig::default()).unwrap();
        let mut server =
            ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();

        let stream = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        for _ in 0..3 {
            stream.write(&vec![0x33; 4096]).await.unwrap();
        }
        // The writes returned once the frames were queued, not written; the
        // graceful close must flush them to the wire before shutdown.
        timeout(WAIT, client.close()).await.unwrap().unwrap();

        let mut remote = timeout(WAIT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut seen = Vec::new();
        while let Some(chunk) = timeout(WAIT, remote.read()).await.unwrap().unwrap() {
            seen.extend_from_slice(&chunk);
        }
        assert_eq!(seen.len(), 3 * 4096);
        assert!(seen.iter().all(|b| *b == 0x33));
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn malformed_frame_fails_the_whole_carrier() {
        let (mut raw, server_side) = tokio::io::duplex(4096);
        let mut server =
            ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();
        // Unknown session status 99 (wire.rs golden invalid fixture).
        raw.write_all(&[0, 4, 0, 1, 99, 0]).await.unwrap();
        let error = timeout(WAIT, server.accept()).await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(server.close().await.is_err());
    }

    #[tokio::test]
    async fn udp_open_is_rejected_explicitly() {
        let (client_side, server_side) = tokio::io::duplex(4096);
        let client = ClientSession::new(Box::new(client_side), SessionConfig::default()).unwrap();
        let server = ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();
        let error = timeout(
            WAIT,
            client.open(Target::new(Network::Udp, "8.8.8.8", 53).unwrap()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("UDP"));
        client.close().await.unwrap();
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_ids_never_reuse_and_budget_is_total_not_active() {
        let (client_side, server_side) = tokio::io::duplex(4096);
        let client = ClientSession::new(
            Box::new(client_side),
            SessionConfig {
                max_connections: 2,
                ..SessionConfig::default()
            },
        )
        .unwrap();
        let server = ServerSession::new(
            Box::new(server_side),
            SessionConfig {
                max_connections: 2,
                ..SessionConfig::default()
            },
        )
        .unwrap();

        let first = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        let second = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((first.id, second.id), (1, 2));
        assert!(client.is_full());

        // Go's count never decreases: closing a stream frees concurrency but
        // not the total connection budget.
        timeout(WAIT, first.close(false)).await.unwrap().unwrap();
        assert_eq!(client.active_streams(), 1);
        assert!(
            timeout(WAIT, client.open(tcp_target()))
                .await
                .unwrap()
                .is_err()
        );
        client.close().await.unwrap();
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn unsolicited_new_discarded_and_unknown_keep_answered_with_end() {
        let (mut raw, client_half) = tokio::io::duplex(4096);
        let client = ClientSession::new(Box::new(client_half), SessionConfig::default()).unwrap();

        // Unsolicited New from the peer (Go's reverse direction): the client
        // drains and discards it, and it never burns a session ID.
        let unsolicited = Frame::new(7, tcp_target(), Some(b"stray".to_vec()));
        raw.write_all(&unsolicited.encode().unwrap()).await.unwrap();

        // KeepAlive frames are ignored, with or without data.
        let mut keepalive = Frame::control(0, Status::KeepAlive);
        keepalive.payload = Some(b"beat".to_vec());
        raw.write_all(&keepalive.encode().unwrap()).await.unwrap();

        // The carrier survived both: a normal open still gets ID 1.
        let stream = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.id, 1);

        let mut buffer = Vec::new();
        let opened = timeout(WAIT, read_frame(&mut raw, &mut buffer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!((opened.session_id, opened.status), (1, Status::New));

        // Keep data for an unknown session: Go answers with a plain End to
        // make the peer close it.
        let mut keep = Frame::control(9, Status::Keep);
        keep.payload = Some(b"orphan".to_vec());
        raw.write_all(&keep.encode().unwrap()).await.unwrap();
        let reply = timeout(WAIT, read_frame(&mut raw, &mut buffer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!((reply.session_id, reply.status), (9, Status::End));
        assert_eq!(reply.options, 0);

        stream.close(false).await.unwrap();
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn end_with_error_resets_after_drain_and_carrier_survives() {
        let (mut raw, client_half) = tokio::io::duplex(4096);
        let client = ClientSession::new(Box::new(client_half), SessionConfig::default()).unwrap();
        let mut stream = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();

        let mut buffer = Vec::new();
        let opened = timeout(WAIT, read_frame(&mut raw, &mut buffer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(opened.session_id, 1);

        let mut keep = Frame::control(1, Status::Keep);
        keep.payload = Some(b"payload".to_vec());
        raw.write_all(&keep.encode().unwrap()).await.unwrap();
        assert_eq!(
            timeout(WAIT, stream.read()).await.unwrap().unwrap(),
            Some(b"payload".to_vec())
        );

        // End with OptionError: buffered data drains first, then the stream
        // fails with ConnectionReset (Go's session is torn down; the OptionError
        // bit marks the failure).
        let mut end = Frame::control(1, Status::End);
        end.options = OPTION_ERROR;
        raw.write_all(&end.encode().unwrap()).await.unwrap();
        assert_eq!(
            timeout(WAIT, stream.read())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionReset
        );
        assert!(stream.write(b"late").await.is_err());

        // One stream ending never breaks the carrier: the next open gets the
        // next ID.
        let second = timeout(WAIT, client.open(tcp_target()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.id, 2);
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_writers_on_one_stream_do_not_interleave_chunks() {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let client = ClientSession::new(Box::new(client_side), SessionConfig::default()).unwrap();
        let mut server =
            ServerSession::new(Box::new(server_side), SessionConfig::default()).unwrap();

        let stream = Arc::new(
            timeout(WAIT, client.open(tcp_target()))
                .await
                .unwrap()
                .unwrap(),
        );
        let mut remote = timeout(WAIT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // Two concurrent writers on the same stream: each write is atomic
        // (Go's single fetchInput goroutine), so the peer must observe each
        // payload contiguously rather than interleaved 8 KiB chunks.
        let payload_a = vec![0x11u8; 20_000];
        let payload_b = vec![0x22u8; 20_000];
        let task_a = {
            let stream = Arc::clone(&stream);
            let payload = payload_a.clone();
            tokio::spawn(async move { stream.write(&payload).await })
        };
        let task_b = {
            let stream = Arc::clone(&stream);
            let payload = payload_b.clone();
            tokio::spawn(async move { stream.write(&payload).await })
        };
        timeout(WAIT, task_a).await.unwrap().unwrap().unwrap();
        timeout(WAIT, task_b).await.unwrap().unwrap().unwrap();

        let mut seen = Vec::new();
        while seen.len() < 40_000 {
            let chunk = timeout(WAIT, remote.read())
                .await
                .unwrap()
                .unwrap()
                .expect("stream EOF before all data arrived");
            seen.extend_from_slice(&chunk);
        }
        let (first, second) = seen.split_at(20_000);
        assert!(
            (first == payload_a && second == payload_b)
                || (first == payload_b && second == payload_a),
            "each writer's chunks must arrive contiguously"
        );
        client.close().await.unwrap();
        server.close().await.unwrap();
    }
}
