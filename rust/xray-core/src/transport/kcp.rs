//! Native Xray KCP over UDP, with bounded reliability queues and byte-stream I/O.
//!
//! `connect` returns immediately, as Go's KCP dialer does. The first successful
//! `flush` confirms acknowledgement of all preceding writes. This is Xray's
//! bespoke KCP format, not stock ikcp. TLS may be composed around the returned
//! stream separately; this module explicitly rejects unimplemented wrappers.
pub mod session;
pub mod wire;
pub use session::{Config, Session, State};
mod adapter;
pub use adapter::connect_destination;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::UdpSocket,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{self, Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;

/// Integration must pass configured wrappers here instead of silently omitting
/// them. Native KCP currently accepts a bare UDP socket only.
#[derive(Clone, Debug, Default)]
pub struct StreamOptions {
    pub security: Option<String>,
    pub udp_masks: Vec<String>,
    pub socket_settings: bool,
    pub legacy_header: Option<String>,
    pub legacy_seed: Option<String>,
}
impl StreamOptions {
    pub fn validate(&self) -> io::Result<()> {
        if self
            .security
            .as_deref()
            .is_some_and(|s| !s.is_empty() && s != "none")
        {
            return Err(unsupported(
                "KCP security must be applied as an explicit outer stream wrapper",
            ));
        }
        if !self.udp_masks.is_empty() {
            return Err(unsupported("KCP UDP masks are not integrated"));
        }
        if self.socket_settings {
            return Err(unsupported("KCP custom socket settings are not integrated"));
        }
        if self
            .legacy_header
            .as_deref()
            .is_some_and(|s| !s.is_empty() && s != "none")
            || self.legacy_seed.as_deref().is_some_and(|s| !s.is_empty())
        {
            return Err(unsupported(
                "legacy KCP header/seed obfuscation is not implemented",
            ));
        }
        Ok(())
    }
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "KCP operation cancelled")
}
type Failure = (io::ErrorKind, String);
type Incoming = io::Result<Vec<wire::Segment>>;

#[derive(Default)]
struct Progress {
    written: u64,
    acknowledged: u64,
    write_closed: bool,
    stopped: bool,
    failure: Option<Failure>,
    flush_waker: Option<Waker>,
    eof_waker: Option<Waker>,
}
#[derive(Default)]
struct Shared(Mutex<Progress>);
impl Shared {
    fn update(&self, engine: &Session) {
        let wake = {
            let mut progress = self.0.lock().expect("KCP progress mutex poisoned");
            progress.acknowledged = engine.acknowledged_bytes();
            progress.write_closed = engine.state() != State::Active;
            if matches!(engine.state(), State::PeerClosed | State::PeerTerminating)
                && progress.acknowledged < progress.written
                && progress.failure.is_none()
            {
                progress.failure = Some((
                    io::ErrorKind::ConnectionReset,
                    "KCP peer closed before acknowledging all writes".into(),
                ));
            }
            progress.flush_waker.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
    fn finish(&self, error: Option<io::Error>) {
        let (flush_wake, eof_wake) = {
            let mut progress = self.0.lock().expect("KCP progress mutex poisoned");
            progress.stopped = true;
            progress.write_closed = true;
            if progress.failure.is_none() {
                progress.failure = error.map(|e| (e.kind(), e.to_string()));
            }
            if progress.failure.is_none() && progress.acknowledged < progress.written {
                progress.failure = Some((
                    io::ErrorKind::ConnectionReset,
                    "KCP stopped with unacknowledged writes".into(),
                ));
            }
            (progress.flush_waker.take(), progress.eof_waker.take())
        };
        if let Some(waker) = flush_wake {
            waker.wake();
        }
        if let Some(waker) = eof_wake {
            waker.wake();
        }
    }
    fn error(&self) -> Option<io::Error> {
        self.0
            .lock()
            .expect("KCP progress mutex poisoned")
            .failure
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }
}

/// A byte stream accepted by `crate::transport::BoxStream`. Shutdown is the
/// full-conversation close used by Xray KCP, not a TCP-style half close.
pub struct KcpStream {
    inner: DuplexStream,
    shared: Arc<Shared>,
    close: CancellationToken,
    cancel: CancellationToken,
    local: SocketAddr,
    peer: SocketAddr,
    conversation: u16,
    shutdown: bool,
}
impl KcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub fn conversation(&self) -> u16 {
        self.conversation
    }
    /// Immediately cancel pending I/O. Dropping normally attempts bounded close.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}
impl Drop for KcpStream {
    fn drop(&mut self) {
        self.close.cancel();
    }
}
impl AsyncRead for KcpStream {
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
                // The worker's pipe drops just before its completion handler
                // records failure. Never turn that race into successful EOF.
                let mut progress = self.shared.0.lock().expect("KCP progress mutex poisoned");
                if progress.stopped {
                    Poll::Ready(progress.failure.as_ref().map_or(Ok(()), |(kind, message)| {
                        Err(io::Error::new(*kind, message.clone()))
                    }))
                } else {
                    progress.eof_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.shared.error().unwrap_or(error))),
            other => other,
        }
    }
}
impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        {
            let progress = self.shared.0.lock().expect("KCP progress mutex poisoned");
            if let Some((kind, message)) = &progress.failure {
                return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
            }
            if self.shutdown || progress.write_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "KCP write side closed",
                )));
            }
        }
        match Pin::new(&mut self.inner).poll_write(cx, bytes) {
            Poll::Ready(Ok(count)) => {
                self.shared
                    .0
                    .lock()
                    .expect("KCP progress mutex poisoned")
                    .written += count as u64;
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.shared.error().unwrap_or(error))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut progress = self.shared.0.lock().expect("KCP progress mutex poisoned");
        if let Some((kind, message)) = &progress.failure {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if progress.acknowledged >= progress.written {
            return Poll::Ready(Ok(()));
        }
        if progress.stopped {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KCP stopped before flush completed",
            )));
        }
        progress.flush_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.shutdown = true;
                self.close.cancel();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

struct SessionIo {
    stream: DuplexStream,
    shared: Arc<Shared>,
    close: CancellationToken,
    cancel: CancellationToken,
}
fn make_stream(
    local: SocketAddr,
    peer: SocketAddr,
    conversation: u16,
    config: &Config,
    cancel: CancellationToken,
) -> (KcpStream, SessionIo) {
    let (inner, stream) = tokio::io::duplex(config.max_sending_window.clamp(config.mtu, 64 * 1024));
    let shared = Arc::new(Shared::default());
    let close = CancellationToken::new();
    (
        KcpStream {
            inner,
            shared: shared.clone(),
            close: close.clone(),
            cancel: cancel.clone(),
            local,
            peer,
            conversation,
            shutdown: false,
        },
        SessionIo {
            stream,
            shared,
            close,
            cancel,
        },
    )
}

struct Completion {
    shared: Arc<Shared>,
    cancel: CancellationToken,
    finished: bool,
}
impl Drop for Completion {
    fn drop(&mut self) {
        if !self.finished {
            self.shared.finish(Some(interrupted()));
        }
        self.cancel.cancel();
    }
}

async fn run_session(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    conversation: u16,
    config: Config,
    mut incoming: mpsc::Receiver<Incoming>,
    io: SessionIo,
) {
    let mut completion = Completion {
        shared: io.shared.clone(),
        cancel: io.cancel.clone(),
        finished: false,
    };
    let result = session_loop(socket, peer, conversation, config, &mut incoming, io).await;
    completion.shared.finish(result.err());
    completion.finished = true;
}

async fn session_loop(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    conversation: u16,
    config: Config,
    incoming: &mut mpsc::Receiver<Incoming>,
    io: SessionIo,
) -> io::Result<()> {
    let since = Instant::now();
    let now = || since.elapsed().as_millis() as u32;
    let mut engine = Session::new(conversation, config.clone(), 0)?;
    let (mut read, mut write) = tokio::io::split(io.stream);
    let mut ticker = time::interval(Duration::from_millis(u64::from(config.tti_ms)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut read_buffer = vec![0; config.mss()];
    let mut delivering: Option<(Vec<u8>, usize)> = None;
    let mut close_requested = false;
    let mut close_requested_at = None;
    let mut queued_bytes = 0u64;
    let mut reader_gone = false;
    loop {
        if io.cancel.is_cancelled() {
            return Err(interrupted());
        }
        if close_requested {
            let started = *close_requested_at.get_or_insert_with(now);
            if engine.state() == State::Active
                && now().wrapping_sub(started) >= config.close_timeout_ms
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "KCP close could not drain application writes",
                ));
            }
        }
        // Drop closes the application pipe, but all bytes previously accepted by
        // poll_write must reach the ARQ queue before advertising protocol close.
        if close_requested
            && engine.state() == State::Active
            && queued_bytes
                >= io
                    .shared
                    .0
                    .lock()
                    .expect("KCP progress mutex poisoned")
                    .written
        {
            engine.close(now());
        }
        io.shared.update(&engine);
        for packet in engine.poll(now())? {
            let count = tokio::select! {
                biased;
                _=io.cancel.cancelled()=>return Err(interrupted()),
                result=time::timeout(Duration::from_secs(5),socket.send_to(&packet,peer))=>result.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"KCP UDP send timeout"))??,
            };
            if count != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short KCP UDP send",
                ));
            }
        }
        io.shared.update(&engine);
        if delivering.is_none() {
            delivering = engine.pop_received().map(|bytes| (bytes, 0));
        }
        if reader_gone {
            while engine.pop_received().is_some() {}
            delivering = None;
        }
        if engine.state() == State::Terminated {
            return Ok(());
        }
        if engine.state() == State::PeerTerminating
            && delivering.is_none()
            && !engine.has_received()
        {
            engine.close(now());
            continue;
        }
        let may_read = engine.writable_bytes() >= config.mss();
        tokio::select! {
            _=io.cancel.cancelled()=>return Err(interrupted()),
            _=io.close.cancelled(),if !close_requested=>{ close_requested=true; },
            _=ticker.tick()=>{},
            packet=incoming.recv()=>match packet {
                Some(Ok(segments))=>engine.input(now(),segments)?,
                Some(Err(error))=>return Err(error),
                // Cancellation also closes the receive channel. Both branches
                // may be ready; retain local cancellation's Interrupted result
                // without biasing fairness among the main loop's I/O branches.
                None=>return Err(if io.cancel.is_cancelled() { interrupted() } else { io::Error::new(io::ErrorKind::ConnectionAborted,"KCP UDP receive loop stopped") }),
            },
            result=read.read(&mut read_buffer),if may_read=>{
                let count=result?;
                if count==0 { close_requested=true; engine.close(now()); }
                else if engine.queue(&read_buffer[..count])?!=count { return Err(io::Error::other("KCP adapter violated send capacity")); }
                else { queued_bytes+=count as u64; }
            },
            result=async { let (bytes,offset)=delivering.as_ref().expect("guarded delivery"); write.write(&bytes[*offset..]).await },if delivering.is_some()=>{
                match result {
                    Ok(0)=>return Err(io::Error::new(io::ErrorKind::WriteZero,"KCP application stream stopped accepting bytes")),
                    Ok(count)=>{ let (bytes,offset)=delivering.as_mut().expect("guarded delivery"); *offset+=count; if *offset==bytes.len() { delivering=None; } },
                    Err(error) if error.kind()==io::ErrorKind::BrokenPipe=>{ reader_gone=true; delivering=None; close_requested=true; },
                    Err(error)=>return Err(error),
                }
            }
        }
    }
}

/// Dial bare Xray KCP. Name resolution and security layering belong to the caller.
pub async fn connect(
    remote: SocketAddr,
    config: Config,
    options: StreamOptions,
) -> io::Result<KcpStream> {
    config.validate()?;
    options.validate()?;
    let bind = SocketAddr::new(
        if remote.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    socket.connect(remote).await?;
    let local = socket.local_addr()?;
    let conversation = rand::random::<u16>();
    let cancel = CancellationToken::new();
    let (stream, session_io) = make_stream(local, remote, conversation, &config, cancel.clone());
    let (sender, receiver) = mpsc::channel(config.datagram_queue);
    let reader_socket = socket.clone();
    let mtu = config.mtu;
    tokio::spawn(async move {
        // Receive the full UDP size so Windows does not turn an oversized
        // untrusted datagram into WSAEMSGSIZE and terminate the receive loop.
        let mut buffer = vec![0; 65_536];
        loop {
            let result = tokio::select! { _=cancel.cancelled()=>break,result=reader_socket.recv(&mut buffer)=>result };
            match result {
                Ok(count) => {
                    if let Ok(segments) = wire::decode_datagram(&buffer[..count], mtu)
                        && segments[0].conversation() == conversation
                    {
                        match sender.try_send(Ok(segments)) {
                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                }
                Err(error) => {
                    let _ = tokio::select! { _=cancel.cancelled()=>Ok(()),result=sender.send(Err(error))=>result };
                    break;
                }
            }
        }
    });
    tokio::spawn(run_session(
        socket,
        remote,
        conversation,
        config,
        receiver,
        session_io,
    ));
    Ok(stream)
}

pub struct KcpListener {
    local: SocketAddr,
    accepted: mpsc::Receiver<(KcpStream, SocketAddr)>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    failure: Arc<Mutex<Option<Failure>>>,
}
impl KcpListener {
    pub async fn bind(
        local: SocketAddr,
        config: Config,
        options: StreamOptions,
    ) -> io::Result<Self> {
        config.validate()?;
        options.validate()?;
        let socket = Arc::new(UdpSocket::bind(local).await?);
        let local = socket.local_addr()?;
        let (sender, accepted) = mpsc::channel(config.accept_backlog);
        let cancel = CancellationToken::new();
        let failure = Arc::new(Mutex::new(None));
        let task = tokio::spawn(listener_loop(
            socket,
            config,
            sender,
            cancel.clone(),
            failure.clone(),
        ));
        Ok(Self {
            local,
            accepted,
            cancel,
            task: Some(task),
            failure,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub async fn accept(&mut self) -> io::Result<(KcpStream, SocketAddr)> {
        self.accepted.recv().await.ok_or_else(|| {
            self.failure
                .lock()
                .expect("KCP listener mutex poisoned")
                .as_ref()
                .map_or_else(
                    || io::Error::new(io::ErrorKind::BrokenPipe, "KCP listener closed"),
                    |(kind, message)| io::Error::new(*kind, message.clone()),
                )
        })
    }
    /// Closing the listener also cancels accepted sessions and releases its socket.
    pub async fn close(mut self) -> io::Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.await.map_err(io::Error::other)?;
        }
        Ok(())
    }
}
impl Drop for KcpListener {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn listener_loop(
    socket: Arc<UdpSocket>,
    config: Config,
    accepted: mpsc::Sender<(KcpStream, SocketAddr)>,
    cancel: CancellationToken,
    failure: Arc<Mutex<Option<Failure>>>,
) {
    let local = match socket.local_addr() {
        Ok(local) => local,
        Err(error) => {
            *failure.lock().expect("KCP listener mutex poisoned") =
                Some((error.kind(), error.to_string()));
            return;
        }
    };
    let mut sessions: HashMap<(SocketAddr, u16), (u64, mpsc::Sender<Incoming>)> = HashMap::new();
    let mut generation = 0u64;
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65_536];
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            completed=tasks.join_next(),if !tasks.is_empty()=>{
                match completed {
                    Some(Ok((key,finished_generation)))=>{ if sessions.get(&key).is_some_and(|(active,_)| *active==finished_generation) { sessions.remove(&key); } },
                    Some(Err(_))=>sessions.retain(|_,(_,sender)|!sender.is_closed()),
                    None=>{},
                }
            },
            result=socket.recv_from(&mut buffer)=>{
                let (count,peer)=match result { Ok(result)=>result,Err(error)=>{ *failure.lock().expect("KCP listener mutex poisoned")=Some((error.kind(),error.to_string())); break; } };
                let segments=match wire::decode_datagram(&buffer[..count],config.mtu) { Ok(segments)=>segments,Err(_)=>continue };
                let conversation=segments[0].conversation(); let key=(peer,conversation);
                if let Some((_,sender))=sessions.get(&key) {
                    if let Err(mpsc::error::TrySendError::Closed(_))=sender.try_send(Ok(segments)) { sessions.remove(&key); }
                    continue;
                }
                if segments[0].is_terminate() || sessions.len()>=config.max_sessions { continue; }
                let permit=match accepted.try_reserve() { Ok(permit)=>permit,Err(_)=>continue };
                let (sender,receiver)=mpsc::channel(config.datagram_queue);
                let (stream,session_io)=make_stream(local,peer,conversation,&config,cancel.child_token());
                if sender.try_send(Ok(segments)).is_err() { continue; }
                generation=generation.wrapping_add(1); let this_generation=generation;
                sessions.insert(key,(this_generation,sender)); permit.send((stream,peer));
                let socket=socket.clone(); let config=config.clone();
                tasks.spawn(async move { run_session(socket,peer,conversation,config,receiver,session_io).await; (key,this_generation) });
            }
        }
    }
    cancel.cancel();
    sessions.clear();
    drop(accepted);
    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    fn local() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }
    fn quick() -> Config {
        Config {
            tti_ms: 5,
            idle_timeout_ms: 1000,
            terminate_linger_ms: 50,
            ..Config::default()
        }
    }

    #[test]
    fn duplex_eof_waits_for_failure_publication_and_drains_bytes_first() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountWake(AtomicUsize);
        impl std::task::Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut context = Context::from_waker(&waker);
        let (mut stream, worker) =
            make_stream(local(), local(), 1, &quick(), CancellationToken::new());
        let SessionIo {
            stream: mut pipe,
            shared,
            ..
        } = worker;
        assert!(matches!(
            Pin::new(&mut pipe).poll_write(&mut context, b"abc"),
            Poll::Ready(Ok(3))
        ));
        drop(pipe);
        let mut storage = [0; 8];
        let mut read = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut context, &mut read),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read.filled(), b"abc");
        read.clear();
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut context, &mut read)
                .is_pending()
        );
        shared.finish(Some(io::Error::new(
            io::ErrorKind::TimedOut,
            "deterministic worker failure",
        )));
        assert!(counter.0.load(Ordering::SeqCst) > 0);
        assert!(
            matches!(Pin::new(&mut stream).poll_read(&mut context, &mut read), Poll::Ready(Err(error)) if error.kind()==io::ErrorKind::TimedOut)
        );
    }
    #[tokio::test]
    async fn udp_client_server_stream_round_trip_and_flush() {
        time::timeout(Duration::from_secs(5), async {
            let mut listener = KcpListener::bind(local(), quick(), StreamOptions::default())
                .await
                .unwrap();
            let mut client = connect(listener.local_addr(), quick(), StreamOptions::default())
                .await
                .unwrap();
            let (mut server, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr());
            assert_eq!(server.conversation(), client.conversation());
            let payload: Vec<_> = (0..200_000).map(|i| i as u8).collect();
            let sent = payload.clone();
            let writer = tokio::spawn(async move {
                client.write_all(&sent).await.unwrap();
                client.flush().await.unwrap();
                client
            });
            let mut received = vec![0; payload.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            let mut client = writer.await.unwrap();
            server.write_all(b"pong").await.unwrap();
            server.flush().await.unwrap();
            let mut pong = [0; 4];
            client.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
            client.shutdown().await.unwrap();
            let mut tail = Vec::new();
            server.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
            listener.close().await.unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn unreachable_peer_flush_and_read_expose_timeout() {
        let blackhole = UdpSocket::bind(local()).await.unwrap();
        let config = Config {
            idle_timeout_ms: 60,
            ..quick()
        };
        let mut client = connect(
            blackhole.local_addr().unwrap(),
            config,
            StreamOptions::default(),
        )
        .await
        .unwrap();
        client.write_all(b"lost").await.unwrap();
        let error = time::timeout(Duration::from_secs(2), client.flush())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut byte = [0];
        assert_eq!(
            client.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[tokio::test]
    async fn cancellation_and_listener_close_wake_waiting_io() {
        time::timeout(Duration::from_secs(2), async {
            let mut listener = KcpListener::bind(local(), quick(), StreamOptions::default())
                .await
                .unwrap();
            let mut client = connect(listener.local_addr(), quick(), StreamOptions::default())
                .await
                .unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            client.cancel();
            let mut byte = [0];
            assert_eq!(
                client.read(&mut byte).await.unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );
            listener.close().await.unwrap();
            assert_eq!(
                server.read(&mut byte).await.unwrap_err().kind(),
                io::ErrorKind::Interrupted
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn receive_loop_shutdown_preserves_explicit_cancellation() {
        // The default current-thread runtime lets the test make both events
        // ready in one scheduler turn while the actor is already in select!.
        time::timeout(Duration::from_secs(5), async {
            for iteration in 0..33 {
                let cancelled = iteration != 0;
                let peer = UdpSocket::bind(local()).await.unwrap();
                let socket = Arc::new(UdpSocket::bind(local()).await.unwrap());
                let token = CancellationToken::new();
                let config = quick();
                let (mut stream, session_io) = make_stream(
                    socket.local_addr().unwrap(),
                    peer.local_addr().unwrap(),
                    7,
                    &config,
                    token.clone(),
                );
                let (sender, incoming) = mpsc::channel(1);
                let worker = tokio::spawn(run_session(
                    socket,
                    peer.local_addr().unwrap(),
                    7,
                    config,
                    incoming,
                    session_io,
                ));
                // An initial ping proves the actor is running. It then waits
                // for input; this yield avoids testing the initial cancel check.
                let mut ping = [0; 1350];
                let (_, source) = peer.recv_from(&mut ping).await.unwrap();
                assert_eq!(source, stream.local_addr());
                tokio::task::yield_now().await;
                if cancelled {
                    token.cancel();
                }
                drop(sender);
                let mut byte = [0];
                let result = stream.read(&mut byte).await;
                worker.await.unwrap();
                assert_eq!(
                    result.unwrap_err().kind(),
                    if cancelled {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::ConnectionAborted
                    },
                    "receive-loop close classification on iteration {iteration}"
                );
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn unsolicited_terminate_and_malformed_packets_do_not_create_sessions() {
        let mut listener = KcpListener::bind(local(), quick(), StreamOptions::default())
            .await
            .unwrap();
        let socket = UdpSocket::bind(local()).await.unwrap();
        let terminate = wire::Segment::Command {
            conv: 7,
            option: 0,
            command: wire::Command::Terminate,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 100,
        }
        .encode()
        .unwrap();
        socket
            .send_to(&terminate, listener.local_addr())
            .await
            .unwrap();
        socket
            .send_to(&[0, 1, 1, 0], listener.local_addr())
            .await
            .unwrap();
        socket
            .send_to(&vec![0; 4096], listener.local_addr())
            .await
            .unwrap();
        assert!(
            time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        let ping = wire::Segment::Command {
            conv: 8,
            option: 0,
            command: wire::Command::Ping,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 100,
        }
        .encode()
        .unwrap();
        socket.send_to(&ping, listener.local_addr()).await.unwrap();
        let (stream, _) = time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.conversation(), 8);
        listener.close().await.unwrap();
    }
    #[tokio::test]
    async fn unsupported_wrappers_fail_before_binding() {
        for options in [
            StreamOptions {
                security: Some("tls".into()),
                ..StreamOptions::default()
            },
            StreamOptions {
                udp_masks: vec!["srtp".into()],
                ..StreamOptions::default()
            },
            StreamOptions {
                socket_settings: true,
                ..StreamOptions::default()
            },
            StreamOptions {
                legacy_seed: Some("seed".into()),
                ..StreamOptions::default()
            },
        ] {
            let result = KcpListener::bind(local(), quick(), options).await;
            assert!(matches!(result,Err(error) if error.kind()==io::ErrorKind::Unsupported));
        }
    }

    #[tokio::test]
    async fn drop_drains_previously_accepted_bytes_before_close() {
        time::timeout(Duration::from_secs(3), async {
            let mut listener = KcpListener::bind(local(), quick(), StreamOptions::default())
                .await
                .unwrap();
            let mut client = connect(listener.local_addr(), quick(), StreamOptions::default())
                .await
                .unwrap();
            let payload = vec![42; 16_000];
            client.write_all(&payload).await.unwrap();
            drop(client);
            let (mut server, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            listener.close().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn expired_session_releases_listener_capacity() {
        time::timeout(Duration::from_secs(2), async {
            let config = Config { max_sessions: 1, idle_timeout_ms: 40, ..quick() };
            let mut listener = KcpListener::bind(local(), config, StreamOptions::default()).await.unwrap();
            let socket = UdpSocket::bind(local()).await.unwrap();
            let packet = |conv| wire::Segment::Command { conv, option: 0, command: wire::Command::Ping, sending_next: 0, receiving_next: 0, peer_rto: 100 }.encode().unwrap();
            socket.send_to(&packet(1), listener.local_addr()).await.unwrap();
            let (mut first, _) = listener.accept().await.unwrap();
            let mut byte = [0]; assert_eq!(first.read(&mut byte).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
            // Completion and datagram routing can race; retransmitting the opener
            // is the normal UDP recovery path when the old slot is still closing.
            let address = listener.local_addr();
            let send = async { loop { socket.send_to(&packet(2), address).await.unwrap(); time::sleep(Duration::from_millis(5)).await; } };
            let (second, _) = tokio::select! { result = listener.accept() => result.unwrap(), _ = send => unreachable!() };
            assert_eq!(second.conversation(), 2); listener.close().await.unwrap();
        }).await.unwrap();
    }
}
