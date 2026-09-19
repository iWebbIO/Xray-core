use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, ToSocketAddrs},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_stream::{
    Stream,
    wrappers::{ReceiverStream, TcpListenerStream},
};
use tokio_util::sync::CancellationToken;
use tonic::{
    service::Routes,
    transport::{Server, server::Connected},
};

use crate::{features::StatsManager, transport::BoxStream};

use super::{StatsService, stats_routes};

/// Extensible gRPC router, independent of how clients reach the API.
#[derive(Clone)]
pub struct ApiServer {
    routes: Routes,
}

impl ApiServer {
    pub fn new(stats: Arc<StatsManager>) -> Self {
        Self::from_routes(stats_routes(StatsService::new(stats)))
    }

    /// Callers may register additional concrete services on `routes` first.
    pub fn from_routes(routes: Routes) -> Self {
        Self { routes }
    }

    pub fn into_routes(self) -> Routes {
        self.routes
    }

    /// Bind before spawning, so address/permission errors are reported now.
    pub async fn bind_tcp(self, address: impl ToSocketAddrs) -> io::Result<RunningApiServer> {
        let listener = TcpListener::bind(address).await?;
        let local_addr = listener.local_addr()?;
        Ok(self.spawn(TcpListenerStream::new(listener), Some(local_addr)))
    }

    /// An already bound listener allows the runtime to apply its socket policy.
    pub async fn serve_tcp(
        self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> Result<(), tonic::transport::Error> {
        self.serve_incoming(TcpListenerStream::new(listener), shutdown)
            .await
    }

    /// The caller owns Unix path creation/cleanup and abstract-socket handling.
    #[cfg(unix)]
    pub async fn serve_unix(
        self,
        listener: tokio::net::UnixListener,
        shutdown: CancellationToken,
    ) -> Result<(), tonic::transport::Error> {
        self.serve_incoming(
            tokio_stream::wrappers::UnixListenerStream::new(listener),
            shutdown,
        )
        .await
    }

    pub fn start_incoming(self, incoming: ApiIncoming) -> RunningApiServer {
        self.spawn(incoming, None)
    }

    /// Accept either system sockets or routed proxy streams. Each connection
    /// carries its own HTTP/2 session; the underlying transport is not guessed.
    pub async fn serve_incoming<I, IO, E>(
        self,
        incoming: I,
        shutdown: CancellationToken,
    ) -> Result<(), tonic::transport::Error>
    where
        I: Stream<Item = Result<IO, E>>,
        IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Server::builder()
            .add_routes(self.routes)
            .serve_with_incoming_shutdown(incoming, shutdown.cancelled_owned())
            .await
    }

    fn spawn<I, IO, E>(self, incoming: I, local_addr: Option<SocketAddr>) -> RunningApiServer
    where
        I: Stream<Item = Result<IO, E>> + Send + 'static,
        IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { self.serve_incoming(incoming, task_shutdown).await });
        RunningApiServer {
            local_addr,
            shutdown,
            task: Some(task),
        }
    }
}

/// Dropping this owner cancels and aborts its listener task. Explicit shutdown
/// allows in-flight RPCs to finish, while `stop` provides Go Server.Stop behavior.
pub struct RunningApiServer {
    local_addr: Option<SocketAddr>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl RunningApiServer {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Wait for server completion without requesting a shutdown.
    pub async fn wait(mut self) -> io::Result<()> {
        self.join().await
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.shutdown.cancel();
        self.join().await
    }

    pub fn stop(self) {
        // Drop handles cancellation and abort even when there are live clients.
    }

    async fn join(&mut self) -> io::Result<()> {
        // Keep the task inside self while awaiting. Cancelling this future then
        // drops self and aborts the task rather than detaching the listener.
        let result = self
            .task
            .as_mut()
            .expect("API task is present until joined")
            .await;
        self.task.take();
        result.map_err(io::Error::other)?.map_err(io::Error::other)
    }
}

impl Drop for RunningApiServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ApiConnectionInfo {
    pub peer_addr: Option<SocketAddr>,
}

/// Transport adapter for proxy-routed streams (the Go OutboundListener case).
pub struct ApiConnection {
    stream: BoxStream,
    info: ApiConnectionInfo,
}

impl ApiConnection {
    pub fn new(stream: BoxStream, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            stream,
            info: ApiConnectionInfo { peer_addr },
        }
    }
}

impl Connected for ApiConnection {
    type ConnectInfo = ApiConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for ApiConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ApiConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
}

pub type ApiIncoming = ReceiverStream<io::Result<ApiConnection>>;

#[derive(Clone)]
pub struct ApiStreamSender {
    sender: mpsc::Sender<io::Result<ApiConnection>>,
}

impl ApiStreamSender {
    /// A bounded queue applies backpressure, as the Go listener's buffer does.
    pub async fn accept(&self, stream: BoxStream, peer_addr: Option<SocketAddr>) -> io::Result<()> {
        self.sender
            .send(Ok(ApiConnection::new(stream, peer_addr)))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "management API listener closed")
            })
    }

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub async fn closed(&self) {
        self.sender.closed().await;
    }
}

pub fn incoming_channel(capacity: usize) -> io::Result<(ApiStreamSender, ApiIncoming)> {
    if capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "API incoming queue capacity must be positive",
        ));
    }
    let (sender, receiver) = mpsc::channel(capacity);
    Ok((ApiStreamSender { sender }, ReceiverStream::new(receiver)))
}
