// P29 xdrive_stream: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]
//! The XDRIVE stream adapter: one bidirectional proxy stream per engine
//! session, following `transport/internet/xdrive/{conn,xdrive,params}.go`.
//!
//! [`XdriveSettings`] parses the `xdriveSettings` JSON object with the exact
//! keys, defaults, and validation of Go's `infra/conf.XDriveConfig`
//! (`transport_method.go`). [`XdriveStream::compile`] selects the storage
//! backend by `service`: `"local"` builds the local-disk backend (creating
//! and canonicalizing `remoteFolder`), `"template"` the explicit HTTP template
//! backend, and anything else fails by name — `"Google Drive"` is identified,
//! validates like Go's Build, and is then rejected as unimplemented by the
//! native engine.
//!
//! [`dial`] opens a fresh session per stream toward the target, exactly like
//! Go's `Dial`; the destination is advisory (Go's `Dial` ignores it too — the
//! shared object store is the actual channel). [`serve`] starts the engine's
//! acceptor like Go's `Serve` — no socket is bound and the address is
//! advisory; the listener polls the store for session announcements and
//! yields accepted sessions through [`XdriveListener::accept`]. Every stream
//! end reports Go's `placeholderAddr` ([`PLACEHOLDER_ADDR`]): the peer lives
//! behind the object store, not a socket.

use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    Config as EngineConfig, Connection, Listener as EngineListener, Params, Storage,
    dial as open_session,
};
use crate::{address::Destination, transport::BoxStream};

/// Go's `placeholderAddr`: both ends of every XDRIVE stream claim 127.0.0.1:0.
pub const PLACEHOLDER_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    0,
);

/// The `xdriveSettings` JSON object: the exact keys, defaults, and validation
/// of Go's `infra/conf.XDriveConfig` (`transport_method.go`).
///
/// Every numeric field defaults to 0 and every string to empty; the engine
/// maps 0 to Go's `paramsFromConfig` fallbacks (512 KiB segments, 20 ms flush,
/// 50/500 ms polling, 2 s eager window, 30 s hole timeout, 300 s session TTL,
/// concurrency 8). Unknown keys are rejected by name. Debug output is
/// redacted: `secrets` and the template may carry credentials.
#[derive(Clone, Default, PartialEq, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct XdriveSettings {
    pub remote_folder: String,
    pub service: String,
    pub secrets: Vec<String>,
    pub segment_bytes: u32,
    pub flush_interval_ms: u32,
    pub poll_interval_ms: u32,
    pub max_poll_interval_ms: u32,
    pub session_ttl_seconds: u32,
    pub concurrency: u32,
    pub eager_window_ms: u32,
    pub hole_timeout_ms: u32,
    pub template: Option<serde_json::Value>,
}

/// Redacted: `secrets` and `template` may carry credentials, so Debug shows
/// only their presence (like the engine's own Config, which derives none).
impl fmt::Debug for XdriveSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdriveSettings")
            .field("remote_folder", &self.remote_folder)
            .field("service", &self.service)
            .field("secrets", &self.secrets.len())
            .field("segment_bytes", &self.segment_bytes)
            .field("flush_interval_ms", &self.flush_interval_ms)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("max_poll_interval_ms", &self.max_poll_interval_ms)
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field("concurrency", &self.concurrency)
            .field("eager_window_ms", &self.eager_window_ms)
            .field("hole_timeout_ms", &self.hole_timeout_ms)
            .field("template", &self.template.is_some())
            .finish()
    }
}

impl XdriveSettings {
    /// Parse a `xdriveSettings` JSON value — the single entry point the config
    /// layer calls. Unknown keys fail with the offending key name.
    pub fn from_value(value: &serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value.clone())?)
    }

    /// Validate exactly like Go's `XDriveConfig.Build`: `"local"` is always
    /// valid, `"Google Drive"` needs exactly 3 secrets in the order ClientID,
    /// ClientSecret, RefreshToken (and is still rejected as unimplemented by
    /// [`XdriveStream::compile`]), `"template"` needs a `template` object, and
    /// any other service fails by name (Go's bare `unsupported service`).
    pub fn validate(&self) -> anyhow::Result<&Self> {
        match self.service.as_str() {
            "local" => {}
            "Google Drive" => anyhow::ensure!(
                self.secrets.len() == 3,
                "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken"
            ),
            "template" => anyhow::ensure!(
                self.template.as_ref().is_some_and(|value| !value.is_null()),
                "service \"template\" needs a \"template\" object"
            ),
            other => anyhow::bail!("unsupported xdrive service \"{other}\""),
        }
        Ok(self)
    }

    fn engine_config(&self) -> EngineConfig {
        EngineConfig {
            remote_folder: self.remote_folder.clone(),
            service: self.service.clone(),
            secrets: self.secrets.clone(),
            segment_bytes: self.segment_bytes,
            flush_interval_ms: self.flush_interval_ms,
            poll_interval_ms: self.poll_interval_ms,
            max_poll_interval_ms: self.max_poll_interval_ms,
            session_ttl_seconds: self.session_ttl_seconds,
            concurrency: self.concurrency,
            eager_window_ms: self.eager_window_ms,
            hole_timeout_ms: self.hole_timeout_ms,
            template: self.template.clone(),
        }
    }
}

/// A compiled XDRIVE transport end: the chosen storage backend plus the engine
/// parameters derived from the settings (Go's `paramsFromConfig`).
///
/// Every [`dial`] from one compiled end shares this storage instance, matching
/// Go's per-config shared template storage (Go's local backend is stateless,
/// so sharing it is equivalent). [`serve`] builds its own instance so that
/// closing a listener can never cancel streams opened through this end.
pub struct XdriveStream {
    config: EngineConfig,
    params: Params,
    storage: Arc<dyn Storage>,
}

impl XdriveStream {
    /// Compile the settings into a transport end. The `service` picks the
    /// backend: `"local"` creates and canonicalizes the `remoteFolder`,
    /// `"template"` parses and validates the HTTP template, `"Google Drive"`
    /// fails here as unimplemented, and any other service fails by name.
    /// Async because the engine's storage constructors are async.
    pub async fn compile(settings: &XdriveSettings) -> anyhow::Result<Self> {
        settings.validate()?;
        let config = settings.engine_config();
        let storage = config.storage().await?;
        let params = Params::from(&config);
        Ok(Self {
            config,
            params,
            storage,
        })
    }

    /// The engine parameters derived from the settings, with Go's
    /// `paramsFromConfig` fallbacks and caps applied.
    pub fn params(&self) -> Params {
        self.params
    }

    /// Cancel the shared dial-side storage backend. Go never closes the
    /// shared storage (its local and template `Close` are no-ops and the
    /// shared instances live for the process); this explicit close exists so
    /// the runtime can tear down in-flight HTTP template requests at
    /// shutdown. Local storage is unaffected.
    pub async fn close(&self) -> io::Result<()> {
        self.storage.close().await
    }
}

impl fmt::Debug for XdriveStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdriveStream")
            .field("service", &self.config.service)
            .field("remote_folder", &self.config.remote_folder)
            .field("params", &self.params)
            .finish()
    }
}

/// The outbound side: open one stream toward `target` through the engine — a
/// fresh session per stream, exactly like Go's `Dial`. The destination is
/// advisory: Go's `Dial` receives and ignores it, because the shared object
/// store is the actual channel. The returned stream reports
/// [`PLACEHOLDER_ADDR`] as its bound address.
pub async fn dial(
    stream: &XdriveStream,
    target: &Destination,
) -> anyhow::Result<(BoxStream, SocketAddr)> {
    let connection = open_session(Arc::clone(&stream.storage), stream.params).await?;
    tracing::debug!(session = connection.session_id(), target = %target, "opened XDRIVE session");
    Ok((Box::new(SessionConn::new(connection)), PLACEHOLDER_ADDR))
}

/// The inbound side: start the engine's acceptor for this transport end, like
/// Go's `Serve`. No socket is bound — the `address` is advisory and ignored
/// just as Go's `Serve` ignores its `net.Address`/`net.Port`; the returned
/// [`XdriveListener`] polls the shared object store for session
/// announcements. Dropping it stops accepting.
pub async fn serve(stream: &XdriveStream, address: SocketAddr) -> anyhow::Result<XdriveListener> {
    // Go's Serve builds its own storage (newStorage); a separate instance keeps
    // Listener::close from cancelling dials opened through `stream`.
    let storage = stream.config.storage().await?;
    let listener = EngineListener::new(storage, stream.params)?;
    tracing::debug!(%address, "XDRIVE listener accepting sessions from the object store");
    Ok(XdriveListener { listener })
}

/// The inbound acceptor returned by [`serve`]; Go's `xdrive.Listener`.
pub struct XdriveListener {
    listener: EngineListener,
}

impl XdriveListener {
    /// Wait for the next announced session and return it as a stream together
    /// with its source address ([`PLACEHOLDER_ADDR`], like Go's masked Conn
    /// addresses). Sessions queue up to the engine's channel capacity while
    /// no one is accepting.
    pub async fn accept(&mut self) -> io::Result<(BoxStream, SocketAddr)> {
        let connection = self.listener.accept().await?;
        tracing::debug!(session = connection.session_id(), "accepted XDRIVE session");
        Ok((Box::new(SessionConn::new(connection)), PLACEHOLDER_ADDR))
    }

    /// Go's `Listener.Addr`: the placeholder address.
    pub fn local_addr(&self) -> SocketAddr {
        PLACEHOLDER_ADDR
    }

    /// Stop accepting, abort the session polls, and close the listener's own
    /// storage (Go's `Listener.Close`).
    pub async fn close(self) -> io::Result<()> {
        self.listener.close().await
    }
}

/// One bidirectional proxy stream over an engine session; Go's `xdrive.Conn`.
///
/// Reads and writes are relayed through the session's WAL in both
/// directions. `shutdown` flushes published data and writes the `.end` marker
/// while leaving reads usable (Go's half-close, where the peer keeps
/// replying after EOF). Dropping the stream closes the session: inside a
/// tokio runtime the `.end` marker is written by a detached task, mirroring
/// Go's synchronous `Close`; outside a runtime the engine's own drop aborts
/// the session tasks without the marker.
struct SessionConn {
    connection: Option<Connection>,
    finished: bool,
}

impl SessionConn {
    fn new(connection: Connection) -> Self {
        Self {
            connection: Some(connection),
            finished: false,
        }
    }

    fn pinned(&mut self) -> Pin<&mut Connection> {
        Pin::new(
            self.connection
                .as_mut()
                .expect("the connection lives until drop"),
        )
    }
}

impl AsyncRead for SessionConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().pinned().poll_read(cx, buf)
    }
}

impl AsyncWrite for SessionConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().pinned().poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().pinned().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.pinned().poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.finished = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl Drop for SessionConn {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        if self.finished {
            // The .end marker is already published; dropping the connection
            // releases the engine's active-session claim.
            return;
        }
        // The runtime closes proxy streams by dropping them; Go's Close writes
        // the .end marker synchronously. Write it from a detached task so the
        // peer observes EOF instead of waiting out the session TTL.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = connection.close().await;
            });
        }
        // Without a runtime the engine's own Drop aborts the session tasks.
    }
}
