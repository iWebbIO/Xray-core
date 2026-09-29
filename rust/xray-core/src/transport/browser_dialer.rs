// P24 browser_dialer: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]

//! Browser dialer: a local WebSocket server that a browser (served the
//! embedded `dialer.html` page) connects to; when an outbound dial must go
//! through the browser, the dialer sends a JSON task frame over that
//! WebSocket and relays the bytes both ways.
//!
//! Port of Go's `transport/internet/browser_dialer` package. The dialer is
//! armed by the `xray.browser.dialer` / `XRAY_BROWSER_DIALER` environment
//! variable (Go's `platform.NewEnvFlag(platform.BrowserDialerAddress)`),
//! which carries the local listen address. Every successful `reload` mints a
//! fresh CSRF token (a UUID v4, like Go's `uuid.New()`), substitutes it for
//! the `csrfToken` placeholder in the embedded page, and only accepts
//! WebSocket upgrades on `/websocket?token=<csrf>` presenting exactly that
//! token. A dial task is the JSON frame `{"method","url","extra",
//! "streamResponse"}`; the browser answers with the literal text `ok` (any
//! other payload is the error text, like Go's `CheckOK`), after which the
//! WebSocket carries the relayed payload in both directions.
//!
//! The task response in this Go revision is the plain string `ok`/`fail`,
//! not a JSON `{id,error}` document; this port mirrors the source.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Context as _;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

/// Go's `transport/internet/browser_dialer/dialer.html`, copied verbatim
/// (CRLF line endings preserved, exactly like Go's `go:embed`). `reload`
/// substitutes the per-server CSRF token for the `csrfToken` placeholder.
const PAGE: &str = concat!(
    "<!DOCTYPE html>\r\n",
    "<html>\r\n",
    "<head>\r\n",
    "	<title>Browser Dialer</title>\r\n",
    "	<link rel=\"icon\" href=\"data:\">\r\n",
    "</head>\r\n",
    "<body>\r\n",
    "	<script>\r\n",
    "		\"use strict\";\r\n",
    "		// Enable a much more aggressive JIT for performance gains\r\n",
    "\r\n",
    "		// Copyright (c) 2021 XRAY. Mozilla Public License 2.0.\r\n",
    "		let url = \"ws://\" + window.location.host + \"/websocket?token=csrfToken\";\r\n",
    "		let clientIdleCount = 0;\r\n",
    "		let upstreamGetCount = 0;\r\n",
    "		let upstreamWsCount = 0;\r\n",
    "		let upstreamPostCount = 0;\r\n",
    "\r\n",
    "		function prepareRequestInit(extra) {\r\n",
    "			const requestInit = {};\r\n",
    "			if (extra.referrer) {\r\n",
    "				// note: we have to strip the protocol and host part.\r\n",
    "				// Browsers disallow that, and will reset the value to current page if attempted.\r\n",
    "				const referrer = URL.parse(extra.referrer);\r\n",
    "				requestInit.referrer = referrer.pathname + referrer.search + referrer.hash;\r\n",
    "				requestInit.referrerPolicy = \"unsafe-url\";\r\n",
    "			}\r\n",
    "\r\n",
    "			if (extra.headers) {\r\n",
    "				requestInit.headers = extra.headers;\r\n",
    "			}\r\n",
    "\r\n",
    "			if (extra.cookies) {\r\n",
    "				requestInit.credentials = 'include';\r\n",
    "			}\r\n",
    "\r\n",
    "			return requestInit;\r\n",
    "		}\r\n",
    "\r\n",
    "		function setCookiesFromTask(task) {\r\n",
    "			if (!task.extra.cookies) {\r\n",
    "				return;\r\n",
    "			}\r\n",
    "\r\n",
    "			const url = new URL(task.url);\r\n",
    "\r\n",
    "			for (const [name, value] of Object.entries(task.extra.cookies)) {\r\n",
    "				document.cookie = encodeURIComponent(name) + '=' + encodeURIComponent(value) + '; path=' + url.pathname;\r\n",
    "			}\r\n",
    "		}\r\n",
    "\r\n",
    "		function clearCookiesFromTask(task) {\r\n",
    "			if (!task.extra.cookies) {\r\n",
    "				return;\r\n",
    "			}\r\n",
    "\r\n",
    "			const url = new URL(task.url);\r\n",
    "\r\n",
    "			for (const [name, value] of Object.entries(task.extra.cookies)) {\r\n",
    "				document.cookie = encodeURIComponent(name) + '=; path=' + url.pathname + '; Max-Age=0';\r\n",
    "			}\r\n",
    "		}\r\n",
    "\r\n",
    "		let check = function () {\r\n",
    "			if (clientIdleCount > 0) {\r\n",
    "				return;\r\n",
    "			}\r\n",
    "			clientIdleCount += 1;\r\n",
    "			console.log(\"Prepare\", url);\r\n",
    "			let ws = new WebSocket(url);\r\n",
    "			// arraybuffer is significantly faster in chrome than default\r\n",
    "			// blob, tested with chrome 123\r\n",
    "			ws.binaryType = \"arraybuffer\";\r\n",
    "			// note: this event listener is later overwritten after the\r\n",
    "			// handshake has completed. do not attempt to modernize it without\r\n",
    "			// double-checking that this continues to work\r\n",
    "			ws.onmessage = function (event) {\r\n",
    "				clientIdleCount -= 1;\r\n",
    "				let task = JSON.parse(event.data);\r\n",
    "				if (task.method == \"WS\") {\r\n",
    "					upstreamWsCount += 1;\r\n",
    "					console.log(\"Dial WS\", task.url, task.extra.protocol);\r\n",
    "					const wss = new WebSocket(task.url, task.extra.protocol);\r\n",
    "					wss.binaryType = \"arraybuffer\";\r\n",
    "					let opened = false;\r\n",
    "					ws.onmessage = function (event) {\r\n",
    "						wss.send(event.data)\r\n",
    "					};\r\n",
    "					wss.onopen = function (event) {\r\n",
    "						opened = true;\r\n",
    "						ws.send(\"ok\")\r\n",
    "					};\r\n",
    "					wss.onmessage = function (event) {\r\n",
    "						ws.send(event.data)\r\n",
    "					};\r\n",
    "					wss.onclose = function (event) {\r\n",
    "						upstreamWsCount -= 1;\r\n",
    "						console.log(\"Dial WS DONE, remaining: \", upstreamWsCount);\r\n",
    "						ws.close()\r\n",
    "					};\r\n",
    "					wss.onerror = function (event) {\r\n",
    "						!opened && ws.send(\"fail\")\r\n",
    "						wss.close()\r\n",
    "					};\r\n",
    "					ws.onclose = function (event) {\r\n",
    "						wss.close()\r\n",
    "					};\r\n",
    "				}\r\n",
    "				else if (task.method == \"GET\" && task.streamResponse) {\r\n",
    "					(async () => {\r\n",
    "						const requestInit = prepareRequestInit(task.extra);\r\n",
    "\r\n",
    "						console.log(\"Dial GET\", task.url);\r\n",
    "						ws.send(\"ok\");\r\n",
    "						const controller = new AbortController();\r\n",
    "\r\n",
    "						/*\r\n",
    "						Aborting a streaming response in JavaScript\r\n",
    "						requires two levers to be pulled:\r\n",
    "\r\n",
    "						First, the streaming read itself has to be cancelled using\r\n",
    "						reader.cancel(), only then controller.abort() will actually work.\r\n",
    "\r\n",
    "						If controller.abort() alone is called while a\r\n",
    "						reader.read() is ongoing, it will block until the server closes the\r\n",
    "						response, the page is refreshed or the network connection is lost.\r\n",
    "						*/\r\n",
    "\r\n",
    "						let reader = null;\r\n",
    "						ws.onclose = (event) => {\r\n",
    "							try {\r\n",
    "								reader && reader.cancel();\r\n",
    "							} catch(e) {}\r\n",
    "\r\n",
    "							try {\r\n",
    "								controller.abort();\r\n",
    "							} catch(e) {}\r\n",
    "						};\r\n",
    "\r\n",
    "						try {\r\n",
    "							upstreamGetCount += 1;\r\n",
    "\r\n",
    "							requestInit.signal = controller.signal;\r\n",
    "							setCookiesFromTask(task);\r\n",
    "							const response = await fetch(task.url, requestInit);\r\n",
    "							clearCookiesFromTask(task);\r\n",
    "\r\n",
    "							const body = await response.body;\r\n",
    "							reader = body.getReader();\r\n",
    "\r\n",
    "							while (true) {\r\n",
    "								const { done, value } = await reader.read();\r\n",
    "								if (value) ws.send(value);  // don't send back \"undefined\" string when received nothing\r\n",
    "								if (done) break;\r\n",
    "							}\r\n",
    "						} finally {\r\n",
    "							upstreamGetCount -= 1;\r\n",
    "							console.log(\"Dial GET DONE, remaining: \", upstreamGetCount);\r\n",
    "							ws.close();\r\n",
    "						}\r\n",
    "					})();\r\n",
    "				}\r\n",
    "				else if (!task.streamResponse) {\r\n",
    "					upstreamPostCount += 1;\r\n",
    "\r\n",
    "					const requestInit = prepareRequestInit(task.extra);\r\n",
    "					requestInit.method = task.method;\r\n",
    "\r\n",
    "					console.log(\"Dial\", task.method, task.url);\r\n",
    "					ws.send(\"ok\");\r\n",
    "					ws.onmessage = async (event) => {\r\n",
    "						try {\r\n",
    "							if (event.data.byteLength > 0) {\r\n",
    "								requestInit.body = event.data;\r\n",
    "							}\r\n",
    "							setCookiesFromTask(task);\r\n",
    "							const response = await fetch(task.url, requestInit);\r\n",
    "							clearCookiesFromTask(task);\r\n",
    "							if (response.ok) {\r\n",
    "								ws.send(\"ok\");\r\n",
    "							} else {\r\n",
    "								console.error(\"bad status code\");\r\n",
    "								ws.send(\"fail\");\r\n",
    "							}\r\n",
    "						} finally {\r\n",
    "							upstreamPostCount -= 1;\r\n",
    "							console.log(\"Dial\", task.method, \"packet DONE, remaining: \", upstreamPostCount);\r\n",
    "							ws.close();\r\n",
    "						}\r\n",
    "					};\r\n",
    "				}\r\n",
    "				else {\r\n",
    "					console.error(`Incorrect task method=${task.method} streamResponse=${task.streamResponse}.`);\r\n",
    "					ws.close();\r\n",
    "				}\r\n",
    "\r\n",
    "				check();\r\n",
    "			};\r\n",
    "			ws.onerror = function (event) {\r\n",
    "				ws.close();\r\n",
    "			};\r\n",
    "		};\r\n",
    "		let checkTask = setInterval(check, 1000);\r\n",
    "	</script>\r\n",
    "</body>\r\n",
    "</html>\r\n",
);

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEADER_BYTES: usize = 8192;
const MAX_HEADERS: usize = 128;
const READ_CHUNK: usize = 16 * 1024;
const WRITE_CHUNK: usize = 64 * 1024;
const QUEUE_DEPTH: usize = 8;
/// Go's `conns` channel buffer.
const IDLE_CAPACITY: usize = 256;
/// gorilla's `upgrader.HandshakeTimeout`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

const ENV_NAME: &str = "xray.browser.dialer";
/// `platform.NormalizeEnvName(ENV_NAME)`.
const ENV_ALT_NAME: &str = "XRAY_BROWSER_DIALER";

const OP_CONTINUATION: u8 = 0;
const OP_TEXT: u8 = 1;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

/// Go's handler writes nothing for a token mismatch, so net/http replies
/// "200 OK" with an empty body; this mirrors that instead of leaking a 101.
const EMPTY_OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Whether the browser dialer is armed: the `XRAY_BROWSER_DIALER` env var
/// parsed like Go's `platform.NewEnvFlag(BrowserDialerAddress)` (empty/unset
/// means off). The primary `xray.browser.dialer` name wins over the
/// normalized `XRAY_BROWSER_DIALER` name, and a set-but-empty value disarms,
/// exactly like Go's empty address.
pub fn address() -> Option<String> {
    #[cfg(test)]
    if let Some(overridden) = test_address_override() {
        return overridden;
    }
    resolve_address(
        std::env::var(ENV_NAME).ok(),
        std::env::var(ENV_ALT_NAME).ok(),
    )
}

/// `platform.EnvFlag.GetValue` for the browser dialer address with the empty
/// default: a found-but-empty value disarms (Go returns `""`).
fn resolve_address(primary: Option<String>, alternate: Option<String>) -> Option<String> {
    primary
        .or(alternate)
        .and_then(|value| (!value.is_empty()).then_some(value))
}

/// `platform.NormalizeEnvName`: uppercase the trimmed name, then replace
/// dots with underscores.
fn normalize_env_name(name: &str) -> String {
    name.trim().to_ascii_uppercase().replace('.', "_")
}

struct SharedState {
    address: Option<String>,
    server: Option<ServerHandle>,
}

struct ServerHandle {
    id: u64,
    address: String,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    pool: Arc<ConnectionPool>,
    local: Option<std::net::SocketAddr>,
}

static STATE: Mutex<SharedState> = Mutex::new(SharedState {
    address: None,
    server: None,
});
/// Serializes `reload` swaps so address changes never interleave.
static RELOAD_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static NEXT_SERVER_ID: AtomicU64 = AtomicU64::new(0);
/// Live browser connections: idle in the pool or owned by a relayed stream.
static LIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

fn lock_state() -> MutexGuard<'static, SharedState> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Counts one live browser connection from the WebSocket upgrade until the
/// socket is closed, wherever it is owned.
struct LiveToken;

impl LiveToken {
    fn new() -> Arc<Self> {
        LIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Arc::new(LiveToken)
    }
}

impl Drop for LiveToken {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

struct IdleConnection {
    stream: TcpStream,
    prefix: Vec<u8>,
    guard: Arc<LiveToken>,
}

#[derive(Default)]
struct IdlePool {
    closed: bool,
    connections: VecDeque<IdleConnection>,
}

/// Connected browsers waiting for tasks (Go's `conns` channel).
struct ConnectionPool {
    idle: Mutex<IdlePool>,
}

impl ConnectionPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(IdlePool::default()),
        })
    }

    fn push(&self, connection: IdleConnection) -> bool {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.closed || idle.connections.len() >= IDLE_CAPACITY {
            return false;
        }
        idle.connections.push_back(connection);
        true
    }

    fn pop(&self) -> Option<IdleConnection> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.closed {
            return None;
        }
        idle.connections.pop_front()
    }

    /// Go drains and closes every queued connection when `Reload` swaps the
    /// dialer; in-flight tasks keep their sockets until they finish.
    fn close_all(&self) {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        idle.closed = true;
        idle.connections.clear();
    }

    #[cfg(test)]
    fn idle_len(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connections
            .len()
    }
}

/// Start (or restart) the dialer server on the armed address, exactly like
/// Go's `Reload()`: binds the WebSocket server serving the embedded page,
/// idempotent for the same address; shutting down cleanly on the token.
///
/// A same-address call while the server is live is a no-op (Go keeps the
/// running server). An address change closes the old server and every idle
/// browser connection, mints a fresh CSRF token, and binds the new server;
/// an empty address disarms the dialer. Unlike Go, which fires
/// `ListenAndServe` in a goroutine and ignores bind errors, the bind is
/// performed inline so failures surface to the caller.
pub async fn reload(cancel: CancellationToken) -> anyhow::Result<()> {
    let address = address();
    let _serialized = RELOAD_LOCK.lock().await;
    let previous = {
        let mut state = lock_state();
        // Go: if addr == currentAddr && (addr == "" || server != nil) return.
        let unchanged = state.address.as_deref() == address.as_deref()
            && (address.is_none() || state.server.is_some());
        if unchanged {
            return Ok(());
        }
        state.address = address.clone();
        state.server.take()
    };
    if let Some(previous) = previous {
        tracing::debug!(address = %previous.address, "browser dialer: stopping previous server");
        previous.cancel.cancel();
        let _ = tokio::time::timeout(STOP_TIMEOUT, previous.task).await;
        previous.pool.close_all();
    }
    let Some(address) = address else {
        tracing::debug!("browser dialer: disarmed");
        return Ok(());
    };
    let csrf_token = uuid::Uuid::new_v4().to_string();
    let page = Arc::new(PAGE.replace("csrfToken", &csrf_token));
    let listener = TcpListener::bind(&address)
        .await
        .with_context(|| format!("browser dialer: cannot bind {address}"))?;
    let local = listener.local_addr().ok();
    tracing::debug!(address = %address, ?local, "browser dialer: listening");
    let pool = ConnectionPool::new();
    let id = NEXT_SERVER_ID.fetch_add(1, Ordering::Relaxed) + 1;
    let task = tokio::spawn(accept_loop(
        listener,
        page,
        csrf_token,
        pool.clone(),
        cancel.clone(),
        id,
    ));
    lock_state().server = Some(ServerHandle {
        id,
        address,
        cancel,
        pool,
        task,
        local,
    });
    Ok(())
}

/// Whether at least one browser connection is live (Go's conns channel).
/// Connections count from the WebSocket upgrade until their socket closes;
/// an armed dialer with no browser yet reports false, so callers fall back
/// to their normal dial path instead of blocking like Go's `<-conns`.
pub fn has_browser() -> bool {
    LIVE_CONNECTIONS.load(Ordering::Relaxed) > 0
}

/// Dial one target through a connected browser (Go's `DialWS`): sends the
/// task frame, expects the response, and returns the relayed bidirectional
/// stream. Fails with a named error when no browser is connected or the
/// browser reports an error. Go blocks on an empty `conns` channel instead;
/// the fail-fast behavior is this port's contract.
pub async fn dial(url: &str) -> anyhow::Result<crate::transport::BoxStream> {
    let (pool, cancel) = {
        let state = lock_state();
        let Some(server) = state.server.as_ref() else {
            return Err(anyhow::anyhow!("browser dialer: no browser connected"));
        };
        (server.pool.clone(), server.cancel.clone())
    };
    let payload = serde_json::to_vec(&ws_task(url))
        .map_err(|error| anyhow::anyhow!("browser dialer: cannot encode task: {error}"))?;
    let connection = loop {
        let Some(next) = pool.pop() else {
            return Err(anyhow::anyhow!("browser dialer: no browser connected"));
        };
        let IdleConnection {
            mut stream,
            prefix,
            guard,
        } = next;
        // Go retries with the next queued connection when the write fails.
        if let Err(error) = write_frame(&mut stream, OP_TEXT, &payload).await {
            tracing::warn!(%error, "browser dialer: discarding stale browser connection");
            continue;
        }
        break IdleConnection {
            stream,
            prefix,
            guard,
        };
    };
    let IdleConnection {
        stream,
        prefix,
        guard,
    } = connection;
    let mut reader = PrefixedReader::new(stream, prefix);
    // Go's CheckOK: any payload other than the literal "ok" is the error.
    let response = read_message(&mut reader)
        .await
        .map_err(|error| anyhow::anyhow!("browser dialer: browser response failed: {error}"))?;
    let answer = String::from_utf8_lossy(&response);
    if answer != "ok" {
        return Err(anyhow::anyhow!(
            "browser dialer: browser reported: {answer}"
        ));
    }
    let (stream, prefix) = reader.into_parts();
    Ok(Box::new(BrowserStream::new(stream, prefix, guard, cancel)))
}

/// The dial task frame, in Go's field order: `{"method","url","extra",
/// "streamResponse"}`. `DialWS` always sets `extra` (an empty object when
/// there is no early-data protocol).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskFrame<'a> {
    method: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<serde_json::Value>,
    stream_response: bool,
}

fn ws_task(url: &str) -> TaskFrame<'_> {
    TaskFrame {
        method: "WS",
        url,
        extra: Some(serde_json::Value::Object(serde_json::Map::new())),
        stream_response: true,
    }
}

async fn accept_loop(
    listener: TcpListener,
    page: Arc<String>,
    csrf_token: String,
    pool: Arc<ConnectionPool>,
    cancel: CancellationToken,
    id: u64,
) {
    loop {
        let stream = tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    tracing::warn!(%error, "browser dialer: accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let page = page.clone();
        let csrf_token = csrf_token.clone();
        let pool = pool.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            handle_connection(stream, page, csrf_token, pool, cancel).await;
        });
    }
    // Go's Reload closes the queued connections when swapping servers; the
    // accept loop owns the same shutdown for its own cancellation.
    pool.close_all();
    let mut state = lock_state();
    if state.server.as_ref().is_some_and(|server| server.id == id) {
        state.server = None;
    }
}

/// Serves one HTTP request: the page for anything that is not exactly
/// `/websocket`, and the token-checked WebSocket upgrade for `/websocket`.
async fn handle_connection(
    mut stream: TcpStream,
    page: Arc<String>,
    csrf_token: String,
    pool: Arc<ConnectionPool>,
    cancel: CancellationToken,
) {
    if cancel.is_cancelled() {
        return;
    }
    let head = tokio::select! {
        _ = cancel.cancelled() => return,
        head = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head(&mut stream)) => match head {
            Ok(Ok(head)) => head,
            _ => return,
        },
    };
    let (head, tail) = head;
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    if !matches!(request.parse(&head), Ok(status) if status.is_complete()) {
        let _ = stream.write_all(error_response(400).as_bytes()).await;
        return;
    }
    let Some(target) = request.path else {
        let _ = stream.write_all(error_response(400).as_bytes()).await;
        return;
    };
    let path = target.split('?').next().unwrap_or_default();
    let decoded = match percent_decode(path, false) {
        Ok(decoded) => decoded,
        Err(_) => {
            let _ = stream.write_all(error_response(400).as_bytes()).await;
            return;
        }
    };
    if decoded != *b"/websocket" {
        let _ = serve_page(&mut stream, &page).await;
        return;
    }
    // The dialer secret: the query token must equal the UUID minted for this
    // server generation (Go compares it to its uuid.New() token).
    if query_value(target, "token").as_deref() != Some(csrf_token.as_str()) {
        let _ = stream.write_all(EMPTY_OK_RESPONSE.as_bytes()).await;
        let _ = stream.flush().await;
        return;
    }
    if request.method != Some("GET") {
        let _ = stream.write_all(error_response(405).as_bytes()).await;
        return;
    }
    if request.version != Some(1)
        || !has_token(request.headers, "Connection", "upgrade")
        || !has_token(request.headers, "Upgrade", "websocket")
    {
        let _ = stream.write_all(error_response(400).as_bytes()).await;
        return;
    }
    if !has_token(request.headers, "Sec-WebSocket-Version", "13") {
        let _ = stream.write_all(error_response(426).as_bytes()).await;
        return;
    }
    let Some(key) = header(request.headers, "Sec-WebSocket-Key") else {
        let _ = stream.write_all(error_response(400).as_bytes()).await;
        return;
    };
    if !matches!(STANDARD.decode(key), Ok(decoded) if decoded.len() == 16) {
        let _ = stream.write_all(error_response(400).as_bytes()).await;
        return;
    }
    let upgrade = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(key)
    );
    if stream.write_all(upgrade.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return;
    }
    let connection = IdleConnection {
        stream,
        prefix: tail,
        guard: LiveToken::new(),
    };
    if !pool.push(connection) {
        tracing::warn!("browser dialer: idle connection queue is full");
    }
}

async fn read_head(stream: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::with_capacity(1024);
    loop {
        if let Some(end) = data
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            if end > MAX_HEADER_BYTES {
                return Err(invalid_data(
                    "browser dialer HTTP headers exceed 8192 bytes",
                ));
            }
            let tail = data.split_off(end);
            return Ok((data, tail));
        }
        if data.len() >= MAX_HEADER_BYTES {
            return Err(invalid_data(
                "browser dialer HTTP headers exceed 8192 bytes",
            ));
        }
        let mut block = [0; 1024];
        let count = stream.read(&mut block).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF during browser dialer handshake",
            ));
        }
        data.extend_from_slice(&block[..count]);
    }
}

async fn serve_page(stream: &mut TcpStream, page: &str) -> io::Result<()> {
    // net/http sniffs the doctype into this content type and sets the
    // length; Access-Control-Allow-Origin comes from the Go handler.
    let head = format!(
        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        page.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(page.as_bytes()).await?;
    stream.flush().await
}

fn error_response(status: u16) -> String {
    let reason = match status {
        405 => "Method Not Allowed",
        426 => "Upgrade Required",
        _ => "Bad Request",
    };
    let version = if status == 426 {
        "Sec-WebSocket-Version: 13\r\n"
    } else {
        ""
    };
    format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n{version}\r\n")
}

fn header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .and_then(|header| std::str::from_utf8(header.value).ok())
}

fn has_token(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .any(|header| {
            header.value.split(|byte| *byte == b',').any(|value| {
                std::str::from_utf8(value)
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case(token))
            })
        })
}

fn accept_key(key: &str) -> String {
    let mut hash = Sha1::new();
    hash.update(key);
    hash.update(GUID);
    STANDARD.encode(hash.finalize())
}

fn percent_decode(input: &str, form: bool) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let hi = bytes.next().and_then(|byte| (byte as char).to_digit(16));
                let lo = bytes.next().and_then(|byte| (byte as char).to_digit(16));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
                    _ => return Err(invalid_input("invalid URL escape")),
                }
            }
            b'+' if form => out.push(b' '),
            _ => out.push(byte),
        }
    }
    Ok(out)
}

/// `r.URL.Query().Get` for one field: the first matching pair with
/// query-form percent decoding.
fn query_value(target: &str, name: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Ok(key) = percent_decode(key, true) else {
            continue;
        };
        if key == name.as_bytes() {
            let value = percent_decode(value, true).ok()?;
            return Some(String::from_utf8_lossy(&value).into_owned());
        }
    }
    None
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

/// A reader that drains a buffered prefix (bytes read past the HTTP head)
/// before touching the socket.
struct PrefixedReader<R> {
    inner: R,
    prefix: Vec<u8>,
    offset: usize,
}

impl<R> PrefixedReader<R> {
    fn new(inner: R, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }

    fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    fn into_parts(self) -> (R, Vec<u8>) {
        let remaining = self.prefix[self.offset..].to_vec();
        (self.inner, remaining)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = buf.remaining().min(self.prefix.len() - self.offset);
            buf.put_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[derive(Debug)]
struct FrameHeader {
    fin: bool,
    opcode: u8,
    len: u64,
    mask: [u8; 4],
}

/// Reads one frame header. The browser is the WebSocket client, so every
/// incoming frame must be masked, like Go's gorilla server.
async fn read_frame_header<R: AsyncRead + Unpin>(
    reader: &mut PrefixedReader<R>,
) -> io::Result<FrameHeader> {
    let mut head = [0; 2];
    reader.read_exact(&mut head).await?;
    let fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    if head[0] & 0x70 != 0 || !masked {
        return Err(invalid_data(
            "invalid browser dialer WebSocket reserved bits or mask direction",
        ));
    }
    let short = head[1] & 0x7f;
    let mut len = u64::from(short);
    if short == 126 {
        let mut bytes = [0; 2];
        reader.read_exact(&mut bytes).await?;
        len = u16::from_be_bytes(bytes).into();
        if len < 126 {
            return Err(invalid_data("nonminimal browser dialer WebSocket length"));
        }
    } else if short == 127 {
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes).await?;
        len = u64::from_be_bytes(bytes);
        if len < 65536 || len > i64::MAX as u64 {
            return Err(invalid_data(
                "invalid browser dialer WebSocket 64-bit length",
            ));
        }
    }
    let mut mask = [0; 4];
    reader.read_exact(&mut mask).await?;
    match opcode {
        0..=2 => {}
        8..=10 if fin && len <= 125 => {}
        _ => {
            return Err(invalid_data(
                "invalid browser dialer WebSocket opcode or control frame",
            ));
        }
    }
    Ok(FrameHeader {
        fin,
        opcode,
        len,
        mask,
    })
}

fn unmask(data: &mut [u8], offset: usize, mask: [u8; 4]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[(offset + index) % 4];
    }
}

fn validate_close(data: &[u8]) -> io::Result<Option<u16>> {
    if data.is_empty() {
        return Ok(None);
    }
    if data.len() == 1 {
        return Err(invalid_data("one-byte WebSocket close payload"));
    }
    let code = u16::from_be_bytes([data[0], data[1]]);
    if !(matches!(code, 1000..=1003 | 1007..=1014) || (3000..=4999).contains(&code)) || code == 1015
    {
        return Err(invalid_data("invalid WebSocket close status"));
    }
    std::str::from_utf8(&data[2..]).map_err(invalid_data)?;
    Ok(Some(code))
}

/// A frame written by the dialer: the Xray side is the server, so frames
/// are unmasked, like gorilla's server writes.
fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    match payload.len() {
        length @ 0..=125 => frame.push(length as u8),
        length @ 126..=65535 => {
            frame.push(126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    writer.write_all(&server_frame(opcode, payload)).await?;
    writer.flush().await
}

/// Reads one complete message (Go's `conn.ReadMessage`), answering pings
/// with pongs and rejecting close frames like Go's read error.
async fn read_message<R: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut PrefixedReader<R>,
) -> io::Result<Vec<u8>> {
    let mut message = Vec::new();
    let mut fragmented = false;
    loop {
        let header = read_frame_header(reader).await?;
        if header.opcode >= OP_CLOSE {
            let mut data = vec![0; header.len as usize];
            reader.read_exact(&mut data).await?;
            unmask(&mut data, 0, header.mask);
            match header.opcode {
                OP_CLOSE => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "browser closed the WebSocket",
                    ));
                }
                OP_PING => {
                    write_frame(reader.inner_mut(), OP_PONG, &data).await?;
                }
                _ => {}
            }
            continue;
        }
        match (header.opcode, fragmented) {
            (OP_CONTINUATION, true) => {}
            (OP_TEXT | OP_BINARY, false) => fragmented = true,
            _ => {
                return Err(invalid_data(
                    "invalid browser dialer WebSocket continuation",
                ));
            }
        }
        let mut remaining = header.len;
        let mut offset = 0usize;
        while remaining != 0 {
            let count = remaining.min(READ_CHUNK as u64) as usize;
            let mut chunk = vec![0; count];
            reader.read_exact(&mut chunk).await?;
            unmask(&mut chunk, offset, header.mask);
            offset = (offset + count) % 4;
            remaining -= count as u64;
            message.extend_from_slice(&chunk);
        }
        if header.fin {
            return Ok(message);
        }
    }
}

#[derive(Clone)]
struct SavedError {
    kind: io::ErrorKind,
    message: String,
}

impl SavedError {
    fn new(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

type ErrorSlot = Arc<Mutex<Option<SavedError>>>;

fn set_error(slot: &ErrorSlot, error: &io::Error) {
    let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(SavedError::new(error));
    }
}

enum Command {
    Binary(Vec<u8>),
    Pong(Vec<u8>),
    Flush(oneshot::Sender<io::Result<()>>),
    Close(Vec<u8>, Option<oneshot::Sender<io::Result<()>>>),
}

enum FrameFlow {
    Continue,
    Closed,
}

/// Reads relayed frames from the browser, forwarding data chunks to the
/// stream and answering control frames, until the connection ends or the
/// server is cancelled.
async fn relay_reader(
    mut reader: PrefixedReader<ReadHalf<TcpStream>>,
    incoming: mpsc::Sender<Vec<u8>>,
    mut outgoing: mpsc::Sender<Command>,
    cancel: CancellationToken,
    errors: ErrorSlot,
) {
    let mut fragmented = false;
    let outcome = loop {
        let served = tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            served = serve_frame(&mut reader, &mut fragmented, &mut outgoing, &incoming) => served,
        };
        match served {
            Ok(FrameFlow::Continue) => continue,
            Ok(FrameFlow::Closed) => break Ok(()),
            Err(error) => break Err(error),
        }
    };
    if let Err(error) = outcome {
        set_error(&errors, &error);
    }
}

async fn serve_frame(
    reader: &mut PrefixedReader<ReadHalf<TcpStream>>,
    fragmented: &mut bool,
    outgoing: &mut mpsc::Sender<Command>,
    incoming: &mpsc::Sender<Vec<u8>>,
) -> io::Result<FrameFlow> {
    let header = read_frame_header(reader).await?;
    if header.opcode >= OP_CLOSE {
        let mut data = vec![0; header.len as usize];
        reader.read_exact(&mut data).await?;
        unmask(&mut data, 0, header.mask);
        return match header.opcode {
            OP_PING => {
                tokio::time::timeout(Duration::from_secs(5), outgoing.send(Command::Pong(data)))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "browser dialer pong queue blocked")
                    })?
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "browser dialer writer closed")
                    })?;
                Ok(FrameFlow::Continue)
            }
            OP_CLOSE => {
                let code = validate_close(&data)?;
                let (done, received) = oneshot::channel();
                tokio::time::timeout(Duration::from_secs(5), async {
                    if outgoing
                        .send(Command::Close(data, Some(done)))
                        .await
                        .is_ok()
                    {
                        let _ = received.await;
                    }
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "browser dialer close reply blocked",
                    )
                })?;
                if code.is_none_or(|code| code == 1000 || code == 1001) {
                    Ok(FrameFlow::Closed)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!(
                            "browser dialer WebSocket closed with status {}",
                            code.unwrap_or(1005)
                        ),
                    ))
                }
            }
            _ => Ok(FrameFlow::Continue),
        };
    }
    match (header.opcode, *fragmented) {
        (OP_CONTINUATION, true) => {}
        (OP_TEXT | OP_BINARY, false) => {}
        _ => {
            return Err(invalid_data(
                "invalid browser dialer WebSocket continuation",
            ));
        }
    }
    let mut remaining = header.len;
    let mut offset = 0usize;
    while remaining != 0 {
        let count = remaining.min(READ_CHUNK as u64) as usize;
        let mut chunk = vec![0; count];
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF inside browser dialer WebSocket frame",
            ));
        }
        chunk.truncate(read);
        unmask(&mut chunk, offset, header.mask);
        offset = (offset + read) % 4;
        remaining -= read as u64;
        if incoming.send(chunk).await.is_err() {
            return Ok(FrameFlow::Closed);
        }
    }
    *fragmented = !header.fin;
    Ok(FrameFlow::Continue)
}

async fn relay_writer(
    mut writer: WriteHalf<TcpStream>,
    mut outgoing: mpsc::Receiver<Command>,
    cancel: CancellationToken,
    errors: ErrorSlot,
) {
    let mut outcome: io::Result<()> = Ok(());
    loop {
        let command = tokio::select! {
            _ = cancel.cancelled() => break,
            command = outgoing.recv() => match command {
                Some(command) => command,
                None => break,
            },
        };
        match command {
            Command::Binary(data) => {
                if let Err(error) = write_frame(&mut writer, OP_BINARY, &data).await {
                    outcome = Err(error);
                    break;
                }
            }
            Command::Pong(data) => {
                if let Err(error) = write_frame(&mut writer, OP_PONG, &data).await {
                    outcome = Err(error);
                    break;
                }
            }
            Command::Flush(done) => {
                let result = writer.flush().await;
                let saved = result.as_ref().err().map(SavedError::new);
                let _ = done.send(result);
                if let Some(error) = saved {
                    outcome = Err(error.error());
                    break;
                }
            }
            Command::Close(data, done) => {
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    write_frame(&mut writer, OP_CLOSE, &data).await?;
                    writer.shutdown().await
                })
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "browser dialer close timed out",
                    ))
                });
                let saved = result.as_ref().err().map(SavedError::new);
                if let Some(error) = &saved {
                    set_error(&errors, &error.error());
                }
                if let Some(done) = done {
                    let _ = done.send(result);
                }
                outcome = saved.map_or(Ok(()), |error| Err(error.error()));
                break;
            }
        }
    }
    if let Err(error) = outcome {
        set_error(&errors, &error);
    }
}

type Reservation = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Command>, mpsc::error::SendError<()>>> + Send>,
>;

/// The relayed side of one dialed connection: a byte stream over the
/// browser's WebSocket, message boundaries hidden, like Go's
/// `websocket.NewConnection` over the gorilla conn.
struct BrowserStream {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Command>,
    reservation: Option<Reservation>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    flush: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown_started: bool,
    shutdown_complete: bool,
    errors: ErrorSlot,
    reader_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

impl BrowserStream {
    fn new(
        stream: TcpStream,
        prefix: Vec<u8>,
        guard: Arc<LiveToken>,
        cancel: CancellationToken,
    ) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        let (incoming_sender, incoming) = mpsc::channel(QUEUE_DEPTH);
        let (outgoing, outgoing_receiver) = mpsc::channel(QUEUE_DEPTH);
        let errors: ErrorSlot = Arc::new(Mutex::new(None));
        let reader_errors = errors.clone();
        let reader_outgoing = outgoing.clone();
        let reader_cancel = cancel.clone();
        let reader_guard = guard.clone();
        let reader_task = tokio::spawn(async move {
            let _held = reader_guard;
            relay_reader(
                PrefixedReader::new(read_half, prefix),
                incoming_sender,
                reader_outgoing,
                reader_cancel,
                reader_errors,
            )
            .await;
        });
        let writer_errors = errors.clone();
        let writer_task = tokio::spawn(async move {
            let _held = guard;
            relay_writer(write_half, outgoing_receiver, cancel, writer_errors).await;
        });
        Self {
            incoming,
            outgoing,
            reservation: None,
            read_buffer: Vec::new(),
            read_offset: 0,
            flush: None,
            shutdown: None,
            shutdown_started: false,
            shutdown_complete: false,
            errors,
            reader_task,
            writer_task,
        }
    }

    fn stored_error(&self) -> Option<io::Error> {
        self.errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(SavedError::error)
    }

    fn poll_permit(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<mpsc::OwnedPermit<Command>>> {
        if let Some(error) = self.stored_error() {
            return Poll::Ready(Err(error));
        }
        if self.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "browser dialer stream is closing",
            )));
        }
        if self.reservation.is_none() {
            self.reservation = Some(Box::pin(self.outgoing.clone().reserve_owned()));
        }
        match self
            .reservation
            .as_mut()
            .expect("browser dialer reservation initialized")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.reservation = None;
                Poll::Ready(result.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "browser dialer writer closed")
                }))
            }
        }
    }
}

impl Drop for BrowserStream {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

fn poll_ack(
    receiver: &mut oneshot::Receiver<io::Result<()>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    match Pin::new(receiver).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(result)) => Poll::Ready(result),
        Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "browser dialer writer stopped",
        ))),
    }
}

impl AsyncRead for BrowserStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_offset == self.read_buffer.len() {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    self.read_buffer = data;
                    self.read_offset = 0;
                }
                Poll::Ready(None) => {
                    if let Some(error) = self.stored_error() {
                        return Poll::Ready(Err(error));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let count = buf
            .remaining()
            .min(self.read_buffer.len() - self.read_offset);
        buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + count]);
        self.read_offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BrowserStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "browser dialer stream is closing",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let permit = match self.poll_permit(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        let count = buf.len().min(WRITE_CHUNK);
        // A canceled flush followed by another write needs a new barrier.
        self.flush = None;
        permit.send(Command::Binary(buf[..count].to_vec()));
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown_started {
            return self.poll_shutdown(cx);
        }
        if let Some(error) = self.stored_error() {
            return Poll::Ready(Err(error));
        }
        if self.flush.is_none() {
            let permit = match self.poll_permit(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            };
            let (done, received) = oneshot::channel();
            self.flush = Some(received);
            permit.send(Command::Flush(done));
        }
        let result = poll_ack(self.flush.as_mut().expect("flush initialized"), cx);
        if result.is_ready() {
            self.flush = None;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown.is_none() {
            let permit = match self.poll_permit(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(_)) => {
                    // The writer is already gone; the socket is closed
                    // either way, so a clean shutdown is close enough.
                    self.shutdown_started = true;
                    self.shutdown_complete = true;
                    return Poll::Ready(self.stored_error().map_or(Ok(()), Err));
                }
            };
            let (done, received) = oneshot::channel();
            self.shutdown = Some(received);
            self.shutdown_started = true;
            permit.send(Command::Close(1000u16.to_be_bytes().to_vec(), Some(done)));
        }
        // Once the close is queued, its write acknowledgement is
        // authoritative: the browser can drop the transport right after
        // receiving it, racing a transport error into the slot.
        let mut result = poll_ack(self.shutdown.as_mut().expect("shutdown initialized"), cx);
        if matches!(&result, Poll::Ready(Err(_))) && self.stored_error().is_none() {
            result = Poll::Ready(Ok(()));
        }
        if result.is_ready() {
            self.shutdown_complete = matches!(&result, Poll::Ready(Ok(())));
            self.shutdown = None;
        }
        result
    }
}

#[cfg(test)]
static TEST_ADDRESS_OVERRIDE: Mutex<Option<Option<String>>> = Mutex::new(None);

#[cfg(test)]
fn test_address_override() -> Option<Option<String>> {
    TEST_ADDRESS_OVERRIDE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// `None` restores the real environment lookup; `Some(None)` disarms;
/// `Some(Some(address))` arms at the address. The workspace forbids the
/// `unsafe std::env::set_var`, so in-crate tests steer the flag this way.
#[cfg(test)]
fn set_test_address(address: Option<Option<String>>) {
    *TEST_ADDRESS_OVERRIDE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = address;
}

#[cfg(test)]
fn test_local_addr() -> Option<std::net::SocketAddr> {
    lock_state().server.as_ref().and_then(|server| server.local)
}

#[cfg(test)]
fn test_idle_connections() -> usize {
    lock_state()
        .server
        .as_ref()
        .map_or(0, |server| server.pool.idle_len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::websocket;

    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn masked_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        assert!(payload.len() <= 125);
        let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        frame
    }

    async fn header_case(bytes: &[u8]) -> io::Result<FrameHeader> {
        let (mut client, server) = tokio::io::duplex(128);
        client.write_all(bytes).await.unwrap();
        let mut reader = PrefixedReader::new(server, Vec::new());
        read_frame_header(&mut reader).await
    }

    #[test]
    fn env_flag_resolution_matches_go_platform_package() {
        assert_eq!(
            normalize_env_name("xray.browser.dialer"),
            "XRAY_BROWSER_DIALER"
        );
        assert_eq!(normalize_env_name(" xray.ConfDir "), "XRAY_CONFDIR");
        assert_eq!(resolve_address(None, None), None);
        assert_eq!(
            resolve_address(Some("127.0.0.1:8080".to_owned()), None),
            Some("127.0.0.1:8080".to_owned())
        );
        // A set-but-empty primary disarms and hides the alternate, like Go's
        // LookupEnv hit returning "".
        assert_eq!(
            resolve_address(Some(String::new()), Some("127.0.0.1:9".to_owned())),
            None
        );
        assert_eq!(
            resolve_address(None, Some("127.0.0.1:9".to_owned())),
            Some("127.0.0.1:9".to_owned())
        );
        assert_eq!(resolve_address(None, Some(String::new())), None);
    }

    #[test]
    fn embedded_page_is_go_dialer_html() {
        // Byte-for-byte copy of Go's dialer.html (CRLF line endings), with
        // the single csrfToken placeholder the server substitutes.
        assert_eq!(PAGE.len(), 5879);
        assert!(PAGE.starts_with("<!DOCTYPE html>\r\n"));
        assert!(PAGE.ends_with("</html>\r\n"));
        assert_eq!(PAGE.matches("csrfToken").count(), 1);
        assert!(PAGE.contains("/websocket?token=csrfToken"));
        assert!(PAGE.contains("task.streamResponse"));
        assert!(PAGE.contains("let checkTask = setInterval(check, 1000);"));
        assert_eq!(PAGE.matches('\r').count(), PAGE.matches('\n').count());
    }

    #[test]
    fn dial_task_frame_matches_go_json_shape() {
        // Go marshals the task struct in field order: method, url, extra,
        // streamResponse; DialWS always sets extra ({} without early data).
        assert_eq!(
            serde_json::to_string(&ws_task("ws://example.test/t")).unwrap(),
            r#"{"method":"WS","url":"ws://example.test/t","extra":{},"streamResponse":true}"#
        );
    }

    #[test]
    fn websocket_accept_key_and_server_frame_fixtures() {
        assert_eq!(accept_key(RFC_KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(server_frame(OP_TEXT, b"ok"), [0x81, 0x02, b'o', b'k']);
        let long = vec![0x42; 126];
        let frame = server_frame(OP_BINARY, &long);
        assert_eq!(&frame[..4], &[0x82, 126, 0x00, 0x7e]);
        assert_eq!(frame.len(), long.len() + 4);
    }

    #[tokio::test]
    async fn frame_header_decoding_validates_go_rules() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let header = header_case(&masked_frame(OP_TEXT, b"ok", [1, 2, 3, 4]))
                .await
                .unwrap();
            assert!(header.fin);
            assert_eq!(header.opcode, OP_TEXT);
            assert_eq!(header.len, 2);
            assert_eq!(header.mask, [1, 2, 3, 4]);

            // Servers only accept masked client frames.
            assert_eq!(
                header_case(&[0x81, 0x02, b'o', b'k'])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            // Nonminimal 16-bit lengths are rejected; pings are fine.
            assert!(
                header_case(&[0x82, 126, 0x00, 0x05, 1, 2, 3, 4, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
            );
            assert!(
                header_case(&masked_frame(OP_PING, &[], [1, 2, 3, 4]))
                    .await
                    .is_ok()
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn read_message_answers_pings_and_reports_close() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut client, server) = tokio::io::duplex(128);
            client
                .write_all(&masked_frame(OP_TEXT, b"ok", [1, 2, 3, 4]))
                .await
                .unwrap();
            let mut reader = PrefixedReader::new(server, Vec::new());
            assert_eq!(read_message(&mut reader).await.unwrap(), b"ok");

            // A ping is answered with an unmasked pong before the message.
            client
                .write_all(&masked_frame(OP_PING, b"x", [5, 6, 7, 8]))
                .await
                .unwrap();
            client
                .write_all(&masked_frame(OP_BINARY, b"payload", [1, 2, 3, 4]))
                .await
                .unwrap();
            assert_eq!(read_message(&mut reader).await.unwrap(), b"payload");
            let mut pong = [0; 3];
            client.read_exact(&mut pong).await.unwrap();
            assert_eq!(pong, [0x8a, 0x01, b'x']);

            // A close frame surfaces as an aborted connection.
            client
                .write_all(&masked_frame(OP_CLOSE, &[0x03, 0xe8], [1, 2, 3, 4]))
                .await
                .unwrap();
            assert_eq!(
                read_message(&mut reader).await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
        })
        .await
        .unwrap();
    }

    async fn fetch_page(port: u16) -> Option<Vec<u8>> {
        let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)).await else {
            return None;
        };
        let request =
            format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .ok()?
            .ok()?;
        Some(response)
    }

    fn page_token(response: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(response).ok()?;
        if !text.starts_with("HTTP/1.1 200 OK\r\n") {
            return None;
        }
        if !text.contains("Access-Control-Allow-Origin: *\r\n") {
            return None;
        }
        let marker = "/websocket?token=";
        let start = text.find(marker)? + marker.len();
        let end = text[start..].find('"')? + start;
        let token = &text[start..end];
        (token.len() == 36).then(|| token.to_owned())
    }

    /// A stand-in for the embedded page: connects like the script would,
    /// handles a WS task by relaying to the target address in the task URL,
    /// and reconnects after each task.
    async fn fake_browser(server_port: u16, cancel: CancellationToken) {
        let mut handled = 0;
        while handled < 4 {
            if cancel.is_cancelled() {
                return;
            }
            let Some(response) = fetch_page(server_port).await else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            };
            let Some(token) = page_token(&response) else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            };
            let Ok(tcp) = TcpStream::connect(("127.0.0.1", server_port)).await else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            };
            let config = websocket::Config {
                path: format!("/websocket?token={token}"),
                ..websocket::Config::default()
            };
            let Ok(mut ws) = websocket::client(
                Box::new(tcp),
                &format!("127.0.0.1:{server_port}"),
                None,
                config,
            )
            .await
            else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            };
            let task = match read_task(&mut ws).await {
                Ok(task) => task,
                Err(_) => continue, // the server went away (restart/disarm)
            };
            assert_eq!(task["method"], "WS");
            assert_eq!(task["streamResponse"], true);
            assert!(
                task["extra"]
                    .as_object()
                    .is_some_and(|extra| extra.is_empty())
            );
            let url = task["url"].as_str().unwrap_or_default().to_owned();
            let host = url
                .strip_prefix("ws://")
                .unwrap_or(&url)
                .split('/')
                .next()
                .unwrap_or_default()
                .to_owned();
            let Ok(mut upstream) = TcpStream::connect(host).await else {
                let _ = ws.shutdown().await;
                continue;
            };
            if ws.write_all(b"ok").await.is_err() || ws.flush().await.is_err() {
                continue;
            }
            handled += 1;
            let _ = tokio::io::copy_bidirectional(&mut ws, &mut upstream).await;
        }
    }

    async fn read_task(ws: &mut crate::transport::BoxStream) -> anyhow::Result<serde_json::Value> {
        let mut buffer = Vec::new();
        let mut chunk = [0; 256];
        loop {
            let count = ws.read(&mut chunk).await?;
            if count == 0 {
                return Err(anyhow::anyhow!("browser connection closed before a task"));
            }
            buffer.extend_from_slice(&chunk[..count]);
            if let Ok(value) = serde_json::from_slice(&buffer) {
                return Ok(value);
            }
        }
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "browser dialer condition not met within 2s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_refused(port: u16) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "browser dialer port {port} still accepting after 2s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn roundtrip(stream: &mut crate::transport::BoxStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn browser_dialer_lifecycle_matches_go_reload_semantics() {
        tokio::time::timeout(Duration::from_secs(5), async {
            set_test_address(Some(Some("127.0.0.1:0".to_owned())));
            reload(CancellationToken::new()).await.unwrap();
            let first = test_local_addr().expect("dialer bound");
            assert!(!has_browser());
            assert_eq!(test_idle_connections(), 0);
            // Armed but no browser: the named rejection.
            let error = dial("ws://example.test/x")
                .await
                .err()
                .expect("dial must fail without a browser");
            assert!(error.to_string().contains("no browser"), "{error}");

            // The page is served verbatim with the CSRF token substituted.
            let response = fetch_page(first.port()).await.expect("page served");
            let token = page_token(&response).expect("csrf token in page");
            let separator = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("HTTP head")
                + 4;
            let body = &response[separator..];
            assert_eq!(body, PAGE.replace("csrfToken", &token).as_bytes());

            // A wrong token gets Go's empty 200 and never registers a conn.
            let mut raw = TcpStream::connect(("127.0.0.1", first.port()))
                .await
                .unwrap();
            raw.write_all(
                format!(
                    "GET /websocket?token=not-the-token HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    first.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut wrong = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), raw.read_to_end(&mut wrong))
                .await
                .unwrap()
                .unwrap();
            assert!(wrong.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(!wrong.starts_with(b"HTTP/1.1 101"));
            assert!(!has_browser());

            // A local TCP echo as the dial target.
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo.local_addr().unwrap().port();
            let echo_task = tokio::spawn(async move {
                while let Ok((socket, _)) = echo.accept().await {
                    tokio::spawn(async move {
                        let (mut reader, mut writer) = socket.into_split();
                        let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    });
                }
            });
            let url = format!("ws://127.0.0.1:{echo_port}/echo");

            let browser_cancel = CancellationToken::new();
            let browser = tokio::spawn(fake_browser(first.port(), browser_cancel.clone()));
            wait_until(|| test_idle_connections() >= 1).await;
            assert!(has_browser());

            // Dial through the browser into the echo: bytes flow both ways.
            let mut stream = dial(&url).await.expect("dial through the browser");
            roundtrip(&mut stream, b"ping").await;
            roundtrip(&mut stream, b"browser-dialer-relay").await;
            stream.shutdown().await.unwrap();
            drop(stream);

            // The page reconnects after each task, so a second dial works.
            wait_until(|| test_idle_connections() >= 1).await;
            let mut second = dial(&url).await.expect("second dial after reconnect");
            roundtrip(&mut second, b"second").await;
            second.shutdown().await.unwrap();
            drop(second);

            // Reload with the same address is a no-op (same bound port).
            reload(CancellationToken::new()).await.unwrap();
            assert_eq!(test_local_addr(), Some(first));
            assert!(has_browser());

            // An address change closes the old server and mints a new token;
            // rebinding the very same port proves the old listener closed.
            set_test_address(Some(Some(format!("127.0.0.1:{}", first.port()))));
            reload(CancellationToken::new()).await.unwrap();
            assert_eq!(
                test_local_addr().map(|address| address.port()),
                Some(first.port())
            );
            let fresh = fetch_page(first.port()).await.expect("page after restart");
            let fresh_token = page_token(&fresh).expect("fresh csrf token");
            assert_ne!(fresh_token, token);
            wait_until(|| test_idle_connections() >= 1).await;
            let mut third = dial(&url).await.expect("dial after restart");
            roundtrip(&mut third, b"third").await;
            third.shutdown().await.unwrap();
            drop(third);

            // Disarm: the server closes and dials are rejected again.
            set_test_address(Some(None));
            reload(CancellationToken::new()).await.unwrap();
            wait_until(|| !has_browser()).await;
            let error = dial(&url)
                .await
                .err()
                .expect("dial must fail when disarmed");
            assert!(error.to_string().contains("no browser"), "{error}");
            assert!(TcpStream::connect(("127.0.0.1", first.port()))
                .await
                .is_err());

            // Re-arm works, and cancelling the token shuts down cleanly.
            set_test_address(Some(Some("127.0.0.1:0".to_owned())));
            let again = CancellationToken::new();
            reload(again.clone()).await.unwrap();
            let second_addr = test_local_addr().expect("re-armed dialer bound");
            assert!(fetch_page(second_addr.port()).await.is_some());
            again.cancel();
            wait_refused(second_addr.port()).await;

            // After the token shutdown the server is gone, so a same-address
            // reload restarts it (Go: server == nil means proceed).
            reload(CancellationToken::new()).await.unwrap();
            assert!(test_local_addr().is_some());

            // Cleanup: disarm fully and clear the override.
            set_test_address(Some(None));
            reload(CancellationToken::new()).await.unwrap();
            browser_cancel.cancel();
            if let Ok(result) = tokio::time::timeout(Duration::from_secs(1), browser).await {
                result.expect("fake browser task panicked");
            }
            echo_task.abort();
            set_test_address(None);
            wait_until(|| !has_browser()).await;
        })
        .await
        .unwrap();
    }
}
