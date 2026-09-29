//! Integration tests for the XDRIVE stream adapter (`transport/xdrive/stream`):
//! `xdriveSettings` parity with Go's `infra/conf.XDriveConfig`, backend
//! selection with named rejections, and full round trips through the
//! local-disk and HTTP-template object stores.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use xray_core::{
    address::Destination,
    transport::xdrive::{
        MAX_CONCURRENCY, MAX_SEGMENT_BYTES,
        stream::{PLACEHOLDER_ADDR, XdriveSettings, XdriveStream, dial, serve},
        wire,
    },
};

/// Every wait is bounded; nothing blocks longer than five seconds.
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("xdrive stream test timed out")
}

/// A unique system-temp directory removed on drop; the same discipline as the
/// engine's own tests.
struct TempFolder(PathBuf);

impl TempFolder {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "xray-xdrive-stream-test-{}",
            wire::new_session_id().unwrap()
        )))
    }
}

impl Drop for TempFolder {
    fn drop(&mut self) {
        if self.0.starts_with(std::env::temp_dir())
            && self.0.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("xray-xdrive-stream-test-")
            })
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Engine-timed local settings so loopback round trips settle quickly while
/// still exercising the real polling/flush cadence.
fn local_settings(folder: &Path) -> Value {
    json!({
        "service": "local",
        "remoteFolder": folder.to_string_lossy(),
        "segmentBytes": 1024,
        "flushIntervalMs": 5,
        "pollIntervalMs": 5,
        "maxPollIntervalMs": 20,
        "sessionTtlSeconds": 2,
        "concurrency": 4,
        "eagerWindowMs": 200,
        "holeTimeoutMs": 2000,
    })
}

fn child_names(path: &Path) -> Vec<String> {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn settings_keys_defaults_and_rejections_match_go() {
    // The exact `xdriveSettings` keys of Go's XDriveConfig parse field for field.
    let settings = XdriveSettings::from_value(&json!({
        "remoteFolder": "shared/folder",
        "service": "template",
        "secrets": ["client", "secret", "refresh"],
        "segmentBytes": 65536,
        "flushIntervalMs": 30,
        "pollIntervalMs": 60,
        "maxPollIntervalMs": 600,
        "sessionTtlSeconds": 120,
        "concurrency": 4,
        "eagerWindowMs": 2500,
        "holeTimeoutMs": 45000,
        "template": {"flatten": true},
    }))
    .unwrap();
    assert_eq!(settings.remote_folder, "shared/folder");
    assert_eq!(settings.service, "template");
    assert_eq!(
        settings.secrets,
        vec![
            "client".to_owned(),
            "secret".to_owned(),
            "refresh".to_owned()
        ]
    );
    assert_eq!(settings.segment_bytes, 65536);
    assert_eq!(settings.flush_interval_ms, 30);
    assert_eq!(settings.poll_interval_ms, 60);
    assert_eq!(settings.max_poll_interval_ms, 600);
    assert_eq!(settings.session_ttl_seconds, 120);
    assert_eq!(settings.concurrency, 4);
    assert_eq!(settings.eager_window_ms, 2500);
    assert_eq!(settings.hole_timeout_ms, 45000);
    assert_eq!(settings.template, Some(json!({"flatten": true})));

    // Defaults are Go's zero values; paramsFromConfig applies the fallbacks.
    let defaults =
        XdriveSettings::from_value(&json!({"service": "local", "remoteFolder": "f"})).unwrap();
    assert_eq!(defaults.remote_folder, "f");
    assert!(defaults.secrets.is_empty());
    assert_eq!(defaults.segment_bytes, 0);
    assert_eq!(defaults.flush_interval_ms, 0);
    assert_eq!(defaults.poll_interval_ms, 0);
    assert_eq!(defaults.max_poll_interval_ms, 0);
    assert_eq!(defaults.session_ttl_seconds, 0);
    assert_eq!(defaults.concurrency, 0);
    assert_eq!(defaults.eager_window_ms, 0);
    assert_eq!(defaults.hole_timeout_ms, 0);
    assert_eq!(defaults.template, None);

    // Unknown keys are rejected naming the key.
    let error = XdriveSettings::from_value(&json!({"service": "local", "fileSize": 1}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("fileSize"), "{error}");

    // Unknown services are rejected naming the service.
    let error = XdriveSettings::from_value(&json!({"service": "yandex disk"}))
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(error.contains("yandex disk"), "{error}");

    // service "template" needs a template object (Go's Build message).
    let error = XdriveSettings::from_value(&json!({"service": "template"}))
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(error.contains("template"), "{error}");

    // Google Drive needs exactly 3 secrets (Go's Build message and order).
    let error =
        XdriveSettings::from_value(&json!({"service": "Google Drive", "secrets": ["a", "b"]}))
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
    assert!(error.contains("3 secrets"), "{error}");
    // With exactly 3 secrets validation passes, like Go's Build.
    XdriveSettings::from_value(&json!({"service": "Google Drive", "secrets": ["a", "b", "c"]}))
        .unwrap()
        .validate()
        .unwrap();
}

#[tokio::test]
async fn compiled_engine_params_match_go_paramsfromconfig_defaults_and_caps() {
    let folder = TempFolder::new();
    // Only the required keys: every timing field takes Go's fallback.
    let end = XdriveStream::compile(
        &XdriveSettings::from_value(&json!({
            "service": "local",
            "remoteFolder": folder.0.to_string_lossy(),
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let params = end.params();
    assert_eq!(params.segment_bytes, 512 * 1024);
    assert_eq!(params.flush_interval, Duration::from_millis(20));
    assert_eq!(params.min_poll_interval, Duration::from_millis(50));
    assert_eq!(params.max_poll_interval, Duration::from_millis(500));
    assert_eq!(params.eager_window, Duration::from_secs(2));
    assert_eq!(params.hole_timeout, Duration::from_secs(30));
    assert_eq!(params.session_ttl, Duration::from_secs(300));
    assert_eq!(params.concurrency, 8);

    // Go's capped(): sizes clamp and maxPoll lifts to pollInterval.
    let end = XdriveStream::compile(
        &XdriveSettings::from_value(&json!({
            "service": "local",
            "remoteFolder": folder.0.to_string_lossy(),
            "segmentBytes": u32::MAX,
            "concurrency": u32::MAX,
            "pollIntervalMs": 400,
            "maxPollIntervalMs": 100,
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let params = end.params();
    assert_eq!(params.segment_bytes, MAX_SEGMENT_BYTES);
    assert_eq!(params.concurrency, MAX_CONCURRENCY);
    assert_eq!(params.max_poll_interval, params.min_poll_interval);
}

#[tokio::test]
async fn compile_rejects_unsupported_services_and_malformed_backends_by_name() {
    // Unknown service fails by name (Go's Build: "unsupported service").
    let error =
        XdriveStream::compile(&XdriveSettings::from_value(&json!({"service": "dropbox"})).unwrap())
            .await
            .unwrap_err()
            .to_string();
    assert!(error.contains("dropbox"), "{error}");

    // Google Drive validates like Go but has no native backend.
    let error = XdriveStream::compile(
        &XdriveSettings::from_value(&json!({
            "service": "Google Drive",
            "secrets": ["id", "secret", "refresh"],
        }))
        .unwrap(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("Google Drive"), "{error}");

    // Local storage needs a remoteFolder (Go's newLocalStorage error).
    let error =
        XdriveStream::compile(&XdriveSettings::from_value(&json!({"service": "local"})).unwrap())
            .await
            .unwrap_err()
            .to_string();
    assert!(error.contains("remoteFolder"), "{error}");

    // A template without the four operations fails.
    let error = XdriveStream::compile(
        &XdriveSettings::from_value(&json!({
            "service": "template",
            "template": {"flatten": true},
        }))
        .unwrap(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("template"), "{error}");
}

#[tokio::test]
async fn local_storage_round_trips_both_directions_through_the_object_store() {
    let folder = TempFolder::new();
    let end =
        XdriveStream::compile(&XdriveSettings::from_value(&local_settings(&folder.0)).unwrap())
            .await
            .unwrap();
    let mut listener = bounded(serve(&end, PLACEHOLDER_ADDR)).await.unwrap();

    // The dial target is advisory, like Go's Dial (the store is the channel).
    let target = Destination::new("proxy.example.com", 443).unwrap();
    let (mut client, bound) = bounded(dial(&end, &target)).await.unwrap();
    assert_eq!(bound, PLACEHOLDER_ADDR);
    let (mut server, source) = bounded(listener.accept()).await.unwrap();
    assert_eq!(source, PLACEHOLDER_ADDR);
    assert_eq!(listener.local_addr(), PLACEHOLDER_ADDR);

    // Uplink, spanning several segments, relayed only via the object store.
    let uplink: Vec<u8> = (0..2500).map(|index| (index % 251) as u8).collect();
    client.write_all(&uplink).await.unwrap();
    client.flush().await.unwrap();
    let mut received = vec![0u8; uplink.len()];
    bounded(server.read_exact(&mut received)).await.unwrap();
    assert_eq!(received, uplink);

    // The session's uplink WAL really exists on disk.
    let sessions = child_names(&folder.0.join("streams"));
    assert_eq!(sessions.len(), 1);
    let segments = child_names(&folder.0.join("streams").join(&sessions[0]).join("c2s"));
    assert!(
        segments.iter().any(|name| name.ends_with(".seg")),
        "{segments:?}"
    );

    // Downlink back through the object store.
    let downlink = b"server to client over the object store".to_vec();
    server.write_all(&downlink).await.unwrap();
    server.flush().await.unwrap();
    let mut replied = vec![0u8; downlink.len()];
    bounded(client.read_exact(&mut replied)).await.unwrap();
    assert_eq!(replied, downlink);

    // Half-close: shutdown publishes .end while reads stay usable (Go's conn).
    client.shutdown().await.unwrap();
    let mut eof = [0u8; 1];
    assert_eq!(bounded(server.read(&mut eof)).await.unwrap(), 0);
    server.write_all(b"final reply after EOF").await.unwrap();
    server.shutdown().await.unwrap();
    let mut tail = Vec::new();
    bounded(client.read_to_end(&mut tail)).await.unwrap();
    assert_eq!(tail, b"final reply after EOF");

    drop(server);
    drop(client);
    bounded(listener.close()).await.unwrap();
}

#[tokio::test]
async fn dropping_the_client_stream_closes_the_session_like_go_close() {
    let folder = TempFolder::new();
    let end =
        XdriveStream::compile(&XdriveSettings::from_value(&local_settings(&folder.0)).unwrap())
            .await
            .unwrap();
    let mut listener = bounded(serve(&end, PLACEHOLDER_ADDR)).await.unwrap();
    let target = Destination::new("proxy.example.com", 443).unwrap();
    let (mut client, _) = bounded(dial(&end, &target)).await.unwrap();
    let (mut server, _) = bounded(listener.accept()).await.unwrap();

    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut received = [0u8; 4];
    bounded(server.read_exact(&mut received)).await.unwrap();
    assert_eq!(&received, b"ping");

    // Dropping the stream (how the runtime closes streams) must still publish
    // the .end marker so the peer sees EOF, like Go's synchronous Close.
    drop(client);
    let mut eof = [0u8; 1];
    assert_eq!(bounded(server.read(&mut eof)).await.unwrap(), 0);

    drop(server);
    bounded(listener.close()).await.unwrap();
}

/// The scripted store's state: the objects plus a count of session-object
/// PUTs (segments are deleted after delivery, so the live map alone cannot
/// prove the session crossed the store).
#[derive(Default)]
struct StoreState {
    objects: BTreeMap<String, Vec<u8>>,
    session_uploads: usize,
}

/// A minimal HTTP/1.1 object store on 127.0.0.1:0 speaking exactly the URL
/// contract the settings' template encodes (the same scripted-server pattern
/// as the engine's template tests): flattened names, one request per
/// connection, PUT/GET/DELETE/LIST only.
struct HttpObjectStore {
    url: String,
    state: Arc<Mutex<StoreState>>,
    task: JoinHandle<()>,
}

impl HttpObjectStore {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state: Arc<Mutex<StoreState>> = Arc::new(Mutex::new(StoreState::default()));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let shared = shared.clone();
                handlers.spawn(async move {
                    let _ = serve_request(socket, &shared).await;
                });
            }
        });
        Self { url, state, task }
    }

    /// How many session objects (streams~*) were uploaded through the store.
    fn session_uploads(&self) -> usize {
        self.state.lock().unwrap().session_uploads
    }

    fn settings(&self) -> Value {
        json!({
            "service": "template",
            "remoteFolder": "bucket",
            "segmentBytes": 1024,
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "sessionTtlSeconds": 2,
            "concurrency": 4,
            "eagerWindowMs": 200,
            "holeTimeoutMs": 3000,
            "template": {
                "flatten": true,
                "put": {"method": "PUT", "url": format!("{}/objects/{{folder}}/{{name}}", self.url)},
                "get": {"url": format!("{}/objects/{{folder}}/{{name}}", self.url)},
                "delete": {"method": "DELETE", "url": format!("{}/objects/{{folder}}/{{name}}", self.url)},
                "list": {"url": format!("{}/list/{{folder}}/{{prefix}}", self.url), "namesRegex": "<name>([^<]+)</name>"},
            },
        })
    }
}

impl Drop for HttpObjectStore {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serve exactly one request per connection, then close (Connection: close).
async fn serve_request(mut socket: TcpStream, shared: &Arc<Mutex<StoreState>>) -> io::Result<()> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).await?;
        header.push(byte[0]);
        if header.len() > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized header",
            ));
        }
    }
    let text = String::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non UTF-8 request header"))?;
    let mut lines = text.split("\r\n");
    let first: Vec<_> = lines.next().unwrap().split_whitespace().collect();
    let (method, target) = (first[0], first[1].to_owned());
    let mut length = 0usize;
    for line in lines.filter(|line| !line.is_empty()) {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    if length > 0 {
        socket.read_exact(&mut body).await?;
    }

    let (status, response) = if method == "PUT" {
        let name = target
            .strip_prefix("/objects/bucket/")
            .unwrap_or_default()
            .to_owned();
        let mut state = shared.lock().unwrap();
        if name.starts_with("streams~") {
            state.session_uploads += 1;
        }
        state.objects.insert(name, body);
        ("201 Created", Vec::new())
    } else if method == "DELETE" {
        let name = target
            .strip_prefix("/objects/bucket/")
            .unwrap_or_default()
            .to_owned();
        {
            let mut state = shared.lock().unwrap();
            state.objects.remove(&name);
            let prefix = format!("{name}~");
            state.objects.retain(|key, _| !key.starts_with(&prefix));
        }
        ("204 No Content", Vec::new())
    } else if method == "GET" && target.starts_with("/list/bucket/") {
        // List immediate children below the flattened prefix.
        let prefix = target.strip_prefix("/list/bucket/").unwrap().to_owned();
        let want = format!("{prefix}~");
        let mut listing = String::new();
        for key in shared.lock().unwrap().objects.keys() {
            if key.starts_with(&want) {
                listing.push_str(&format!("<name>{key}</name>"));
            }
        }
        ("200 OK", listing.into_bytes())
    } else if method == "GET" {
        let name = target
            .strip_prefix("/objects/bucket/")
            .unwrap_or_default()
            .to_owned();
        match shared.lock().unwrap().objects.get(&name) {
            Some(data) => ("200 OK", data.clone()),
            None => ("404 Not Found", Vec::new()),
        }
    } else {
        ("405 Method Not Allowed", Vec::new())
    };

    let mut raw = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )
    .into_bytes();
    raw.extend_from_slice(&response);
    socket.write_all(&raw).await?;
    socket.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn template_backend_round_trips_through_a_minimal_http_object_store() {
    let store = HttpObjectStore::start().await;
    let end = XdriveStream::compile(&XdriveSettings::from_value(&store.settings()).unwrap())
        .await
        .unwrap();
    let mut listener = bounded(serve(&end, PLACEHOLDER_ADDR)).await.unwrap();
    let target = Destination::new("template.example.org", 8443).unwrap();
    let (mut client, _) = bounded(dial(&end, &target)).await.unwrap();
    let (mut server, _) = bounded(listener.accept()).await.unwrap();

    let payload: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received = vec![0u8; payload.len()];
    bounded(server.read_exact(&mut received)).await.unwrap();
    assert_eq!(received, payload);

    server.write_all(b"template echo").await.unwrap();
    server.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    bounded(client.read_to_end(&mut echoed)).await.unwrap();
    assert_eq!(echoed, b"template echo");

    // The bytes really crossed the HTTP object store: session objects were
    // uploaded through it (they are deleted again after delivery).
    assert!(
        store.session_uploads() > 0,
        "the template store never saw the session objects"
    );

    drop(server);
    drop(client);
    bounded(listener.close()).await.unwrap();
}
