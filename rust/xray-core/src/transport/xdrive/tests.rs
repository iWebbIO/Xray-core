use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{self, timeout},
};
use tokio_util::sync::CancellationToken;

use super::*;

#[derive(Default)]
struct MemoryStorage {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    puts: Mutex<Vec<String>>,
    inline: AtomicBool,
    missing_gets: Mutex<HashMap<String, usize>>,
    get_count: AtomicUsize,
    fail_segments: AtomicBool,
    delayed_uploads: AtomicBool,
    active_uploads: AtomicUsize,
    peak_uploads: AtomicUsize,
    block_announcements: AtomicBool,
    announcement_delete_started: AtomicBool,
}

impl MemoryStorage {
    fn contains(&self, name: &str) -> bool {
        self.objects.lock().unwrap().contains_key(name)
    }
    fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(name).cloned()
    }
}

impl Storage for MemoryStorage {
    fn put<'a>(&'a self, name: &'a str, data: Vec<u8>) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            if self.fail_segments.load(Ordering::Relaxed) && name.ends_with(".seg") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected storage failure",
                ));
            }
            let active = self.active_uploads.fetch_add(1, Ordering::Relaxed) + 1;
            self.peak_uploads.fetch_max(active, Ordering::Relaxed);
            if self.delayed_uploads.load(Ordering::Relaxed) && name.ends_with(".seg") {
                let delay = if name.ends_with("000000000.seg") {
                    30
                } else {
                    3
                };
                time::sleep(Duration::from_millis(delay)).await;
            }
            self.objects.lock().unwrap().insert(name.to_owned(), data);
            self.puts.lock().unwrap().push(name.to_owned());
            self.active_uploads.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> StorageFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.get_count.fetch_add(1, Ordering::Relaxed);
            if let Some(count) = self.missing_gets.lock().unwrap().get_mut(name) {
                if *count > 0 {
                    *count -= 1;
                    return Err(io::Error::new(io::ErrorKind::NotFound, "not yet visible"));
                }
            }
            self.objects
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing object"))
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            if name.starts_with("sessions/") && self.block_announcements.load(Ordering::Relaxed) {
                self.announcement_delete_started
                    .store(true, Ordering::Relaxed);
                std::future::pending::<()>().await;
            }
            let prefix = format!("{name}/");
            self.objects
                .lock()
                .unwrap()
                .retain(|key, _| key != name && !key.starts_with(&prefix));
            Ok(())
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> StorageFuture<'a, Vec<Entry>> {
        Box::pin(async move {
            let prefix = format!("{prefix}/");
            let mut found = BTreeMap::new();
            for (name, data) in self.objects.lock().unwrap().iter() {
                let Some(tail) = name.strip_prefix(&prefix) else {
                    continue;
                };
                let (name, inline) = if let Some((child, _)) = tail.split_once('/') {
                    (child, None)
                } else {
                    (
                        tail,
                        self.inline.load(Ordering::Relaxed).then(|| data.clone()),
                    )
                };
                found.insert(
                    name.to_owned(),
                    Entry {
                        name: name.to_owned(),
                        inline,
                    },
                );
            }
            Ok(found.into_values().collect())
        })
    }
}

fn fast_params() -> Params {
    Params {
        segment_bytes: 64,
        flush_interval: Duration::from_millis(10),
        min_poll_interval: Duration::from_millis(5),
        max_poll_interval: Duration::from_millis(20),
        eager_window: Duration::from_millis(30),
        hole_timeout: Duration::from_millis(40),
        session_ttl: Duration::from_millis(200),
        concurrency: 3,
    }
}

fn unpaired(storage: Arc<dyn Storage>, params: Params) -> Connection {
    Connection::new(
        "test".to_owned(),
        storage,
        "write".to_owned(),
        "read".to_owned(),
        params,
        CancellationToken::new(),
        None,
    )
}

async fn wait_for(mut check: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !check() {
            time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn config_defaults_zero_fallback_caps_and_proto_fields_match_go() {
    let params = Params::default();
    assert_eq!(params.segment_bytes, 512 * 1024);
    assert_eq!(params.concurrency, 8);
    assert_eq!(params.flush_interval, Duration::from_millis(20));
    assert_eq!(params.min_poll_interval, Duration::from_millis(50));
    assert_eq!(params.max_poll_interval, Duration::from_millis(500));
    assert_eq!(params.eager_window, Duration::from_secs(2));
    assert_eq!(params.hole_timeout, Duration::from_secs(30));
    assert_eq!(params.session_ttl, Duration::from_secs(300));
    let config = Config {
        segment_bytes: u32::MAX,
        concurrency: u32::MAX,
        poll_interval_ms: 400,
        max_poll_interval_ms: 100,
        ..Default::default()
    };
    let params = Params::from(&config);
    assert_eq!(params.segment_bytes, MAX_SEGMENT_BYTES);
    assert_eq!(params.concurrency, MAX_CONCURRENCY);
    assert_eq!(params.min_poll_interval, params.max_poll_interval);
    let proto = xray_proto::xray::transport::internet::xdrive::Config {
        remote_folder: "folder".to_owned(),
        service: "local".to_owned(),
        segment_bytes: 71,
        template: "{\"a\":1}".to_owned(),
        ..Default::default()
    };
    let decoded = Config::from_proto(&proto).unwrap();
    assert_eq!(decoded.segment_bytes, 71);
    assert_eq!(decoded.template.unwrap()["a"], 1);
}

#[test]
fn wire_names_sequences_and_nanosecond_announcements_match_go() {
    use wire::ObjectKind::*;
    assert_eq!(
        wire::object_name("streams/demo/c2s", 42, Segment).unwrap(),
        "streams/demo/c2s/000000042.seg"
    );
    assert_eq!(
        wire::object_name("p", 1_000_000_000, End).unwrap(),
        "p/1000000000.end"
    );
    for (name, expected) in [
        ("000000000.seg", Some((0, Segment))),
        ("000000042.end", Some((42, End))),
        ("+7.err", Some((7, Error))),
        ("-0.seg", Some((0, Segment))),
        ("-1.seg", None),
        ("1.tmp", None),
        ("no.seg", None),
        ("9223372036854775808.seg", None),
    ] {
        assert_eq!(wire::parse_entry(name), expected);
    }
    // Use a representable SystemTime fixture on Windows (100 ns precision).
    // Independently check the wire parser retains all nine fractional digits.
    let at = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_700);
    let name = wire::announcement_name("demo", at).unwrap();
    assert_eq!(name, "sessions/1700000000123456700-demo");
    assert_eq!(
        wire::parse_announcement_nanos("1700000000123456789-demo"),
        Some(("demo".to_owned(), 1_700_000_000_123_456_789))
    );
    assert_eq!(
        wire::parse_announcement(name.strip_prefix("sessions/").unwrap()),
        Some(("demo".to_owned(), at))
    );
    assert!(wire::parse_announcement("123-../escape").is_none());
    assert!(wire::parse_announcement("-1-demo").is_none());
    let first = wire::new_session_id().unwrap();
    let second = wire::new_session_id().unwrap();
    assert_eq!(first.len(), 32);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(first, second);
    assert_eq!(
        wire::flatten("streams/abc/c2s/000000000.seg"),
        "streams~abc~c2s~000000000.seg"
    );
}

#[tokio::test]
async fn memory_storage_sessions_exchange_data_and_preserve_half_close() {
    let storage = Arc::new(MemoryStorage::default());
    let params = fast_params();
    let mut listener = Listener::new(storage.clone(), params).unwrap();
    let mut client = dial(storage, params).await.unwrap();
    let mut server = timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(client.session_id(), server.session_id());
    assert_eq!(listener.active_sessions(), 1);
    client.write_all(b"ping").await.unwrap();
    let mut ping = [0; 4];
    server.read_exact(&mut ping).await.unwrap();
    assert_eq!(&ping, b"ping");
    client.shutdown().await.unwrap();
    assert_eq!(server.read(&mut [0; 1]).await.unwrap(), 0);
    server.write_all(b"reply after EOF").await.unwrap();
    server.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"reply after EOF");
    drop(server);
    assert_eq!(listener.active_sessions(), 0);
    listener.close().await.unwrap();
}

#[tokio::test]
async fn concurrent_uploads_can_publish_out_of_order_but_end_waits_for_all_segments() {
    let storage = Arc::new(MemoryStorage::default());
    storage.delayed_uploads.store(true, Ordering::Relaxed);
    let params = fast_params();
    let mut connection = unpaired(storage.clone(), params);
    let payload = vec![7; 8 * params.segment_bytes + 5];
    connection.write_all(&payload).await.unwrap();
    connection.shutdown().await.unwrap();
    let names = storage.puts.lock().unwrap().clone();
    assert_eq!(names.last().unwrap(), "write/000000009.end");
    let zero = names
        .iter()
        .position(|name| name == "write/000000000.seg")
        .unwrap();
    let one = names
        .iter()
        .position(|name| name == "write/000000001.seg")
        .unwrap();
    assert!(one < zero);
    let peak = storage.peak_uploads.load(Ordering::Relaxed);
    assert!(peak > 1 && peak <= params.concurrency);
    let recovered: Vec<u8> = (0..9)
        .flat_map(|seq| {
            storage
                .bytes(&wire::object_name("write", seq, wire::ObjectKind::Segment).unwrap())
                .unwrap()
        })
        .collect();
    assert_eq!(recovered, payload);
}

#[tokio::test(start_paused = true)]
async fn timer_coalesces_growing_small_writes_but_flushes_at_eight_held_ticks() {
    let storage = Arc::new(MemoryStorage::default());
    let mut params = fast_params();
    params.segment_bytes = 4096;
    let mut connection = unpaired(storage.clone(), params);
    connection.write_all(b"x").await.unwrap();
    tokio::task::yield_now().await;
    for _ in 0..8 {
        time::advance(params.flush_interval).await;
        tokio::task::yield_now().await;
        assert!(!storage.contains("write/000000000.seg"));
        connection.write_all(b"x").await.unwrap();
        tokio::task::yield_now().await;
    }
    time::advance(params.flush_interval).await;
    wait_for(|| storage.contains("write/000000000.seg")).await;
    assert_eq!(storage.bytes("write/000000000.seg").unwrap(), b"xxxxxxxxx");
}

#[tokio::test]
async fn reader_waits_for_missing_earlier_segment_then_delivers_in_sequence() {
    let storage = Arc::new(MemoryStorage::default());
    let params = fast_params();
    storage
        .put("read/000000001.seg", b"second".to_vec())
        .await
        .unwrap();
    storage.put("read/000000002.end", Vec::new()).await.unwrap();
    let mut connection = unpaired(storage.clone(), params);
    assert!(
        timeout(Duration::from_millis(15), connection.read_u8())
            .await
            .is_err()
    );
    storage
        .put("read/000000000.seg", b"first".to_vec())
        .await
        .unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(1), connection.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"firstsecond");
}

#[tokio::test(start_paused = true)]
async fn hole_timeout_requires_later_objects_and_does_not_expire_an_idle_stream() {
    let storage = Arc::new(MemoryStorage::default());
    let params = fast_params();
    let mut connection = unpaired(storage.clone(), params);
    assert!(
        timeout(params.hole_timeout * 3, connection.read_u8())
            .await
            .is_err()
    );
    storage.put("read/000000002.seg", vec![1]).await.unwrap();
    let error = timeout(Duration::from_secs(1), connection.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("segment 0"));
}

#[tokio::test]
async fn eventual_get_visibility_retries_whole_batch_without_duplicate_delivery() {
    let storage = Arc::new(MemoryStorage::default());
    storage
        .put("read/000000000.seg", b"a".to_vec())
        .await
        .unwrap();
    storage
        .put("read/000000001.seg", b"b".to_vec())
        .await
        .unwrap();
    storage.put("read/000000002.end", Vec::new()).await.unwrap();
    storage
        .missing_gets
        .lock()
        .unwrap()
        .insert("read/000000000.seg".to_owned(), 1);
    let mut connection = unpaired(storage.clone(), fast_params());
    let mut bytes = Vec::new();
    connection.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"ab");
    assert!(storage.get_count.load(Ordering::Relaxed) >= 4);
}

#[tokio::test]
async fn inline_objects_skip_get_and_empty_segments_do_not_become_eof() {
    let storage = Arc::new(MemoryStorage::default());
    storage.inline.store(true, Ordering::Relaxed);
    storage.put("read/000000000.seg", Vec::new()).await.unwrap();
    storage
        .put("read/000000001.seg", b"payload".to_vec())
        .await
        .unwrap();
    storage.put("read/000000002.end", Vec::new()).await.unwrap();
    let mut connection = unpaired(storage.clone(), fast_params());
    let mut bytes = Vec::new();
    connection.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"payload");
    assert_eq!(storage.get_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn upload_failure_publishes_error_marker_and_never_clean_end() {
    let storage = Arc::new(MemoryStorage::default());
    storage.fail_segments.store(true, Ordering::Relaxed);
    let mut connection = unpaired(storage.clone(), fast_params());
    connection.write_all(b"data").await.unwrap();
    assert_eq!(
        connection.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(storage.contains("write/000000000.err"));
    assert!(!storage.contains("write/000000001.end"));
}

#[tokio::test]
async fn peer_failure_is_sticky_and_cannot_be_hidden_by_a_duplicate_segment() {
    let storage = Arc::new(MemoryStorage::default());
    storage
        .put("read/000000000.seg", b"possibly committed".to_vec())
        .await
        .unwrap();
    storage.put("read/000000000.err", Vec::new()).await.unwrap();
    let mut connection = unpaired(storage, fast_params());
    for _ in 0..2 {
        assert!(
            connection
                .read_u8()
                .await
                .unwrap_err()
                .to_string()
                .contains("peer could not store")
        );
    }
}

#[tokio::test]
async fn read_and_write_deadlines_can_be_cleared_without_poisoning_the_stream() {
    let storage = Arc::new(MemoryStorage::default());
    let mut connection = unpaired(storage.clone(), fast_params());
    connection.set_deadline(Some(std::time::Instant::now()));
    assert_eq!(
        connection.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        connection.write_all(b"x").await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    connection.set_deadline(None);
    storage.put("read/000000000.seg", vec![91]).await.unwrap();
    assert_eq!(connection.read_u8().await.unwrap(), 91);
    connection.write_all(b"x").await.unwrap();
    connection.set_write_deadline(Some(std::time::Instant::now()));
    assert_eq!(
        connection.flush().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    connection.set_write_deadline(None);
    connection.flush().await.unwrap();
    assert!(storage.contains("write/000000000.seg"));
    connection.set_write_deadline(Some(std::time::Instant::now()));
    assert_eq!(
        connection.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    connection.set_write_deadline(None);
    connection.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancellation_during_announcement_deletion_releases_active_session_claim() {
    let storage = Arc::new(MemoryStorage::default());
    storage.block_announcements.store(true, Ordering::Relaxed);
    let listener = Listener::new(storage.clone(), fast_params()).unwrap();
    let _client = dial(storage.clone(), fast_params()).await.unwrap();
    wait_for(|| storage.announcement_delete_started.load(Ordering::Relaxed)).await;
    assert_eq!(listener.active_sessions(), 1);
    listener.cancellation_token().cancel();
    wait_for(|| listener.active_sessions() == 0).await;
}

#[tokio::test(start_paused = true)]
async fn expired_write_deadline_rejects_ready_buffer_before_timer_dispatch() {
    let storage = Arc::new(MemoryStorage::default());
    let mut connection = unpaired(storage.clone(), fast_params());
    connection.set_write_deadline(Some(time::Instant::now().into_std()));
    assert_eq!(
        connection
            .write_all(b"must not enqueue")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    connection.set_write_deadline(None);
    connection.shutdown().await.unwrap();
    assert!(!storage.contains("write/000000000.seg"));
    assert!(storage.contains("write/000000000.end"));
}

#[test]
fn manually_constructed_params_reject_unrepresentable_timer_deadlines() {
    let params = Params {
        flush_interval: Duration::MAX,
        ..Params::default()
    };
    assert_eq!(
        params.validate().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test(start_paused = true)]
async fn listener_drops_stale_announcements_and_deduplicates_active_sessions() {
    let storage = Arc::new(MemoryStorage::default());
    let params = fast_params();
    let stale =
        wire::announcement_name("stale", SystemTime::now() - Duration::from_secs(5)).unwrap();
    storage.put(&stale, Vec::new()).await.unwrap();
    storage
        .put("streams/stale/c2s/000000000.seg", vec![1])
        .await
        .unwrap();
    let mut listener = Listener::new(storage.clone(), params).unwrap();
    let client = dial(storage.clone(), params).await.unwrap();
    let server = listener.accept().await.unwrap();
    assert!(!storage.contains(&stale));
    assert!(!storage.contains("streams/stale/c2s/000000000.seg"));
    let duplicate = wire::announcement_name(client.session_id(), SystemTime::now()).unwrap();
    storage.put(&duplicate, Vec::new()).await.unwrap();
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(listener.active_sessions(), 1);
    drop(server);
    assert_eq!(listener.active_sessions(), 0);
}

#[tokio::test(start_paused = true)]
async fn garbage_collection_waits_a_full_idle_ttl_and_keeps_active_sessions() {
    let storage = Arc::new(MemoryStorage::default());
    let params = fast_params();
    storage
        .put("streams/abandoned/c2s/000000000.seg", vec![1])
        .await
        .unwrap();
    let mut listener = Listener::new(storage.clone(), params).unwrap();
    let mut client = dial(storage.clone(), params).await.unwrap();
    let server = listener.accept().await.unwrap();
    client.write_all(b"live").await.unwrap();
    client.flush().await.unwrap();
    time::advance(params.session_ttl / 2).await;
    tokio::task::yield_now().await;
    assert!(storage.contains("streams/abandoned/c2s/000000000.seg"));
    time::advance(params.session_ttl).await;
    wait_for(|| !storage.contains("streams/abandoned/c2s/000000000.seg")).await;
    assert_eq!(listener.active_sessions(), 1);
    drop(server);
}

struct TempFolder(PathBuf);
impl TempFolder {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "xray-xdrive-test-{}",
            wire::new_session_id().unwrap()
        )))
    }
}
impl Drop for TempFolder {
    fn drop(&mut self) {
        // Only remove the test-specific directory under the system temp root.
        if self.0.starts_with(std::env::temp_dir())
            && self
                .0
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("xray-xdrive-test-"))
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[tokio::test]
async fn local_backend_publishes_atomically_clamps_parent_paths_and_hides_temporaries() {
    let folder = TempFolder::new();
    let storage = LocalStorage::new(&folder.0).await.unwrap();
    storage
        .put("../escaped", b"inside root".to_vec())
        .await
        .unwrap();
    assert_eq!(storage.get("escaped").await.unwrap(), b"inside root");
    storage
        .put("streams/one/000000000.seg", b"first".to_vec())
        .await
        .unwrap();
    storage
        .put("streams/one/000000000.seg", b"replacement".to_vec())
        .await
        .unwrap();
    assert_eq!(
        storage.get("streams/one/000000000.seg").await.unwrap(),
        b"replacement"
    );
    std::fs::write(folder.0.join("streams/one/.xdrive-tmp-hidden"), b"partial").unwrap();
    assert_eq!(
        storage.list("streams/one").await.unwrap(),
        [Entry {
            name: "000000000.seg".to_owned(),
            inline: None
        }]
    );
    assert_eq!(
        storage.get("missing").await.unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(storage.list("missing").await.unwrap().is_empty());
    for name in [
        "/",
        "..",
        "evil\\..\\file",
        "C:escape",
        "NUL",
        ".xdrive-tmp-reserved",
    ] {
        assert!(storage.put(name, vec![1]).await.is_err(), "accepted {name}");
    }
    storage.delete("streams/one").await.unwrap();
    storage.delete("streams/one").await.unwrap();
    assert!(storage.list("streams").await.unwrap().is_empty());
}

#[tokio::test]
async fn unsupported_drive_service_is_not_treated_as_local_storage() {
    for service in ["Google Drive"] {
        let config = Config {
            service: service.to_owned(),
            remote_folder: "not-a-local-folder".to_owned(),
            ..Default::default()
        };
        assert!(
            matches!(config.storage().await, Err(error) if error.kind() == io::ErrorKind::Unsupported)
        );
    }
}

struct GoFixture(Child);
impl Drop for GoFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_go(mode: &str, folder: &PathBuf) -> GoFixture {
    let executable = std::env::var_os("XRAY_XDRIVE_GO_FIXTURE")
        .expect("build xdrive/interop/main.go and set XRAY_XDRIVE_GO_FIXTURE");
    let mut command = Command::new(executable);
    command
        .arg(mode)
        .arg(folder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = GoFixture(command.spawn().unwrap());
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "ready");
    child
}

#[tokio::test]
#[ignore = "requires XRAY_XDRIVE_GO_FIXTURE pointing to compiled xdrive/interop/main.go"]
async fn pinned_go_xdrive_local_interoperability_in_both_directions() {
    let payload: Vec<_> = (0..131_071).map(|index| (index % 251) as u8).collect();
    let mut params = fast_params();
    params.segment_bytes = 32768;
    params.session_ttl = Duration::from_secs(5);
    {
        let folder = TempFolder::new();
        let storage = Arc::new(LocalStorage::new(&folder.0).await.unwrap());
        let _server = start_go("server", &folder.0);
        let mut stream = dial(storage, params).await.unwrap();
        let mut echoed = Vec::new();
        timeout(Duration::from_secs(15), async {
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            stream.read_to_end(&mut echoed).await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(echoed, payload);
    }
    {
        let folder = TempFolder::new();
        let storage = Arc::new(LocalStorage::new(&folder.0).await.unwrap());
        let mut listener = Listener::new(storage, params).unwrap();
        let mut client = start_go("client", &folder.0);
        let mut stream = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; payload.len()];
        timeout(Duration::from_secs(15), async {
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            stream.write_all(&received).await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await
        .unwrap();
        assert!(client.0.wait().unwrap().success());
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    }
}
