//! Unix-domain-socket transport: the platform-independent address and
//! destination parsing through the public surface, and — on unix builds —
//! the real bind/accept/dial round trip, the octal permission, the abstract
//! socket, and the lockfile exclusivity of Go's system_listener.go UnixAddr
//! branch. On non-unix builds every bind/dial must fail with the named
//! platform rejection; there is no silent fallback.

use xray_core::transport::unix_listener::{
    REQUIRES_UNIX_BUILD, SOCKADDR_UNIX_PATH_LEN, UnixListenAddress, UnixListener,
    parse_unix_destination, unix_destination_string, unix_dial,
};

/// Every wait is bounded (conventions: no unbounded awaits anywhere).
#[cfg(unix)]
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(5), future)
        .await
        .expect("bounded wait")
}

/// A unique per-process socket path under the system temp dir (no tempfile
/// dependency in this crate; uniqueness via pid + counter).
#[cfg(unix)]
fn temp_socket(name: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}-{}-{}.sock",
        name,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    std::env::temp_dir()
        .join(unique)
        .to_string_lossy()
        .into_owned()
}

// -----------------------------------------------------------------------
// Platform-independent surface: parsing, permission split, lockfile
// naming, destination rendering.
// -----------------------------------------------------------------------

#[test]
fn parses_listen_addresses_like_go() {
    let plain = UnixListenAddress::parse("/var/run/xray.sock").unwrap();
    assert_eq!(plain.path(), "/var/run/xray.sock");
    assert!(!plain.is_abstract());
    assert_eq!(plain.permission(), None);
    assert_eq!(plain.lock_path(), "/var/run/xray.sock.lock");

    let abstract_address = UnixListenAddress::parse("@xray").unwrap();
    assert!(abstract_address.is_abstract());
    assert!(!abstract_address.haproxy_padded());
    assert_eq!(abstract_address.abstract_name(), b"xray".to_vec());

    let padded = UnixListenAddress::parse("@@haproxy").unwrap();
    assert!(padded.haproxy_padded());
    let name = padded.abstract_name();
    assert_eq!(name.len(), SOCKADDR_UNIX_PATH_LEN - 1);
    assert_eq!(&name[..7], b"haproxy");

    let permitted = UnixListenAddress::parse("/tmp/xray.sock,0644").unwrap();
    assert_eq!(permitted.path(), "/tmp/xray.sock");
    assert_eq!(permitted.permission(), Some(0o644));
    assert_eq!(permitted.lock_path(), "/tmp/xray.sock.lock");
}

#[test]
fn rejects_invalid_octal_permission_with_go_message() {
    let error = UnixListenAddress::parse("/tmp/xray.sock,09").expect_err("09 is not octal");
    assert_eq!(error.to_string(), "failed to parse permission: 09");
    assert!(UnixListenAddress::parse("/tmp/xray.sock,8").is_err());
    assert!(UnixListenAddress::parse("/tmp/xray.sock,").is_err());
}

#[test]
fn renders_network_unix_destinations() {
    assert_eq!(unix_destination_string("/tmp/x.sock"), "unix:/tmp/x.sock");
    assert_eq!(
        parse_unix_destination("unix:/tmp/x.sock").as_deref(),
        Some("/tmp/x.sock")
    );
    assert_eq!(parse_unix_destination("tcp:127.0.0.1:80"), None);
}

// -----------------------------------------------------------------------
// Unix builds: the real sockets.
// -----------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn binds_accepts_and_dials_an_echo_round_trip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let path = temp_socket("p27-echo");
    let address = UnixListenAddress::parse(&path).unwrap();
    let mut listener = UnixListener::bind(&address).await.unwrap();
    assert_eq!(listener.local_addr_string(), path);

    let dial_path = path.clone();
    let dial = tokio::spawn(async move { unix_dial(&dial_path).await });
    let (mut inbound, peer, bound) = bounded(listener.accept()).await.unwrap();
    // A filesystem client that never bound its own path is unnamed.
    assert_eq!(peer, "");
    assert_eq!(bound, path);

    let mut outbound = bounded(dial).await.expect("dial task bounded").unwrap();

    outbound.write_all(b"unix round trip").await.unwrap();
    let mut buffer = [0u8; 16];
    let count = bounded(inbound.read(&mut buffer)).await.unwrap();
    assert_eq!(&buffer[..count], b"unix round trip");

    inbound.write_all(b"echo").await.unwrap();
    let mut echo = [0u8; 4];
    bounded(outbound.read_exact(&mut echo)).await.unwrap();
    assert_eq!(&echo, b"echo");

    drop(inbound);
    drop(outbound);
    listener.close().unwrap();
    // Close unlinked the socket file this listener created.
    assert!(!std::path::Path::new(&path).exists());
}

#[cfg(unix)]
#[tokio::test]
async fn applies_the_octal_permission_suffix() {
    use std::os::unix::fs::PermissionsExt;

    let path = temp_socket("p27-perm");
    let address = UnixListenAddress::parse(&format!("{path},0644")).unwrap();
    assert_eq!(address.permission(), Some(0o644));
    let listener = UnixListener::bind(&address).await.unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o644);

    listener.close().unwrap();
    assert!(!std::path::Path::new(&path).exists());
}

#[cfg(unix)]
#[tokio::test]
async fn lockfile_excludes_a_second_listener_while_the_first_lives() {
    let path = temp_socket("p27-lock");
    let address = UnixListenAddress::parse(&path).unwrap();
    let lock_path = address.lock_path();

    let first = UnixListener::bind(&address).await.unwrap();
    assert!(std::path::Path::new(&lock_path).exists());

    // The live listener holds the lock: a second bind fails immediately
    // (Go blocks here; this port fails the startup by name).
    let second = UnixListener::bind(&address)
        .await
        .err()
        .expect("a second listener on the same socket must fail");
    assert!(
        format!("{second:#}").contains("failed to lock file"),
        "unexpected error: {second:#}"
    );

    // Closing the first releases the lock, removes the lockfile and the
    // socket, so a fresh bind succeeds on the same path.
    first.close().unwrap();
    assert!(!std::path::Path::new(&path).exists());
    assert!(!std::path::Path::new(&lock_path).exists());
    let third = UnixListener::bind(&address).await;
    assert!(third.is_ok(), "rebind after close must succeed");
    drop(third.unwrap());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn binds_and_dials_abstract_sockets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let name = format!("@p27-abstract-{}", std::process::id());
    let address = UnixListenAddress::parse(&name).unwrap();
    assert!(address.is_abstract());
    let mut listener = UnixListener::bind(&address).await.unwrap();
    assert_eq!(listener.local_addr_string(), name);

    let dial_name = name.clone();
    let dial = tokio::spawn(async move { unix_dial(&dial_name).await });
    let (mut inbound, peer, _) = bounded(listener.accept()).await.unwrap();
    assert_eq!(peer, name);
    let mut outbound = bounded(dial).await.expect("dial bounded").unwrap();

    outbound.write_all(b"abstract").await.unwrap();
    let mut buffer = [0u8; 8];
    let count = bounded(inbound.read(&mut buffer)).await.unwrap();
    assert_eq!(&buffer[..count], b"abstract");

    drop(inbound);
    drop(outbound);
    listener.close().unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn haproxy_padded_abstract_socket_does_not_match_the_plain_name() {
    // The '@@' padding renames the socket to name+NULs; Go does not pad the
    // dial side, so an unpadded dial does not reach it (haproxy, which pads
    // its own addresses, is the intended client).
    let padded = format!("@@p27-hap-{}", std::process::id());
    let address = UnixListenAddress::parse(&padded).unwrap();
    assert!(address.haproxy_padded());
    let listener = UnixListener::bind(&address).await.unwrap();
    assert_eq!(listener.local_addr_string(), padded);

    let plain = padded[1..].to_owned();
    let refused = unix_dial(&plain).await;
    assert!(
        refused.is_err(),
        "the unpadded name must not reach the padded socket"
    );
    listener.close().unwrap();
}

// -----------------------------------------------------------------------
// Non-unix builds: the named rejection, never a fallback.
// -----------------------------------------------------------------------

#[cfg(not(unix))]
#[tokio::test]
async fn non_unix_builds_reject_bind_and_dial_by_name() {
    let address = UnixListenAddress::parse("/tmp/xray.sock").unwrap();
    let error = UnixListener::bind(&address)
        .await
        .err()
        .expect("bind must fail on a non-unix build");
    assert_eq!(error.to_string(), REQUIRES_UNIX_BUILD);

    let error = unix_dial("/tmp/xray.sock")
        .await
        .err()
        .expect("dial must fail on a non-unix build");
    assert_eq!(error.to_string(), REQUIRES_UNIX_BUILD);
}
