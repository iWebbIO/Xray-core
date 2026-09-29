// P27 unix stream: the `net.Network_UNIX` listen and dial paths of
// transport/internet/system_listener.go and system_dialer.go.
#![allow(dead_code)]
//! The unix-domain-socket stream transport: a dokodemo-door inbound with
//! `network: "unix"` listens on one (the `listen` field is the socket
//! path), and a freedom outbound with a unix destination dials one.
//!
//! Go reference:
//! - `transport/internet/system_listener.go` — the `*net.UnixAddr` branch of
//!   `DefaultListener.Listen`: Linux abstract sockets (the leading `@`), the
//!   `@@` haproxy NUL padding, the `path,octal-perm` suffix split, the
//!   FileLocker acquired before bind, the post-bind chmod, and
//!   `UnixListenerWrapper`/`UnixConnWrapper` (the locker closes with the
//!   listener; the peer address is masked to `0.0.0.0` downstream).
//! - `transport/internet/filelocker.go` + `filelocker_other.go` — the
//!   `address + ".lock"` lockfile held for the listener's lifetime.
//!   `filelocker_windows.go` is a no-op because Go-on-Windows cannot listen
//!   on AF_UNIX at all; same here (see [REQUIRES_UNIX_BUILD]).
//! - `transport/internet/system_dialer.go` — the unix dial: the path goes
//!   to the OS dialer as-is (a leading `@` dials the Linux abstract
//!   namespace; the `@@` padding and the `,perm` suffix are listener-side
//!   only and are NOT interpreted on dial, exactly like Go).
//! - `common/net/destination.go` — `Network_UNIX` destinations render as
//!   `unix:/path` ([unix_destination_string]/[parse_unix_destination]).
//!
//! Platform split (the doctrine for this build): tokio's
//! `UnixListener`/`UnixStream` compile only on unix, so the real listener and
//! dialer live under `#[cfg(unix)]`; every other platform gets the named
//! [REQUIRES_UNIX_BUILD] rejection — never a silent fallback. Everything
//! parseable ([UnixListenAddress], the destination rendering, the lockfile
//! naming) is platform-independent and unit-tested on every platform.
//!
//! `sockopt.AcceptProxyProtocol` is not handled here: Go wraps the listener
//! with `proxyproto.Listener`, this build applies the protocol in the
//! runtime's accept chain (`transport::proxy_protocol_runtime`).
//!
//! Go deviations (both deliberate, discussed at each site):
//! - `FileLocker.Acquire` blocks on `flock(LOCK_EX)` in Go, so a second
//!   listener on the same socket path hangs until the first exits. This port
//!   uses `File::try_lock` and fails the bind immediately with Go's wrapper
//!   message — a server must not hang at startup.
//! - Go's teardown releases the lock before closing the listener, leaving a
//!   rebinding instance racing the socket-file unlink; this port unlinks the
//!   socket and releases the lock only after the bound socket is gone, which
//!   is the ordering the locker exists to guarantee.

use anyhow::{Result, anyhow, ensure};
use std::io;

#[cfg(unix)]
use anyhow::Context;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt as _;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt as _;
#[cfg(unix)]
use std::time::Duration;

/// The named rejection every bind/dial returns on a non-unix build: tokio's
/// AF_UNIX listener does not exist there, and Go cannot listen on one
/// either (`filelocker_windows.go` is a no-op for the same reason).
pub const REQUIRES_UNIX_BUILD: &str = "the unix domain socket transport requires a Unix build (AF_UNIX listeners are not available on this platform build)";

/// Go's `syscall.RawSockaddrUnix{}.Path` length: the `sun_path` size the
/// `@@` haproxy padding pads the abstract name to.
pub const SOCKADDR_UNIX_PATH_LEN: usize = 108;

// -----------------------------------------------------------------------
// Address parsing (platform-independent; mirrors Go's Linux branch for the
// '@' prefix and the filesystem branch for everything else).
// -----------------------------------------------------------------------

/// One parsed unix listen address: Go's system_listener.go `UnixAddr`
/// branch.
///
/// The `listen` field of a unix inbound is the raw path: a leading `@` names
/// a Linux abstract socket (`@@` additionally pads the name with NULs to the
/// full sockaddr path so haproxy — which pads its own addresses — can
/// connect), and a trailing `,0ooo` suffix splits off an octal permission
/// applied to the socket file after bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixListenAddress {
    /// The filesystem socket path (the part before the `,perm` suffix), or
    /// the raw listen string — `@` prefix included — for abstract sockets.
    path: String,
    /// A leading `@`: a Linux abstract socket (no lockfile, no permission).
    abstract_socket: bool,
    /// A `@@` prefix: pad the abstract name with NULs to `sun_path`.
    haproxy_padding: bool,
    /// The parsed octal permission of the `,0ooo` suffix, as raw mode bits.
    permission: Option<u32>,
}

impl UnixListenAddress {
    /// Parse the raw listen path, mirroring Go's parsing and its error
    /// messages.
    ///
    /// Go's `strings.Split(address, ",")` splits a permission only when it
    /// yields exactly two parts — `path,a,b` keeps its commas, like Go.
    /// Abstract addresses (`@...`) never split: on Linux the whole string is
    /// the abstract name, `,0644` included. An empty address is rejected by
    /// name where Go's `address[0]` would panic with an index out of range.
    pub fn parse(path: &str) -> Result<Self> {
        ensure!(!path.is_empty(), "unix listen address is empty");
        let bytes = path.as_bytes();
        if bytes[0] == b'@' {
            // Go: linux abstract sockets are lockfree; the padding needs
            // len(address) > 1 && address[1] == '@'.
            let haproxy_padding = bytes.len() > 1 && bytes[1] == b'@';
            return Ok(Self {
                path: path.to_owned(),
                abstract_socket: true,
                haproxy_padding,
                permission: None,
            });
        }
        let parts: Vec<&str> = path.split(',').collect();
        if parts.len() != 2 {
            return Ok(Self {
                path: path.to_owned(),
                abstract_socket: false,
                haproxy_padding: false,
                permission: None,
            });
        }
        let permission = parse_octal_permission(parts[1])?;
        Ok(Self {
            path: parts[0].to_owned(),
            abstract_socket: false,
            haproxy_padding: false,
            permission: Some(permission),
        })
    }

    /// The filesystem socket path: the part before the `,perm` suffix. For
    /// an abstract address this is the raw listen string, `@` included.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The raw listen string as configured.
    pub fn listen_name(&self) -> &str {
        &self.path
    }

    /// A leading `@` selected the (Linux-only at bind time) abstract
    /// namespace.
    pub fn is_abstract(&self) -> bool {
        self.abstract_socket
    }

    /// A `@@` prefix selected the haproxy NUL padding.
    pub fn haproxy_padded(&self) -> bool {
        self.haproxy_padding
    }

    /// The octal permission of the `,0ooo` suffix (e.g. `0644` -> `0o644`),
    /// as raw mode bits for `Permissions::from_mode`. `None` without a
    /// suffix — and always for abstract sockets, like Go's Linux branch.
    pub fn permission(&self) -> Option<u32> {
        self.permission
    }

    /// The lockfile path Go pairs with a filesystem socket:
    /// `address + ".lock"` on the post-split path. Abstract sockets take no
    /// lock on Linux; the name is still derived for diagnostics (and is
    /// what Go's non-Linux builds would lock, where `@name` is a plain
    /// filesystem path).
    pub fn lock_path(&self) -> String {
        format!("{}.lock", self.path)
    }

    /// The abstract namespace name Go binds for this address: everything
    /// after the leading `@`, NUL-padded to the full sockaddr path when the
    /// `@@` haproxy padding is set — Go's `copy(fullAddr, address[1:])` over
    /// `syscall.RawSockaddrUnix{}.Path`. Empty for non-abstract addresses.
    pub fn abstract_name(&self) -> Vec<u8> {
        let raw = self.path.as_bytes();
        if !self.abstract_socket || raw.is_empty() {
            return Vec::new();
        }
        let name = if self.haproxy_padding {
            &raw[2..]
        } else {
            &raw[1..]
        };
        if !self.haproxy_padding {
            return name.to_vec();
        }
        let mut padded = vec![0u8; SOCKADDR_UNIX_PATH_LEN - 1];
        let keep = name.len().min(SOCKADDR_UNIX_PATH_LEN - 1);
        padded[..keep].copy_from_slice(&name[..keep]);
        padded
    }
}

/// Go's `strconv.ParseUint(s, 8, 32)` on the permission suffix: octal digits
/// only (no sign, no `0o` prefix, no separators), fitting a u32. The failure
/// is Go's exact message: "failed to parse permission: <suffix>".
fn parse_octal_permission(value: &str) -> Result<u32> {
    let valid = !value.is_empty() && value.bytes().all(|byte| (b'0'..=b'7').contains(&byte));
    ensure!(valid, "failed to parse permission: {value}");
    u32::from_str_radix(value, 8).map_err(|_| anyhow!("failed to parse permission: {value}"))
}

// -----------------------------------------------------------------------
// Destination rendering (Go's common/net/destination.go Network_UNIX).
// -----------------------------------------------------------------------

/// Go's `Destination.String()` for a `Network_UNIX` destination:
/// `unix:` + the socket path.
pub fn unix_destination_string(path: &str) -> String {
    format!("unix:{path}")
}

/// Go's `ParseDestination` unix arm: a `unix:`-prefixed string is a unix
/// destination whose address is the remainder of the string. `None` lets the
/// caller continue with the `tcp:`/`udp:`/`host:port` forms.
pub fn parse_unix_destination(destination: &str) -> Option<String> {
    destination.strip_prefix("unix:").map(str::to_owned)
}

// -----------------------------------------------------------------------
// The listener (unix builds bind; everything else rejects by name).
// -----------------------------------------------------------------------

/// The bound listener (unix builds) or the platform rejection holder: Go's
/// `UnixListenerWrapper` — the tokio listener plus the FileLocker it owns
/// for its lifetime, with the socket file it created unlinked on close.
pub struct UnixListener {
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(unix)]
    locker: Option<FileLocker>,
    #[cfg(unix)]
    unlink: Option<std::path::PathBuf>,
    /// The bound address as Go's `net.UnixAddr` renders it: the socket
    /// path, or the `@name` listen string for abstract sockets.
    bound: String,
}

impl UnixListener {
    /// Bind (acquiring Go's FileLocker first on non-abstract addresses),
    /// apply the octal permission, and own the lock for the lifetime.
    ///
    /// Abstract addresses bind only on Linux/Android (Go's
    /// `runtime.GOOS == "linux" || "android"` check); other unix builds
    /// reject them by name, and non-unix builds reject everything by name.
    #[cfg(not(unix))]
    pub async fn bind(_address: &UnixListenAddress) -> Result<Self> {
        Err(anyhow::Error::msg(REQUIRES_UNIX_BUILD))
    }

    #[cfg(unix)]
    pub async fn bind(address: &UnixListenAddress) -> Result<Self> {
        if address.abstract_socket {
            let listener = bind_abstract(address)?;
            return Ok(Self {
                listener,
                locker: None,
                bound: address.path.clone(),
                unlink: None,
            });
        }
        // Filesystem socket: Go acquires the lockfile BEFORE binding, and
        // releases it when bind fails (the Listen callback).
        let locker = FileLocker::acquire(&address.lock_path())?;
        let listener = match tokio::net::UnixListener::bind(&address.path) {
            Ok(listener) => listener,
            Err(error) => {
                locker.release();
                return Err(anyhow::Error::new(error)
                    .context(format!("failed to listen on unix socket {}", address.path)));
            }
        };
        let listener = Self {
            listener,
            locker: Some(locker),
            bound: address.path.clone(),
            unlink: Some(std::path::PathBuf::from(&address.path)),
        };
        if let Some(mode) = address.permission {
            // Go's callback chmods right after the bind; a failure closes
            // the listener (releasing the lock) and fails the listen.
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(&address.path, std::fs::Permissions::from_mode(mode))
            {
                drop(listener);
                return Err(anyhow::Error::new(error)
                    .context(format!("failed to set permission for {}", address.path)));
            }
        }
        Ok(listener)
    }

    /// The bound address as a string (Go's `net.UnixAddr.String`): the
    /// socket path for filesystem sockets, the `@name` listen string for
    /// abstract ones.
    pub fn local_addr_string(&self) -> String {
        self.bound.clone()
    }

    /// Accept one connection: the stream plus the peer and bound paths.
    ///
    /// Go's `UnixConnWrapper` masks the peer to `0.0.0.0` for the proxy
    /// layer; the real peer path is returned here and the runtime decides
    /// what the inbound session sees. Filesystem clients that never bind
    /// their own path are unnamed, so the peer string is empty for them.
    #[cfg(not(unix))]
    pub async fn accept(&mut self) -> io::Result<(crate::transport::BoxStream, String, String)> {
        Err(io::Error::other(REQUIRES_UNIX_BUILD))
    }

    #[cfg(unix)]
    pub async fn accept(&mut self) -> io::Result<(crate::transport::BoxStream, String, String)> {
        let (stream, peer) = self.listener.accept().await?;
        Ok((Box::new(stream), peer_string(&peer), self.bound.clone()))
    }

    /// Go's `UnixListenerWrapper.Close` plus the `net.UnixListener`
    /// unlink-on-close: dropping tears the listener down (unlinks the
    /// socket file it created, then releases and removes the lockfile).
    /// Teardown failures are logged, never surfaced — Go's
    /// `FileLocker.Release` only logs them too.
    pub fn close(self) -> io::Result<()> {
        drop(self);
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for UnixListener {
    fn drop(&mut self) {
        // Unlink the socket before releasing the lock: the lockfile exists
        // to serialize bind/unlink across instances, and releasing it first
        // (Go's order) lets a rebinding instance hit a still-present socket
        // file. The bound socket itself closes with the `listener` field,
        // after this method returns.
        if let Some(path) = self.unlink.take() {
            if let Err(error) = std::fs::remove_file(&path) {
                tracing::debug!(path = %path.display(), %error, "failed to remove unix socket on close");
            }
        }
        if let Some(locker) = self.locker.take() {
            locker.release();
        }
    }
}

/// The abstract bind, split by platform: Linux/Android bind the abstract
/// namespace; other unix builds reject by name (Go's parse is
/// platform-conditional and would treat `@name` as a plain filesystem path —
/// this port's parse is platform-independent, so the bind names it instead).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_abstract(address: &UnixListenAddress) -> Result<tokio::net::UnixListener> {
    let name = address.abstract_name();
    let socket_address = std::os::unix::net::SocketAddr::from_abstract_name(&name)
        .with_context(|| format!("invalid abstract unix socket name {}", address.path))?;
    tokio::net::UnixListener::bind_addr(&socket_address)
        .with_context(|| format!("failed to bind abstract unix socket {}", address.path))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn bind_abstract(address: &UnixListenAddress) -> Result<tokio::net::UnixListener> {
    Err(anyhow!(
        "abstract unix sockets ('@' listen addresses) require a Linux or Android build; \
         this platform build supports filesystem unix sockets only: {}",
        address.path
    ))
}

/// Render a peer address like Go's `net.UnixAddr.String`: the pathname, or
/// `@name` for abstract sockets; unnamed peers are empty.
#[cfg(unix)]
fn peer_string(address: &tokio::net::unix::SocketAddr) -> String {
    if let Some(path) = address.as_pathname() {
        return path.to_string_lossy().into_owned();
    }
    match abstract_peer_string(address) {
        Some(name) => name,
        None => String::new(),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn abstract_peer_string(address: &tokio::net::unix::SocketAddr) -> Option<String> {
    address
        .as_abstract_name()
        .map(|name| format!("@{}", String::from_utf8_lossy(name)))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn abstract_peer_string(_address: &tokio::net::unix::SocketAddr) -> Option<String> {
    None
}

// -----------------------------------------------------------------------
// The FileLocker (Go's filelocker.go + filelocker_other.go).
// -----------------------------------------------------------------------

/// Go's `FileLocker`: the `.lock` companion of a filesystem unix socket,
/// acquired before bind and released (and removed) on close. The OS drops
/// the lock when the holder dies, so a stale lockfile never blocks a new
/// instance — `File::create` re-truncates it like Go's `os.Create`.
#[cfg(unix)]
struct FileLocker {
    path: String,
    file: Option<std::fs::File>,
}

#[cfg(unix)]
impl FileLocker {
    /// Go's `Acquire`: create the lockfile, then take the exclusive lock.
    /// Go blocks on `flock(LOCK_EX)` until the holder exits; this port takes
    /// the lock non-blocking so a live sibling fails startup immediately
    /// with Go's wrapper message instead of hanging (see module docs).
    fn acquire(path: &str) -> Result<Self> {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to create lock file {path}"))?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                path: path.to_owned(),
                file: Some(file),
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(anyhow!(
                "failed to lock file {path}: the unix socket is in use by another listener"
            )),
            Err(error) => Err(anyhow!("failed to lock file {path}: {error}")),
        }
    }

    /// Go's `Release`: unlock, close, and remove the lockfile. Failures are
    /// logged, never surfaced.
    fn release(mut self) {
        if let Some(file) = self.file.take() {
            if let Err(error) = file.unlock() {
                tracing::debug!(path = %self.path, %error, "failed to unlock lock file");
            }
            drop(file);
        }
        if let Err(error) = std::fs::remove_file(&self.path) {
            tracing::debug!(path = %self.path, %error, "failed to remove lock file");
        }
    }
}

// -----------------------------------------------------------------------
// The dial (Go's system_dialer.go unix path).
// -----------------------------------------------------------------------

/// Dial one unix destination path (the freedom outbound's unix arm): Go's
/// `DefaultSystemDialer.Dial` for a `Network_UNIX` destination, with the
/// same 16-second dialer timeout. The path is passed to the OS dialer
/// as-is — a leading `@` dials the Linux abstract namespace, and neither the
/// `@@` haproxy padding nor the `,perm` suffix is interpreted here, exactly
/// like Go.
pub async fn unix_dial(path: &str) -> Result<crate::transport::BoxStream> {
    dial(path).await
}

#[cfg(not(unix))]
async fn dial(path: &str) -> Result<crate::transport::BoxStream> {
    let _ = path;
    Err(anyhow::Error::msg(REQUIRES_UNIX_BUILD))
}

#[cfg(unix)]
async fn dial(path: &str) -> Result<crate::transport::BoxStream> {
    let stream = tokio::time::timeout(Duration::from_secs(16), dial_once(path))
        .await
        .map_err(|_| {
            anyhow::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "unix socket dial timed out after 16s",
            ))
        })??;
    Ok(Box::new(stream))
}

#[cfg(unix)]
async fn dial_once(path: &str) -> io::Result<tokio::net::UnixStream> {
    if let Some(address) = abstract_dial_address(path) {
        let address = address?;
        return tokio::net::UnixStream::connect_addr(&address).await;
    }
    // A filesystem path (Go's non-Linux builds dial '@name' the same way:
    // the raw string is the path).
    tokio::net::UnixStream::connect(path).await
}

/// The Linux abstract-namespace dial: a leading `@` strips to the abstract
/// name, like Go's net package. Non-Linux unix builds have no abstract
/// namespace and pass the raw string through as a filesystem path.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn abstract_dial_address(path: &str) -> Option<io::Result<std::os::unix::net::SocketAddr>> {
    let name = path.strip_prefix('@')?;
    Some(std::os::unix::net::SocketAddr::from_abstract_name(
        name.as_bytes(),
    ))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn abstract_dial_address(_path: &str) -> Option<io::Result<std::os::unix::net::SocketAddr>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_filesystem_path() {
        let address = UnixListenAddress::parse("/var/run/xray.sock").unwrap();
        assert_eq!(address.path(), "/var/run/xray.sock");
        assert_eq!(address.listen_name(), "/var/run/xray.sock");
        assert!(!address.is_abstract());
        assert!(!address.haproxy_padded());
        assert_eq!(address.permission(), None);
        assert_eq!(address.lock_path(), "/var/run/xray.sock.lock");
        assert!(address.abstract_name().is_empty());
    }

    #[test]
    fn parses_abstract_and_padded_abstract() {
        let abstract_address = UnixListenAddress::parse("@xray").unwrap();
        assert!(abstract_address.is_abstract());
        assert!(!abstract_address.haproxy_padded());
        assert_eq!(abstract_address.path(), "@xray");
        assert_eq!(abstract_address.abstract_name(), b"xray".to_vec());
        // Abstract addresses never split a suffix: the whole string is the
        // abstract name on Linux (Go's branch order).
        let with_suffix = UnixListenAddress::parse("@sock,0644").unwrap();
        assert!(with_suffix.is_abstract());
        assert_eq!(with_suffix.permission(), None);
        assert_eq!(with_suffix.abstract_name(), b"sock,0644".to_vec());
        assert_eq!(with_suffix.lock_path(), "@sock,0644.lock");

        let padded = UnixListenAddress::parse("@@haproxy").unwrap();
        assert!(padded.is_abstract());
        assert!(padded.haproxy_padded());
        let name = padded.abstract_name();
        assert_eq!(name.len(), SOCKADDR_UNIX_PATH_LEN - 1);
        assert_eq!(&name[..7], b"haproxy");
        assert!(name[7..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn mirrors_go_prefix_edge_cases() {
        // Go's padding needs len(address) > 1: "@" alone is a plain
        // (kernel-named) abstract socket, "@@" pads the empty name.
        let bare = UnixListenAddress::parse("@").unwrap();
        assert!(bare.is_abstract());
        assert!(!bare.haproxy_padded());
        assert!(bare.abstract_name().is_empty());
        let double = UnixListenAddress::parse("@@").unwrap();
        assert!(double.haproxy_padded());
        assert_eq!(
            double.abstract_name(),
            vec![0u8; SOCKADDR_UNIX_PATH_LEN - 1]
        );
        // An overlong padded name truncates to the sockaddr path, like Go's
        // copy into RawSockaddrUnix{}.Path.
        let long_name = "n".repeat(200);
        let long = UnixListenAddress::parse(&format!("@@{long_name}")).unwrap();
        let name = long.abstract_name();
        assert_eq!(name.len(), SOCKADDR_UNIX_PATH_LEN - 1);
        assert!(name.iter().all(|byte| *byte == b'n'));
    }

    #[test]
    fn splits_octal_permission_suffix() {
        let address = UnixListenAddress::parse("/tmp/xray.sock,0644").unwrap();
        assert_eq!(address.path(), "/tmp/xray.sock");
        assert!(!address.is_abstract());
        assert_eq!(address.permission(), Some(0o644));
        assert_eq!(address.lock_path(), "/tmp/xray.sock.lock");
        // Go's os.Chmod carries any FileMode bits, setuid included.
        assert_eq!(
            UnixListenAddress::parse("/tmp/xray.sock,4755")
                .unwrap()
                .permission(),
            Some(0o4755)
        );
        assert_eq!(
            UnixListenAddress::parse("/tmp/xray.sock,0")
                .unwrap()
                .permission(),
            Some(0)
        );
        assert_eq!(
            UnixListenAddress::parse("/tmp/xray.sock,777")
                .unwrap()
                .permission(),
            Some(0o777)
        );
    }

    #[test]
    fn rejects_invalid_permissions_with_go_message() {
        for suffix in [
            "",
            "8",
            "09",
            "9",
            "+644",
            "-644",
            "0o644",
            "6 44",
            "777777777777",
        ] {
            let error = UnixListenAddress::parse(&format!("/tmp/x.sock,{suffix}"))
                .expect_err(&format!("suffix {suffix:?} must be rejected"));
            assert_eq!(
                error.to_string(),
                format!("failed to parse permission: {suffix}"),
                "suffix {suffix:?}"
            );
        }
    }

    #[test]
    fn leaves_other_comma_counts_unsplit() {
        // Go splits only when strings.Split yields exactly two parts.
        for path in ["/tmp/a,b,c", "/tmp/plain", "/tmp/a,,b", "sock"] {
            let address = UnixListenAddress::parse(path).unwrap();
            assert_eq!(address.path(), path);
            assert_eq!(address.permission(), None);
            assert_eq!(address.lock_path(), format!("{path}.lock"));
        }
    }

    #[test]
    fn rejects_empty_listen_address_by_name() {
        // Go would panic (address[0] on an empty string); the port rejects.
        let error = UnixListenAddress::parse("").expect_err("empty listen address");
        assert_eq!(error.to_string(), "unix listen address is empty");
    }

    #[test]
    fn renders_unix_destinations_like_go() {
        assert_eq!(unix_destination_string("/tmp/x.sock"), "unix:/tmp/x.sock");
        assert_eq!(unix_destination_string("@name"), "unix:@name");
        assert_eq!(
            parse_unix_destination("unix:/tmp/x.sock").as_deref(),
            Some("/tmp/x.sock")
        );
        assert_eq!(parse_unix_destination("unix:"), Some(String::new()));
        assert_eq!(parse_unix_destination("tcp:127.0.0.1:80"), None);
        assert_eq!(parse_unix_destination("udp:127.0.0.1:80"), None);
        assert_eq!(parse_unix_destination("127.0.0.1:80"), None);
        assert_eq!(parse_unix_destination("/tmp/x.sock"), None);
    }

    #[test]
    fn lockfile_naming_follows_go() {
        // The lockfile names the post-split path, never the raw string.
        assert_eq!(
            UnixListenAddress::parse("/run/x,0644").unwrap().lock_path(),
            "/run/x.lock"
        );
        assert_eq!(
            UnixListenAddress::parse("/run/x").unwrap().lock_path(),
            "/run/x.lock"
        );
        // Go's non-Linux builds treat '@' paths as filesystem paths and
        // lock them the same way; abstract binds on Linux take no lock.
        assert_eq!(
            UnixListenAddress::parse("@abs").unwrap().lock_path(),
            "@abs.lock"
        );
    }
}
