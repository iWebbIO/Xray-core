//! Opt-in, actual Go <-> native Rust KCP and gRPC transport interoperability.
//!
//! Set XRAY_GO_BINARY to an existing Go Xray executable, then run:
//! cargo test -p xray --test transport_interop -- --nocapture --test-threads=1
//!
//! Missing XRAY_GO_BINARY prints SKIPPED; that is not external interoperability
//! evidence. A configured but invalid reference executable is an error. The Rust
//! side uses library transports plus VLESS, so these fixtures do not assert Rust
//! CLI transport-config integration. No Go build, runtime fallback, external
//! server, additional dependency, or existing test-file modification is used.
//!
//! Coverage: bare UDP KCP, cleartext HTTP/2 gRPC Tun, and gRPC TunMulti, each in
//! both directions. TLS, masks, custom socket settings, packet-loss injection,
//! gRPC connection pooling/custom method names and transport authentication are
//! deliberately outside this process fixture. Each case verifies 270,338 bytes
//! through an independently owned TCP transformer, across four payload sizes.
//! One 30-second deadline covers startup and exchanges. Direct child processes,
//! async tasks, listening sockets, logs and configs have RAII cleanup.

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::Read as _,
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time,
};
use xray_core::{
    address::Destination,
    protocol::vless,
    transport::{BoxStream, grpc, kcp},
};

const CASE_TIMEOUT: Duration = Duration::from_secs(30);
const USER_ID: &str = "a1761a0e-758f-4e41-9397-783c60eccbf3";
const AUTHORITY: &str = "transport-interop.xray.test";
const SERVICE: &str = "xray.interop.Transport";
const FRAME_LENGTHS: [usize; 4] = [1, 8191, 65_537, 196_609];
const TOTAL_BYTES: usize = 270_338;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
enum Case {
    Kcp,
    GrpcTun,
    GrpcTunMulti,
}
#[derive(Clone, Copy, Debug)]
enum Direction {
    RustToGo,
    GoToRust,
}

impl Case {
    fn grpc_config(self) -> grpc::Config {
        grpc::Config {
            authority: AUTHORITY.into(),
            service_name: SERVICE.into(),
            multi_mode: matches!(self, Self::GrpcTunMulti),
            ..grpc::Config::default()
        }
    }
    fn stream_settings(self) -> Value {
        match self {
            Self::Kcp => json!({"network":"kcp", "security":"none", "kcpSettings": {
                "mtu":1350, "tti":50, "uplinkCapacity":5, "downlinkCapacity":20,
                "cwndMultiplier":1, "maxSendingWindow":2*1024*1024
            }}),
            Self::GrpcTun | Self::GrpcTunMulti => {
                json!({"network":"grpc", "security":"none", "grpcSettings": {
                    "authority":AUTHORITY, "serviceName":SERVICE, "multiMode":matches!(self,Self::GrpcTunMulti),
                    "idle_timeout":0, "health_check_timeout":0, "permit_without_stream":false
                }})
            }
        }
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}
fn account() -> vless::Account {
    vless::Account {
        id: *uuid::Uuid::parse_str(USER_ID)
            .expect("fixed fixture UUID")
            .as_bytes(),
        email: "transport-interop@xray.test".into(),
        flow: String::new(),
        level: 0,
    }
}

/// Only directly spawned, owned processes and this newly created temp directory
/// are ever removed. On Windows the child is explicitly hidden.
struct Fixture {
    directory: PathBuf,
    child: Option<Child>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = env::temp_dir().join(format!(
            "xray-transport-interop-{}-{unique}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).context("create owned transport fixture directory")?;
        Ok(Self {
            directory,
            child: None,
        })
    }
    fn spawn(&mut self, binary: &Path, config: Value) -> Result<()> {
        ensure!(self.child.is_none(), "fixture already owns a Go process");
        let config_path = self.directory.join("go.json");
        fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
        let log = fs::File::create(self.directory.join("go.log"))?;
        let mut command = Command::new(binary);
        command
            .args(["run", "-c"])
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        self.child = Some(
            command
                .spawn()
                .context("start explicitly selected Go reference")?,
        );
        Ok(())
    }
    fn check_alive(&mut self) -> Result<()> {
        if let Some(child) = &mut self.child
            && let Some(status) = child.try_wait()?
        {
            bail!("Go reference exited during transport case: {status}");
        }
        Ok(())
    }
    async fn wait_ready(&mut self, address: SocketAddr) -> Result<()> {
        loop {
            self.check_alive()?;
            if matches!(
                time::timeout(Duration::from_millis(100), TcpStream::connect(address)).await,
                Ok(Ok(_))
            ) {
                return Ok(());
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn diagnostics(&self) -> String {
        let mut bytes = Vec::new();
        if let Ok(log) = fs::File::open(self.directory.join("go.log")) {
            let _ = log.take(64 * 1024).read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Tokio detaches a dropped JoinHandle. This owner instead aborts unfinished work
/// on timeout or assertion failure, including all sockets captured by the task.
struct OwnedTask<T> {
    handle: Option<JoinHandle<Result<T>>>,
}
impl<T: Send + 'static> OwnedTask<T> {
    fn spawn(future: impl Future<Output = Result<T>> + Send + 'static) -> Self {
        Self {
            handle: Some(tokio::spawn(future)),
        }
    }
    async fn join(mut self) -> Result<T> {
        self.handle
            .as_mut()
            .expect("owned task handle")
            .await
            .context("fixture task panicked or was cancelled")?
    }
}
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

enum PortReservation {
    Tcp(StdTcpListener),
    Udp(StdUdpSocket),
}
impl PortReservation {
    fn for_case(case: Case) -> Result<Self> {
        Ok(match case {
            Case::Kcp => Self::Udp(StdUdpSocket::bind(loopback())?),
            _ => Self::Tcp(StdTcpListener::bind(loopback())?),
        })
    }
    fn address(&self) -> Result<SocketAddr> {
        Ok(match self {
            Self::Tcp(socket) => socket.local_addr()?,
            Self::Udp(socket) => socket.local_addr()?,
        })
    }
}

fn socks_inbound(address: SocketAddr) -> Value {
    json!({"listen":"127.0.0.1","port":address.port(),"protocol":"socks","settings":{"auth":"noauth","udp":false}})
}
fn go_server_config(
    case: Case,
    address: SocketAddr,
    readiness: SocketAddr,
    target: SocketAddr,
) -> Value {
    json!({"log":{"loglevel":"debug"}, "inbounds":[
        {"listen":"127.0.0.1","port":address.port(),"protocol":"vless",
         "settings":{"clients":[{"id":USER_ID}],"decryption":"none"},"streamSettings":case.stream_settings()},
        socks_inbound(readiness)
    ],"outbounds":[{"protocol":"freedom","settings":{
        // The VLESS inbound enables Go's private-target freedom default.
        // Open exactly the owned transformer endpoint, as interop.rs does;
        // default denial itself is covered by dedicated core tests.
        "finalRules":[{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":target.port()}]
    }}]})
}
fn go_client_config(case: Case, native: SocketAddr, socks: SocketAddr) -> Value {
    json!({"log":{"loglevel":"debug"},"inbounds":[socks_inbound(socks)],"outbounds":[
        {"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":native.port(),
         "users":[{"id":USER_ID,"encryption":"none"}]}]},"streamSettings":case.stream_settings()}
    ]})
}

fn transform(byte: u8) -> u8 {
    byte.rotate_left(1) ^ 0xa5
}
fn payloads() -> Vec<Vec<u8>> {
    FRAME_LENGTHS
        .iter()
        .enumerate()
        .map(|(frame, &length)| {
            (0..length)
                .map(|offset| ((offset * 131 + frame * 17) ^ (offset >> 3)) as u8)
                .collect()
        })
        .collect()
}

async fn start_transformer() -> Result<(SocketAddr, OwnedTask<usize>)> {
    let listener = TcpListener::bind(loopback()).await?;
    let address = listener.local_addr()?;
    let task = OwnedTask::spawn(async move {
        let (mut socket, peer) = listener.accept().await?;
        ensure!(
            peer.ip().is_loopback(),
            "transformer received a non-loopback connection"
        );
        let mut bytes = [0; 8192];
        let mut completed = 0;
        while completed < TOTAL_BYTES {
            let limit = bytes.len().min(TOTAL_BYTES - completed);
            let count = socket
                .read(&mut bytes[..limit])
                .await
                .context("read transformer input")?;
            ensure!(
                count > 0,
                "transformer got EOF after {completed}/{TOTAL_BYTES} bytes"
            );
            for byte in &mut bytes[..count] {
                *byte = transform(*byte);
            }
            socket
                .write_all(&bytes[..count])
                .await
                .context("write transformer reply")?;
            completed += count;
        }
        socket.flush().await?;
        socket.shutdown().await?;
        Ok(completed)
    });
    Ok((address, task))
}

/// Writes and reads progress concurrently: a 196 KB payload must not deadlock
/// either transport's bounded buffers or HTTP/2 receive windows.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    read_vless_response: bool,
) -> Result<()> {
    let frames = payloads();
    let expected: Vec<_> = frames.iter().flatten().copied().map(transform).collect();
    ensure!(
        expected.len() == TOTAL_BYTES,
        "fixture payload count changed"
    );
    let (mut reader, mut writer) = tokio::io::split(stream);
    let sending = async {
        for frame in &frames {
            writer
                .write_all(frame)
                .await
                .context("write deterministic transport payload")?;
            writer
                .flush()
                .await
                .context("flush deterministic transport payload")?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let receiving = async {
        if read_vless_response {
            vless::read_response(&mut reader)
                .await
                .context("native client VLESS response")?;
        }
        let mut offset = 0;
        let mut bytes = [0; 5003];
        while offset < expected.len() {
            let count = bytes.len().min(expected.len() - offset);
            reader
                .read_exact(&mut bytes[..count])
                .await
                .with_context(|| format!("read transformed payload at byte {offset}"))?;
            if bytes[..count] != expected[offset..offset + count] {
                bail!(
                    "transport payload mismatch in byte range {offset}..{}",
                    offset + count
                );
            }
            offset += count;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(sending, receiving)?;
    Ok(())
}

async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    ensure!(
        target.ip().is_loopback(),
        "SOCKS fixture target must be loopback"
    );
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    ensure!(
        method == [5, 0],
        "Go SOCKS auth negotiation failed: {method:?}"
    );
    stream.write_all(&[5, 1, 0]).await?;
    Destination::from(target).write_socks(&mut stream).await?;
    let mut reply = [0; 3];
    stream.read_exact(&mut reply).await?;
    ensure!(reply == [5, 0, 0], "Go SOCKS CONNECT failed: {reply:?}");
    let _bound = Destination::read_socks(&mut stream).await?;
    Ok(stream)
}

async fn native_connect(case: Case, remote: SocketAddr) -> Result<BoxStream> {
    match case {
        Case::Kcp => Ok(Box::new(
            kcp::connect(
                remote,
                kcp::Config::default(),
                kcp::StreamOptions::default(),
            )
            .await?,
        )),
        Case::GrpcTun | Case::GrpcTunMulti => {
            let tcp = TcpStream::connect(remote).await?;
            tcp.set_nodelay(true)?;
            let client =
                grpc::Client::handshake(Box::new(tcp), case.grpc_config(), &remote.to_string())
                    .await?;
            Ok(client.open().await?.boxed())
        }
    }
}

async fn copy_count<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    count: usize,
) -> Result<()> {
    let mut remaining = count;
    let mut bytes = [0; 8192];
    while remaining > 0 {
        let n = bytes.len().min(remaining);
        reader.read_exact(&mut bytes[..n]).await?;
        writer.write_all(&bytes[..n]).await?;
        remaining -= n;
    }
    writer.flush().await?;
    Ok(())
}

async fn relay_vless<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: SocketAddr,
) -> Result<()> {
    let accepted = vless::read_request(stream, &[account()])
        .await
        .context("native server VLESS request")?;
    let request = accepted.request;
    ensure!(
        request.destination == Destination::from(target),
        "native server received unexpected destination {}",
        request.destination
    );
    ensure!(
        target.ip().is_loopback(),
        "native fixture cannot dial outside loopback"
    );
    let mut target_stream = TcpStream::connect(target).await?;
    vless::write_response(stream).await?;
    let (mut inbound_read, mut inbound_write) = tokio::io::split(stream);
    let (mut target_read, mut target_write) = tokio::io::split(&mut target_stream);
    tokio::try_join!(
        copy_count(&mut inbound_read, &mut target_write, TOTAL_BYTES),
        copy_count(&mut target_read, &mut inbound_write, TOTAL_BYTES)
    )?;
    Ok(())
}

enum NativeServer {
    Kcp(kcp::KcpListener),
    Grpc(TcpListener),
}
impl NativeServer {
    async fn bind(case: Case) -> Result<Self> {
        Ok(match case {
            Case::Kcp => Self::Kcp(
                kcp::KcpListener::bind(
                    loopback(),
                    kcp::Config::default(),
                    kcp::StreamOptions::default(),
                )
                .await?,
            ),
            _ => Self::Grpc(TcpListener::bind(loopback()).await?),
        })
    }
    fn address(&self) -> Result<SocketAddr> {
        Ok(match self {
            Self::Kcp(listener) => listener.local_addr(),
            Self::Grpc(listener) => listener.local_addr()?,
        })
    }
    async fn serve(
        self,
        case: Case,
        target: SocketAddr,
        completed: oneshot::Receiver<()>,
    ) -> Result<()> {
        match self {
            Self::Kcp(mut listener) => {
                let (mut stream, peer) = listener.accept().await?;
                ensure!(peer.ip().is_loopback(), "KCP peer is not loopback");
                relay_vless(&mut stream, target).await?;
                // Keep the transport alive until the SOCKS client verifies all
                // response bytes, so teardown cannot race queued response data.
                completed
                    .await
                    .context("client dropped completion signal")?;
                drop(stream);
                listener.close().await?;
            }
            Self::Grpc(listener) => {
                let (tcp, peer) = listener.accept().await?;
                ensure!(peer.ip().is_loopback(), "gRPC peer is not loopback");
                tcp.set_nodelay(true)?;
                let mut server = grpc::Server::handshake(Box::new(tcp), case.grpc_config()).await?;
                let mut accepted = server
                    .accept()
                    .await?
                    .context("Go closed HTTP/2 before opening a tunnel")?;
                let mode = if matches!(case, Case::GrpcTunMulti) {
                    grpc::Mode::TunMulti
                } else {
                    grpc::Mode::Tun
                };
                ensure!(
                    accepted.mode == mode,
                    "Go selected the wrong gRPC tunnel mode"
                );
                ensure!(
                    accepted.authority == AUTHORITY,
                    "Go gRPC authority mismatch: {}",
                    accepted.authority
                );
                relay_vless(&mut accepted.stream, target).await?;
                accepted.stream.finish(grpc::Status::ok()).await?;
                completed
                    .await
                    .context("client dropped completion signal")?;
            }
        }
        Ok(())
    }
}

async fn rust_to_go(case: Case, binary: &Path, fixture: &mut Fixture) -> Result<()> {
    let (target, transformer) = start_transformer().await?;
    let transport_port = PortReservation::for_case(case)?;
    let remote = transport_port.address()?;
    let ready_port = StdTcpListener::bind(loopback())?;
    let ready = ready_port.local_addr()?;
    let config = go_server_config(case, remote, ready, target);
    // Go cannot inherit portable listener handles; release reservations only
    // immediately before spawn. Any collision fails startup with captured logs.
    drop(transport_port);
    drop(ready_port);
    fixture.spawn(binary, config)?;
    fixture.wait_ready(ready).await?;
    let mut stream = native_connect(case, remote)
        .await
        .context("native transport client connect")?;
    vless::write_request(&mut stream, &account(), &Destination::from(target)).await?;
    // Do not await a VLESS response before sending payload: Go may emit it only
    // with the target's first reply.
    exchange(&mut stream, true).await?;
    ensure!(
        transformer.join().await? == TOTAL_BYTES,
        "transformer byte count mismatch"
    );
    fixture.check_alive()?;
    Ok(())
}

async fn go_to_rust(case: Case, binary: &Path, fixture: &mut Fixture) -> Result<()> {
    let (target, transformer) = start_transformer().await?;
    let server = NativeServer::bind(case).await?;
    let native = server.address()?;
    let (done, completed) = oneshot::channel();
    let native_task = OwnedTask::spawn(server.serve(case, target, completed));
    let socks_port = StdTcpListener::bind(loopback())?;
    let proxy = socks_port.local_addr()?;
    let config = go_client_config(case, native, proxy);
    drop(socks_port);
    fixture.spawn(binary, config)?;
    fixture.wait_ready(proxy).await?;
    let mut stream = socks_connect(proxy, target).await?;
    exchange(&mut stream, false).await?;
    let _ = done.send(());
    native_task
        .join()
        .await
        .context("native VLESS transport server")?;
    ensure!(
        transformer.join().await? == TOTAL_BYTES,
        "transformer byte count mismatch"
    );
    fixture.check_alive()?;
    Ok(())
}

fn run(case: Case, direction: Direction) {
    let Some(binary) = env::var_os("XRAY_GO_BINARY") else {
        eprintln!(
            "SKIPPED transport interoperability {direction:?} {case:?}: XRAY_GO_BINARY absent; no Go/Rust exchange ran"
        );
        return;
    };
    let binary = PathBuf::from(binary);
    assert!(
        binary.is_file(),
        "XRAY_GO_BINARY must name an existing Go executable: {}",
        binary.display()
    );
    let binary = fs::canonicalize(binary).expect("canonicalize explicit Go reference executable");
    let mut fixture = Fixture::new().expect("create transport interop fixture");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("transport fixture Tokio runtime");
    let result = runtime.block_on(time_bounded(case, direction, &binary, &mut fixture));
    if let Err(error) = result {
        panic!(
            "ACTUAL transport interoperability failed: {direction:?} {case:?}: {error:#}\nGo reference log:\n{}",
            fixture.diagnostics()
        );
    }
    eprintln!(
        "PASSED ACTUAL transport interoperability {direction:?} {case:?}: {TOTAL_BYTES} payload bytes each way using {}",
        binary.display()
    );
}

async fn time_bounded(
    case: Case,
    direction: Direction,
    binary: &Path,
    fixture: &mut Fixture,
) -> Result<()> {
    time::timeout(CASE_TIMEOUT, async {
        match direction {
            Direction::RustToGo => rust_to_go(case, binary, fixture).await,
            Direction::GoToRust => go_to_rust(case, binary, fixture).await,
        }
    })
    .await
    .context("transport fixture exceeded its 30-second startup/exchange deadline")?
}

#[test]
fn rust_kcp_client_to_go_server() {
    run(Case::Kcp, Direction::RustToGo);
}
#[test]
fn go_kcp_client_to_rust_server() {
    run(Case::Kcp, Direction::GoToRust);
}
#[test]
fn rust_grpc_tun_client_to_go_server() {
    run(Case::GrpcTun, Direction::RustToGo);
}
#[test]
fn go_grpc_tun_client_to_rust_server() {
    run(Case::GrpcTun, Direction::GoToRust);
}
#[test]
fn rust_grpc_tun_multi_client_to_go_server() {
    run(Case::GrpcTunMulti, Direction::RustToGo);
}
#[test]
fn go_grpc_tun_multi_client_to_rust_server() {
    run(Case::GrpcTunMulti, Direction::GoToRust);
}
