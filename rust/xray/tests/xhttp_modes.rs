//! Opt-in Go <-> Rust process tests for HTTP/1.1 XHTTP streaming modes.
//!
//! Set XRAY_GO_BINARY to an existing executable, then run:
//! cargo test -p xray --test xhttp_modes -- --nocapture --test-threads=1
//! Missing XRAY_GO_BINARY prints SKIPPED and is not interoperability evidence.
//! The tests build no Go code, launch no shells, and use only owned loopback
//! listeners, temporary configs, and a per-test TLS CA trusted by those configs.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const USER_ID: &str = "407b5891-80b8-4f87-b899-6f82e3a17025";
const HOST: &str = "xhttp-modes.xray.test";
const CASE_TIMEOUT: Duration = Duration::from_secs(30);
static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
enum Direction {
    RustToGo,
    GoToRust,
}

struct Fixture {
    directory: PathBuf,
    children: Vec<(&'static str, Child)>,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "xray-xhttp-modes-{}-{timestamp}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            children: Vec::new(),
        })
    }

    fn spawn(&mut self, label: &'static str, executable: &Path, config: &Value) -> io::Result<()> {
        let path = self.directory.join(format!("{label}.json"));
        fs::write(&path, serde_json::to_vec_pretty(config)?)?;
        let log = fs::File::create(self.directory.join(format!("{label}.log")))?;
        let mut command = Command::new(executable);
        command
            .args(["run", "-c"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        self.children.push((label, command.spawn()?));
        Ok(())
    }

    fn check_alive(&mut self) -> io::Result<()> {
        for (label, child) in &mut self.children {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "{label} exited before exchanges finished: {status}"
                )));
            }
        }
        Ok(())
    }

    fn wait_ready(&mut self, address: SocketAddr, deadline: Instant) -> io::Result<()> {
        loop {
            self.check_alive()?;
            let left = remaining(deadline)?;
            if TcpStream::connect_timeout(&address, left.min(Duration::from_millis(50))).is_ok() {
                return Ok(());
            }
            thread::sleep(left.min(Duration::from_millis(10)));
        }
    }

    fn diagnostics(&self) -> String {
        let mut output = String::new();
        for (label, _) in &self.children {
            let mut bytes = Vec::new();
            if let Ok(log) = fs::File::open(self.directory.join(format!("{label}.log"))) {
                let _ = log.take(64 * 1024).read_to_end(&mut bytes);
            }
            output.push_str(&format!(
                "\n--- {label} ---\n{}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        output
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct Echo {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Echo {
    fn start(deadline: Instant) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Windows inherits the listener's nonblocking mode.
                        // The echo worker uses blocking writes with deadlines;
                        // a WouldBlock must not truncate its response.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                        let mut bytes = [0; 8192];
                        while !stopping.load(Ordering::Relaxed) && Instant::now() < deadline {
                            match stream.read(&mut bytes) {
                                Ok(0) => break,
                                Ok(count) => {
                                    for byte in &mut bytes[..count] {
                                        *byte ^= 0xa5;
                                    }
                                    write_all(&mut stream, &bytes[..count], deadline)?;
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        io::ErrorKind::WouldBlock
                                            | io::ErrorKind::TimedOut
                                            | io::ErrorKind::Interrupted
                                    ) => {}
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => (),
                Ok(Err(error)) => eprintln!("owned XHTTP echo fixture stopped: {error}"),
                Err(_) => eprintln!("owned XHTTP echo fixture panicked"),
            }
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "XHTTP interoperability deadline exceeded",
            )
        })
}

fn write_all(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "XHTTP proxy closed during write",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_exact(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XHTTP proxy closed before response completed",
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn socks_connect(
    address: SocketAddr,
    target: SocketAddr,
    deadline: Instant,
) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    stream.set_nodelay(true)?;
    write_all(&mut stream, &[5, 1, 0], deadline)?;
    let mut method = [0; 2];
    read_exact(&mut stream, &mut method, deadline)?;
    if method != [5, 0] {
        return Err(io::Error::other(format!("SOCKS method failed: {method:?}")));
    }
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    write_all(&mut stream, &request, deadline)?;
    let mut reply = [0; 4];
    read_exact(&mut stream, &mut reply, deadline)?;
    if reply[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!("SOCKS CONNECT failed: {reply:?}")));
    }
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut size = [0];
            read_exact(&mut stream, &mut size, deadline)?;
            usize::from(size[0])
        }
        kind => {
            return Err(io::Error::other(format!(
                "invalid SOCKS address type {kind}"
            )));
        }
    };
    read_exact(&mut stream, &mut vec![0; length + 2], deadline)?;
    Ok(stream)
}

struct Certificates {
    ca: String,
    server: String,
    key: String,
}

impl Certificates {
    fn new() -> io::Result<Self> {
        let ca_key = KeyPair::generate().map_err(io::Error::other)?;
        let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        ca.distinguished_name.push(
            DnType::CommonName,
            "Owned XHTTP interoperability fixture CA",
        );
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        ca.not_before = rcgen::date_time_ymd(2020, 1, 1);
        ca.not_after = rcgen::date_time_ymd(2045, 1, 1);
        let ca_certificate = ca.self_signed(&ca_key).map_err(io::Error::other)?;
        let server_key = KeyPair::generate().map_err(io::Error::other)?;
        let mut server = CertificateParams::new(vec![HOST.to_owned()]).map_err(io::Error::other)?;
        server.distinguished_name.push(DnType::CommonName, HOST);
        server.not_before = ca.not_before;
        server.not_after = ca.not_after;
        server.is_ca = IsCa::ExplicitNoCa;
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = server
            .signed_by(&server_key, &Issuer::from_params(&ca, &ca_key))
            .map_err(io::Error::other)?;
        Ok(Self {
            ca: ca_certificate.pem(),
            server: certificate.pem(),
            key: server_key.serialize_pem(),
        })
    }
}

fn stream_settings(mode: &str, server: bool, certificates: Option<&Certificates>) -> Value {
    let mut settings = json!({
        "network": "xhttp",
        "xhttpSettings": {
            "mode": mode, "host": HOST, "path": "/modes/",
            "extra": {"xPaddingBytes": 100, "scMaxEachPostBytes": 128, "scStreamUpServerSecs": 1}
        }
    });
    if let Some(certificates) = certificates {
        settings["security"] = json!("tls");
        settings["tlsSettings"] = if server {
            json!({"alpn": ["http/1.1"], "certificates": [{
                "certificate": certificates.server.lines().collect::<Vec<_>>(),
                "key": certificates.key.lines().collect::<Vec<_>>()
            }]})
        } else {
            json!({"alpn": ["http/1.1"], "serverName": HOST, "disableSystemRoot": true,
                "certificates": [{"usage":"verify", "certificate": certificates.ca.lines().collect::<Vec<_>>() }]
            })
        };
    }
    settings
}

fn run(direction: Direction, mode: &str, secure: bool) {
    let Some(go) = env::var_os("XRAY_GO_BINARY") else {
        eprintln!(
            "SKIPPED XHTTP interoperability {direction:?} {mode} TLS={secure}: XRAY_GO_BINARY absent; no cross-language exchange ran"
        );
        return;
    };
    let go = PathBuf::from(go);
    assert!(
        go.is_file(),
        "XRAY_GO_BINARY must name an existing executable: {}",
        go.display()
    );
    let rust = Path::new(env!("CARGO_BIN_EXE_xray"));
    let (client_binary, server_binary) = match direction {
        Direction::RustToGo => (rust, go.as_path()),
        Direction::GoToRust => (go.as_path(), rust),
    };
    let mut fixture = Fixture::new().expect("create owned XHTTP fixture");
    let deadline = Instant::now() + CASE_TIMEOUT;
    let outcome = (|| -> io::Result<()> {
        let echo = Echo::start(deadline)?;
        let server_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let client_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let server_address = server_port.local_addr()?;
        let client_address = client_port.local_addr()?;
        let certificates = if secure {
            Some(Certificates::new()?)
        } else {
            None
        };
        let server_config = json!({
            "log": {"access":"none", "loglevel":"debug"},
            "inbounds": [{"listen":"127.0.0.1", "port":server_address.port(), "protocol":"vless",
                "settings":{"clients":[{"id":USER_ID}], "decryption":"none"},
                "streamSettings":stream_settings(mode, true, certificates.as_ref())}],
            // The exception is scoped to the one owned echo listener for both
            // implementations, preserving their encrypted-inbound defaults.
            "outbounds": [{"protocol":"freedom", "settings":{"finalRules":[{
                "action":"allow", "network":"tcp", "ip":["127.0.0.1/32"], "port":echo.address.port()
            }]}}]
        });
        let client_config = json!({
            "log": {"access":"none", "loglevel":"debug"},
            "inbounds": [{"listen":"127.0.0.1", "port":client_address.port(), "protocol":"socks", "settings":{"auth":"noauth", "udp":false}}],
            "outbounds": [{"protocol":"vless", "settings":{"vnext":[{"address":"127.0.0.1", "port":server_address.port(), "users":[{"id":USER_ID, "encryption":"none"}]}]},
                "streamSettings":stream_settings(mode, false, certificates.as_ref())}]
        });
        drop(server_port);
        fixture.spawn("server", server_binary, &server_config)?;
        fixture.wait_ready(server_address, deadline)?;
        drop(client_port);
        fixture.spawn("client", client_binary, &client_config)?;
        fixture.wait_ready(client_address, deadline)?;
        let mut stream = socks_connect(client_address, echo.address, deadline)?;
        // Each response must arrive while the upload HTTP body remains open.
        // Two exchanges prove continuing duplex operation, not an EOF-only reply.
        for (size, seed) in [(200_123usize, 17usize), (7_901, 203)] {
            let payload: Vec<u8> = (0..size)
                .map(|index| index.wrapping_mul(73).wrapping_add(seed) as u8)
                .collect();
            let mut response = vec![0; size];
            let mut sender = stream.try_clone()?;
            thread::scope(|scope| -> io::Result<()> {
                let writing = scope.spawn(|| write_all(&mut sender, &payload, deadline));
                let received = read_exact(&mut stream, &mut response, deadline);
                writing
                    .join()
                    .map_err(|_| io::Error::other("fixture writer panicked"))??;
                received
            })?;
            if !payload
                .iter()
                .zip(response)
                .all(|(sent, received)| *sent ^ 0xa5 == received)
            {
                return Err(io::Error::other("cross-language XHTTP payload corruption"));
            }
        }
        fixture.check_alive()?;
        drop(stream);
        drop(echo);
        Ok(())
    })();
    if let Err(error) = outcome {
        panic!(
            "XHTTP interoperability {direction:?} {mode} TLS={secure} failed: {error}{}",
            fixture.diagnostics()
        );
    }
    eprintln!(
        "INTEROP PASSED XHTTP {direction:?} {mode} TLS={secure}: two live duplex exchanges, 208024 transformed bytes"
    );
}

macro_rules! interop {
    ($rust:ident, $go:ident, $mode:literal, $secure:literal) => {
        #[test]
        fn $rust() {
            run(Direction::RustToGo, $mode, $secure);
        }
        #[test]
        fn $go() {
            run(Direction::GoToRust, $mode, $secure);
        }
    };
}

interop!(
    rust_to_go_stream_up,
    go_to_rust_stream_up,
    "stream-up",
    false
);
interop!(
    rust_to_go_stream_one,
    go_to_rust_stream_one,
    "stream-one",
    false
);
interop!(
    rust_to_go_stream_up_tls_http11,
    go_to_rust_stream_up_tls_http11,
    "stream-up",
    true
);
interop!(
    rust_to_go_stream_one_tls_http11,
    go_to_rust_stream_one_tls_http11,
    "stream-one",
    true
);
