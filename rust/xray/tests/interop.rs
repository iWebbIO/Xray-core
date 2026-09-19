//! Opt-in, real-process interoperability against the current Go implementation.
//!
//! Set XRAY_GO_BINARY to an existing Go Xray executable and run
//! `cargo test -p xray --test interop -- --nocapture --test-threads=1`.
//! An absent variable prints SKIPPED; it is not evidence of interoperability.
//! No external network, Go build, shell command, or additional crate is used.

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

const CASE_TIMEOUT: Duration = Duration::from_secs(20);
const USER_ID: &str = "3f28f03e-2e0d-4dc9-a42e-1ea2f6d2d4ee";
const PASSWORD: &str = "interop-only-password";
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
enum Direction {
    RustToGo,
    GoToRust,
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Socks(bool),
    Http(bool),
    Vless,
    Vmess(&'static str),
    Trojan,
    Shadowsocks(&'static str),
    VlessTls(&'static str),
    VlessXhttp(bool),
}

struct Fixture {
    root: PathBuf,
    children: Vec<(String, Child)>,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "xray-interop-{}-{timestamp}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        Ok(Self {
            root,
            children: Vec::new(),
        })
    }

    fn spawn(&mut self, label: &str, executable: &Path, config: &Value) -> io::Result<()> {
        let path = self.root.join(format!("{label}.json"));
        fs::write(&path, serde_json::to_vec_pretty(config)?)?;
        let log = fs::File::create(self.root.join(format!("{label}.log")))?;
        let child = Command::new(executable)
            .args(["run", "-c"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        self.children.push((label.to_owned(), child));
        Ok(())
    }

    fn check_alive(&mut self) -> io::Result<()> {
        for (label, child) in &mut self.children {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "{label} exited before the exchange completed: {status}"
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
            let path = self.root.join(format!("{label}.log"));
            let mut log = Vec::new();
            if let Ok(file) = fs::File::open(path) {
                let _ = file.take(64 * 1024).read_to_end(&mut log);
            }
            output.push_str(&format!(
                "\n--- {label} ---\n{}",
                String::from_utf8_lossy(&log)
            ));
        }
        output
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Children are created directly, never through a shell or detached helper.
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Echo {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Echo {
    fn start(deadline: Instant) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let task = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Windows can inherit the listener's nonblocking mode.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                        let mut buffer = [0; 4096];
                        while !worker_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(count) => {
                                    // Transform bytes so a local accidental loopback cannot pass.
                                    for byte in &mut buffer[..count] {
                                        *byte ^= 0xa5;
                                    }
                                    write_all(&mut stream, &buffer[..count], deadline)?;
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                    ) => {}
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            stop,
            task: Some(task),
        })
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "interop case deadline exceeded"))
}

fn write_all(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "proxy write returned zero",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
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
                    "proxy closed before expected response",
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
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
        return Err(io::Error::other(format!(
            "local SOCKS negotiation failed: {method:?}"
        )));
    }
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    write_all(&mut stream, &request, deadline)?;
    let mut reply = [0; 4];
    read_exact(&mut stream, &mut reply, deadline)?;
    if reply[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!("SOCKS CONNECT failed: {reply:?}")));
    }
    let address_size = match reply[3] {
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
    read_exact(&mut stream, &mut vec![0; address_size + 2], deadline)?;
    Ok(stream)
}

fn stream_settings(case: Case, server: bool) -> Value {
    let xhttp = matches!(case, Case::VlessXhttp(_));
    let tls = matches!(case, Case::VlessTls(_) | Case::VlessXhttp(true));
    let mut value = json!({"network": if xhttp { "xhttp" } else { "tcp" }});
    if xhttp {
        value["xhttpSettings"] = json!({
            "path": "/interop/", "host": "interop.xray.test", "mode": "packet-up",
            "extra": {"xPaddingBytes": "100-100", "scMaxEachPostBytes": 16384,
                      "scMinPostsIntervalMs": 1}
        });
    }
    if tls {
        value["security"] = json!("tls");
        let mut settings = if server {
            json!({"certificates": [{"certificate": TEST_CERTIFICATE.lines().collect::<Vec<_>>(),
                                    "key": TEST_PRIVATE_KEY.lines().collect::<Vec<_>>()}]})
        } else {
            json!({"serverName": "interop.xray.test", "disableSystemRoot": true,
                   "certificates": [{"certificate": TEST_CA.lines().collect::<Vec<_>>(), "usage": "verify"}]})
        };
        settings["alpn"] = json!(["http/1.1"]);
        if let Case::VlessTls(version) = case {
            settings["minVersion"] = json!(version);
            settings["maxVersion"] = json!(version);
        }
        value["tlsSettings"] = settings;
    }
    value
}

fn configs(case: Case, server: SocketAddr, client: SocketAddr) -> (Value, Value) {
    let (protocol, inbound_settings, outbound_settings) = match case {
        Case::Socks(auth) | Case::Http(auth) => {
            let protocol = if matches!(case, Case::Socks(_)) {
                "socks"
            } else {
                "http"
            };
            let mut inbound = json!({});
            let mut remote = json!({"address": "127.0.0.1", "port": server.port()});
            if auth {
                inbound["accounts"] = json!([{"user": "interop", "pass": PASSWORD}]);
                remote["users"] = json!([{"user": "interop", "pass": PASSWORD}]);
            }
            if protocol == "socks" {
                inbound["auth"] = json!(if auth { "password" } else { "noauth" });
                inbound["udp"] = json!(false);
            }
            (protocol, inbound, json!({"servers": [remote]}))
        }
        Case::Vless | Case::VlessTls(_) | Case::VlessXhttp(_) => (
            "vless",
            json!({"clients": [{"id": USER_ID}], "decryption": "none"}),
            json!({"vnext": [{"address": "127.0.0.1", "port": server.port(),
                             "users": [{"id": USER_ID, "encryption": "none"}]}]}),
        ),
        Case::Vmess(security) => (
            "vmess",
            json!({"clients": [{"id": USER_ID, "security": security}]}),
            json!({"vnext": [{"address": "127.0.0.1", "port": server.port(),
                             "users": [{"id": USER_ID, "security": security}]}]}),
        ),
        Case::Trojan => (
            "trojan",
            json!({"clients": [{"password": PASSWORD}]}),
            json!({"servers": [{"address": "127.0.0.1", "port": server.port(), "password": PASSWORD}]}),
        ),
        Case::Shadowsocks(method) => {
            let password = if method.starts_with("2022-") {
                use base64::{Engine, engine::general_purpose::STANDARD};
                STANDARD.encode(vec![23; if method.contains("128") { 16 } else { 32 }])
            } else {
                PASSWORD.to_owned()
            };
            (
                "shadowsocks",
                json!({"method": method, "password": password, "network": "tcp"}),
                json!({"servers": [{"address": "127.0.0.1", "port": server.port(), "method": method, "password": password}]}),
            )
        }
    };
    (
        json!({"log": {"loglevel": "debug"},
               "inbounds": [{"listen": "127.0.0.1", "port": server.port(), "protocol": protocol,
                             "settings": inbound_settings, "streamSettings": stream_settings(case, true)}],
               "outbounds": [{"protocol": "freedom", "settings": {}}]}),
        json!({"log": {"loglevel": "debug"},
               "inbounds": [{"listen": "127.0.0.1", "port": client.port(), "protocol": "socks",
                             "settings": {"auth": "noauth", "udp": false}}],
               "outbounds": [{"protocol": protocol, "settings": outbound_settings,
                              "streamSettings": stream_settings(case, false)}]}),
    )
}

fn run(direction: Direction, case: Case) {
    let Some(go) = env::var_os("XRAY_GO_BINARY") else {
        eprintln!(
            "SKIPPED interoperability {direction:?} {case:?}: XRAY_GO_BINARY is absent; no cross-language exchange ran"
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
    let mut fixture = Fixture::new().expect("create isolated interop fixture");
    let deadline = Instant::now() + CASE_TIMEOUT;
    let outcome = (|| -> io::Result<()> {
        let echo = Echo::start(deadline)?;
        // Hold distinct ephemeral reservations until each process is spawned.
        let server_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let client_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let server_address = server_port.local_addr()?;
        let client_address = client_port.local_addr()?;
        let (mut server_config, client_config) = configs(case, server_address, client_address);
        // Both implementations enforce private-target defaults for encrypted
        // inbounds. Open exactly the owned echo address/port in either direction;
        // these tests measure the wire, while separate tests cover default denial.
        server_config["outbounds"][0]["settings"]["finalRules"] = json!([{
            "action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"],
            "port": echo.address.port()
        }]);
        drop(server_port);
        fixture.spawn("server", server_binary, &server_config)?;
        fixture.wait_ready(server_address, deadline)?;
        drop(client_port);
        fixture.spawn("client", client_binary, &client_config)?;
        fixture.wait_ready(client_address, deadline)?;
        let mut stream = socks_connect(client_address, echo.address, deadline)?;
        // Cross multiple Shadowsocks records/XHTTP packets and include every byte.
        // A second exchange on the same connection checks continued stream state.
        for (size, seed) in [(98_321usize, 17usize), (3_097, 203)] {
            let payload: Vec<_> = (0..size)
                .map(|i| (i.wrapping_mul(73) + seed) as u8)
                .collect();
            write_all(&mut stream, &payload, deadline)?;
            let mut response = vec![0; size];
            read_exact(&mut stream, &mut response, deadline)?;
            if !payload
                .iter()
                .zip(response)
                .all(|(sent, received)| sent ^ 0xa5 == received)
            {
                return Err(io::Error::other("cross-language payload corruption"));
            }
        }
        fixture.check_alive()?;
        drop(stream);
        drop(echo);
        Ok(())
    })();
    if let Err(error) = outcome {
        panic!(
            "interop {direction:?} {case:?} failed: {error}{}",
            fixture.diagnostics()
        );
    }
    eprintln!("INTEROP PASSED {direction:?} {case:?}: two exchanges, 101418 transformed bytes");
}

macro_rules! interop {
    ($rust_name:ident, $go_name:ident, $case:expr) => {
        #[test]
        fn $rust_name() {
            run(Direction::RustToGo, $case);
        }
        #[test]
        fn $go_name() {
            run(Direction::GoToRust, $case);
        }
    };
}

interop!(rust_to_go_socks, go_to_rust_socks, Case::Socks(false));
interop!(
    rust_to_go_socks_auth,
    go_to_rust_socks_auth,
    Case::Socks(true)
);
interop!(rust_to_go_http, go_to_rust_http, Case::Http(false));
interop!(rust_to_go_http_auth, go_to_rust_http_auth, Case::Http(true));
interop!(rust_to_go_vless, go_to_rust_vless, Case::Vless);
interop!(
    rust_to_go_vmess_aes128,
    go_to_rust_vmess_aes128,
    Case::Vmess("aes-128-gcm")
);
interop!(
    rust_to_go_vmess_chacha,
    go_to_rust_vmess_chacha,
    Case::Vmess("chacha20-poly1305")
);
interop!(rust_to_go_trojan, go_to_rust_trojan, Case::Trojan);
interop!(
    rust_to_go_ss_aes128,
    go_to_rust_ss_aes128,
    Case::Shadowsocks("aes-128-gcm")
);
interop!(
    rust_to_go_ss_aes256,
    go_to_rust_ss_aes256,
    Case::Shadowsocks("aes-256-gcm")
);
interop!(
    rust_to_go_ss_chacha,
    go_to_rust_ss_chacha,
    Case::Shadowsocks("chacha20-ietf-poly1305")
);
interop!(
    rust_to_go_ss2022_aes128,
    go_to_rust_ss2022_aes128,
    Case::Shadowsocks("2022-blake3-aes-128-gcm")
);
interop!(
    rust_to_go_ss2022_aes256,
    go_to_rust_ss2022_aes256,
    Case::Shadowsocks("2022-blake3-aes-256-gcm")
);
interop!(rust_to_go_tls12, go_to_rust_tls12, Case::VlessTls("1.2"));
interop!(rust_to_go_tls13, go_to_rust_tls13, Case::VlessTls("1.3"));
interop!(rust_to_go_xhttp, go_to_rust_xhttp, Case::VlessXhttp(false));
interop!(
    rust_to_go_xhttp_tls,
    go_to_rust_xhttp_tls,
    Case::VlessXhttp(true)
);

// Fixed, public test-only CA and server key. Trusted only in these loopback configs.
// Certificates have a SAN for interop.xray.test and validity from 2020 to 2045.

const TEST_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIBbDCCARKgAwIBAgICCe0wCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgWHJheSBp
bnRlcm9wZXJhYmlsaXR5IGZpeHR1cmUgQ0EwHhcNMjAwMTAxMDAwMDAwWhcNNDUw
MTAxMDAwMDAwWjArMSkwJwYDVQQDDCBYcmF5IGludGVyb3BlcmFiaWxpdHkgZml4
dHVyZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNtAk/S8PXdYKCPBYJzD
BGBNyQg8RXvkxbBpQeg65oQbrlwKpPIU+s/tLxTu+ShvD2G3hEmMfkN5AP8E81fD
OnWjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqG
SM49BAMCA0gAMEUCIBcahoSNMzivfyUkmTwnOGvBJVWwigFFl94Dz05T55OCAiEA
mYuUePRpQ/Gm7hzyqvaq0nnGX+4ZpNBrHautVmTJ6JY=
-----END CERTIFICATE-----
"#;

const TEST_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBgDCCASagAwIBAgICCe4wCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgWHJheSBp
bnRlcm9wZXJhYmlsaXR5IGZpeHR1cmUgQ0EwHhcNMjAwMTAxMDAwMDAwWhcNNDUw
MTAxMDAwMDAwWjAcMRowGAYDVQQDDBFpbnRlcm9wLnhyYXkudGVzdDBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABMj8IddWzi+t8JeXYZHCLyoRD8a6HxqtDeIOMPDO
QEp2B6mafCLfNFnYj6Bl9uqljuWq2xeg51EgffQAg6RB5xejSTBHMAwGA1UdEwEB
/wQCMAAwIgYDVR0RBBswGYIRaW50ZXJvcC54cmF5LnRlc3SHBH8AAAEwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIgQN8oRKDdI5ACKK5c1XPQ
WL1cvVacVi3lDQO6DR3OjKECIQCTw2DzYuLBHMXrLnxGw9MFnidhuLW1TjVX6zcZ
uDQRWA==
-----END CERTIFICATE-----
"#;

const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnkEGjkvE1zIzW0AI
6tLjy6+y8imQGgVFRUy8QMgqKI2hRANCAATI/CHXVs4vrfCXl2GRwi8qEQ/Guh8a
rQ3iDjDwzkBKdgepmnwi3zRZ2I+gZfbqpY7lqtsXoOdRIH30AIOkQecX
-----END PRIVATE KEY-----
"#;
