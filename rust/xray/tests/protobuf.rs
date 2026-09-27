//! Native CLI loading of a real Go-produced binary configuration.

use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const CONFIG: &[u8] = include_bytes!("../../fixtures/protobuf/basic.pb");

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xray"));
    command
        .env_remove("xray.location.confdir")
        .env_remove("XRAY_LOCATION_CONFDIR");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
}

fn stdin(args: &[&str], bytes: &[u8]) -> Output {
    let mut child = binary()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "xray-protobuf-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "Configuration OK."
    );
}

#[test]
#[allow(invalid_from_utf8)] // deliberately asserting the binary fixture is not UTF-8
fn binary_file_auto_detection_and_format_override() {
    assert!(std::str::from_utf8(CONFIG).is_err());
    let fixture = Fixture::new();
    let path = fixture.0.join("config.pb");
    fs::write(&path, CONFIG).unwrap();
    assert_success(
        binary()
            .args(["run", "-test", "-c"])
            .arg(&path)
            .output()
            .unwrap(),
    );
    let path = fixture.0.join("input.data");
    fs::write(&path, CONFIG).unwrap();
    assert_success(
        binary()
            .args(["run", "-test", "-format", "protobuf", "-c"])
            .arg(path)
            .output()
            .unwrap(),
    );
}

#[test]
fn binary_stdin_validation_and_dump_preserve_raw_payload() {
    for format in ["pb", "protobuf"] {
        assert_success(stdin(
            &["run", "-test", "-format", format, "-c", "stdin:"],
            CONFIG,
        ));
    }
    let output = stdin(&["run", "-dump", "-format", "pb", "-c", "-"], CONFIG);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dump: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        dump["outbounds"][1]["settings"]["response"]["customResponseData"],
        "/wABgA=="
    );
    assert_eq!(dump["policy"]["levels"]["0"]["handshake"], 0);
}

#[test]
fn malformed_and_multiple_binary_inputs_fail_closed() {
    let output = stdin(&["run", "-test", "-format", "pb", "-c", "stdin:"], &[0xff]);
    assert_eq!(output.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&output.stderr).contains("protobuf"));
    let fixture = Fixture::new();
    let path = fixture.0.join("input.pb");
    fs::write(&path, CONFIG).unwrap();
    let output = binary()
        .args(["run", "-test", "-c"])
        .arg(&path)
        .arg("-c")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&output.stderr).contains("only one protobuf"));
}
