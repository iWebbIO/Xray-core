use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xray"))
}

#[test]
fn uuid_matches_go_fixture() {
    let result = binary().args(["uuid", "-i", "example"]).output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        "feb54431-301b-52bb-a6dd-e1e93e81bb9e"
    );
}

#[test]
fn config_stdin_and_legacy_test_flag() {
    let mut child = binary()
        .args(["run", "-c", "stdin:", "-test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"outbounds":[{"protocol":"freedom"}]}"#)
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        "Configuration OK."
    );
    let mut child = binary()
        .args(["-c", "stdin:", "-test"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"outbounds":[{"protocol":"invalid-protocol"}]}"#)
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(23));
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("not migrated")
    );
}

#[test]
fn x25519_matches_rfc7748_public_key() {
    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    let private = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let public = bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let result = binary()
        .args(["x25519", "-i", &URL_SAFE_NO_PAD.encode(private)])
        .output()
        .unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(&format!(
        "Password (PublicKey): {}",
        URL_SAFE_NO_PAD.encode(&public)
    )));
    assert!(text.contains(&format!(
        "Hash32: {}",
        URL_SAFE_NO_PAD.encode(blake3::hash(&public).as_bytes())
    )));
}
