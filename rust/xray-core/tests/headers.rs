//! Integration of the TCP header obfuscation codecs against the exact
//! expectations of Go's `transport/internet/headers/http/http_test.go`:
//! the connection roundtrip (TestConnection), the invalid-path 404 flow
//! (TestConnectionInvPath), the non-HTTP request 400 flow
//! (TestConnectionInvReq), body replay after the header block, and the
//! noop identity codec. Everything runs over loopback TCP with bounded
//! waits, or over in-memory duplex streams where the codec is pure.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use xray_core::transport::{
    BoxStream,
    headers::{HeaderCodec, HeaderSettings, accept_side, dial_side},
};

const WAIT: Duration = Duration::from_secs(5);

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    timeout(WAIT, future)
        .await
        .expect("tcp header test timed out")
}

/// The TestConnection/TestConnectionInvPath configuration: a Post request
/// for /testpath answered by a 404 response.
fn http_header_config(path: &str) -> Value {
    json!({
        "type": "http",
        "request": {
            "version": "1.1",
            "method": "Post",
            "path": [path],
            "headers": {
                "Host": ["www.example.com", "www.google.com"],
                "User-Agent": ["Test-Agent"]
            }
        },
        "response": {
            "version": "1.1",
            "status": "404",
            "reason": "Not Found"
        }
    })
}

fn codec(value: &Value) -> HeaderCodec {
    HeaderCodec::compile(&HeaderSettings::from_value(value).unwrap()).unwrap()
}

/// Reads from a raw peer until the stream ends, bounded.
async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    bytes
}

/// An echo server behind accept_side, mirroring Go's test goroutine.
fn echo_server(listener: TcpListener, header: Value) -> JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream: BoxStream = accept_side(codec(&header), Box::new(tcp)).await?;
        let mut buffer = [0_u8; 256];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            stream.write_all(&buffer[..read]).await?;
        }
        Ok(())
    })
}

#[tokio::test]
async fn go_test_connection_roundtrip_over_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = echo_server(listener, http_header_config("/testpath"));

    let tcp = bounded(TcpStream::connect(address)).await.unwrap();
    let mut client: BoxStream = dial_side(codec(&http_header_config("/testpath")), Box::new(tcp))
        .await
        .unwrap();
    client.write_all(b"Test payload").await.unwrap();
    client.write_all(b"Test payload 2").await.unwrap();

    let expected: &[u8] = b"Test payloadTest payload 2";
    let mut received = Vec::new();
    while received.len() < expected.len() {
        let mut chunk = [0_u8; 64];
        let read = bounded(client.read(&mut chunk)).await.unwrap();
        assert!(read > 0, "client stream closed early");
        received.extend_from_slice(&chunk[..read]);
    }
    // The response header was skipped: exactly the echoed payload remains.
    assert_eq!(received, expected);
    client.shutdown().await.unwrap();
    bounded(server).await.unwrap().unwrap();
}

#[tokio::test]
async fn dial_side_emits_the_go_request_header_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // A single Host value keeps the rendered request deterministic.
    let header = json!({
        "type": "http",
        "request": {
            "version": "1.1",
            "method": "Post",
            "path": ["/testpath"],
            "headers": {"Host": ["www.example.com"], "User-Agent": ["Test-Agent"]}
        }
    });
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut expected =
            b"Post /testpath HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Test-Agent\r\n\r\n"
                .to_vec();
        expected.extend_from_slice(b"Test payload");
        let mut wire = vec![0_u8; expected.len()];
        tcp.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire, expected);
    });

    let tcp = bounded(TcpStream::connect(address)).await.unwrap();
    let mut client: BoxStream = dial_side(codec(&header), Box::new(tcp)).await.unwrap();
    client.write_all(b"Test payload").await.unwrap();
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn go_test_connection_inv_path_answers_404_and_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let error = accept_side(codec(&http_header_config("/testpath")), Box::new(tcp))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("Header Mismatch."), "{error}");
    });

    let mut tcp = bounded(TcpStream::connect(address)).await.unwrap();
    tcp.write_all(
        b"Post /testpathErr HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Test-Agent\r\n\r\n",
    )
    .await
    .unwrap();
    tcp.write_all(b"Test payload").await.unwrap();
    tcp.write_all(b"Test payload 2").await.unwrap();

    let wire = bounded(read_to_end(&mut tcp)).await;
    let text = String::from_utf8_lossy(&wire).to_string();
    assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
    assert!(text.contains("Connection: close\r\n"), "{text}");
    assert!(text.contains("Cache-Control: private\r\n"), "{text}");
    assert!(text.contains("Content-Length: 0\r\n"), "{text}");
    assert!(text.contains("Date: "), "{text}");
    // The payload was never relayed back.
    assert!(!text.contains("Test payload"), "{text}");
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn go_test_connection_inv_req_answers_400_to_non_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let error = accept_side(codec(&http_header_config("/testpath")), Box::new(tcp))
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("malformed HTTP request"),
            "{error}"
        );
    });

    let mut tcp = bounded(TcpStream::connect(address)).await.unwrap();
    tcp.write_all(b"ABCDEFGHIJKMLN\r\n\r\n").await.unwrap();
    let wire = bounded(read_to_end(&mut tcp)).await;
    let text = String::from_utf8_lossy(&wire).to_string();
    assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
    assert!(text.contains("Content-Length: 0\r\n"), "{text}");
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn body_bytes_coalesced_with_the_header_are_never_lost() {
    // Loopback with a binary payload that itself contains CRLFCRLF: the
    // wrapper must consume only the request header and relay the rest
    // verbatim, and the client must skip only the response header.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut payload: Vec<u8> = (0..=255).collect();
    payload.extend_from_slice(b"\r\n\r\nBODY-AFTER-ENDING");
    let echo_payload = payload.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream: BoxStream = accept_side(codec(&json!({"type": "http"})), Box::new(tcp))
            .await
            .unwrap();
        let mut received = Vec::new();
        let mut chunk = [0_u8; 128];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(received, echo_payload);
        stream.write_all(&echo_payload).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let tcp = bounded(TcpStream::connect(address)).await.unwrap();
    let mut client: BoxStream = dial_side(codec(&json!({"type": "http"})), Box::new(tcp))
        .await
        .unwrap();
    // One write: the request header is injected in front of the payload.
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    let mut chunk = [0_u8; 128];
    loop {
        let read = bounded(client.read(&mut chunk)).await.unwrap();
        if read == 0 {
            break;
        }
        received.extend_from_slice(&chunk[..read]);
    }
    assert_eq!(received, payload);
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn noop_header_is_a_pure_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let payload: Vec<u8> = (0..=255).collect();
    let echo_payload = payload.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream: BoxStream = accept_side(codec(&json!({"type": "none"})), Box::new(tcp))
            .await
            .unwrap();
        let mut received = vec![0_u8; echo_payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, echo_payload);
        stream.write_all(&echo_payload).await.unwrap();
    });

    let tcp = bounded(TcpStream::connect(address)).await.unwrap();
    let mut client: BoxStream = dial_side(codec(&json!({"type": ""})), Box::new(tcp))
        .await
        .unwrap();
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0_u8; payload.len()];
    bounded(client.read_exact(&mut received)).await.unwrap();
    assert_eq!(received, payload);
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn client_skips_any_terminated_response_header_without_parsing() {
    // resp.go "tolerance": the outbound side never parses the response, so
    // even a nonsense status block is skipped and the body is relayed.
    let (mut peer, client) = tokio::io::duplex(4096);
    let mut client: BoxStream = dial_side(codec(&json!({"type": "http"})), Box::new(client))
        .await
        .unwrap();
    peer.write_all(b"HTTP/0.9 999 nonsense\r\nX: [\x7f-free\r\n\r\nBODY")
        .await
        .unwrap();
    let mut body = vec![0_u8; 4];
    bounded(client.read_exact(&mut body)).await.unwrap();
    assert_eq!(&body, b"BODY");
    peer.write_all(b"tail").await.unwrap();
    let mut tail = [0_u8; 4];
    bounded(client.read_exact(&mut tail)).await.unwrap();
    assert_eq!(&tail, b"tail");
}

#[test]
fn json_surface_rejections_and_defaults() {
    // Unknown types fail with Go's loader error text.
    let error = HeaderSettings::from_value(&json!({"type": "srtp"}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown config id: srtp"), "{error}");
    // A missing type key fails like Go's loader.
    let error = HeaderSettings::from_value(&json!({}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("type not found in JSON context"), "{error}");
    // Null header values parse but fail at compile, like Go's Build.
    let settings = HeaderSettings::from_value(&json!({
        "type": "http",
        "request": {"headers": {"Host": null}}
    }))
    .unwrap();
    let error = HeaderCodec::compile(&settings).err().unwrap().to_string();
    assert!(error.contains("empty HTTP header value: Host"), "{error}");
    // Malformed list values fail at parse, like Go's StringList.
    let error = HeaderSettings::from_value(&json!({
        "type": "http",
        "request": {"path": 123}
    }))
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("unknown format of a string list: 123"),
        "{error}"
    );
    // Empty type means noop, and the type match is case-insensitive.
    assert_eq!(
        HeaderSettings::from_value(&json!({"type": ""}))
            .unwrap()
            .kind(),
        xray_core::transport::headers::HeaderKind::Noop
    );
    assert_eq!(
        HeaderSettings::from_value(&json!({"type": "HTTP"}))
            .unwrap()
            .kind(),
        xray_core::transport::headers::HeaderKind::Http
    );
}
