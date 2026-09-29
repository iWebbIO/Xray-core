//! The xdrive transport through the real runtime: a SOCKS server proxy whose
//! inbound listens on the object store, and a SOCKS client proxy dialing
//! through it — the proxy traffic rides shared object storage, not a socket.

use std::time::Duration;

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use xray_core::{Config, Server};

const ENVELOPE: Duration = Duration::from_secs(15);

/// A TCP echo server the chain relays to, through freedom.
async fn echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(size) => {
                            if stream.write_all(&buffer[..size]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// A unique object-store directory per test run.
fn store_dir() -> String {
    std::env::temp_dir()
        .join(format!(
            "xdrive-runtime-{}-{}.d",
            std::process::id(),
            line!()
        ))
        .to_string_lossy()
        .replace('\\', "/")
}

/// The `xdriveSettings` both sides share (local storage, Go's keys).
fn xdrive_settings(folder: &str) -> serde_json::Value {
    json!({
        "service": "local",
        "remoteFolder": folder,
        "segmentBytes": 65536,
        "flushIntervalMs": 20,
        "pollIntervalMs": 50,
        "maxPollIntervalMs": 500,
        "sessionTtlSeconds": 60,
        "concurrency": 4,
        "eagerWindowMs": 2000,
        "holeTimeoutMs": 10000
    })
}

async fn socks_connect(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
) -> std::io::Result<TcpStream> {
    let mut client = TcpStream::connect(proxy).await?;
    client.write_all(&[5, 1, 0]).await?;
    let mut methods = [0; 2];
    client.read_exact(&mut methods).await?;
    client.write_all(&[5, 1, 0]).await?;
    xray_core::address::Destination::from(target)
        .write_socks(&mut client)
        .await
        .map_err(std::io::Error::other)?;
    let mut head = [0; 3];
    client.read_exact(&mut head).await?;
    if head != [5, 0, 0] {
        return Err(std::io::Error::other("SOCKS CONNECT rejected"));
    }
    xray_core::address::Destination::read_socks(&mut client)
        .await
        .map_err(std::io::Error::other)?;
    Ok(client)
}

#[tokio::test]
async fn xdrive_transport_relays_through_two_runtimes() {
    timeout(ENVELOPE, async {
        let echo = echo_server().await;
        let store = store_dir();

        // The server proxy: a SOCKS inbound whose listener is the object
        // store, freedom to the echo.
        let server_config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "xdrive-in", "protocol": "socks",
                    "settings": {"auth": "noauth"},
                    "streamSettings": {
                        "network": "xdrive",
                        "xdriveSettings": xdrive_settings(&store)
                    }
                }],
                "outbounds": [{
                    "tag": "direct", "protocol": "freedom",
                    "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo.port()}
                    ]}
                }]
            })
            .to_string(),
        )
        .unwrap();
        let server = Server::start(server_config).await.unwrap();

        // The client proxy: SOCKS inbound, SOCKS outbound over the same
        // object store.
        let client_config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "socks-in", "protocol": "socks",
                    "settings": {"auth": "noauth"}
                }],
                "outbounds": [{
                    "tag": "proxy", "protocol": "socks",
                    "settings": {"address": "example.invalid", "port": 1},
                    "streamSettings": {
                        "network": "xdrive",
                        "xdriveSettings": xdrive_settings(&store)
                    }
                }]
            })
            .to_string(),
        )
        .unwrap();
        let client = Server::start(client_config).await.unwrap();

        // The relay: SOCKS through both hops to the echo target — every
        // proxy byte of the second hop rides the object store.
        let mut proxy = socks_connect(client.local_addresses()[0], echo)
            .await
            .expect("the SOCKS handshake through both hops");
        proxy.write_all(b"xdrive relay").await.unwrap();
        let mut echoed = [0u8; 12];
        proxy.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"xdrive relay");

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    })
    .await
    .expect("the xdrive runtime test timed out");
}

#[tokio::test]
async fn xdrive_config_names_its_rejections() {
    let base = json!({
        "inbounds": [{
            "listen": "127.0.0.1", "port": 0, "protocol": "socks",
            "settings": {"auth": "noauth"},
            "streamSettings": {"network": "xdrive", "xdriveSettings": xdrive_settings(&store_dir())}
        }],
        "outbounds": [{"protocol": "freedom"}]
    });
    // An empty remoteFolder passes Build-time validation and fails at the
    // storage compile (Go's newStorage), surfacing at startup by name.
    let mut empty = base.clone();
    empty["inbounds"][0]["streamSettings"]["xdriveSettings"]["remoteFolder"] = json!("");
    let config = Config::from_json(&empty.to_string()).unwrap();
    config.validate().expect("Build-time validation passes");
    let error = match Server::start(config).await {
        Err(error) => error,
        Ok(_) => panic!("an empty remoteFolder must fail at startup, not serve"),
    };
    assert!(
        format!("{error:#}").contains("remoteFolder"),
        "the compile-time rejection must name the folder: {error:#}"
    );

    // Security must be none over the object store.
    let mut tls = base.clone();
    tls["inbounds"][0]["streamSettings"]["security"] = json!("tls");
    let error = Config::from_json(&tls.to_string())
        .and_then(|config| config.validate())
        .unwrap_err();
    assert!(format!("{error:#}").contains("security none"), "{error:#}");

    // xdriveSettings belongs to the xdrive transport only.
    let mut misplaced = base.clone();
    misplaced["inbounds"][0]["streamSettings"]["network"] = json!("tcp");
    let error = Config::from_json(&misplaced.to_string())
        .and_then(|config| config.validate())
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("xdrive transport"),
        "{error:#}"
    );

    // Unknown services fail by name.
    let mut unknown = base.clone();
    unknown["inbounds"][0]["streamSettings"]["xdriveSettings"]["service"] = json!("dropbox");
    let error = Config::from_json(&unknown.to_string())
        .and_then(|config| config.validate())
        .unwrap_err();
    assert!(format!("{error:#}").contains("service"), "{error:#}");
}
