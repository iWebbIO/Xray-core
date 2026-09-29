//! The `tcpSettings.header` obfuscation through the real runtime: a SOCKS
//! client proxy whose outbound carries the HTTP camouflage dialing a SOCKS
//! server proxy whose inbound strips it — the bytes on the wire between the
//! two runtimes are HTTP request/response headers, not a SOCKS handshake.

use std::time::Duration;

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use xray_core::{Config, Server};

const ENVELOPE: Duration = Duration::from_secs(10);

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

/// The HTTP camouflage header both sides share (transport/headers' fixture
/// shape: a POST whose path the client picks from the configured entries).
fn http_header() -> serde_json::Value {
    json!({
        "type": "http",
        "request": {
            "version": "1.1",
            "method": "GET",
            "path": ["/"],
            "headers": {"Host": ["camouflage.example"], "User-Agent": ["curl/8.0.1"]}
        },
        "response": {"version": "1.1", "status": "200", "reason": "OK"}
    })
}

/// A SOCKS5 noauth CONNECT helper.
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
async fn tcp_header_obfs_relays_through_two_runtimes() {
    timeout(ENVELOPE, async {
        let echo = echo_server().await;

        // The server proxy: a SOCKS inbound whose TCP listener strips the
        // camouflage, then freedom to the echo.
        let server_config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "obfs-in", "protocol": "socks",
                    "settings": {"auth": "noauth"},
                    "streamSettings": {
                        "network": "tcp",
                        "tcpSettings": {"header": http_header()}
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
        let server_address = server.local_addresses()[0];

        // The client proxy: SOCKS inbound, SOCKS outbound whose dial emits
        // the camouflage in front of its own handshake.
        let client_config = Config::from_json(
            &json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": 0, "tag": "socks-in", "protocol": "socks",
                    "settings": {"auth": "noauth"}
                }],
                "outbounds": [{
                    "tag": "proxy", "protocol": "socks",
                    "settings": {
                        "address": "127.0.0.1", "port": server_address.port()
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "tcpSettings": {"header": http_header()}
                    }
                }]
            })
            .to_string(),
        )
        .unwrap();
        let client = Server::start(client_config).await.unwrap();

        // The relay: SOCKS through both hops to the echo target.
        let mut proxy = socks_connect(client.local_addresses()[0], echo)
            .await
            .expect("the SOCKS handshake through both hops");
        proxy.write_all(b"obfs relay").await.unwrap();
        let mut echoed = [0u8; 10];
        proxy.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"obfs relay");

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    })
    .await
    .expect("the tcp header runtime test timed out");
}

#[tokio::test]
async fn tcp_header_config_rejects_misplacement() {
    // The header object rides tcpSettings; on any other transport it fails
    // by name, and a null header fails like Go's loader.
    let misplaced = json!({
        "inbounds": [{
            "listen": "127.0.0.1", "port": 0, "protocol": "socks",
            "settings": {"auth": "noauth"},
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": "/"},
                "tcpSettings": {"header": http_header()}
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    });
    let error = Config::from_json(&misplaced.to_string())
        .and_then(|config| config.validate())
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("plain TCP transport"),
        "{error:#}"
    );

    let nulled = json!({
        "inbounds": [{
            "listen": "127.0.0.1", "port": 0, "protocol": "socks",
            "settings": {"auth": "noauth"},
            "streamSettings": {"network": "tcp", "tcpSettings": {"header": null}}
        }],
        "outbounds": [{"protocol": "freedom"}]
    });
    let error = Config::from_json(&nulled.to_string())
        .and_then(|config| config.validate())
        .unwrap_err();
    assert!(format!("{error:#}").contains("header"), "{error:#}");
}
