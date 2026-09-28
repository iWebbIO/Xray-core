//! End-to-end reverse proxying with two `Server` instances in one process,
//! mirroring Go's documented reverse topology: the portal side faces the
//! client and exposes a carrier tunnel inbound, the bridge side hosts the
//! final target and dials its carriers out to the portal.

use std::{net::SocketAddr, time::Duration};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use xray_core::{Config, Server, address::Destination};

/// Fixed carrier domain; the portal's selector and the bridge's dial target.
const BRIDGE_DOMAIN: &str = "bridge.reverse.test";
/// Shared short VLESS user id for the carrier tunnel (short ids are hashed
/// like Go's `parse_id`, so both sides derive the same UUID).
const TUNNEL_USER: &str = "reverse-e2e";

/// Persistent TCP echo service; every accepted connection echoes its bytes.
struct Echo {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn echo() -> Echo {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if stream.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Echo { address, task }
}

/// The client-facing side: a portal (reverse `portals`), a carrier tunnel
/// inbound the bridge dials into, and a SOCKS inbound for the real client.
/// Client requests are routed to the portal tag, the outbound that opens
/// sessions through the reverse tunnel.
fn portal_config() -> Config {
    Config::from_json(
        &json!({
            "reverse": {"portals": [{"tag": "portal", "domain": BRIDGE_DOMAIN}]},
            "inbounds": [
                {"tag": "tunnel", "listen": "127.0.0.1", "port": 0, "protocol": "vless",
                 "settings": {"decryption": "none", "clients": [{"id": TUNNEL_USER}]}},
                {"tag": "client-in", "listen": "127.0.0.1", "port": 0, "protocol": "socks",
                 "settings": {"auth": "noauth"}}
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"inboundTag": ["client-in"], "outboundTag": "portal"}]}
        })
        .to_string(),
    )
    .unwrap()
}

/// The target-hosting side: a bridge (reverse `bridges`) that dials its
/// `domain:0`/TCP carriers to the portal's tunnel inbound and dispatches the
/// portal's inner sessions to the final target through freedom.
fn bridge_config(tunnel: SocketAddr) -> Config {
    Config::from_json(
        &json!({
            "reverse": {"bridges": [{"tag": "bridge", "domain": BRIDGE_DOMAIN}]},
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "to-portal", "protocol": "vless",
                 "settings": {"address": "127.0.0.1", "port": tunnel.port(),
                              "id": TUNNEL_USER, "encryption": "none"}}
            ],
            "routing": {"rules": [{"domain": [format!("full:{BRIDGE_DOMAIN}")],
                                    "outboundTag": "to-portal"}]}
        })
        .to_string(),
    )
    .unwrap()
}

/// SOCKS5 noauth CONNECT to `destination` over `proxy`.
async fn socks_connect(proxy: SocketAddr, destination: SocketAddr) -> std::io::Result<TcpStream> {
    let mut client = TcpStream::connect(proxy).await?;
    client.write_all(&[5, 1, 0]).await?;
    let mut methods = [0; 2];
    client.read_exact(&mut methods).await?;
    if methods != [5, 0] {
        return Err(std::io::Error::other("SOCKS server rejected noauth"));
    }
    client.write_all(&[5, 1, 0]).await?;
    Destination::from(destination)
        .write_socks(&mut client)
        .await
        .map_err(std::io::Error::other)?;
    let mut reply = [0; 3];
    client.read_exact(&mut reply).await?;
    if reply != [5, 0, 0] {
        return Err(std::io::Error::other("SOCKS CONNECT rejected"));
    }
    Destination::read_socks(&mut client)
        .await
        .map_err(std::io::Error::other)?;
    Ok(client)
}

/// One full exchange through the portal; `None` while the first carrier is
/// still being dialed or attached so the caller can retry.
async fn try_exchange(
    client_in: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let result = timeout(Duration::from_secs(2), async {
        let mut client = socks_connect(client_in, target).await?;
        client.write_all(payload).await?;
        let mut response = vec![0_u8; payload.len()];
        client.read_exact(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    })
    .await;
    match result {
        Ok(Ok(response)) if response.as_slice() == payload => Some(response),
        _ => None,
    }
}

#[tokio::test]
async fn reverse_relays_tcp_from_portal_client_to_bridge_echo() {
    timeout(Duration::from_secs(10), async {
        let echo = echo().await;
        // The portal starts first: its tunnel inbound must be listening
        // before the bridge dials its first carrier.
        let portal = Server::start(portal_config()).await.unwrap();
        let addresses = portal.local_addresses();
        let (tunnel, client_in) = (addresses[0], addresses[1]);
        let bridge = Server::start(bridge_config(tunnel)).await.unwrap();

        // A SOCKS client of the portal asks for the echo service "behind" the
        // bridge: client → portal inbound → carrier → bridge → freedom → echo.
        // Retry while the bridge's first carrier is still being dialed.
        let payload = b"reverse runtime payload";
        let response = loop {
            if let Some(response) = try_exchange(client_in, echo.address, payload).await {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(response, payload.to_vec());

        // A second request on a fresh connection reuses the live carrier.
        let response = loop {
            if let Some(response) = try_exchange(client_in, echo.address, b"second").await {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(response, b"second".to_vec());

        bridge.shutdown().await.unwrap();
        portal.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_reverse_entries_fail_startup_before_listening() {
    // Go NewPortal order: an empty portal tag aborts Reverse.Init.
    let config = Config::from_json(
        &json!({
            "reverse": {"portals": [{"tag": "", "domain": BRIDGE_DOMAIN}]},
            "outbounds": [{"protocol": "freedom"}]
        })
        .to_string(),
    )
    .unwrap();
    let error = match Server::start(config).await {
        Err(error) => error.to_string(),
        Ok(server) => {
            server.shutdown().await.unwrap();
            panic!("empty portal tag must fail")
        }
    };
    assert!(error.contains("portal tag is empty"), "{error}");

    let config = Config::from_json(
        &json!({
            "reverse": {"bridges": [{"tag": "bridge", "domain": "bridge.reverse.test", "extra": true}]},
            "outbounds": [{"protocol": "freedom"}]
        })
        .to_string(),
    )
    .unwrap();
    assert!(Server::start(config).await.is_err());
}
