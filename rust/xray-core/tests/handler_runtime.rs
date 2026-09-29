//! HandlerService runtime-mutation tests: AddInbound binds and serves a real
//! listener through the runtime's own accept loop, RemoveInbound closes it,
//! and the error contracts (duplicate tag, unknown tag) surface over gRPC.

use std::{net::SocketAddr, time::Duration};

use prost::Message as _;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tonic::{
    Request,
    transport::{Channel, Endpoint},
};
use xray_core::{
    Config, Server,
    proto::xray::{
        app::proxyman::{
            ReceiverConfig,
            command::{
                AddInboundRequest, GetInboundUserRequest, ListInboundsRequest,
                RemoveInboundRequest, handler_service_client::HandlerServiceClient,
            },
        },
        common::{
            net::{IpOrDomain, PortList, PortRange, ip_or_domain},
            serial::TypedMessage,
        },
        core::InboundHandlerConfig,
        proxy::socks::{AuthType, ServerConfig as SocksServerConfig},
    },
};

const ENVELOPE: Duration = Duration::from_secs(10);

/// A TCP echo server the added inbound relays to, through freedom.
async fn echo_server() -> SocketAddr {
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

/// Reserve a free loopback port by binding and dropping a listener.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// One SOCKS InboundHandlerConfig: receiver on the loopback port, the socks
/// ServerConfig with password auth, exactly what `xray api adi` sends.
fn socks_inbound(tag: &str, port: u16) -> InboundHandlerConfig {
    let receiver = ReceiverConfig {
        port_list: Some(PortList {
            range: vec![PortRange {
                from: u32::from(port),
                to: u32::from(port),
            }],
        }),
        listen: Some(IpOrDomain {
            address: Some(ip_or_domain::Address::Ip([127, 0, 0, 1].to_vec())),
        }),
        ..Default::default()
    };
    let proxy = SocksServerConfig {
        auth_type: AuthType::Password as i32,
        accounts: [("user".to_owned(), "pass".to_owned())]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    InboundHandlerConfig {
        tag: tag.to_owned(),
        receiver_settings: Some(TypedMessage {
            r#type: "xray.app.proxyman.ReceiverConfig".to_owned(),
            value: receiver.encode_to_vec(),
        }),
        proxy_settings: Some(TypedMessage {
            r#type: "xray.proxy.socks.ServerConfig".to_owned(),
            value: proxy.encode_to_vec(),
        }),
    }
}

/// A SOCKS5 password CONNECT through the given inbound.
async fn socks_connect(proxy: SocketAddr, destination: SocketAddr) -> std::io::Result<TcpStream> {
    let mut client = TcpStream::connect(proxy).await?;
    client.write_all(&[5, 1, 2]).await?;
    let mut methods = [0; 2];
    client.read_exact(&mut methods).await?;
    if methods != [5, 2] {
        return Err(std::io::Error::other("SOCKS server did not pick password"));
    }
    // The RFC 1929 sub-negotiation: version, then length-prefixed user/pass.
    client
        .write_all(&[1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'])
        .await?;
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await?;
    if reply != [1, 0] {
        return Err(std::io::Error::other("SOCKS password rejected"));
    }
    // The whole request goes on the wire before the reply: head + destination.
    client.write_all(&[5, 1, 0]).await?;
    xray_core::address::Destination::from(destination)
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

/// The runtime with the HandlerService API bound on a loopback port; freedom's
/// finalRules allow the echo port exactly like the interop suites.
async fn runtime_with_api(echo_port: u16) -> (Server, HandlerServiceClient<Channel>) {
    let config = Config::from_json(
        &json!({
            "inbounds": [{
                "listen": "127.0.0.1", "port": 0, "tag": "socks-in", "protocol": "socks",
                "settings": {"auth": "noauth"}
            }],
            "outbounds": [{
                "tag": "direct", "protocol": "freedom",
                "settings": {"finalRules": [
                    {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": echo_port}
                ]}
            }],
            "api": {"tag": "management", "listen": "127.0.0.1:0", "services": ["HandlerService"]}
        })
        .to_string(),
    )
    .unwrap();
    let server = Server::start(config).await.unwrap();
    let address = server.api_address().expect("the API listener is bound");
    let channel = Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (server, HandlerServiceClient::new(channel))
}

#[tokio::test]
async fn add_inbound_binds_and_serves_then_remove_closes() {
    timeout(ENVELOPE, async {
        let echo = echo_server().await;
        let (server, mut client) = runtime_with_api(echo.port()).await;
        let port = free_port();

        client
            .add_inbound(Request::new(AddInboundRequest {
                inbound: Some(socks_inbound("added", port)),
            }))
            .await
            .expect("AddInbound succeeds");

        // The new listener serves a real SOCKS password relay to the echo.
        let proxy = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = socks_connect(proxy, echo)
            .await
            .expect("relay via added inbound");
        stream.write_all(b"added inbound").await.unwrap();
        let mut echoed = [0u8; 13];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"added inbound");

        // The runtime-added inbound lists, and its user queries answer.
        let listed = client
            .list_inbounds(Request::new(ListInboundsRequest {
                is_only_tags: false,
            }))
            .await
            .expect("list inbounds")
            .into_inner();
        assert!(
            listed.inbounds.iter().any(|inbound| inbound.tag == "added"),
            "the added inbound must list"
        );
        // SOCKS carries its accounts in the config, not a user manager: the
        // registry lists no user records for it (Go's GetInboundUser errors
        // on non-user-managed proxies instead — a documented deviation).
        let user = client
            .get_inbound_users(Request::new(GetInboundUserRequest {
                tag: "added".to_owned(),
                email: "user".to_owned(),
            }))
            .await
            .expect("get inbound user")
            .into_inner();
        assert!(
            user.users.is_empty(),
            "the SOCKS inbound has no user-manager records"
        );

        // Duplicate tags are rejected exactly like Go's manager.
        assert!(
            client
                .add_inbound(Request::new(AddInboundRequest {
                    inbound: Some(socks_inbound("added", port))
                }))
                .await
                .is_err(),
            "a duplicate tag must fail"
        );

        // RemoveInbound closes exactly that tag's listeners.
        client
            .remove_inbound(Request::new(RemoveInboundRequest {
                tag: "added".to_owned(),
            }))
            .await
            .expect("RemoveInbound succeeds");
        // The close is asynchronous: poll for the refusal, bounded.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect(proxy).await {
                Err(_) => break,
                Ok(_) if tokio::time::Instant::now() > deadline => {
                    panic!("the removed listener still accepts")
                }
                Ok(_) => sleep(Duration::from_millis(50)).await,
            }
        }
        // An unknown tag fails (Go's ErrNoClue).
        assert!(
            client
                .remove_inbound(Request::new(RemoveInboundRequest {
                    tag: "no-such-inbound".to_owned()
                }))
                .await
                .is_err(),
            "removing an unknown tag must fail"
        );

        server.shutdown().await.unwrap();
    })
    .await
    .expect("the handler runtime test timed out");
}

#[tokio::test]
async fn add_inbound_rejects_unintegrated_configs_by_name() {
    timeout(ENVELOPE, async {
        let echo = echo_server().await;
        let (server, mut client) = runtime_with_api(echo.port()).await;
        let port = free_port();

        // A proxy settings type the decoder does not carry fails explicitly.
        let mut inbound = socks_inbound("mux-in", port);
        inbound.proxy_settings = Some(TypedMessage {
            r#type: "xray.proxy.mux.ServerConfig".to_owned(),
            value: Vec::new(),
        });
        let rejected = client
            .add_inbound(Request::new(AddInboundRequest {
                inbound: Some(inbound),
            }))
            .await;
        let message = rejected.err().map(|status| status.message().to_owned());
        assert!(
            message
                .as_deref()
                .is_some_and(|m| m.contains("not integrated")),
            "the unsupported inbound must fail by name, got {message:?}"
        );
        // Nothing was registered.
        let listed = client
            .list_inbounds(Request::new(ListInboundsRequest {
                is_only_tags: false,
            }))
            .await
            .expect("list inbounds")
            .into_inner();
        assert!(
            !listed
                .inbounds
                .iter()
                .any(|inbound| inbound.tag == "mux-in"),
            "the rejected inbound must not list"
        );

        server.shutdown().await.unwrap();
    })
    .await
    .expect("the rejection test timed out");
}
