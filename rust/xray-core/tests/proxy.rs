use std::{net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use xray_core::{Config, Server, address::Destination};

struct Echo {
    address: SocketAddr,
    task: JoinHandle<()>,
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
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    Echo { address, task }
}

fn config(protocol: &str, settings: Value) -> Config {
    Config::from_json(&json!({
        "inbounds": [{"listen":"127.0.0.1", "port":0, "tag":"test-in", "protocol":protocol, "settings":settings}],
        "outbounds": [{"tag":"direct", "protocol":"freedom"}]
    }).to_string()).unwrap()
}

async fn socks_connect(address: SocketAddr, destination: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut methods = [0; 2];
    client.read_exact(&mut methods).await.unwrap();
    assert_eq!(methods, [5, 0]);
    client.write_all(&[5, 1, 0]).await.unwrap();
    Destination::from(destination)
        .write_socks(&mut client)
        .await
        .unwrap();
    let mut reply = [0; 3];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0]);
    Destination::read_socks(&mut client).await.unwrap();
    client
}

async fn read_http_header(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        data.push(stream.read_u8().await.unwrap());
    }
    data
}

#[tokio::test]
async fn socks5_preserves_large_payload_and_half_close() {
    timeout(Duration::from_secs(10), async {
        let echo = echo().await;
        let server = Server::start(config("socks", json!({}))).await.unwrap();
        let mut client = socks_connect(server.local_addresses()[0], echo.address).await;
        let payload: Vec<_> = (0..131_072).map(|i| (i % 251) as u8).collect();
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, payload);
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks4a_resolves_domain_and_transfers_payload() {
    timeout(Duration::from_secs(10), async {
        let echo = echo().await;
        let server = Server::start(config("socks", json!({}))).await.unwrap();
        let mut client = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        client.write_all(&[4, 1]).await.unwrap();
        client.write_u16(echo.address.port()).await.unwrap();
        client
            .write_all(b"\x00\x00\x00\x01anonymous\x00localhost\x00hello")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[0, 90]);
        assert_eq!(&response[8..], b"hello");
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_password_authentication_rejects_wrong_password_and_noauth() {
    timeout(Duration::from_secs(5), async {
        let server = Server::start(config(
            "socks",
            json!({"auth":"password","accounts":[{"user":"alice","pass":"secret"}]}),
        ))
        .await
        .unwrap();
        let address = server.local_addresses()[0];
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 255]);
        for (password, status) in [("wrong!", 255), ("secret", 0)] {
            let mut client = TcpStream::connect(address).await.unwrap();
            for byte in [5, 1, 2] {
                client.write_u8(byte).await.unwrap();
            }
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 2]);
            client.write_all(b"\x01\x05alice\x06").await.unwrap();
            client.write_all(password.as_bytes()).await.unwrap();
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, status]);
        }
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_unsupported_command_gets_protocol_error() {
    timeout(Duration::from_secs(5), async {
        let server = Server::start(config("socks", json!({}))).await.unwrap();
        let mut client = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        client.write_all(&[5, 1, 0, 5, 2, 0]).await.unwrap();
        let mut response = [0; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..5], &[5, 0, 5, 7, 0]);
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_outbound_does_not_report_success() {
    timeout(Duration::from_secs(5), async {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = unused.local_addr().unwrap();
        drop(unused);
        let server = Server::start(config("socks", json!({}))).await.unwrap();
        let mut client = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        client.write_all(&[5, 1, 0, 5, 1, 0]).await.unwrap();
        Destination::from(target)
            .write_socks(&mut client)
            .await
            .unwrap();
        let mut response = [0; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..5], &[5, 0, 5, 5, 0]);
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_connect_preserves_pipelined_tunnel_data() {
    timeout(Duration::from_secs(5), async {
        let echo = echo().await;
        let server = Server::start(config("http", json!({}))).await.unwrap();
        let mut client = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        client
            .write_all(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nearly data",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert!(
            read_http_header(&mut client)
                .await
                .starts_with(b"HTTP/1.1 200 ")
        );
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"early data");
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_forward_rewrites_target_and_keeps_credentials_private() {
    timeout(Duration::from_secs(5), async {
        let echo = echo().await;
        let server = Server::start(config("http", json!({"accounts":[{"user":"alice","pass":"secret"}]}))).await.unwrap();
        let mut client = TcpStream::connect(server.local_addresses()[0]).await.unwrap();
        client.write_all(format!("GET http://{}/path?q=1 HTTP/1.1\r\nHost: wrong.invalid\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\nProxy-Connection: keep-alive\r\n\r\n", echo.address).as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = String::new(); client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(response.contains(&format!("Host: {}\r\n", echo.address)));
        assert!(!response.contains("Proxy-") && !response.contains("YWxpY2U") && !response.contains("wrong.invalid"));
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn http_requires_authentication() {
    timeout(Duration::from_secs(5), async {
        let server = Server::start(config(
            "http",
            json!({"accounts":[{"user":"alice","pass":"secret"}]}),
        ))
        .await
        .unwrap();
        let mut client = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        client
            .write_all(b"CONNECT example.org:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert!(
            read_http_header(&mut client)
                .await
                .starts_with(b"HTTP/1.1 407 ")
        );
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn routing_blackhole_returns_custom_response_without_dialing() {
    timeout(Duration::from_secs(5), async {
        let mut config = config("socks", json!({}));
        config.outbounds.push(serde_json::from_value(json!({"tag":"blocked","protocol":"blackhole","settings":{"response":{"type":"custom","customResponseData":"YmxvY2tlZA=="}}})).unwrap());
        config.routing = serde_json::from_value(json!({"rules":[{"inboundTag":["test-in"],"outboundTag":"blocked"}]})).unwrap();
        let server = Server::start(config).await.unwrap();
        let mut client = socks_connect(server.local_addresses()[0], "192.0.2.1:443".parse().unwrap()).await;
        let mut response = Vec::new(); client.read_to_end(&mut response).await.unwrap(); assert_eq!(response, b"blocked");
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn dokodemo_and_shutdown_release_connections_and_port() {
    timeout(Duration::from_secs(5), async {
        let echo = echo().await;
        let server = Server::start(config(
            "dokodemo-door",
            json!({"address":"127.0.0.1","port":echo.address.port()}),
        ))
        .await
        .unwrap();
        let address = server.local_addresses()[0];
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"dokodemo").await.unwrap();
        client.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"dokodemo");
        server.shutdown().await.unwrap();
        assert!(TcpListener::bind(address).await.is_ok());
        let server = Server::start(config("socks", json!({}))).await.unwrap();
        let mut pending = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        pending.write_all(&[5]).await.unwrap();
        server.shutdown().await.unwrap();
        let mut byte = [0];
        assert!(matches!(pending.read(&mut byte).await, Ok(0) | Err(_)));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bind_failure_rolls_back_previous_listeners() {
    timeout(Duration::from_secs(5), async {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = reserved.local_addr().unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = occupied.local_addr().unwrap();
        let mut config = config("socks", json!({}));
        config.inbounds[0].port = xray_core::config::PortSpec::single(first.port());
        let mut next = config.inbounds[0].clone();
        next.tag = "conflicting".into();
        next.port = xray_core::config::PortSpec::single(second.port());
        config.inbounds.push(next);
        drop(reserved);
        assert!(Server::start(config).await.is_err());
        assert!(TcpListener::bind(first).await.is_ok());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_outbound_chains_socks_http_vless_and_trojan() {
    timeout(Duration::from_secs(10), async {
        for protocol in ["socks", "http", "vless", "vmess", "trojan", "shadowsocks"] {
            let echo = echo().await;
            let inbound_settings = match protocol {
                "socks" => json!({"auth":"password","accounts":[{"user":"alice","pass":"secret"}]}),
                "http" => json!({"accounts":[{"user":"alice","pass":"secret"}]}),
                "vless" => json!({"decryption":"none","clients":[{"id":"example","email":"test@example.org"}]}),
                "vmess" => json!({"clients":[{"id":"example","email":"test@example.org"}]}),
                "trojan" => json!({"clients":[{"password":"secret","email":"test@example.org"}]}),
                "shadowsocks" => json!({"method":"aes-128-gcm","password":"secret"}),
                _ => unreachable!(),
            };
            let mut remote_config = config(protocol, inbound_settings);
            remote_config.outbounds[0].settings=json!({"finalRules":[{"action":"allow","ip":["127.0.0.1"],"port":echo.address.port()}]});
            let remote = Server::start(remote_config).await.unwrap();
            let address = remote.local_addresses()[0];
            let settings = match protocol {
                "socks" | "http" => json!({"address":"127.0.0.1","port":address.port(),"user":"alice","pass":"secret"}),
                "vless" => json!({"address":"127.0.0.1","port":address.port(),"id":"example","encryption":"none"}),
                "vmess" => json!({"address":"127.0.0.1","port":address.port(),"id":"example","security":"aes-128-gcm"}),
                "trojan" => json!({"address":"127.0.0.1","port":address.port(),"password":"secret"}),
                "shadowsocks" => json!({"address":"127.0.0.1","port":address.port(),"method":"aes-128-gcm","password":"secret"}),
                _ => unreachable!(),
            };
            let mut front = config("socks", json!({}));
            front.outbounds[0] = serde_json::from_value(json!({"protocol":protocol,"settings":settings})).unwrap();
            let front = Server::start(front).await.unwrap();
            let mut client = socks_connect(front.local_addresses()[0], echo.address).await;
            client.write_all(b"chained proxy payload").await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new(); client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"chained proxy payload", "{protocol}");
            front.shutdown().await.unwrap(); remote.shutdown().await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn shadowsocks_2022_runtime_chains_both_aes_ciphers() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    timeout(Duration::from_secs(15), async {
        for (method, key_len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
        ] {
            let target = echo().await;
            let password = STANDARD.encode(vec![11; key_len]);
            let mut remote_config = config(
                "shadowsocks",
                json!({"method":method,"password":password,"email":"ss2022@test"}),
            );
            remote_config.outbounds[0].settings = json!({"finalRules":[{
                "action":"allow","ip":["127.0.0.1"],"port":target.address.port()
            }]});
            let remote = Server::start(remote_config).await.unwrap();
            let address = remote.local_addresses()[0];
            let mut front_config = config("socks", json!({}));
            front_config.outbounds[0] = serde_json::from_value(json!({
                "protocol":"shadowsocks","settings":{"servers":[{
                    "address":"127.0.0.1","port":address.port(),
                    "method":method,"password":password
                }]}
            }))
            .unwrap();
            let front = Server::start(front_config).await.unwrap();
            let mut client = socks_connect(front.local_addresses()[0], target.address).await;
            let payload: Vec<u8> = (0..140_017).map(|i| (i % 251) as u8).collect();
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload, "{method}");
            front.shutdown().await.unwrap();
            remote.shutdown().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn configured_tls_and_xhttp_proxy_chains_transfer_bytes() {
    timeout(Duration::from_secs(20), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem: Vec<_> = certificate.cert.pem().lines().map(str::to_owned).collect();
        let key: Vec<_> = certificate.signing_key.serialize_pem().lines().map(str::to_owned).collect();
        for (network, secure) in [("tcp", true), ("xhttp", false), ("xhttp", true), ("ws", false), ("ws", true), ("httpupgrade", false), ("httpupgrade", true)] {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_address = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (mut connection, _) = target.accept().await.unwrap();
                let mut input = [0; 14]; connection.read_exact(&mut input).await.unwrap();
                assert_eq!(&input, b"transport-test");
                connection.write_all(&input).await.unwrap(); connection.shutdown().await.unwrap();
            });
            let mut inbound_stream = json!({"network":network});
            let mut outbound_stream = json!({"network":network});
            if network == "xhttp" {
                let settings = json!({"path":"/tunnel","mode":"packet-up","scMinPostsIntervalMs":1});
                inbound_stream["xhttpSettings"] = settings.clone(); outbound_stream["xhttpSettings"] = settings;
            }
            if network == "ws" || network == "httpupgrade" {
                let field=if network == "ws" { "wsSettings" } else { "httpupgradeSettings" };
                inbound_stream[field]=json!({"path":"/tunnel"});
                outbound_stream[field]=json!({"path":"/tunnel"});
            }
            if secure {
                inbound_stream["security"] = json!("tls");
                inbound_stream["tlsSettings"] = json!({"certificates":[{"certificate":pem,"key":key}]});
                outbound_stream["security"] = json!("tls");
                outbound_stream["tlsSettings"] = json!({"serverName":"localhost","disableSystemRoot":true,"certificates":[{"certificate":pem,"usage":"verify"}]});
            }
            let mut remote_config = config("vless", json!({"decryption":"none","clients":[{"id":"example"}]}));
            remote_config.outbounds[0].settings=json!({"finalRules":[{"action":"allow","ip":["127.0.0.1"],"port":target_address.port()}]});
            remote_config.inbounds[0].stream_settings = serde_json::from_value(inbound_stream).unwrap();
            let remote = Server::start(remote_config).await.unwrap();
            let mut front_config = config("socks", json!({}));
            front_config.outbounds[0] = serde_json::from_value(json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":remote.local_addresses()[0].port(),"id":"example","encryption":"none"},"streamSettings":outbound_stream})).unwrap();
            let front = Server::start(front_config).await.unwrap();
            let mut client = socks_connect(front.local_addresses()[0], target_address).await;
            client.write_all(b"transport-test").await.unwrap();
            let mut response = [0;14]; client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"transport-test", "{network} TLS={secure}");
            drop(client); front.shutdown().await.unwrap(); remote.shutdown().await.unwrap(); target_task.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn private_target_default_never_dials_and_shutdown_cancels_blackhole() {
    timeout(Duration::from_secs(5), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = Server::start(config(
            "vless",
            json!({"decryption":"none","clients":[{"id":"example"}]}),
        ))
        .await
        .unwrap();
        let mut stream = TcpStream::connect(remote.local_addresses()[0])
            .await
            .unwrap();
        let account = xray_core::protocol::vless::Account {
            id: *xray_core::user::parse_id("example").unwrap().as_bytes(),
            email: String::new(),
            flow: String::new(),
            level: 0,
        };
        xray_core::protocol::vless::write_request(
            &mut stream,
            &account,
            &Destination::from(target.local_addr().unwrap()),
        )
        .await
        .unwrap();
        stream
            .write_all(b"must never reach loopback")
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        remote.shutdown().await.unwrap();
        let mut data = Vec::new();
        let _ = stream.read_to_end(&mut data).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn configured_policy_statistics_and_access_file_follow_real_traffic() {
    timeout(Duration::from_secs(5),async {
        let target=echo().await;
        let log=std::env::temp_dir().join(format!("xray-rust-access-{}.log",uuid::Uuid::new_v4()));
        let mut value=serde_json::to_value(config("vless",json!({"decryption":"none","clients":[{"id":"example","email":"alice@example.org"}]}))).unwrap();
        value["outbounds"][0]["settings"]=json!({"finalRules":[{"action":"allow","ip":["127.0.0.1"],"port":target.address.port()}]});
        value["log"]=json!({"access":log,"error":"none","maskAddress":"half"});
        value["stats"]=json!({});
        value["policy"]=json!({"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}},"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}});
        let server=Server::start(serde_json::from_value(value).unwrap()).await.unwrap();
        let stats=server.stats().unwrap();
        let stream=TcpStream::connect(server.local_addresses()[0]).await.unwrap();
        let account=xray_core::protocol::vless::Account{id:*xray_core::user::parse_id("example").unwrap().as_bytes(),email:String::new(),flow:String::new(),level:0};
        let mut stream=stream;
        xray_core::protocol::vless::write_request(&mut stream,&account,&Destination::from(target.address)).await.unwrap();
        let mut stream=xray_core::protocol::vless::VlessStream::new(stream);
        let payload=vec![42;65000];
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response=Vec::new(); stream.read_to_end(&mut response).await.unwrap(); assert_eq!(response,payload);
        server.shutdown().await.unwrap();
        for (identity, uplink, downlink) in [
            ("user>>>alice@example.org", 65000, 65000),
            ("inbound>>>test-in", 65026, 65002),
            ("outbound>>>direct", 65000, 65000),
        ] {
            for (direction, expected) in [("uplink",uplink),("downlink",downlink)] {
                assert_eq!(stats.stat(&format!("{identity}>>>traffic>>>{direction}"),false).unwrap().value,expected);
            }
        }
        assert_eq!(stats.get_online_map("user>>>alice@example.org>>>online").unwrap().count(),0);
        let text=std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("accepted") && text.contains("alice@example.org"));
        assert!(!text.contains("127.0.0.1"));
        std::fs::remove_file(&log).unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn configured_handshake_timeout_closes_an_idle_peer() {
    timeout(Duration::from_secs(3), async {
        let mut config = config("socks", json!({}));
        config.policy =
            Some(serde_json::from_value(json!({"levels":{"0":{"handshake":0}}})).unwrap());
        let server = Server::start(config).await.unwrap();
        let mut stream = TcpStream::connect(server.local_addresses()[0])
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn configured_management_api_reads_runtime_counters_directly_and_via_routing() {
    timeout(Duration::from_secs(10),async {
        let mut cfg=serde_json::to_value(config("socks",json!({}))).unwrap();
        cfg["stats"]=json!({});
        cfg["policy"]=json!({"system":{"statsInboundUplink":true,"statsInboundDownlink":true}});
        cfg["api"]=json!({"tag":"management","listen":"127.0.0.1:0","services":["StatsService","LoggerService"]});
        cfg["inbounds"].as_array_mut().unwrap().push(json!({"tag":"api-in","listen":"127.0.0.1","port":0,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":1}}));
        cfg["routing"]=json!({"rules":[{"inboundTag":["api-in"],"outboundTag":"management"}]});
        let server=Server::start(serde_json::from_value(cfg).unwrap()).await.unwrap();
        let target=echo().await;
        let mut stream=socks_connect(server.local_addresses()[0],target.address).await;
        stream.write_all(b"api counted payload").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response=Vec::new();stream.read_to_end(&mut response).await.unwrap();assert_eq!(response,b"api counted payload");
        for address in [server.api_address().unwrap(),server.local_addresses()[1]] {
            use xray_core::api::wire::{GetStatsRequest,stats_service_client::StatsServiceClient};
            let endpoint=format!("http://{address}");
            let mut client=StatsServiceClient::connect(endpoint.clone()).await.unwrap();
            let stat=client.get_stats(GetStatsRequest{name:"inbound>>>test-in>>>traffic>>>uplink".into(),reset:false}).await.unwrap().into_inner().stat.unwrap();
            assert_eq!(stat.value,32);
            use xray_core::api::logger::logger_wire::{RestartLoggerRequest,logger_service_client::LoggerServiceClient};
            let mut client=LoggerServiceClient::connect(endpoint).await.unwrap();
            client.restart_logger(RestartLoggerRequest{}).await.unwrap();
        }
        let api=server.api_address().unwrap();
        server.shutdown().await.unwrap();
        assert!(TcpListener::bind(api).await.is_ok());
    }).await.unwrap();
}
