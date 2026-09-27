//! Ordinary observatory root wiring must use real selected outbound paths.
use std::time::Duration;

use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};
use tonic::transport::Channel;
use xray_core::{
    Config, Server,
    api::observatory::{
        observation_wire::OutboundStatus,
        observatory_wire::{
            GetOutboundStatusRequest, observatory_service_client::ObservatoryServiceClient,
        },
    },
};

fn root(outbounds: Value, observatory: Value) -> Config {
    Config::from_json(
        &json!({
            "outbounds":outbounds,
            "observatory":observatory,
            "stats":{},
            "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
            "api":{"tag":"management","listen":"127.0.0.1:0","services":["ObservatoryService"]}
        })
        .to_string(),
    )
    .unwrap()
}

async fn service(server: &Server) -> ObservatoryServiceClient<Channel> {
    ObservatoryServiceClient::connect(format!("http://{}", server.api_address().unwrap()))
        .await
        .unwrap()
}

async fn statuses(client: &mut ObservatoryServiceClient<Channel>) -> Vec<OutboundStatus> {
    client
        .get_outbound_status(GetOutboundStatusRequest {})
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap()
        .status
}

async fn completed(client: &mut ObservatoryServiceClient<Channel>) -> OutboundStatus {
    timeout(Duration::from_secs(3), async {
        loop {
            let mut status = statuses(client).await;
            if !status.is_empty() {
                assert_eq!(status.len(), 1);
                return status.remove(0);
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordinary observatory did not publish its completed probe")
}

async fn headers<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 32 * 1024);
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn service_requires_real_configuration_and_burst_remains_rejected() {
    let missing = Config::from_json(
        &json!({
            "outbounds":[{"tag":"direct","protocol":"freedom"}],
            "api":{"tag":"management","services":["ObservatoryService"]}
        })
        .to_string(),
    )
    .unwrap();
    assert!(
        missing
            .validate()
            .unwrap_err()
            .to_string()
            .contains("observatory")
    );
    let disabled = root(json!([{"tag":"direct","protocol":"freedom"}]), json!({}));
    disabled.validate().unwrap();
    let invalid = root(
        json!([{"tag":"direct","protocol":"freedom"}]),
        json!({"probeURL":"ftp://probe.invalid/"}),
    );
    assert!(invalid.validate().is_err());
    // `burstObservatory` is now a recognized root key: an empty object parses
    // and fails validation through the batch parser's own Go-accurate rule
    // (a valid pingConfig is mandatory).
    let burst = Config::from_json(
        &json!({"outbounds":[{"protocol":"freedom"}],"burstObservatory":{}}).to_string(),
    )
    .unwrap();
    assert!(burst.validate().is_err());
}

#[tokio::test]
async fn real_proxy_probe_publishes_http_response_and_outbound_statistics() {
    timeout(Duration::from_secs(6), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let connect = headers(&mut stream).await;
            assert!(connect.starts_with("CONNECT probe.invalid:80 HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
            let request = headers(&mut stream).await;
            assert!(request.starts_with("GET /health?source=observatory HTTP/1.1\r\n"));
            assert!(request.contains("Host: probe.invalid\r\n"));
            // The ordinary Go observer treats any final HTTP response as alive.
            stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let server = Server::start(root(
            json!([
                {"tag":"default-reject","protocol":"blackhole"},
                {"tag":"proxy-http","protocol":"http","settings":{"address":"127.0.0.1","port":address.port()}}
            ]),
            json!({"subjectSelector":["proxy-"],"probeURL":"http://probe.invalid/health?source=observatory","probeInterval":"1h"}),
        )).await.unwrap();
        let stats = server.stats().unwrap();
        let mut client = service(&server).await;
        let result = completed(&mut client).await;
        assert_eq!(result.outbound_tag, "proxy-http");
        assert!(result.alive);
        assert!(result.last_error_reason.is_empty());
        assert!(result.last_seen_time > 0 && result.last_try_time > 0);
        assert!(result.health_ping.is_none());
        peer.await.unwrap();
        assert!(stats.stat("outbound>>>proxy-http>>>traffic>>>uplink", false).unwrap().value > 0);
        assert!(stats.stat("outbound>>>proxy-http>>>traffic>>>downlink", false).unwrap().value > 0);
        assert_eq!(stats.stat("outbound>>>default-reject>>>traffic>>>uplink", false).unwrap().value, 0);
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn freedom_probe_enforces_final_rule_on_redirect_without_dialing() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server::start(root(
            json!([{"tag":"probe-direct","protocol":"freedom","settings":{
                "redirect":address.to_string(),
                "finalRules":[{"action":"block","ip":["127.0.0.1"],"port":address.port(),"blockDelay":90}]
            }}]),
            json!({"subjectSelector":["probe-direct"],"probeURL":"http://probe.invalid/health","probeInterval":"1h"}),
        )).await.unwrap();
        let mut client = service(&server).await;
        let result = completed(&mut client).await;
        assert_eq!(result.outbound_tag, "probe-direct");
        assert!(!result.alive);
        assert!(result.last_error_reason.contains("freedom final rule blocked observatory target"));
        assert!(result.health_ping.is_none());
        assert!(timeout(Duration::from_millis(50), listener.accept()).await.is_err());
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn unsupported_selected_outbound_never_falls_back_to_direct() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server::start(root(
            json!([{"tag":"default-direct","protocol":"freedom"},{"tag":"reject","protocol":"blackhole"}]),
            json!({"subjectSelector":["reject"],"probeURL":format!("http://{address}/health"),"probeInterval":"1h"}),
        )).await.unwrap();
        let mut client = service(&server).await;
        let result = completed(&mut client).await;
        assert_eq!(result.outbound_tag, "reject");
        assert!(!result.alive);
        assert!(result.last_error_reason.contains("cannot carry observatory TCP probes"));
        assert!(timeout(Duration::from_millis(50), listener.accept()).await.is_err());
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn empty_selector_keeps_server_running_without_invented_observations() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = Server::start(root(
            json!([{"tag":"direct","protocol":"freedom"}]),
            json!({"subjectSelector":[],"probeURL":format!("http://{address}/health"),"probeInterval":"1ms"}),
        )).await.unwrap();
        let mut client = service(&server).await;
        assert!(statuses(&mut client).await.is_empty());
        sleep(Duration::from_millis(100)).await;
        assert!(statuses(&mut client).await.is_empty());
        assert!(timeout(Duration::from_millis(50), listener.accept()).await.is_err());
        server.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn shutdown_cancels_owned_probe_dial_and_preserves_unfinished_status() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (entered, waiting) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            entered.send(()).unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        });
        let server = Server::start(root(
            json!([{"tag":"probe-socks","protocol":"socks","settings":{"address":"127.0.0.1","port":address.port()}}]),
            json!({"subjectSelector":["probe-"],"probeURL":"http://probe.invalid/health","probeInterval":"1h"}),
        )).await.unwrap();
        waiting.await.unwrap();
        let mut client = service(&server).await;
        assert!(statuses(&mut client).await.is_empty());
        timeout(Duration::from_secs(2), server.shutdown()).await.unwrap().unwrap();
        timeout(Duration::from_secs(2), peer).await.unwrap().unwrap();
    }).await.unwrap();
}
