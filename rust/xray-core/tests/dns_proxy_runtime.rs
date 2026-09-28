//! The dns proxy component and the loopback outbound against local
//! fixtures: the inbound answers wire queries through a hand-built UDP DNS
//! fixture (like dns/app.rs's own tests), `nonDNSQuery` forwarding runs
//! through a TCP echo, and loopback relays through a mock dispatcher seam.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use xray_core::{
    address::{Address, Destination},
    config::SniffingConfig,
    dns::wire,
    protocol::{dns_proxy, loopback},
    transport::BoxStream,
};

/// Every wait is bounded by the outer five-second budget.
const BUDGET: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A local UDP DNS fixture built like dns/app.rs's own tests: every query
/// is answered with the fixed address for its family, and the queries are
/// recorded.
struct UdpDnsFixture {
    address: SocketAddr,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
}

impl UdpDnsFixture {
    async fn start(ipv4: IpAddr, ipv6: IpAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                let Ok(query) = wire::decode(&buffer[..size]) else {
                    continue;
                };
                let Some(question) = query.questions.first().cloned() else {
                    continue;
                };
                log.lock()
                    .unwrap()
                    .push((question.name.clone(), question.record_type.0));
                let ip = if question.record_type == wire::RecordType::A {
                    ipv4
                } else {
                    ipv6
                };
                let answer = wire::encode_response(
                    query.header.id,
                    &question,
                    &[ip],
                    60,
                    0,
                    None,
                    wire::MAX_MESSAGE_SIZE,
                )
                .unwrap();
                let _ = socket.send_to(&answer, peer).await;
            }
        });
        Self {
            address,
            queries,
            task,
        }
    }

    fn saw(&self, name: &str, q_type: u16) -> bool {
        self.queries
            .lock()
            .unwrap()
            .iter()
            .any(|(seen, seen_type)| seen == name && *seen_type == q_type)
    }
}

impl Drop for UdpDnsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The DNS client seam over the fixture: one UDP query per lookup, exactly
/// what the integrator builds over `dns::app::DnsApp`.
struct FixtureResolver {
    server: SocketAddr,
}

impl dns_proxy::DnsQuery for FixtureResolver {
    fn lookup(&self, domain: &str, ipv4: bool, _ipv6: bool) -> dns_proxy::DnsLookupFuture {
        let server = self.server;
        let domain = domain.to_owned();
        Box::pin(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let record = if ipv4 {
                wire::RecordType::A
            } else {
                wire::RecordType::AAAA
            };
            let question = wire::Question::new(&domain, record).map_err(io::Error::other)?;
            let query = wire::encode_query(0x4d53, &question, None).map_err(io::Error::other)?;
            socket.send_to(&query, server).await?;
            let mut buffer = vec![0u8; 1500];
            let (size, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .map_err(|_| io::Error::other("fixture resolver timed out"))??;
            let response = wire::decode(&buffer[..size]).map_err(io::Error::other)?;
            Ok(response
                .answers
                .into_iter()
                .filter_map(|record| match record.data {
                    wire::RecordData::A(ip) => Some(IpAddr::V4(ip)),
                    wire::RecordData::Aaaa(ip) => Some(IpAddr::V6(ip)),
                    _ => None,
                })
                .collect())
        })
    }
}

/// The dial seam over plain TCP, like the runtime's freedom transport.
struct TcpDialer;

static DIALER: TcpDialer = TcpDialer;

impl dns_proxy::DnsForwardDial for TcpDialer {
    fn dial_forward(&self, destination: &Destination) -> dns_proxy::DnsDialFuture {
        let destination = destination.clone();
        Box::pin(async move {
            let stream = match &destination.address {
                Address::Ip(ip) => {
                    TcpStream::connect(SocketAddr::new(*ip, destination.port)).await?
                }
                Address::Domain(name) => {
                    TcpStream::connect((name.as_str(), destination.port)).await?
                }
            };
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// A TCP echo server: every accepted connection echoes its bytes back.
async fn tcp_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 2048];
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
    (address, task)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn query(id: u16, name: &str, record: wire::RecordType) -> Vec<u8> {
    wire::encode_query(id, &wire::Question::new(name, record).unwrap(), None).unwrap()
}

fn framed(message: &[u8]) -> Vec<u8> {
    let mut frame = (message.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    frame
}

async fn read_frame<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await?;
    let mut payload = vec![0u8; u16::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

// ---------------------------------------------------------------------------
// The DNS inbound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dns_inbound_answers_queries_through_the_dns_app() {
    timeout(BUDGET, async {
        let fixture = UdpDnsFixture::start(
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        )
        .await;
        let resolver = Arc::new(FixtureResolver {
            server: fixture.address,
        });
        let settings = dns_proxy::DnsProxySettings::from_value(&json!({})).unwrap();
        let proxy = dns_proxy::DnsProxy::compile(&settings).unwrap();
        let cancel = CancellationToken::new();
        let (mut client, server_end) = tokio::io::duplex(4096);
        let task = {
            let resolver = Arc::clone(&resolver);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                proxy
                    .serve_inbound(Box::new(server_end), Some(&*resolver), &DIALER, &cancel)
                    .await
            })
        };

        // An A query: answered with the fixture's fixed IPv4, in Go's
        // AA/RD/RA response form.
        client
            .write_all(&framed(&query(
                0x0102,
                "fixed.example",
                wire::RecordType::A,
            )))
            .await
            .unwrap();
        let message = wire::decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(message.header.id, 0x0102);
        assert_eq!(message.questions[0].name, "fixed.example.");
        assert_eq!(message.header.flags & 0x000f, 0);
        assert_ne!(message.header.flags & 0x0400, 0, "authoritative");
        assert_ne!(message.header.flags & 0x0080, 0, "recursion available");
        assert_eq!(message.answers.len(), 1);
        assert_eq!(
            message.answers[0].data,
            wire::RecordData::A("192.0.2.10".parse().unwrap())
        );
        assert_eq!(message.answers[0].ttl, 300, "features/dns DefaultTTL");

        // An AAAA query: the fixture's fixed IPv6.
        client
            .write_all(&framed(&query(
                0x0304,
                "v6.example",
                wire::RecordType::AAAA,
            )))
            .await
            .unwrap();
        let message = wire::decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(
            message.answers[0].data,
            wire::RecordData::Aaaa("2001:db8::10".parse().unwrap())
        );

        // A non-IP query under the default profile returns Go's empty
        // NOERROR answer (applyRules' Return rule).
        client
            .write_all(&framed(&query(0x0506, "txt.example", wire::RecordType(16))))
            .await
            .unwrap();
        let message = wire::decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(message.header.id, 0x0506);
        assert_eq!(message.questions[0].record_type, wire::RecordType(16));
        assert!(message.answers.is_empty());
        assert_eq!(message.header.flags & 0x000f, 0);

        // Both lookups went through the DNS app seam.
        assert!(fixture.saw("fixed.example.", 1));
        assert!(fixture.saw("v6.example.", 28));

        // Client EOF ends the session cleanly.
        drop(client);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn non_dns_query_forwards_through_the_forward_server() {
    timeout(BUDGET, async {
        let (echo, echo_task) = tcp_echo().await;
        let settings = dns_proxy::DnsProxySettings::from_value(&json!({
            "address": "127.0.0.1",
            "port": echo.port(),
            "nonDNSQuery": true
        }))
        .unwrap();
        let proxy = dns_proxy::DnsProxy::compile(&settings).unwrap();
        let cancel = CancellationToken::new();

        // A non-IP DNS query (TXT) forwards to the forward server and the
        // response relays back, frame for frame.
        let (mut client, server_end) = tokio::io::duplex(4096);
        let task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                proxy
                    .serve_inbound(Box::new(server_end), None, &DIALER, &cancel)
                    .await
            })
        };
        let txt = query(0x0708, "forward.example", wire::RecordType(16));
        client.write_all(&framed(&txt)).await.unwrap();
        assert_eq!(read_frame(&mut client).await.unwrap(), txt);
        drop(client);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // A stream that is not DNS at all relays raw — the consumed frame
        // prefix is replayed byte for byte.
        let (mut raw_client, raw_server_end) = tokio::io::duplex(4096);
        let proxy = dns_proxy::DnsProxy::compile(&settings).unwrap();
        let task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                proxy
                    .serve_inbound(Box::new(raw_server_end), None, &DIALER, &cancel)
                    .await
            })
        };
        let bytes = b"not a dns stream at all\r\n";
        raw_client.write_all(bytes).await.unwrap();
        let mut echoed = vec![0u8; bytes.len()];
        raw_client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, bytes);
        drop(raw_client);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        echo_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn inbound_without_non_dns_query_fails_non_dns_streams() {
    timeout(BUDGET, async {
        // Without nonDNSQuery, Go's oversized-frame error fails the
        // connection explicitly instead of relaying raw.
        let settings = dns_proxy::DnsProxySettings::from_value(&json!({})).unwrap();
        let proxy = dns_proxy::DnsProxy::compile(&settings).unwrap();
        let cancel = CancellationToken::new();
        let (mut client, server_end) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            proxy
                .serve_inbound(Box::new(server_end), None, &DIALER, &cancel)
                .await
        });
        client.write_all(&[0xff, 0xff, 1, 2, 3]).await.unwrap();
        drop(client);
        let result = timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
    })
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// The DNS outbound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dns_outbound_hijacks_hijacked_dns_traffic() {
    timeout(BUDGET, async {
        let fixture = UdpDnsFixture::start(
            "192.0.2.20".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
        )
        .await;
        let resolver = Arc::new(FixtureResolver {
            server: fixture.address,
        });
        // Go's zero config: hijack A/AAAA, empty NOERROR for other types.
        let proxy = dns_proxy::DnsProxy::compile(&dns_proxy::DnsProxySettings::default()).unwrap();
        let target = Destination::new("8.8.8.8", 53).unwrap();
        let cancel = CancellationToken::new();
        let (mut client, server_end) = tokio::io::duplex(4096);
        let task = {
            let resolver = Arc::clone(&resolver);
            let target = target.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                proxy
                    .serve_outbound(
                        Box::new(server_end),
                        &target,
                        dns_proxy::Framing::Tcp,
                        Some(&*resolver),
                        &DIALER,
                        &cancel,
                    )
                    .await
            })
        };

        // The hijacked A query answers through the DNS app seam.
        client
            .write_all(&framed(&query(0x1122, "out.example", wire::RecordType::A)))
            .await
            .unwrap();
        let message = wire::decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(message.header.id, 0x1122);
        assert_eq!(
            message.answers[0].data,
            wire::RecordData::A("192.0.2.20".parse().unwrap())
        );
        assert!(fixture.saw("out.example.", 1));

        // A non-IP query returns the default empty NOERROR answer.
        client
            .write_all(&framed(&query(0x1133, "mx.example", wire::RecordType(15))))
            .await
            .unwrap();
        let message = wire::decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert!(message.answers.is_empty());
        assert_eq!(message.header.flags & 0x000f, 0);

        drop(client);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// Loopback
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockDispatcher {
    inbound_tag: Arc<Mutex<Option<String>>>,
    destination: Arc<Mutex<Option<Destination>>>,
    sniffing_enabled: Arc<Mutex<Option<bool>>>,
}

impl loopback::LoopbackDispatch for MockDispatcher {
    fn dispatch_to_inbound(
        &self,
        inbound_tag: &str,
        destination: &Destination,
        mut stream: BoxStream,
        sniffing: &Option<SniffingConfig>,
    ) -> loopback::LoopbackDispatchFuture {
        // The future must own its captures (the seam returns a boxed
        // 'static future), so the recorded state is cloned out of self.
        let seen_tag = Arc::clone(&self.inbound_tag);
        let seen_destination = Arc::clone(&self.destination);
        let seen_sniffing = Arc::clone(&self.sniffing_enabled);
        let inbound_tag = inbound_tag.to_owned();
        let destination = destination.clone();
        let sniffing = sniffing.as_ref().map(|config| config.enabled);
        Box::pin(async move {
            *seen_tag.lock().unwrap() = Some(inbound_tag);
            *seen_destination.lock().unwrap() = Some(destination);
            *seen_sniffing.lock().unwrap() = sniffing;
            // The dispatcher relays the stream: echo every byte until the
            // client closes, proving the stream is live on both sides of
            // the seam.
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => stream.write_all(&buffer[..count]).await?,
                }
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn loopback_relays_the_stream_through_the_dispatcher_seam() {
    timeout(BUDGET, async {
        let mock = Arc::new(MockDispatcher::default());
        let settings = loopback::LoopbackSettings::from_value(&json!({
            "inboundTag": "the-in",
            "sniffing": {"enabled": true, "destOverride": ["http"]}
        }))
        .unwrap();
        let dispatch: Arc<dyn loopback::LoopbackDispatch> = mock.clone();
        let proxy = loopback::Loopback::new(settings, dispatch);
        let destination = Destination::new("internal.example", 443).unwrap();
        let (mut client, server_end) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(async move { proxy.process(&destination, Box::new(server_end)).await });

        // The stream relays both ways through the component: bytes the
        // client writes arrive inside the dispatch, and bytes the dispatch
        // writes arrive back at the client.
        client.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");
        client.write_all(b"loop").await.unwrap();
        let mut buffer = [0u8; 4];
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"loop");

        // Client EOF ends the dispatch and the component returns.
        drop(client);
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // The session was re-dispatched on the loopback's inbound tag,
        // with the original destination and the loopback's sniffing.
        assert_eq!(mock.inbound_tag.lock().unwrap().as_deref(), Some("the-in"));
        assert_eq!(
            mock.destination.lock().unwrap().as_ref(),
            Some(&Destination::new("internal.example", 443).unwrap())
        );
        assert_eq!(*mock.sniffing_enabled.lock().unwrap(), Some(true));
    })
    .await
    .unwrap();
}
