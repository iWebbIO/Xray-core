use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[allow(clippy::type_complexity)] // test wiring pair
fn fixture() -> (
    mpsc::Sender<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    Dispatcher,
    CancellationToken,
    JoinHandle<io::Result<()>>,
) {
    let config = TunConfig::default();
    let (endpoint, dispatcher) = channels(8).unwrap();
    let (ingress_tx, ingress) = mpsc::channel(8);
    let (egress, egress_rx) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_packets(
        config,
        ingress,
        egress,
        endpoint,
        shutdown.clone(),
    ));
    (ingress_tx, egress_rx, dispatcher, shutdown, task)
}

async fn next<T>(receiver: &mut mpsc::Receiver<T>) -> T {
    timeout(Duration::from_secs(3), receiver.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn packet_runtime_replies_to_icmp_and_dispatches_full_cone_udp() {
    let (input, mut output, mut dispatcher, shutdown, task) = fixture();
    input
        .send(hex(
            "4500001f0000000040018ea7c0000201c63364020800189712345678aabbcc",
        ))
        .await
        .unwrap();
    assert_eq!(
        next(&mut output).await,
        hex("4500001f0000000040018ea7c6336402c00002010000209712345678aabbcc")
    );
    let client = "192.0.2.1:1234".parse().unwrap();
    let target = "198.51.100.2:53".parse().unwrap();
    input
        .send(packet::build_udp(client, target, b"query").unwrap())
        .await
        .unwrap();
    let session = match next(&mut dispatcher.events).await {
        TunEvent::Udp {
            session,
            is_new,
            destination,
            payload,
        } => {
            assert!(is_new);
            assert_eq!(destination, target);
            assert_eq!(payload, b"query");
            assert_eq!(session.source, client);
            session
        }
        _ => panic!("expected UDP event"),
    };
    let other_target = "203.0.113.4:9876".parse().unwrap();
    input
        .send(packet::build_udp(client, other_target, b"second").unwrap())
        .await
        .unwrap();
    match next(&mut dispatcher.events).await {
        TunEvent::Udp {
            session: second,
            is_new,
            destination,
            ..
        } => {
            assert!(!is_new);
            assert_eq!(second, session);
            assert_eq!(destination, other_target);
        }
        _ => panic!("expected UDP event"),
    }
    dispatcher
        .udp
        .send(session, other_target, b"answer".to_vec())
        .await
        .unwrap();
    let raw = next(&mut output).await;
    let ip = packet::parse_ip(&raw).unwrap();
    let udp = packet::parse_udp(&ip).unwrap();
    assert_eq!(udp.source, other_target);
    assert_eq!(udp.destination, client);
    assert_eq!(udp.payload, b"answer");
    dispatcher.udp.close(session).await.unwrap();
    assert!(
        matches!(next(&mut dispatcher.events).await, TunEvent::UdpClosed(key) if key == session)
    );
    assert!(
        dispatcher
            .udp
            .send(session, other_target, b"stale".to_vec())
            .await
            .is_err()
    );
    shutdown.cancel();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancellation_releases_a_blocked_packet_output() {
    let config = TunConfig::default();
    let (endpoint, _dispatcher) = channels(1).unwrap();
    let (input, ingress) = mpsc::channel(1);
    let (egress, _output) = mpsc::channel(1);
    egress.send(vec![0]).await.unwrap(); // Consumer deliberately never drains.
    input
        .send(hex(
            "4500001f0000000040018ea7c0000201c63364020800189712345678aabbcc",
        ))
        .await
        .unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_packets(
        config,
        ingress,
        egress,
        endpoint,
        shutdown.clone(),
    ));
    tokio::task::yield_now().await;
    shutdown.cancel();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancellation_releases_a_blocked_dispatcher_notification() {
    let config = TunConfig::default();
    let (endpoint, mut dispatcher) = channels(1).unwrap();
    let (input, ingress) = mpsc::channel(8);
    let (egress, _output) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_packets(
        config,
        ingress,
        egress,
        endpoint,
        shutdown.clone(),
    ));
    let client = "192.0.2.1:1234".parse().unwrap();
    let remote = "198.51.100.2:53".parse().unwrap();
    input
        .send(packet::build_udp(client, remote, b"1").unwrap())
        .await
        .unwrap();
    let session = match next(&mut dispatcher.events).await {
        TunEvent::Udp { session, .. } => session,
        _ => panic!("UDP event"),
    };
    input
        .send(packet::build_udp(client, remote, b"2").unwrap())
        .await
        .unwrap();
    // Wait until the second packet occupies the only event slot, then close
    // the association so run_udp blocks sending its closure notification.
    timeout(Duration::from_secs(3), async {
        while dispatcher.events.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    dispatcher.udp.close(session).await.unwrap();
    tokio::task::yield_now().await;
    shutdown.cancel();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn closed_ingress_is_an_error_instead_of_successful_tunnel() {
    let (input, _output, _dispatcher, _shutdown, task) = fixture();
    drop(input);
    assert_eq!(
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

fn client_tcp(sequence: u32, acknowledgement: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut tcp = vec![0x30, 0x39, 0x01, 0xbb]; // ports 12345 -> 443
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&acknowledgement.to_be_bytes());
    tcp.extend_from_slice(&[0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0]);
    tcp.extend_from_slice(data);
    let mut pseudo = vec![192, 0, 2, 1, 198, 51, 100, 2, 0, 6];
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    tcp[16..18].copy_from_slice(&packet::checksum(&pseudo).to_be_bytes());
    packet::build_ip(
        "192.0.2.1".parse().unwrap(),
        "198.51.100.2".parse().unwrap(),
        TCP,
        &tcp,
    )
    .unwrap()
}

#[tokio::test]
async fn userspace_tcp_handshake_and_bidirectional_payload_without_tun_device() {
    let (input, mut output, mut dispatcher, shutdown, task) = fixture();
    // Independent Python-generated IPv4/TCP SYN fixture.
    input
        .send(hex(
            "450000280000000040068e99c0000201c6336402303901bb10203040000000005002faf056660000",
        ))
        .await
        .unwrap();
    let syn_ack = next(&mut output).await;
    let ip = packet::parse_ip(&syn_ack).unwrap();
    packet::validate_tcp(&ip).unwrap();
    assert_eq!(ip.payload[13] & 0x12, 0x12);
    assert_eq!(
        u32::from_be_bytes(ip.payload[8..12].try_into().unwrap()),
        0x10203041
    );
    let server_sequence = u32::from_be_bytes(ip.payload[4..8].try_into().unwrap());
    input
        .send(client_tcp(
            0x10203041,
            server_sequence.wrapping_add(1),
            0x10,
            &[],
        ))
        .await
        .unwrap();
    let mut stream = match next(&mut dispatcher.events).await {
        TunEvent::Tcp {
            stream,
            source,
            destination,
        } => {
            assert_eq!(source, "192.0.2.1:12345".parse().unwrap());
            assert_eq!(destination, "198.51.100.2:443".parse().unwrap());
            stream
        }
        _ => panic!("TCP event"),
    };
    input
        .send(client_tcp(
            0x10203041,
            server_sequence.wrapping_add(1),
            0x18,
            b"hello",
        ))
        .await
        .unwrap();
    let mut data = [0; 5];
    timeout(Duration::from_secs(3), stream.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data, b"hello");
    timeout(Duration::from_secs(3), stream.write_all(b"reply"))
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(3), async {
        loop {
            let bytes = output.recv().await.unwrap();
            let ip = packet::parse_ip(&bytes).unwrap();
            packet::validate_tcp(&ip).unwrap();
            let tcp_header = usize::from(ip.payload[12] >> 4) * 4;
            if ip.payload.len() > tcp_header {
                assert_eq!(&ip.payload[tcp_header..], b"reply");
                break;
            }
        }
    })
    .await
    .unwrap();
    shutdown.cancel();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn unsupported_os_never_reports_a_started_device() {
    let (endpoint, _dispatcher) = channels(1).unwrap();
    assert_eq!(
        run_native(TunConfig::default(), endpoint, CancellationToken::new())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}
