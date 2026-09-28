//! Transport-level integration of the generic MASQUE transport arm in
//! `OutboundTransport::connect_resolved` against the component hub: the arm
//! dials one TLS+h2 connection at the resolved address, opens an extended
//! CONNECT targeting the dialed destination, and the hub bridges the
//! accepted session, which this harness relays to a local TCP echo.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use xray_core::{
    address::Destination,
    transport::{OutboundTransport, masque, tls},
};

/// Bounded wait, the same discipline as the masque component's own tests.
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("MASQUE transport test timed out")
}

/// Self-signed TLS fixture, mirroring the masque component's test pair: the
/// server holds the key, the client trusts only the pinned certificate.
fn tls_pair() -> (tls::TlsSettings, tls::TlsSettings) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["masque.test".into()]).unwrap();
    let certificate: Vec<_> = cert.pem().lines().map(str::to_owned).collect();
    let server = tls::TlsSettings {
        alpn: vec!["h2".into()],
        certificates: vec![tls::TlsCertificate {
            certificate: certificate.clone(),
            key: signing_key
                .serialize_pem()
                .lines()
                .map(str::to_owned)
                .collect(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let client = tls::TlsSettings {
        disable_system_root: true,
        alpn: vec!["h2".into()],
        certificates: vec![tls::TlsCertificate {
            certificate,
            usage: "verify".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    (server, client)
}

/// A loopback TCP echo server whose accept loop aborts on drop.
struct Echo {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_echo() -> Echo {
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
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Echo { address, task }
}

/// Accepts one hub session, asserts its extended-CONNECT target, and bridges
/// the tunnel to the echo server until either side resets or EOFs.
fn bridge_session(
    mut hub: masque::Hub,
    expected: masque::Target,
    echo: SocketAddr,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let request = bounded(hub.accept()).await.expect("hub accept");
        assert_eq!(request.target, expected);
        let masque::RequestHandle::Stream(mut tunnel) = request.handle else {
            panic!("a TCP target must bridge a stream");
        };
        let mut echo = TcpStream::connect(echo).await.unwrap();
        // A reset or EOF on either side ends the bridge; copy_bidirectional
        // propagates shutdowns so both directions drain cleanly.
        let _ = tokio::io::copy_bidirectional(&mut tunnel, &mut echo).await;
    })
}

fn masque_transport(client_tls: tls::TlsSettings) -> OutboundTransport {
    OutboundTransport {
        masque: Some(masque::Settings::default()),
        masque_tls: Some(client_tls),
        server_name: "masque.test".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn masque_transport_bridges_the_destination_target_to_tcp() {
    let (server_tls, client_tls) = tls_pair();
    let echo = bounded(spawn_echo()).await;
    let hub = masque::Hub::bind("127.0.0.1:0", &masque::Settings::default(), &server_tls)
        .await
        .unwrap();
    let hub_address = hub.local_addr();
    // The tunneled target is the destination — for a generic proxy over the
    // masque transport that is the proxy server itself — while the resolved
    // override decides where the TLS+h2 connection is dialed, which is how a
    // routing-resolved proxy address reaches the masque server.
    let destination = Destination::from(echo.address);
    let server = bridge_session(
        hub,
        masque::Target::tcp("127.0.0.1", echo.address.port()),
        echo.address,
    );
    let (mut stream, bound) =
        bounded(masque_transport(client_tls).connect_resolved(&destination, Some(&[hub_address])))
            .await
            .expect("masque connect");
    // The tunnel's real socket lives inside the retained client; the xhttp
    // arm's placeholder is returned instead of a local address.
    assert_eq!(bound, SocketAddr::from(([0, 0, 0, 0], 0)));
    stream.write_all(b"masque payload").await.unwrap();
    let mut echoed = [0_u8; 14];
    bounded(stream.read_exact(&mut echoed))
        .await
        .expect("echo read");
    assert_eq!(&echoed, b"masque payload");
    // A second exchange proves the tunnel stays open across reads.
    stream.write_all(b"second round").await.unwrap();
    let mut echoed = [0_u8; 12];
    bounded(stream.read_exact(&mut echoed))
        .await
        .expect("echo read 2");
    assert_eq!(&echoed, b"second round");
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    bounded(stream.read_to_end(&mut rest))
        .await
        .expect("client eof");
    assert!(rest.is_empty());
    bounded(server).await.expect("server task");
}

#[tokio::test]
async fn masque_transport_connect_dials_the_destination_directly() {
    let (server_tls, client_tls) = tls_pair();
    let echo = bounded(spawn_echo()).await;
    let hub = masque::Hub::bind("127.0.0.1:0", &masque::Settings::default(), &server_tls)
        .await
        .unwrap();
    let hub_address = hub.local_addr();
    // Without the resolved override an IP destination dials its literal —
    // the production shape, where the masque server and the tunneled proxy
    // server are the same host.
    let destination = Destination::from(hub_address);
    let server = bridge_session(
        hub,
        masque::Target::tcp("127.0.0.1", hub_address.port()),
        echo.address,
    );
    let (mut stream, _bound) = bounded(masque_transport(client_tls).connect(&destination))
        .await
        .expect("masque connect");
    stream.write_all(b"direct dial").await.unwrap();
    let mut echoed = [0_u8; 11];
    bounded(stream.read_exact(&mut echoed))
        .await
        .expect("echo read");
    assert_eq!(&echoed, b"direct dial");
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    bounded(stream.read_to_end(&mut rest))
        .await
        .expect("client eof");
    assert!(rest.is_empty());
    bounded(server).await.expect("server task");
}

#[tokio::test]
async fn dropping_the_returned_stream_tears_down_the_tunnel() {
    let (server_tls, client_tls) = tls_pair();
    let echo = bounded(spawn_echo()).await;
    let hub = masque::Hub::bind("127.0.0.1:0", &masque::Settings::default(), &server_tls)
        .await
        .unwrap();
    let hub_address = hub.local_addr();
    let destination = Destination::from(echo.address);
    let server = bridge_session(
        hub,
        masque::Target::tcp("127.0.0.1", echo.address.port()),
        echo.address,
    );
    let (mut stream, _bound) =
        bounded(masque_transport(client_tls).connect_resolved(&destination, Some(&[hub_address])))
            .await
            .expect("masque connect");
    // Establish the session first so the bridge holds a tunnel end that can
    // observe the reset.
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    bounded(stream.read_exact(&mut echoed))
        .await
        .expect("echo read");
    assert_eq!(&echoed, b"ping");
    // Dropping the stream must reset the CONNECT stream, abort the retained
    // client's h2 driver, and end the hub-side bridge without a panic.
    drop(stream);
    bounded(server).await.expect("server task");
}

#[tokio::test]
async fn masque_without_tls_settings_fails_before_dialing() {
    let transport = OutboundTransport {
        masque: Some(masque::Settings::default()),
        masque_tls: None,
        ..Default::default()
    };
    // Port 9 (discard) is never reached: the arm rejects the configuration
    // before resolving or connecting.
    let destination = Destination::from(SocketAddr::from(([127, 0, 0, 1], 9)));
    let error = match bounded(transport.connect_resolved(&destination, None)).await {
        Err(error) => error,
        Ok(_) => panic!("masque without TLS settings must fail"),
    };
    assert!(error.to_string().contains("security"), "{error}");
}

#[tokio::test]
async fn masque_transport_arm_rejects_http3_alpn() {
    let (_, mut client_tls) = tls_pair();
    client_tls.alpn = vec!["h3".into()];
    let transport = masque_transport(client_tls);
    let destination = Destination::from(SocketAddr::from(([127, 0, 0, 1], 9)));
    let error = match bounded(transport.connect_resolved(&destination, None)).await {
        Err(error) => error,
        Ok(_) => panic!("an h3-only ALPN must not dial"),
    };
    // The arm surfaces the component dialer's policy error; the anyhow
    // context keeps the cause chain, so check the full chain.
    assert!(format!("{error:#}").contains("HTTP/3"), "{error:#}");
}
