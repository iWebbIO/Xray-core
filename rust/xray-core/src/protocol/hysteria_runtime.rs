// P10 hysteria_runtime: the hysteria inbound and outbound proxy sessions
// over the QUIC endpoint, ported from Go proxy/hysteria/{server,client}.go.
// The inbound accepts the protocol's TCP streams and UDP sessions from
// transport::hysteria_endpoint and dispatches them through the
// HysteriaDispatch seam (Go's routing.Dispatcher.DispatchLink); the outbound
// dials through the endpoint's tested Quinn client helpers and speaks the
// tested wire codecs for the target.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, ensure};
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::protocol::hysteria::{
    ReassemblyLimits, TcpRequest, TcpResponse, UdpMessage, UdpReassembler,
};
use crate::{
    address::Destination,
    transport::{
        BoxStream,
        hysteria::{
            AuthRequest, AuthenticatedConnection, ClientOptions, NativeCongestion, PaddingKind,
            random_padding,
        },
        hysteria_endpoint::{
            HysteriaClientDialer, HysteriaConnection, HysteriaEvent, QuicProxyStream, UdpSession,
        },
    },
};

/// Go's `HysteriaUserConfig` (infra/conf/hysteria.go): the inbound's account
/// rows, exactly those keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct HysteriaUser {
    /// The shared secret presented in the `Hysteria-Auth` header.
    pub auth: String,
    pub level: u32,
    pub email: String,
}

/// Go's `HysteriaServerConfig` (the inbound proxy settings): `version` must
/// be 2 and `clients` replaces `users` when present (a JSON `null` or an
/// absent field keeps `users`, exactly like Go's nil check).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct HysteriaInboundSettings {
    pub version: i32,
    pub users: Vec<HysteriaUser>,
    pub clients: Option<Vec<HysteriaUser>>,
}

impl HysteriaInboundSettings {
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid hysteria inbound settings")
    }

    /// Go `HysteriaServerConfig.Build`: only version 2 exists.
    pub fn validate(&self) -> Result<&Self> {
        ensure!(self.version == 2, "hysteria inbound version != 2");
        Ok(self)
    }

    /// The users after Go's `clients` override.
    pub fn effective_users(&self) -> &[HysteriaUser] {
        match &self.clients {
            Some(clients) => clients,
            None => &self.users,
        }
    }
}

/// Go's `HysteriaClientConfig` (the outbound proxy settings): `version` must
/// be 2; the server is `address` (a host, never `host:port` — Go parses it
/// with net.ParseAddress) plus `port`.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct HysteriaOutboundSettings {
    pub version: i32,
    pub address: String,
    pub port: u16,
}

impl HysteriaOutboundSettings {
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("invalid hysteria outbound settings")
    }

    pub fn validate(&self) -> Result<&Self> {
        ensure!(self.version == 2, "hysteria outbound version != 2");
        Ok(self)
    }

    /// The dialed server destination (Go's ServerEndpoint).
    pub fn server(&self) -> Result<Destination> {
        Destination::new(&self.address, self.port)
    }
}

// ---------------------------------------------------------------------------
// The dispatch seam
// ---------------------------------------------------------------------------

pub type HysteriaDispatchFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Go's `routing.Dispatcher.DispatchLink` payload for one established
/// hysteria TCP proxy stream: route, establish and relay all run inside the
/// returned future, exactly like Go's DispatchLink.
pub struct TcpDispatch {
    pub destination: Destination,
    /// The QUIC peer address.
    pub source: SocketAddr,
    /// The authenticated user; `None` when the transport-level `auth`
    /// secret authenticated the connection (Go's empty MemoryUser).
    pub user: Option<HysteriaUser>,
    pub stream: BoxStream,
}

/// Go's DispatchLink payload for one hysteria UDP session: each outgoing
/// datagram carries its own destination; replies are addressed to
/// `destination` — the first packet's target, the fixed address of Go's
/// `UDPWriter`.
pub struct UdpDispatch {
    pub destination: Destination,
    pub source: SocketAddr,
    pub user: Option<HysteriaUser>,
    /// Reassembled client datagrams (payload plus per-packet destination).
    pub packets: mpsc::Receiver<(Destination, Vec<u8>)>,
    /// Reply payloads for the session's client.
    pub responses: mpsc::Sender<Vec<u8>>,
}

/// The seam the integrator implements over the runtime dispatcher. The
/// inbound hands every authenticated TCP stream and UDP session here.
pub trait HysteriaDispatch: Send + Sync {
    fn dispatch_stream(&self, connection: TcpDispatch) -> HysteriaDispatchFuture;
    fn dispatch_udp(&self, session: UdpDispatch) -> HysteriaDispatchFuture;
}

// ---------------------------------------------------------------------------
// The inbound server
// ---------------------------------------------------------------------------

/// Go's proxy/hysteria Server over the QUIC endpoint: one instance serves
/// every accepted connection of one inbound.
pub struct HysteriaInbound {
    seam: Arc<dyn HysteriaDispatch>,
    handshake_timeout: Duration,
}

impl HysteriaInbound {
    pub fn new(seam: Arc<dyn HysteriaDispatch>) -> Self {
        Self {
            seam,
            handshake_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_handshake_timeout(mut self, limit: Duration) -> Self {
        self.handshake_timeout = limit;
        self
    }

    /// Serve one accepted QUIC connection until it ends: every TCP request
    /// reads its header, answers with an OK response and dispatches through
    /// the seam; every UDP session is handed over the same way.
    pub async fn serve_connection(&self, mut connection: HysteriaConnection) -> Result<()> {
        let source = connection.remote_address();
        let mut sessions = tokio::task::JoinSet::new();
        let result = loop {
            tokio::select! {
                event = connection.next() => {
                    let Some(event) = event else {
                        break Ok(());
                    };
                    match event {
                        HysteriaEvent::Tcp { user, stream } => {
                            let seam = self.seam.clone();
                            let limit = self.handshake_timeout;
                            sessions.spawn(async move {
                                if let Err(error) =
                                    serve_tcp(seam, stream, source, user, limit).await
                                {
                                    tracing::debug!(%source, %error, "hysteria TCP session ended");
                                }
                            });
                        }
                        HysteriaEvent::Udp { user, session } => {
                            let seam = self.seam.clone();
                            sessions.spawn(async move {
                                if let Err(error) =
                                    serve_udp_session(seam, session, source, user).await
                                {
                                    tracing::debug!(%source, %error, "hysteria UDP session ended");
                                }
                            });
                        }
                    }
                }
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    // The session tasks log their own outcomes; reap the join.
                    if let Some(Err(error)) = joined {
                        tracing::debug!(%error, "hysteria session task panicked");
                    }
                }
            }
        };
        while sessions.join_next().await.is_some() {}
        result
    }
}

/// Go's Server.Process TCP branch: read the request under the handshake
/// deadline, answer OK, then hand the whole stream to the dispatcher.
async fn serve_tcp(
    seam: Arc<dyn HysteriaDispatch>,
    streams: (quinn::SendStream, quinn::RecvStream),
    source: SocketAddr,
    user: Option<HysteriaUser>,
    handshake_timeout: Duration,
) -> Result<()> {
    let (mut send, mut recv) = streams;
    // The endpoint consumed the 0x401 frame varint; Go's ReadTCPRequest
    // reads the address and padding fields with a read deadline set.
    let request = timeout(handshake_timeout, TcpRequest::read(&mut recv))
        .await
        .context("hysteria TCP request timed out")??;
    let destination = Destination::parse_authority(&request.address, None)?;
    // Go's WriteTCPResponse(buffered, true, ""): status 0, empty message.
    let response = TcpResponse {
        status: 0,
        message: Vec::new(),
        padding: random_padding(PaddingKind::TcpResponse).into_bytes(),
    };
    send.write_all(&response.encode()?).await?;
    let stream = QuicProxyStream::new((send, recv));
    seam.dispatch_stream(TcpDispatch {
        destination,
        source,
        user,
        stream: Box::new(stream),
    })
    .await
}

/// Go's Server.Process InterConn branch: the first reassembled datagram
/// fixes the link destination, every further datagram keeps its own
/// destination, and replies go back to the client session.
async fn serve_udp_session(
    seam: Arc<dyn HysteriaDispatch>,
    session: UdpSession,
    source: SocketAddr,
    user: Option<HysteriaUser>,
) -> Result<()> {
    let mut session = session;
    let mut reassembler = UdpReassembler::new(ReassemblyLimits::default())?;
    // Go's UDPReader.ReadFrom blocks until one complete datagram arrives.
    let first = loop {
        let Some(frame) = session.recv_raw().await else {
            anyhow::bail!("hysteria UDP session ended before its first datagram");
        };
        let Some(message) = decode_frame(&frame) else {
            continue;
        };
        if let Some(complete) = feed(&mut reassembler, message) {
            break complete;
        }
    };
    let destination = Destination::parse_authority(&first.address, None)?;
    let (packets, packet_queue) = mpsc::channel::<(Destination, Vec<u8>)>(64);
    let (responses, mut response_queue) = mpsc::channel::<Vec<u8>>(64);
    // Go replays the first datagram through reader.firstBuf.
    packets.send((destination.clone(), first.payload)).await?;
    let address = destination.to_string();
    let mut pump = tokio::spawn(async move {
        loop {
            tokio::select! {
                frame = session.recv_raw() => {
                    let Some(frame) = frame else { break };
                    let Some(message) = decode_frame(&frame) else { continue };
                    let Some(complete) = feed(&mut reassembler, message) else { continue };
                    let Ok(target) = Destination::parse_authority(&complete.address, None) else {
                        continue;
                    };
                    if packets.send((target, complete.payload)).await.is_err() {
                        break;
                    }
                }
                response = response_queue.recv() => {
                    let Some(payload) = response else { break };
                    let message = UdpMessage {
                        session_id: 0,
                        packet_id: 0,
                        fragment_id: 0,
                        fragment_count: 1,
                        address: address.clone(),
                        payload,
                    };
                    if session.send(message).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let dispatch = seam.dispatch_udp(UdpDispatch {
        destination,
        source,
        user,
        packets: packet_queue,
        responses,
    });
    let result = tokio::select! {
        result = dispatch => result,
        _ = &mut pump => Ok(()),
    };
    pump.abort();
    result
}

fn decode_frame(frame: &Bytes) -> Option<UdpMessage> {
    UdpMessage::decode(frame).ok()
}

/// Go's Defragger.Feed discards malformed or conflicting packets; the
/// bounded reassembler keeps the same behavior with explicit limits.
fn feed(reassembler: &mut UdpReassembler, message: UdpMessage) -> Option<UdpMessage> {
    match reassembler.feed(message, Instant::now()) {
        Ok(complete) => complete,
        Err(error) => {
            tracing::debug!(%error, "hysteria UDP fragment dropped");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// The outbound client
// ---------------------------------------------------------------------------

struct ClientUdpState {
    connection: Option<AuthenticatedConnection>,
    next_session: u32,
    sessions: Arc<StdMutex<HashMap<u32, mpsc::Sender<UdpMessage>>>>,
    router: Option<JoinHandle<()>>,
}

impl ClientUdpState {
    fn install(&mut self, connection: AuthenticatedConnection) {
        self.shutdown();
        let sessions: Arc<StdMutex<HashMap<u32, mpsc::Sender<UdpMessage>>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let router_sessions = sessions.clone();
        let router_connection = connection.clone();
        let router = tokio::spawn(async move {
            // Go's udpSessionManager.run: route every received datagram to
            // its session and close them all when the loop ends.
            while let Ok(message) = router_connection.receive_udp_fragment().await {
                let sessions = router_sessions.lock().expect("hysteria UDP sessions");
                if let Some(sender) = sessions.get(&message.session_id) {
                    let _ = sender.try_send(message);
                }
            }
            router_sessions
                .lock()
                .expect("hysteria UDP sessions")
                .clear();
        });
        self.connection = Some(connection);
        self.sessions = sessions;
        self.router = Some(router);
        self.next_session = 1;
    }

    fn shutdown(&mut self) {
        if let Some(router) = self.router.take() {
            router.abort();
        }
        if let Some(connection) = self.connection.take() {
            connection.close();
        }
        self.sessions.lock().expect("hysteria UDP sessions").clear();
    }
}

/// Go's proxy/hysteria Client: one shared authenticated QUIC session per
/// outbound (Go's clientManager cache), one 0x401 stream per TCP request and
/// one datagram session per UDP request.
pub struct HysteriaOutbound {
    dialer: HysteriaClientDialer,
    state: tokio::sync::Mutex<ClientUdpState>,
}

impl HysteriaOutbound {
    pub fn new(dialer: HysteriaClientDialer) -> Self {
        Self {
            dialer,
            state: tokio::sync::Mutex::new(ClientUdpState {
                connection: None,
                next_session: 1,
                sessions: Arc::new(StdMutex::new(HashMap::new())),
                router: None,
            }),
        }
    }

    async fn ensure_connection(
        &self,
        state: &mut ClientUdpState,
    ) -> Result<AuthenticatedConnection> {
        if state.connection.is_none() {
            let connection = self.dialer.connect().await?;
            state.install(connection);
        }
        Ok(state
            .connection
            .clone()
            .expect("just installed or already present"))
    }

    /// Go Process, TCP branch: open one stream toward `target` on the shared
    /// authenticated session (the request/response handshake happens inside
    /// the tested client helper) and relay until either side closes.
    pub async fn process_tcp<D: AsyncRead + AsyncWrite + Unpin>(
        &self,
        target: &Destination,
        downstream: &mut D,
    ) -> Result<()> {
        let mut stream = self.open_tcp(target).await?;
        match tokio::io::copy_bidirectional(downstream, &mut stream).await {
            Ok(_) => Ok(()),
            Err(error) => Err(anyhow::Error::new(error).context("connection ends")),
        }
    }

    /// Open one proxy stream, redialing once if the cached session died
    /// (Go's `client.dial` status check and reconnect).
    async fn open_tcp(
        &self,
        target: &Destination,
    ) -> Result<crate::transport::hysteria::HysteriaStream> {
        let address = target.to_string();
        let mut state = self.state.lock().await;
        let limit = Duration::from_secs(10);
        for attempt in 0..2 {
            let connection = self.ensure_connection(&mut state).await?;
            let opened = timeout(limit, connection.open_tcp(&address)).await;
            match opened {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) if attempt == 0 => {
                    // The cached session is unusable; close and redial once.
                    state.shutdown();
                    tracing::debug!(%error, "hysteria outbound session was stale; redialing");
                    continue;
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => anyhow::bail!("hysteria TCP request timed out"),
            }
        }
        unreachable!("the loop returns on its second iteration")
    }

    /// One proxy stream for the runtime's establish path: the shared
    /// authenticated session stays cached inside this outbound (Go's
    /// clientManager cache).
    pub async fn open_stream(
        &self,
        target: &Destination,
    ) -> Result<crate::transport::hysteria::HysteriaStream> {
        self.open_tcp(target).await
    }

    /// Go Process, UDP branch: allocate one session id on the shared
    /// authenticated connection and relay `target`'s datagrams both ways.
    pub async fn process_udp(
        &self,
        target: &Destination,
        outbound: mpsc::Receiver<Vec<u8>>,
        inbound: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        // Allocate the session id and register its channel in the router's
        // table (Go's udpSM.udp), then release the state lock.
        let (connection, session_id, mut session_rx) = {
            let mut state = self.state.lock().await;
            let connection = self.ensure_connection(&mut state).await?;
            let session_id = state.next_session;
            state.next_session = state
                .next_session
                .checked_add(1)
                .context("UDP session ids exhausted")?;
            let (session_tx, session_rx) = mpsc::channel::<UdpMessage>(64);
            state
                .sessions
                .lock()
                .expect("hysteria UDP sessions")
                .insert(session_id, session_tx);
            (connection, session_id, session_rx)
        };
        let address = target.to_string();
        let sender = tokio::spawn(async move {
            let mut outbound = outbound;
            while let Some(payload) = outbound.recv().await {
                let message = UdpMessage {
                    session_id,
                    packet_id: 0,
                    fragment_id: 0,
                    fragment_count: 1,
                    address: address.clone(),
                    payload,
                };
                if connection.send_udp(message).is_err() {
                    break;
                }
            }
        });
        let receiver = tokio::spawn(async move {
            while let Some(message) = session_rx.recv().await {
                if inbound.send(message.payload).await.is_err() {
                    break;
                }
            }
        });
        tokio::select! {
            _ = sender => {}
            _ = receiver => {}
        };
        self.state
            .lock()
            .await
            .sessions
            .lock()
            .expect("hysteria UDP sessions")
            .remove(&session_id);
        Ok(())
    }
}

impl Drop for HysteriaOutbound {
    fn drop(&mut self) {
        // Close synchronously what can be closed without awaiting.
        if let Ok(mut state) = self.state.try_lock() {
            state.shutdown();
        }
    }
}

/// Assemble the outbound dialer from the config pieces: the proxy settings'
/// server, the transport settings' auth secret and congestion, the TLS
/// client config, and the QUIC receive bandwidth (`quicParams.brutalDown`).
pub fn client_dialer(
    server: &Destination,
    server_name: &str,
    tls: tokio_rustls::rustls::ClientConfig,
    auth: &str,
    receive_bytes_per_second: u64,
    congestion: NativeCongestion,
) -> HysteriaClientDialer {
    HysteriaClientDialer::new(
        SocketAddr::from(([0, 0, 0, 0], 0)),
        server.clone(),
        server_name.to_owned(),
        tls,
        ClientOptions::new(
            AuthRequest {
                auth: auth.to_owned(),
                receive_bytes_per_second,
            },
            congestion,
        ),
    )
}

/// A cancellation-driven variant the integrator may prefer: stops both
/// pumps when the runtime's token fires.
pub async fn serve_until(
    inbound: Arc<HysteriaInbound>,
    mut listener: crate::transport::hysteria_endpoint::HysteriaEndpointListener,
    cancel: &CancellationToken,
) -> Result<()> {
    loop {
        let connection = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            connection = listener.accept() => match connection {
                Some(connection) => connection,
                None => return Ok(()),
            },
        };
        let inbound = inbound.clone();
        tokio::spawn(async move {
            if let Err(error) = inbound.serve_connection(connection).await {
                tracing::debug!(%error, "hysteria inbound connection ended");
            }
        });
    }
}

// Re-exported for the integrator's convenience: the server options assembled
// from the config pieces.
pub use crate::transport::hysteria_endpoint::{HysteriaServerOptions, Masquerade};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inbound_settings_match_go_keys_and_version() {
        let settings = HysteriaInboundSettings::from_value(&json!({
            "version": 2,
            "users": [{"auth": "a", "level": 3, "email": "u@example"}]
        }))
        .unwrap();
        settings.validate().unwrap();
        assert_eq!(
            settings.effective_users(),
            &[HysteriaUser {
                auth: "a".into(),
                level: 3,
                email: "u@example".into()
            }]
        );
        // clients replaces users when the key is present (Go: != nil).
        let clients = HysteriaInboundSettings::from_value(&json!({
            "version": 2,
            "users": [{"auth": "a"}],
            "clients": [{"auth": "b"}]
        }))
        .unwrap();
        assert_eq!(clients.effective_users()[0].auth, "b");
        assert_eq!(
            HysteriaInboundSettings::from_value(&json!({
                "version": 2, "users": [{"auth": "a"}], "clients": null
            }))
            .unwrap()
            .effective_users()[0]
                .auth,
            "a"
        );
        // Go rejects any other version and unknown keys fail explicitly.
        let wrong = HysteriaInboundSettings::from_value(&json!({"version": 1})).unwrap();
        assert!(wrong.validate().is_err());
        assert!(
            HysteriaInboundSettings::from_value(&json!({"version": 2, "password": "x"})).is_err()
        );
        assert!(
            HysteriaInboundSettings::from_value(
                &json!({"version": 2, "users": [{"auth": "a", "obfs": "x"}]})
            )
            .is_err()
        );
    }

    #[test]
    fn outbound_settings_match_go_keys_and_version() {
        let settings = HysteriaOutboundSettings::from_value(&json!({
            "version": 2, "address": "127.0.0.1", "port": 443
        }))
        .unwrap();
        settings.validate().unwrap();
        assert_eq!(
            settings.server().unwrap(),
            Destination::new("127.0.0.1", 443).unwrap()
        );
        assert!(
            HysteriaOutboundSettings::from_value(&json!({"version": 1, "address": "h", "port": 1}))
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            HysteriaOutboundSettings::from_value(
                &json!({"version": 2, "address": "h", "port": 1, "upMbps": 100})
            )
            .is_err()
        );
        assert!(
            HysteriaOutboundSettings::from_value(&json!({"version": 2}))
                .unwrap()
                .server()
                .is_err()
        );
    }
}
