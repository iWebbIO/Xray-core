use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use boringtun::{
    noise::{Packet, Tunn, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    x25519::{PublicKey, StaticSecret},
};

use super::{DeviceConfig, IpPacket, MAX_DATAGRAM_SIZE, MAX_INNER_PACKET_SIZE, Role, RouteTable};

/// Work returned to the caller. Network packets are UDP payloads, and Tunnel
/// packets are complete IP packets suitable for a TCP/IP stack or TUN device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketAction {
    Network {
        /// Stateless cookie replies precede peer identification and have no peer.
        peer: Option<usize>,
        endpoint: SocketAddr,
        packet: Vec<u8>,
    },
    Tunnel {
        peer: usize,
        packet: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub time_since_last_handshake: Option<Duration>,
    /// Provider totals include WireGuard plaintext padding on transmission.
    pub transmitted_bytes: usize,
    pub received_bytes: usize,
    pub estimated_loss: f32,
    pub last_handshake_rtt_ms: Option<u32>,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Debug, Default)]
pub struct TimerEvents {
    pub actions: Vec<PacketAction>,
    /// One peer expiring must not prevent the other peers' timers from running.
    pub errors: Vec<(usize, String)>,
}

enum Outcome {
    Done,
    Network(Vec<u8>),
    Tunnel(Vec<u8>),
}

fn own_result(result: TunnResult<'_>) -> Result<Outcome> {
    Ok(match result {
        TunnResult::Done => Outcome::Done,
        TunnResult::Err(error) => bail!("WireGuard packet rejected: {error:?}"),
        TunnResult::WriteToNetwork(packet) => Outcome::Network(packet.to_vec()),
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            Outcome::Tunnel(packet.to_vec())
        }
    })
}

/// Portable, synchronous WireGuard packet engine. Peer IDs are zero-based
/// configuration positions and stay stable for this device's lifetime.
///
/// Run update_timers about every 250ms, deliver every returned action, and resolve
/// hostname endpoints with the runtime's DNS policy before starting traffic.
/// Up to 256 outgoing packets per peer can await its first handshake inside
/// BoringTun; its bounded queue drops additional packets like a network device.
///
/// This type owns no socket and implements no TCP/IP stack. It must not be used
/// to advertise stream-proxy support before those runtime adapters are wired.
pub struct WireGuardDevice {
    config: DeviceConfig,
    private_key: StaticSecret,
    public_key: PublicKey,
    peers: Vec<Tunn>,
    peers_by_public_key: HashMap<[u8; 32], usize>,
    endpoints: Vec<Option<SocketAddr>>,
    routes: RouteTable,
    rate_limiter: Arc<RateLimiter>,
}

impl WireGuardDevice {
    pub fn new(config: DeviceConfig) -> Result<Self> {
        Self::with_verification_limit(config, 200)
    }

    fn with_verification_limit(
        config: DeviceConfig,
        verifications_per_second: u64,
    ) -> Result<Self> {
        ensure!(
            config.mtu > 0 && config.mtu <= MAX_INNER_PACKET_SIZE,
            "invalid WireGuard MTU"
        );
        ensure!(
            config.peers.len() <= 0x00ff_ffff,
            "WireGuard peer index space exhausted"
        );
        ensure!(
            config.role == Role::Server || !config.peers.is_empty(),
            "WireGuard client requires at least one peer"
        );
        let private_key = StaticSecret::from(*config.private_key.bytes());
        let public_key = PublicKey::from(&private_key);
        // Public BoringTun APIs require a pre-demux MAC/cookie check and a
        // second verification inside Tunn::decapsulate. Share the cookie key
        // and budget 200 verifications (about 100 accepted handshakes/second).
        // Separate limiters would send incompatible cookies under load.
        let rate_limiter = Arc::new(RateLimiter::new(&public_key, verifications_per_second));
        let mut peers = Vec::with_capacity(config.peers.len());
        let mut endpoints = Vec::with_capacity(config.peers.len());
        let mut peers_by_public_key = HashMap::new();
        let mut routes = RouteTable::default();
        for (id, peer) in config.peers.iter().enumerate() {
            ensure!(
                config.role == Role::Server || peer.endpoint.is_some(),
                "WireGuard client peer requires an endpoint"
            );
            if let Some(endpoint) = &peer.endpoint {
                ensure!(
                    endpoint.port != 0 && !endpoint.host.is_empty(),
                    "invalid WireGuard peer endpoint"
                );
            }
            ensure!(
                peer.public_key != *public_key.as_bytes(),
                "WireGuard peer cannot use the local public key"
            );
            ensure!(
                peers_by_public_key.insert(peer.public_key, id).is_none(),
                "duplicate WireGuard peer public key"
            );
            let peer_key = PublicKey::from(peer.public_key);
            ensure!(
                private_key.diffie_hellman(&peer_key).was_contributory(),
                "invalid low-order WireGuard peer public key"
            );
            peers.push(Tunn::new(
                private_key.clone(),
                peer_key,
                peer.preshared_key.as_ref().map(|key| *key.bytes()),
                peer.persistent_keepalive.filter(|interval| *interval != 0),
                (id + 1) as u32,
                Some(Arc::clone(&rate_limiter)),
            ));
            endpoints.push(
                peer.endpoint
                    .as_ref()
                    .and_then(|endpoint| endpoint.socket_addr()),
            );
            for prefix in &peer.allowed_ips {
                routes.insert(*prefix, id);
            }
        }
        Ok(Self {
            config,
            private_key,
            public_key,
            peers,
            peers_by_public_key,
            endpoints,
            routes,
            rate_limiter,
        })
    }

    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    pub fn route(&self, address: std::net::IpAddr) -> Option<usize> {
        self.routes.lookup(address)
    }

    /// Install a trusted DNS resolution or administrative endpoint. Network
    /// packets can subsequently roam this endpoint only after authentication.
    pub fn set_peer_endpoint(&mut self, peer: usize, endpoint: SocketAddr) -> Result<()> {
        ensure!(
            endpoint.port() != 0,
            "WireGuard endpoint port must be nonzero"
        );
        *self
            .endpoints
            .get_mut(peer)
            .context("unknown WireGuard peer")? = Some(endpoint);
        Ok(())
    }

    pub fn peer_stats(&self, peer: usize) -> Result<PeerStats> {
        let tunnel = self.peers.get(peer).context("unknown WireGuard peer")?;
        let (time, tx, rx, loss, rtt) = tunnel.stats();
        Ok(PeerStats {
            time_since_last_handshake: time,
            transmitted_bytes: tx,
            received_bytes: rx,
            estimated_loss: loss,
            last_handshake_rtt_ms: rtt,
            endpoint: self.endpoints[peer],
        })
    }

    /// Initiate/retry a real Noise IKpsk2 handshake. Normal calls should pass
    /// false; the provider's timer state machine handles retransmissions.
    pub fn initiate_handshake(
        &mut self,
        peer: usize,
        force_resend: bool,
    ) -> Result<Vec<PacketAction>> {
        let endpoint = self.endpoint(peer)?;
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        let outcome =
            own_result(self.peers[peer].format_handshake_initiation(&mut buffer, force_resend))?;
        let mut actions = Vec::new();
        self.emit(peer, endpoint, outcome, &mut actions)?;
        Ok(actions)
    }

    /// Encrypt one IP packet using the destination's longest-prefix peer. When
    /// there is no session, the provider queues it and starts the handshake.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<Vec<PacketAction>> {
        let header = IpPacket::parse(packet)?;
        ensure!(
            header.length == packet.len(),
            "outgoing IP packet has trailing bytes"
        );
        ensure!(
            packet.len() <= self.config.mtu,
            "IP packet exceeds WireGuard MTU"
        );
        let peer = self
            .routes
            .lookup(header.destination)
            .context("no WireGuard allowed-IP route for destination")?;
        let endpoint = self.endpoint(peer)?;
        // BoringTun 0.7.1 leaves padding to its caller. WireGuard pads to a
        // multiple of 16 without exceeding the configured inner MTU.
        let padded_length = packet
            .len()
            .div_ceil(16)
            .saturating_mul(16)
            .min(self.config.mtu);
        let mut padded = vec![0; padded_length];
        padded[..packet.len()].copy_from_slice(packet);
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        let outcome = own_result(self.peers[peer].encapsulate(&padded, &mut buffer))?;
        let mut actions = Vec::new();
        self.emit(peer, endpoint, outcome, &mut actions)?;
        Ok(actions)
    }

    /// Authenticate and process an encrypted UDP payload. Replayed, tampered,
    /// unknown-peer and spoofed inner-source packets produce errors, never IP
    /// output. Cookie replies do not authenticate a peer or change endpoints.
    pub fn decapsulate(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
    ) -> Result<Vec<PacketAction>> {
        ensure!(
            (4..=MAX_DATAGRAM_SIZE).contains(&datagram.len()),
            "invalid WireGuard datagram length"
        );
        let mut normalized = datagram.to_vec();
        // Xray's bind.go clears these bytes on receive regardless of the
        // configured outgoing marker; MACs were computed with reserved zero.
        normalized[1..4].fill(0);
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        self.rate_limiter.reset_count();
        let parsed =
            match self
                .rate_limiter
                .verify_packet(Some(source.ip()), &normalized, &mut buffer)
            {
                Ok(packet) => packet,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    let mut packet = cookie.to_vec();
                    self.mark_reserved(&mut packet);
                    return Ok(vec![PacketAction::Network {
                        peer: None,
                        endpoint: source,
                        packet,
                    }]);
                }
                Err(TunnResult::Err(error)) => bail!("WireGuard datagram rejected: {error:?}"),
                Err(_) => bail!("unexpected WireGuard rate limiter result"),
            };
        let peer = match &parsed {
            Packet::HandshakeInit(packet) => {
                let identity = parse_handshake_anon(&self.private_key, &self.public_key, packet)
                    .map_err(|error| anyhow!("WireGuard handshake rejected: {error:?}"))?;
                *self
                    .peers_by_public_key
                    .get(&identity.peer_static_public)
                    .context("unknown WireGuard peer")?
            }
            Packet::HandshakeResponse(packet) => self.peer_from_receiver(packet.receiver_idx)?,
            Packet::PacketCookieReply(packet) => self.peer_from_receiver(packet.receiver_idx)?,
            Packet::PacketData(packet) => self.peer_from_receiver(packet.receiver_idx)?,
        };
        let outcome =
            own_result(self.peers[peer].decapsulate(Some(source.ip()), &normalized, &mut buffer))?;
        let authenticated = match (&parsed, &outcome) {
            (Packet::HandshakeInit(_), Outcome::Network(packet)) => packet.first() == Some(&2),
            (Packet::HandshakeResponse(_), Outcome::Network(packet)) => packet.first() == Some(&4),
            (Packet::PacketData(_), Outcome::Done | Outcome::Tunnel(_)) => true,
            _ => false,
        };
        let flush = matches!(outcome, Outcome::Network(_)) && authenticated;
        let mut actions = Vec::new();
        self.emit(peer, source, outcome, &mut actions)?;
        if authenticated {
            self.endpoints[peer] = Some(source);
        }
        if flush {
            // Drain the provider's bounded pre-handshake queue. A hard bound
            // also protects callers from future provider contract changes.
            for _ in 0..256 {
                let outcome = own_result(self.peers[peer].decapsulate(None, &[], &mut buffer))?;
                if matches!(outcome, Outcome::Done) {
                    break;
                }
                self.emit(peer, source, outcome, &mut actions)?;
            }
        }
        Ok(actions)
    }

    /// Poll around every 250ms for retransmissions, keepalives, rekeys and
    /// expiration. Timer errors are per-peer so other peers keep making progress.
    pub fn update_timers(&mut self) -> TimerEvents {
        self.rate_limiter.reset_count();
        let mut events = TimerEvents::default();
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
        for peer in 0..self.peers.len() {
            let Some(endpoint) = self.endpoints[peer] else {
                continue;
            };
            match own_result(self.peers[peer].update_timers(&mut buffer)) {
                Ok(outcome) => {
                    if let Err(error) = self.emit(peer, endpoint, outcome, &mut events.actions) {
                        events.errors.push((peer, error.to_string()));
                    }
                }
                Err(error) => events.errors.push((peer, error.to_string())),
            }
        }
        events
    }

    fn endpoint(&self, peer: usize) -> Result<SocketAddr> {
        self.endpoints
            .get(peer)
            .context("unknown WireGuard peer")?
            .context("WireGuard peer endpoint is unresolved or has not been learned")
    }

    fn peer_from_receiver(&self, receiver: u32) -> Result<usize> {
        let peer = (receiver >> 8)
            .checked_sub(1)
            .context("invalid WireGuard receiver index")? as usize;
        ensure!(peer < self.peers.len(), "unknown WireGuard receiver index");
        Ok(peer)
    }

    fn mark_reserved(&self, packet: &mut [u8]) {
        if packet.len() >= 4 {
            packet[1..4].copy_from_slice(&self.config.reserved);
        }
    }

    fn emit(
        &self,
        peer: usize,
        endpoint: SocketAddr,
        outcome: Outcome,
        actions: &mut Vec<PacketAction>,
    ) -> Result<()> {
        match outcome {
            Outcome::Done => (),
            Outcome::Network(mut packet) => {
                self.mark_reserved(&mut packet);
                actions.push(PacketAction::Network {
                    peer: Some(peer),
                    endpoint,
                    packet,
                });
            }
            Outcome::Tunnel(packet) => {
                let header = IpPacket::parse(&packet)?;
                ensure!(
                    header.length == packet.len(),
                    "invalid decrypted IP packet length"
                );
                ensure!(
                    self.routes.lookup(header.source) == Some(peer),
                    "WireGuard peer is not authorized for inner source IP"
                );
                actions.push(PacketAction::Tunnel { peer, packet });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wireguard::{SecretKey, WireGuardConfig, WireGuardPeerConfig};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn only_network(actions: Vec<PacketAction>) -> Vec<u8> {
        assert_eq!(actions.len(), 1);
        match actions.into_iter().next().unwrap() {
            PacketAction::Network { packet, .. } => packet,
            _ => panic!("expected a UDP datagram"),
        }
    }

    #[test]
    fn cookie_challenge_never_roams_but_authenticated_retry_does() {
        let client_key = SecretKey::from_bytes([11; 32]);
        let server_key = SecretKey::from_bytes([22; 32]);
        let client_address: SocketAddr = "127.0.0.1:60001".parse().unwrap();
        let server_address: SocketAddr = "127.0.0.1:60002".parse().unwrap();
        let client_roamed: SocketAddr = "127.0.0.2:60003".parse().unwrap();
        let forged_source: SocketAddr = "127.0.0.3:60004".parse().unwrap();
        let mut client = WireGuardDevice::new(
            WireGuardConfig {
                secret_key: STANDARD.encode(client_key.bytes()),
                peers: vec![WireGuardPeerConfig {
                    public_key: STANDARD.encode(server_key.public_key()),
                    endpoint: server_address.to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .build(Role::Client)
            .unwrap(),
        )
        .unwrap();
        let mut server = WireGuardDevice::with_verification_limit(
            WireGuardConfig {
                secret_key: STANDARD.encode(server_key.bytes()),
                peers: vec![WireGuardPeerConfig {
                    public_key: STANDARD.encode(client_key.public_key()),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .build(Role::Server)
            .unwrap(),
            0,
        )
        .unwrap();
        server.set_peer_endpoint(0, client_address).unwrap();
        let init = only_network(client.initiate_handshake(0, false).unwrap());
        let cookie = only_network(server.decapsulate(client_roamed, &init).unwrap());
        assert_eq!(cookie[0], 3);
        assert_eq!(cookie.len(), 64);
        assert_eq!(server.peer_stats(0).unwrap().endpoint, Some(client_address));
        assert!(
            client
                .decapsulate(forged_source, &cookie)
                .unwrap()
                .is_empty()
        );
        assert_eq!(client.peer_stats(0).unwrap().endpoint, Some(server_address));
        let retry = only_network(client.initiate_handshake(0, true).unwrap());
        let response = only_network(server.decapsulate(client_roamed, &retry).unwrap());
        assert_eq!(response[0], 2);
        assert_eq!(server.peer_stats(0).unwrap().endpoint, Some(client_roamed));
        let confirmation = only_network(client.decapsulate(server_address, &response).unwrap());
        assert!(
            server
                .decapsulate(client_roamed, &confirmation)
                .unwrap()
                .is_empty()
        );
        assert!(
            server
                .peer_stats(0)
                .unwrap()
                .time_since_last_handshake
                .is_some()
        );
    }
}
