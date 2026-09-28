//! Account-backed, socket-free Shadowsocks 2022 AES UDP sessions and routing.
//!
//! Wire cryptography, address validation, replay windows, and session rotation
//! reuse [`crate::protocol::shadowsocks_udp`]. This module adds authenticated
//! return-address associations: a packet may rebind a session only after all
//! authentication, timestamp, address, and replay checks succeed. One `Server`
//! belongs to one listener/account; callers serialize access and supply clocks,
//! randomness, socket I/O, and remote-destination forwarding.
//!
//! The parent [`Account`] supports single-key AES128/AES256 only. Extended
//! identity headers and relay chains are not added.

use super::{Account, CipherKind};
use crate::{
    address::Destination,
    protocol::shadowsocks_udp::{Client2022, Method2022, Server2022},
};
use rand::{CryptoRng, Rng, RngCore};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

pub use crate::protocol::shadowsocks_udp::{
    Cipher2022 as Cipher, DEFAULT_SESSION_TIMEOUT, Datagram, Direction, MAX_CLOCK_SKEW,
    MAX_PACKET_SIZE, Packet2022 as Packet,
};

pub const DEFAULT_SESSION_CAPACITY: usize = 4096;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Build the existing stateless UDP wire codec from a normalized TCP account.
/// Callers using this primitive directly must manage session IDs, counters, and
/// replay protection themselves; `Client` and `Server` manage those invariants.
pub fn cipher(account: &Account) -> io::Result<Cipher> {
    let method = match account.kind {
        CipherKind::Aes128Gcm => Method2022::Aes128Gcm,
        CipherKind::Aes256Gcm => Method2022::Aes256Gcm,
        // The single-key XChaCha layout (Go's chacha20poly1305.NewX on the
        // PSK; no encrypted header, no session subkeys).
        CipherKind::ChaCha20Poly1305 => Method2022::ChaCha20Poly1305,
    };
    Cipher::new(method, account.key.as_slice())
}

/// Encrypted UDP bytes and the socket endpoint to which the caller sends them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedDatagram {
    pub peer: SocketAddr,
    pub wire: Vec<u8>,
}

/// One local UDP client session bound to a configured server endpoint.
/// Packets from another endpoint are rejected before they can mutate replay or
/// remote-session state. Create a fresh client to change server endpoints.
pub struct Client {
    inner: Client2022,
    server: SocketAddr,
}

impl Client {
    pub fn new<R: RngCore + CryptoRng + ?Sized>(
        account: &Account,
        server: SocketAddr,
        rng: &mut R,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: Client2022::new(cipher(account)?, rng),
            server,
        })
    }

    pub fn session_id(&self) -> u64 {
        self.inner.session_id()
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn encode_request<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        destination: &Destination,
        payload: &[u8],
        unix_now: u64,
        rng: &mut R,
    ) -> io::Result<RoutedDatagram> {
        Ok(RoutedDatagram {
            peer: self.server,
            wire: self.inner.encode(destination, payload, unix_now, rng)?,
        })
    }

    pub fn accept_from(
        &mut self,
        peer: SocketAddr,
        wire: &[u8],
        unix_now: u64,
    ) -> io::Result<Datagram> {
        if peer != self.server {
            return Err(invalid(
                "Shadowsocks2022 UDP reply is from another server endpoint",
            ));
        }
        Ok(self.inner.decode(wire, unix_now)?.datagram)
    }
}

#[derive(Debug)]
struct SessionIdentity {
    client_session_id: u64,
}

/// An opaque capability to reply to one admitted session in one `Server`.
/// Clones remain valid across authenticated NAT rebinding. Expiration invalidates
/// all outstanding clones, even if the same numeric session ID is admitted again.
#[derive(Clone, Debug)]
pub struct SessionToken {
    identity: Arc<SessionIdentity>,
}

impl SessionToken {
    pub fn session_id(&self) -> u64 {
        self.identity.client_session_id
    }
}

/// Fully authenticated plaintext and the session needed to route replies.
/// `peer` records this packet's source; later replies resolve the session's most
/// recently authenticated source instead of retaining this possibly old address.
#[derive(Clone, Debug)]
pub struct AcceptedDatagram {
    pub session: SessionToken,
    pub peer: SocketAddr,
    pub datagram: Datagram,
}

struct Association {
    identity: Arc<SessionIdentity>,
    peer: SocketAddr,
    last_seen: Instant,
}

/// A bounded account/listener-scoped table of authenticated UDP return routes.
/// Successful requests and replies refresh inactivity expiry, matching the
/// underlying `Server2022`. Invalid packets never rebind or refresh a route.
pub struct Server {
    inner: Server2022,
    associations: HashMap<u64, Association>,
    timeout: Duration,
}

impl Server {
    pub fn new(account: &Account) -> io::Result<Self> {
        Self::with_limits(account, DEFAULT_SESSION_TIMEOUT, DEFAULT_SESSION_CAPACITY)
    }

    /// Timeout must be at least 61 seconds to retain replay history throughout
    /// the inclusive +/-30-second timestamp window. Capacity must be positive.
    pub fn with_limits(account: &Account, timeout: Duration, capacity: usize) -> io::Result<Self> {
        Ok(Self {
            inner: Server2022::with_limits(cipher(account)?, timeout, capacity)?,
            associations: HashMap::new(),
            timeout,
        })
    }

    /// Includes inactive sessions until `expire`, `accept_from`, or `encode_reply`.
    pub fn session_count(&self) -> usize {
        self.associations.len()
    }

    pub fn expire(&mut self, now: Instant) {
        self.inner.expire(now);
        self.associations.retain(|_, association| {
            now.checked_duration_since(association.last_seen)
                .is_none_or(|age| age < self.timeout)
        });
    }

    pub fn accept_from<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        peer: SocketAddr,
        wire: &[u8],
        unix_now: u64,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<AcceptedDatagram> {
        self.expire(now);
        let packet = self.inner.accept(wire, unix_now, now, rng)?;
        // Commit the source endpoint only after the existing codec has accepted
        // every authenticated field and admitted this packet's replay counter.
        let association = self
            .associations
            .entry(packet.session_id)
            .or_insert_with(|| Association {
                identity: Arc::new(SessionIdentity {
                    client_session_id: packet.session_id,
                }),
                peer,
                last_seen: now,
            });
        association.peer = peer;
        association.last_seen = now;
        Ok(AcceptedDatagram {
            session: SessionToken {
                identity: Arc::clone(&association.identity),
            },
            peer,
            datagram: packet.datagram,
        })
    }

    /// Encode a reply whose address is the actual remote response origin.
    /// A token may cover multiple destinations in its session. Routing follows
    /// the latest authenticated peer; expired or other-server tokens fail closed.
    pub fn encode_reply<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        session: &SessionToken,
        origin: &Destination,
        payload: &[u8],
        unix_now: u64,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<RoutedDatagram> {
        self.expire(now);
        let association = self
            .associations
            .get_mut(&session.session_id())
            .filter(|association| Arc::ptr_eq(&association.identity, &session.identity))
            .ok_or_else(|| {
                invalid("unknown, expired, or foreign Shadowsocks2022 UDP reply token")
            })?;
        let wire =
            self.inner
                .encode_reply(session.session_id(), origin, payload, unix_now, now, rng)?;
        association.last_seen = now;
        Ok(RoutedDatagram {
            peer: association.peer,
            wire,
        })
    }
}

#[cfg(test)]
mod tests;
