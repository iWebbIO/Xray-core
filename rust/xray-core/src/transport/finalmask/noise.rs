//! Per-destination UDP noise bursts, matching `noise/conn.go`.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use rand::{CryptoRng, Rng};
use tokio::net::UdpSocket;

use super::{SampleRange, UDP_SIZE, invalid, random_bytes};

#[derive(Clone, Debug)]
pub enum Payload {
    Packet(Vec<u8>),
    Random {
        length: SampleRange,
        byte_min: u8,
        byte_max: u8,
    },
}

#[derive(Clone, Debug)]
pub struct Item {
    pub payload: Payload,
    pub delay_ms: SampleRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Emission {
    pub packet: Vec<u8>,
    pub delay_after: Duration,
}

pub struct Noise {
    items: Vec<Item>,
    reset_seconds: SampleRange,
    peers: HashMap<SocketAddr, Instant>,
}

impl Noise {
    pub fn new(items: Vec<Item>, reset_seconds: SampleRange) -> io::Result<Self> {
        for item in &items {
            let size = match &item.payload {
                Payload::Packet(bytes) => bytes.len() as u64,
                Payload::Random { length, .. } => length.upper(),
            };
            if size > UDP_SIZE as u64 {
                return Err(invalid("noise packet exceeds UDP buffer size"));
            }
        }
        // Check before a connection is used, rather than panic at Instant + reset.
        if Instant::now()
            .checked_add(Duration::from_secs(reset_seconds.upper()))
            .is_none()
        {
            return Err(invalid("noise reset duration exceeds clock range"));
        }
        Ok(Self {
            items,
            reset_seconds,
            peers: HashMap::new(),
        })
    }

    /// A zero reset range sends noise once per peer. A positive reset is an idle
    /// timeout: every payload write refreshes it. At exactly the deadline the Go
    /// source still suppresses noise (`time.Now().After`, not `>=`).
    pub fn before_payload<R: Rng + CryptoRng + ?Sized>(
        &self,
        peer: SocketAddr,
        now: Instant,
        rng: &mut R,
    ) -> Vec<Emission> {
        if self
            .peers
            .get(&peer)
            .is_some_and(|expiry| self.reset_seconds.upper() == 0 || now <= *expiry)
        {
            return Vec::new();
        }
        self.items
            .iter()
            .map(|item| {
                let packet = match &item.payload {
                    Payload::Packet(bytes) => bytes.clone(),
                    Payload::Random {
                        length,
                        byte_min,
                        byte_max,
                    } => {
                        let mut bytes = vec![0; length.sample(rng) as usize];
                        random_bytes(&mut bytes, *byte_min, *byte_max, rng);
                        bytes
                    }
                };
                Emission {
                    packet,
                    delay_after: Duration::from_millis(item.delay_ms.sample(rng)),
                }
            })
            .collect()
    }

    /// Call after the noise burst and before sending the actual payload, even
    /// if a noise datagram failed to send. This matches Go's ignored noise errors.
    pub fn record_payload<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        peer: SocketAddr,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<()> {
        let expiry = now
            .checked_add(Duration::from_secs(self.reset_seconds.sample(rng)))
            .ok_or_else(|| invalid("noise reset duration exceeds clock range"))?;
        self.peers.insert(peer, expiry);
        Ok(())
    }

    /// Explicit session cleanup; do not expire zero-reset peers automatically,
    /// since that would change the once-per-peer behavior.
    pub fn forget_peer(&mut self, peer: SocketAddr) {
        self.peers.remove(&peer);
    }

    pub async fn send_to<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        socket: &UdpSocket,
        payload: &[u8],
        peer: SocketAddr,
        rng: &mut R,
    ) -> io::Result<usize> {
        for emission in self.before_payload(peer, Instant::now(), rng) {
            let _ = socket.send_to(&emission.packet, peer).await;
            if !emission.delay_after.is_zero() {
                tokio::time::sleep(emission.delay_after).await;
            }
        }
        self.record_payload(peer, Instant::now(), rng)?;
        socket.send_to(payload, peer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn noise(reset: u64) -> Noise {
        Noise::new(
            vec![
                Item {
                    payload: Payload::Packet(b"hello".to_vec()),
                    delay_ms: SampleRange::fixed(2),
                },
                Item {
                    payload: Payload::Random {
                        length: SampleRange::fixed(3),
                        byte_min: 42,
                        byte_max: 42,
                    },
                    delay_ms: SampleRange::fixed(0),
                },
            ],
            SampleRange::fixed(reset),
        )
        .unwrap()
    }

    #[test]
    fn burst_bytes_and_idle_reset_are_source_derived() {
        let peer = "127.0.0.1:443".parse().unwrap();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(1);
        let mut n = noise(5);
        let burst = n.before_payload(peer, now, &mut rng);
        assert_eq!(burst[0].packet, b"hello");
        assert_eq!(burst[0].delay_after, Duration::from_millis(2));
        assert_eq!(burst[1].packet, [42, 42, 42]);
        n.record_payload(peer, now, &mut rng).unwrap();
        assert!(
            n.before_payload(peer, now + Duration::from_secs(5), &mut rng)
                .is_empty()
        );
        n.record_payload(peer, now + Duration::from_secs(4), &mut rng)
            .unwrap();
        assert!(
            n.before_payload(peer, now + Duration::from_secs(6), &mut rng)
                .is_empty()
        );
        assert_eq!(
            n.before_payload(peer, now + Duration::from_secs(10), &mut rng)
                .len(),
            2
        );
    }

    #[test]
    fn zero_reset_is_once_per_peer_and_peers_are_isolated() {
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(2);
        let mut n = noise(0);
        n.record_payload(a, now, &mut rng).unwrap();
        assert!(
            n.before_payload(a, now + Duration::from_secs(100), &mut rng)
                .is_empty()
        );
        assert_eq!(n.before_payload(b, now, &mut rng).len(), 2);
        n.forget_peer(a);
        assert_eq!(n.before_payload(a, now, &mut rng).len(), 2);
    }
}
