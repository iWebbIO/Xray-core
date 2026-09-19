//! Bounded source-keyed UDP association lifecycle, matching Go full-cone TUN.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    pub source: SocketAddr,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    generation: u64,
    last_activity: Instant,
}

#[derive(Debug)]
pub struct UdpSessions {
    entries: HashMap<SocketAddr, Entry>,
    next_generation: u64,
    capacity: usize,
    idle_timeout: Duration,
    closed: bool,
}

impl UdpSessions {
    pub fn new(capacity: usize, idle_timeout: Duration) -> io::Result<Self> {
        if capacity == 0 || idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP session limits must be nonzero",
            ));
        }
        Ok(Self {
            entries: HashMap::new(),
            next_generation: 0,
            capacity,
            idle_timeout,
            closed: false,
        })
    }

    /// Destination is deliberately not part of the key. Return `(key, is_new)`.
    /// The caller must first expire idle entries and notify its dispatcher.
    pub fn register(&mut self, source: SocketAddr, now: Instant) -> io::Result<(SessionKey, bool)> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN UDP sessions are closed",
            ));
        }
        if let Some(entry) = self.entries.get_mut(&source) {
            if now.saturating_duration_since(entry.last_activity) >= self.idle_timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "expire idle UDP sessions before registering packets",
                ));
            }
            entry.last_activity = now;
            return Ok((
                SessionKey {
                    source,
                    generation: entry.generation,
                },
                false,
            ));
        }
        if self.entries.len() >= self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TUN UDP session limit reached",
            ));
        }
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("TUN UDP generation exhausted"))?;
        let generation = self.next_generation;
        self.entries.insert(
            source,
            Entry {
                generation,
                last_activity: now,
            },
        );
        Ok((SessionKey { source, generation }, true))
    }

    /// Permit replies from any remote address in the same family, but only to
    /// an extant, unexpired generation. Old replies cannot revive recycled ports.
    pub fn accept_reply(
        &mut self,
        key: SessionKey,
        remote: SocketAddr,
        now: Instant,
    ) -> io::Result<()> {
        let entry = self
            .entries
            .get_mut(&key.source)
            .filter(|entry| !self.closed && entry.generation == key.generation)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stale TUN UDP session"))?;
        if now.saturating_duration_since(entry.last_activity) >= self.idle_timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TUN UDP session expired",
            ));
        }
        if key.source.is_ipv4() != remote.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN UDP reply address family differs from client",
            ));
        }
        entry.last_activity = now;
        Ok(())
    }

    pub fn remove(&mut self, key: SessionKey) -> bool {
        if self
            .entries
            .get(&key.source)
            .is_some_and(|entry| entry.generation == key.generation)
        {
            self.entries.remove(&key.source);
            true
        } else {
            false
        }
    }

    pub fn expire(&mut self, now: Instant) -> Vec<SessionKey> {
        let mut expired = Vec::new();
        self.entries.retain(|source, entry| {
            if now.saturating_duration_since(entry.last_activity) >= self.idle_timeout {
                expired.push(SessionKey {
                    source: *source,
                    generation: entry.generation,
                });
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn close(&mut self) -> Vec<SessionKey> {
        self.closed = true;
        self.entries
            .drain()
            .map(|(source, entry)| SessionKey {
                source,
                generation: entry.generation,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_cone_keys_source_and_rejects_stale_replies_after_expiration() {
        let start = Instant::now();
        let source = "192.0.2.1:1234".parse().unwrap();
        let mut sessions = UdpSessions::new(1, Duration::from_secs(10)).unwrap();
        let (first, new) = sessions.register(source, start).unwrap();
        assert!(new);
        assert_eq!(sessions.register(source, start).unwrap(), (first, false));
        sessions
            .accept_reply(first, "203.0.113.1:53".parse().unwrap(), start)
            .unwrap();
        sessions
            .accept_reply(first, "198.51.100.2:4321".parse().unwrap(), start)
            .unwrap();
        assert!(
            sessions
                .register("192.0.2.2:1234".parse().unwrap(), start)
                .is_err()
        );
        let later = start + Duration::from_secs(10);
        assert!(
            sessions
                .accept_reply(first, "203.0.113.1:53".parse().unwrap(), later)
                .is_err()
        );
        assert_eq!(sessions.expire(later), vec![first]);
        let (second, _) = sessions.register(source, later).unwrap();
        assert_ne!(first, second);
        assert!(!sessions.remove(first));
        assert!(
            sessions
                .accept_reply(first, "203.0.113.1:53".parse().unwrap(), later)
                .is_err()
        );
        assert_eq!(sessions.close(), vec![second]);
        assert!(sessions.close().is_empty());
        assert!(sessions.register(source, later).is_err());
    }
}
