//! XUDP framing and reusable UDP-association leases, from common/xudp and
//! common/mux/session.go. The registry owns real caller-provided resources;
//! generation checks prevent an old carrier from expiring a replacement lease.

use super::wire::{Frame, MAX_PACKET, Network, OPTION_DATA, Status, Target};
use std::{
    collections::HashMap,
    io,
    sync::Arc,
    time::{Duration, Instant},
};

pub type GlobalId = [u8; 8];
pub const MAX_XUDP_PAYLOAD: usize = MAX_PACKET - 666;
pub const ASSOCIATION_RETENTION: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub target: Option<Target>,
    pub payload: Vec<u8>,
}

pub struct PacketEncoder {
    initial: Option<Target>,
    global_id: GlobalId,
}

impl PacketEncoder {
    pub fn new(target: Target, global_id: GlobalId) -> io::Result<Self> {
        if target.network != Network::Udp {
            return Err(invalid("XUDP requires a UDP target"));
        }
        Ok(Self {
            initial: Some(target),
            global_id,
        })
    }
    /// A per-packet target marks a user packet. Only such first packets carry
    /// the global ID in Go, while the first target itself remains configured.
    pub fn encode(&mut self, payload: &[u8], target: Option<Target>) -> io::Result<Vec<u8>> {
        if payload.is_empty() || payload.len() > MAX_XUDP_PAYLOAD {
            return Err(invalid("XUDP payload must contain 1..7526 bytes"));
        }
        if target.as_ref().is_some_and(|t| t.network != Network::Udp) {
            return Err(invalid("XUDP endpoint must use UDP"));
        }
        let frame = if let Some(initial) = &self.initial {
            let mut frame = Frame::new(0, initial.clone(), Some(payload.to_vec()));
            if target.is_some() {
                frame.global_id = Some(self.global_id);
            }
            frame
        } else {
            let mut frame = Frame::control(0, Status::Keep);
            frame.target = target;
            frame.payload = Some(payload.to_vec());
            frame
        };
        let bytes = frame.encode()?;
        self.initial = None;
        Ok(bytes)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Reply {
    Packet(Packet),
    Ignore,
    End,
}

pub fn decode_reply(frame: Frame) -> io::Result<Reply> {
    match frame.status {
        Status::KeepAlive => Ok(Reply::Ignore),
        Status::End => Ok(Reply::End),
        Status::New => Err(invalid("XUDP reply must use Keep, KeepAlive or End")),
        Status::Keep => {
            if frame.options != 0 && frame.options != OPTION_DATA {
                return Err(invalid("invalid XUDP reply options"));
            }
            match frame.payload {
                Some(payload) if payload.len() > MAX_PACKET => {
                    Err(invalid("XUDP reply exceeds 8192 bytes"))
                }
                Some(payload) if !payload.is_empty() => Ok(Reply::Packet(Packet {
                    target: frame.target,
                    payload,
                })),
                _ => Ok(Reply::Ignore),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationState {
    Active,
    Expiring { deadline: Instant },
}

struct Entry<T> {
    resource: Arc<T>,
    generation: u64,
    state: AssociationState,
}

pub struct Lease<T> {
    pub global_id: GlobalId,
    pub generation: u64,
    pub resource: Arc<T>,
    /// Cancel/detach this prior carrier's session before forwarding responses.
    pub replaced_generation: Option<u64>,
}

pub struct AssociationRegistry<T> {
    entries: HashMap<GlobalId, Entry<T>>,
    next_generation: u64,
}

impl<T> Default for AssociationRegistry<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            next_generation: 1,
        }
    }
}

impl<T> AssociationRegistry<T> {
    /// Call under the runtime's registry lock. The resource may hold a live UDP
    /// socket plus response routing state. The callback runs only for new/expired
    /// associations; existing resources are reused across Mux carriers.
    pub fn acquire(
        &mut self,
        global_id: GlobalId,
        now: Instant,
        create: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<Lease<T>> {
        if global_id == [0; 8] {
            return Err(invalid("zero XUDP ID is not a resumable association"));
        }
        if self.next_generation == u64::MAX {
            return Err(io::Error::other("XUDP lease generation exhausted"));
        }
        if self.entries.get(&global_id).is_some_and(|entry| matches!(entry.state, AssociationState::Expiring { deadline } if now > deadline)) {
            self.entries.remove(&global_id);
        }
        let generation = self.next_generation;
        let (resource, replaced_generation) = if let Some(entry) = self.entries.get(&global_id) {
            (Arc::clone(&entry.resource), Some(entry.generation))
        } else {
            (Arc::new(create()?), None)
        };
        self.next_generation += 1;
        self.entries.insert(
            global_id,
            Entry {
                resource: Arc::clone(&resource),
                generation,
                state: AssociationState::Active,
            },
        );
        Ok(Lease {
            global_id,
            generation,
            resource,
            replaced_generation,
        })
    }
    /// A detached association stays reusable for one minute. A stale previous
    /// session cannot detach the currently active replacement generation.
    pub fn detach(&mut self, global_id: GlobalId, generation: u64, now: Instant) -> bool {
        let Some(entry) = self.entries.get_mut(&global_id) else {
            return false;
        };
        if entry.generation != generation || entry.state != AssociationState::Active {
            return false;
        }
        entry.state = AssociationState::Expiring {
            deadline: now + ASSOCIATION_RETENTION,
        };
        true
    }
    pub fn state(&self, global_id: &GlobalId) -> Option<AssociationState> {
        self.entries.get(global_id).map(|entry| entry.state)
    }
    pub fn remove(&mut self, global_id: &GlobalId, generation: u64) -> bool {
        if self
            .entries
            .get(global_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.entries.remove(global_id);
            true
        } else {
            false
        }
    }
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !matches!(entry.state, AssociationState::Expiring { deadline } if now > deadline));
        before - self.entries.len()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::super::wire::{MetadataMode, decode};
    use super::*;
    #[test]
    fn first_packet_has_global_id_followup_has_optional_override() {
        let target = Target::new(Network::Udp, "1.1.1.1", 53).unwrap();
        let alternate = Target::new(Network::Udp, "8.8.8.8", 5353).unwrap();
        let mut encoder = PacketEncoder::new(target.clone(), [7; 8]).unwrap();
        let bytes = encoder.encode(b"query", Some(alternate.clone())).unwrap();
        let first = decode(&bytes, MetadataMode::Ordinary).unwrap().unwrap().0;
        assert_eq!(first.status, Status::New);
        assert_eq!(first.target, Some(target));
        assert_eq!(first.global_id, Some([7; 8]));
        let bytes = encoder.encode(b"query2", Some(alternate.clone())).unwrap();
        let next = decode(&bytes, MetadataMode::Ordinary).unwrap().unwrap().0;
        assert_eq!(next.status, Status::Keep);
        assert_eq!(next.target, Some(alternate));
        assert_eq!(next.global_id, None);
    }
    #[test]
    fn rejected_packet_does_not_consume_first_frame_state() {
        let mut encoder = PacketEncoder::new(
            Target::new(Network::Udp, "example.com", 53).unwrap(),
            [1; 8],
        )
        .unwrap();
        assert!(encoder.encode(&[], None).is_err());
        assert!(
            encoder
                .encode(&vec![0; MAX_XUDP_PAYLOAD + 1], None)
                .is_err()
        );
        let bytes = encoder.encode(b"x", None).unwrap();
        let first = decode(&bytes, MetadataMode::Ordinary).unwrap().unwrap().0;
        assert_eq!(first.status, Status::New);
        assert_eq!(first.global_id, None);
    }
    #[test]
    fn leases_survive_carrier_replacement_and_ignore_stale_detach() {
        let now = Instant::now();
        let mut registry = AssociationRegistry::default();
        let first = registry.acquire([1; 8], now, || Ok(123_u32)).unwrap();
        assert!(registry.detach(first.global_id, first.generation, now));
        let second = registry
            .acquire([1; 8], now + Duration::from_secs(30), || {
                panic!("must reuse socket")
            })
            .unwrap();
        assert!(Arc::ptr_eq(&first.resource, &second.resource));
        assert_eq!(second.replaced_generation, Some(first.generation));
        assert!(!registry.detach(first.global_id, first.generation, now));
        assert_eq!(registry.expire(now + Duration::from_secs(120)), 0);
        assert!(registry.detach(second.global_id, second.generation, now));
        assert_eq!(registry.expire(now + Duration::from_secs(61)), 1);
        assert!(registry.is_empty());
    }
    #[test]
    fn expired_association_recreates_resource_and_failure_is_not_cached() {
        let now = Instant::now();
        let mut registry = AssociationRegistry::default();
        let first = registry.acquire([2; 8], now, || Ok(1)).unwrap();
        registry.detach(first.global_id, first.generation, now);
        let second = registry
            .acquire([2; 8], now + Duration::from_secs(61), || Ok(2))
            .unwrap();
        assert_eq!(*second.resource, 2);
        assert!(
            registry
                .acquire([3; 8], now, || Err(io::Error::other("socket failed")))
                .is_err()
        );
        assert_eq!(registry.len(), 1);
        assert!(registry.acquire([0; 8], now, || Ok(3)).is_err());
    }
}
