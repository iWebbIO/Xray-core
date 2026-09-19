use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use super::{DnsAnswer, RecordType};

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub serve_stale: bool,
    /// Go's serveExpiredTTL: zero means unlimited stale age when enabled.
    pub max_stale: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 4096,
            serve_stale: false,
            max_stale: Duration::ZERO,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct CacheKey {
    pub name: String,
    pub record_type: RecordType,
}

pub(super) struct Entry {
    answer: DnsAnswer,
    inserted: Instant,
}

pub(super) enum Cached {
    Fresh(DnsAnswer),
    Stale(DnsAnswer),
}

#[derive(Default)]
pub(super) struct Cache {
    entries: HashMap<CacheKey, Entry>,
}

impl Cache {
    pub fn get(&mut self, key: &CacheKey, config: &CacheConfig, now: Instant) -> Option<Cached> {
        if !config.enabled {
            return None;
        }
        let entry = self.entries.get(key)?;
        let age = now.saturating_duration_since(entry.inserted);
        let lifetime = Duration::from_secs(u64::from(entry.answer.ttl));
        let mut answer = entry.answer.clone();
        answer.from_cache = true;
        if age < lifetime {
            // Go getIPs rounds remaining TTL upward, preventing early expiry.
            let remaining = lifetime - age;
            answer.ttl = remaining.as_secs() as u32 + u32::from(remaining.subsec_nanos() != 0);
            return Some(Cached::Fresh(answer));
        }
        if config.serve_stale && (config.max_stale.is_zero() || age - lifetime < config.max_stale) {
            answer.ttl = 1;
            answer.stale = true;
            return Some(Cached::Stale(answer));
        }
        self.entries.remove(key);
        None
    }

    pub fn insert(&mut self, key: CacheKey, answer: DnsAnswer, config: &CacheConfig, now: Instant) {
        if !config.enabled || config.max_entries == 0 {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= config.max_entries {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            Entry {
                answer,
                inserted: now,
            },
        );
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
