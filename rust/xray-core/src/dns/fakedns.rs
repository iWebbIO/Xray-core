//! FakeDNS: pool-backed fake addresses for domains, from `app/dns/fakedns`.
//!
//! A pool leases each queried domain a fake address from its CIDR: the
//! candidate address rotates with the millisecond clock (Go's
//! `time.Now().UnixMilli() % rooms` counter, wrapping to the pool base),
//! skipping addresses still leased. The bounded LRU keeps both directions —
//! domain → fake address and fake address → domain — evicting the least
//! recently used lease when full, exactly like Go's `cache.Lru`.
//!
//! Default pools mirror `infra/conf/fakedns.go`: both families get
//! 198.18.0.0/15 and 2001:2::/48 with 32768 slots each; a single-family
//! strategy gets one pool of 65535. DNS answers carry TTL 1 (Go's
//! `fakeDnsAnswers`); reverse mapping happens wherever a fake address could
//! be dialed (the runtime swaps the domain back in before routing).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

/// Go's `dns.FakeIPv4Pool`.
pub const FAKE_IPV4_POOL: &str = "198.18.0.0/15";
/// Go's `dns.FakeIPv6Pool`.
pub const FAKE_IPV6_POOL: &str = "2001:2::/48";

/// The DNS answer TTL Go serves for fake addresses (`fakeDnsAnswers`).
pub const FAKE_DNS_TTL: u32 = 1;

/// One pool element of the `"fakeDns"` root object: a CIDR plus its LRU size
/// (`ipPool` / `poolSize`).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FakeDnsPoolSettings {
    #[serde(rename = "ipPool")]
    pub ip_pool: String,
    #[serde(rename = "poolSize")]
    pub pool_size: i64,
}

/// The `"fakeDns"` root object: one pool element or a `pools` array (Go's
/// untagged `FakeDNSConfig`).
#[derive(Clone, Debug, serde::Serialize)]
pub struct FakeDnsSettings {
    pub pools: Vec<FakeDnsPoolSettings>,
}

impl Default for FakeDnsSettings {
    fn default() -> Self {
        Self {
            pools: vec![FakeDnsPoolSettings::default()],
        }
    }
}

impl<'de> serde::Deserialize<'de> for FakeDnsSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Shape {
            Pool(FakeDnsPoolSettings),
            Pools(Vec<FakeDnsPoolSettings>),
        }
        match Shape::deserialize(deserializer)? {
            Shape::Pool(pool) => Ok(Self { pools: vec![pool] }),
            Shape::Pools(pools) => Ok(Self { pools }),
        }
    }
}

impl FakeDnsSettings {
    /// Go's `FakeDNSPostProcessingStage`: the default pools for a config that
    /// uses the `fakedns` nameserver without a `fakeDns` object, derived from
    /// the DNS app's effective query strategy.
    pub fn defaults(ipv4: bool, ipv6: bool) -> Self {
        let pool = |ip_pool: &str, pool_size: i64| FakeDnsPoolSettings {
            ip_pool: ip_pool.to_owned(),
            pool_size,
        };
        match (ipv4, ipv6) {
            (true, true) => Self {
                pools: vec![pool(FAKE_IPV4_POOL, 32768), pool(FAKE_IPV6_POOL, 32768)],
            },
            (false, true) => Self {
                pools: vec![pool(FAKE_IPV6_POOL, 65535)],
            },
            (true, false) => Self {
                pools: vec![pool(FAKE_IPV4_POOL, 65535)],
            },
            (false, false) => Self { pools: Vec::new() },
        }
    }
}

/// A bounded LRU over domain ↔ fake address leases, in both directions.
struct Lru {
    capacity: usize,
    forward: HashMap<String, IpAddr>,
    backward: HashMap<IpAddr, String>,
    order: Vec<String>,
}

impl Lru {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            forward: HashMap::new(),
            backward: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn get(&mut self, domain: &str) -> Option<IpAddr> {
        let ip = self.forward.get(domain).copied()?;
        self.touch(domain);
        Some(ip)
    }

    fn touch(&mut self, domain: &str) {
        if let Some(position) = self.order.iter().position(|name| name == domain) {
            let name = self.order.remove(position);
            self.order.push(name);
        }
    }

    fn put(&mut self, domain: String, ip: IpAddr) {
        if let Some(previous) = self.forward.insert(domain.clone(), ip) {
            self.backward.remove(&previous);
        } else if self.forward.len() > self.capacity {
            // Evict the least recently used lease.
            if let Some(oldest) = self.order.first().cloned() {
                if let Some(ip) = self.forward.remove(&oldest) {
                    self.backward.remove(&ip);
                }
                self.order.retain(|name| name != &oldest);
            }
        }
        self.backward.insert(ip, domain.clone());
        if !self.order.contains(&domain) {
            self.order.push(domain.clone());
        }
        self.touch(&domain);
    }

    fn domain_of(&mut self, ip: IpAddr) -> Option<String> {
        let domain = self.backward.get(&ip).cloned()?;
        self.touch(&domain);
        Some(domain)
    }

    fn contains_ip(&self, ip: IpAddr) -> bool {
        self.backward.contains_key(&ip)
    }
}

/// One pool: a CIDR base and size with its lease LRU (Go's Holder mutex).
struct Pool {
    base: u128,
    rooms: u32,
    is_ipv6: bool,
    lru: std::sync::Mutex<Lru>,
}

impl Pool {
    fn new(settings: &FakeDnsPoolSettings) -> anyhow::Result<Self> {
        let (address, prefix) = parse_cidr(&settings.ip_pool)?;
        let (base, bits, is_ipv6) = match address {
            IpAddr::V4(ip) => (u32::from(ip) as u128, 32, false),
            IpAddr::V6(ip) => (u128::from(ip), 128, true),
        };
        let rooms = bits - prefix;
        let lru_size = settings.pool_size;
        anyhow::ensure!(lru_size > 0, "fakeDns poolSize must be positive");
        anyhow::ensure!(
            (lru_size as f64).log2() < f64::from(rooms),
            "LRU size is bigger than subnet size"
        );
        Ok(Self {
            base,
            rooms,
            is_ipv6,
            lru: std::sync::Mutex::new(Lru::new(lru_size as usize)),
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let (value, bits, is_ipv6) = match ip {
            IpAddr::V4(ip) => (u32::from(ip) as u128, 32, false),
            IpAddr::V6(ip) => (u128::from(ip), 128, true),
        };
        // `rooms` is the host-bit count: shifting by it compares the network
        // prefixes (a /15 pool compares `value >> 17`).
        let _ = bits;
        is_ipv6 == self.is_ipv6 && (value >> self.rooms) == (self.base >> self.rooms)
    }

    fn ip_at(&self, offset: u128) -> IpAddr {
        let value = self.base + (offset % (1u128 << self.rooms));
        if self.is_ipv6 {
            IpAddr::V6(Ipv6Addr::from(value))
        } else {
            IpAddr::V4(Ipv4Addr::from(value as u32))
        }
    }

    /// Go's clock-rotated allocation: the millisecond timestamp picks the
    /// candidate; an in-use candidate steps forward, wrapping to the base.
    fn lease(&self, domain: &str) -> IpAddr {
        let mut lru = self
            .lru
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ip) = lru.get(domain) {
            return ip;
        }
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);
        let mut offset = millis % (1u128 << self.rooms);
        loop {
            let ip = self.ip_at(offset);
            if !lru.contains_ip(ip) {
                lru.put(domain.to_owned(), ip);
                return ip;
            }
            offset = (offset + 1) % (1u128 << self.rooms);
        }
    }
}

fn parse_cidr(value: &str) -> anyhow::Result<(IpAddr, u32)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("fakeDns ipPool {value:?} must be a CIDR"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| anyhow::anyhow!("fakeDns ipPool {value:?} has an invalid address"))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| anyhow::anyhow!("fakeDns ipPool {value:?} has an invalid prefix"))?;
    let bits = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    anyhow::ensure!(
        prefix <= bits,
        "fakeDns ipPool {value:?} prefix exceeds its family"
    );
    Ok((address, prefix))
}

/// The FakeDNS engine over one or more pools (`Holder`/`HolderMulti`).
pub struct FakeDnsEngine {
    pools: Vec<Pool>,
}

impl FakeDnsEngine {
    pub fn new(settings: &FakeDnsSettings) -> anyhow::Result<Self> {
        anyhow::ensure!(!settings.pools.is_empty(), "no valid FakeDNS config");
        let pools = settings
            .pools
            .iter()
            .map(Pool::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { pools })
    }

    /// Whether the address belongs to any pool.
    pub fn is_ip_in_pool(&self, ip: IpAddr) -> bool {
        self.pools.iter().any(|pool| pool.contains(ip))
    }

    /// Lease the domain fake addresses for the requested families.
    pub fn fake_ip_for_domain(&self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
        // The engine is shared behind the DNS app; leases mutate the LRU.
        // Interior mutability keeps the engine shareable like Go's Holder.
        self.pools
            .iter()
            .filter(|pool| (pool.is_ipv6 && ipv6) || (!pool.is_ipv6 && ipv4))
            .map(|pool| pool.lease(domain))
            .collect()
    }

    #[cfg(test)]
    fn domain_from_ip_of(&self, domain: &str) -> Option<String> {
        let ip = self
            .fake_ip_for_domain(domain, true, false)
            .first()
            .copied()?;
        self.domain_from_ip(ip)
    }

    /// The domain leased to a fake address, if any.
    pub fn domain_from_ip(&self, ip: IpAddr) -> Option<String> {
        self.pools
            .iter()
            .find(|pool| pool.contains(ip))
            .and_then(|pool| {
                pool.lru
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .domain_of(ip)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> FakeDnsEngine {
        FakeDnsEngine::new(&FakeDnsSettings {
            pools: vec![FakeDnsPoolSettings {
                ip_pool: "198.18.0.0/15".to_owned(),
                pool_size: 8,
            }],
        })
        .unwrap()
    }

    #[test]
    fn pools_validate_cidrs_sizes_and_families() {
        assert!(
            Pool::new(&FakeDnsPoolSettings {
                ip_pool: "198.18.0.0/15".into(),
                pool_size: 65535,
            })
            .is_ok()
        );
        // LRU bigger than the subnet.
        assert!(
            Pool::new(&FakeDnsPoolSettings {
                ip_pool: "198.18.0.0/32".into(),
                pool_size: 8,
            })
            .is_err()
        );
        // Malformed CIDRs.
        for bad in ["198.18.0.0", "not-an-ip/8", "198.18.0.0/99"] {
            assert!(parse_cidr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn leases_are_stable_within_the_lru_and_reverse_mappable() {
        let engine = engine();
        let first = engine.fake_ip_for_domain("one.example", true, false);
        assert_eq!(first.len(), 1);
        assert!(
            engine.is_ip_in_pool(first[0]),
            "is_ip_in_pool({:?}) false",
            first[0]
        );
        // A repeat lease returns the same address.
        assert_eq!(engine.fake_ip_for_domain("one.example", true, false), first);
        // The reverse mapping recovers the domain.
        assert_eq!(
            engine.domain_from_ip(first[0]),
            Some("one.example".to_owned())
        );
        // Addresses outside the pool map to nothing.
        assert_eq!(engine.domain_from_ip("127.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn eviction_recycles_addresses_and_keeps_both_directions() {
        let engine = engine();
        // Fill every slot; the next lease evicts the least recently used.
        for index in 0..8 {
            engine.fake_ip_for_domain(&format!("host{index}.example"), true, false);
        }
        engine.fake_ip_for_domain("new.example", true, false);
        // Every live address reverse-maps to exactly its own domain.
        for domain in ["host7.example", "new.example"] {
            let ip = engine
                .fake_ip_for_domain(domain, true, false)
                .first()
                .copied()
                .unwrap();
            assert_eq!(engine.domain_from_ip(ip), Some(domain.to_owned()));
        }
        // No address serves two live domains at once.
        let mut seen = std::collections::HashSet::new();
        for index in 0..8 {
            let domain = format!("host{index}.example");
            if engine.domain_from_ip_of(&domain).is_some() {
                let ip = engine
                    .fake_ip_for_domain(&domain, true, false)
                    .first()
                    .copied()
                    .unwrap();
                assert!(seen.insert(ip), "two domains share a fake address");
            }
        }
    }

    #[test]
    fn multi_family_defaults_match_go() {
        let both = FakeDnsSettings::defaults(true, true);
        assert_eq!(both.pools.len(), 2);
        assert_eq!(both.pools[0].pool_size, 32768);
        let v6_only = FakeDnsSettings::defaults(false, true);
        assert_eq!(v6_only.pools.len(), 1);
        assert_eq!(v6_only.pools[0].pool_size, 65535);
        let engine = FakeDnsEngine::new(&both).unwrap();
        let addresses = engine.fake_ip_for_domain("dual.example", true, true);
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().any(IpAddr::is_ipv4));
        assert!(addresses.iter().any(IpAddr::is_ipv6));
    }
}
