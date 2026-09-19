use std::{
    net::IpAddr,
    sync::{Arc, Mutex, RwLock, Weak},
};

use anyhow::Result;

use super::{DomainMatcher, DomainRule, GeoDataStore, IpMatcher, IpRule};

#[derive(Debug)]
struct RegistryState {
    store: GeoDataStore,
    domains: Vec<Weak<DynamicDomainMatcher>>,
    ips: Vec<Weak<DynamicIpMatcher>>,
}

/// Owns live reloadable matchers through weak references. Reload validates every
/// live matcher before publishing any replacements; failure retains the old data.
/// Publication is atomic per matcher, as with the source registries, not across
/// an entire concurrent request involving several independent matchers.
#[derive(Debug)]
pub struct GeoDataRegistry {
    state: Mutex<RegistryState>,
}

impl GeoDataRegistry {
    pub fn new(store: GeoDataStore) -> Self {
        Self {
            state: Mutex::new(RegistryState {
                store,
                domains: Vec::new(),
                ips: Vec::new(),
            }),
        }
    }

    pub fn from_env() -> Result<Self> {
        Ok(Self::new(GeoDataStore::from_env()?))
    }

    pub fn build_domain_matcher(&self, rules: &[DomainRule]) -> Result<Arc<DynamicDomainMatcher>> {
        let mut state = self.state.lock().expect("geodata registry poisoned");
        let matcher = Arc::new(DynamicDomainMatcher {
            rules: rules.to_vec(),
            matcher: RwLock::new(state.store.build_domain_matcher(rules)?),
        });
        state.domains.retain(|weak| weak.strong_count() > 0);
        state.domains.push(Arc::downgrade(&matcher));
        Ok(matcher)
    }

    pub fn build_ip_matcher(&self, rules: &[IpRule]) -> Result<Arc<DynamicIpMatcher>> {
        let mut state = self.state.lock().expect("geodata registry poisoned");
        let matcher = Arc::new(DynamicIpMatcher {
            rules: rules.to_vec(),
            state: RwLock::new(IpState {
                matcher: state.store.build_ip_matcher(rules)?,
                reverse: false,
                reverse_set: false,
            }),
        });
        state.ips.retain(|weak| weak.strong_count() > 0);
        state.ips.push(Arc::downgrade(&matcher));
        Ok(matcher)
    }

    /// Reread files and rebuild all surviving domain and IP matchers.
    /// Runtime reversal overrides persist across reloads.
    pub fn reload(&self) -> Result<()> {
        let mut state = self.state.lock().expect("geodata registry poisoned");
        let store = state.store.fresh();
        let domains: Vec<_> = state.domains.iter().filter_map(Weak::upgrade).collect();
        let ips: Vec<_> = state.ips.iter().filter_map(Weak::upgrade).collect();
        let new_domains = domains
            .iter()
            .map(|matcher| store.build_domain_matcher(&matcher.rules))
            .collect::<Result<Vec<_>>>()?;
        let new_ips = ips
            .iter()
            .map(|matcher| store.build_ip_matcher(&matcher.rules))
            .collect::<Result<Vec<_>>>()?;
        for (dynamic, matcher) in domains.iter().zip(new_domains) {
            *dynamic.matcher.write().expect("domain matcher poisoned") = matcher;
        }
        for (dynamic, mut matcher) in ips.iter().zip(new_ips) {
            let mut ip_state = dynamic.state.write().expect("IP matcher poisoned");
            if ip_state.reverse_set {
                matcher.set_reverse(ip_state.reverse);
            } else if ip_state.reverse {
                matcher.toggle_reverse();
            }
            ip_state.matcher = matcher;
        }
        state.domains.retain(|weak| weak.strong_count() > 0);
        state.ips.retain(|weak| weak.strong_count() > 0);
        state.store = store;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DynamicDomainMatcher {
    rules: Vec<DomainRule>,
    matcher: RwLock<DomainMatcher>,
}

impl DynamicDomainMatcher {
    pub fn match_any(&self, input: &str) -> bool {
        self.matcher
            .read()
            .expect("domain matcher poisoned")
            .match_any(input)
    }
    pub fn match_host(&self, input: &str) -> bool {
        self.matcher
            .read()
            .expect("domain matcher poisoned")
            .match_host(input)
    }
    pub fn matching_rules(&self, input: &str) -> Vec<u32> {
        self.matcher
            .read()
            .expect("domain matcher poisoned")
            .matching_rules(input)
    }
}

#[derive(Debug)]
struct IpState {
    matcher: IpMatcher,
    reverse: bool,
    reverse_set: bool,
}

#[derive(Debug)]
pub struct DynamicIpMatcher {
    rules: Vec<IpRule>,
    state: RwLock<IpState>,
}

impl DynamicIpMatcher {
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .match_ip(ip)
    }
    pub fn match_bytes(&self, ip: &[u8]) -> bool {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .match_bytes(ip)
    }
    pub fn any_match(&self, ips: &[IpAddr]) -> bool {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .any_match(ips)
    }
    pub fn matches(&self, ips: &[IpAddr]) -> bool {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .matches(ips)
    }
    pub fn filter_ips(&self, ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .filter_ips(ips)
    }
    pub fn any_match_bytes(&self, ips: &[Vec<u8>]) -> bool {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .any_match_bytes(ips)
    }
    pub fn matches_bytes(&self, ips: &[Vec<u8>]) -> bool {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .matches_bytes(ips)
    }
    pub fn filter_ip_bytes(&self, ips: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        self.state
            .read()
            .expect("IP matcher poisoned")
            .matcher
            .filter_ip_bytes(ips)
    }

    pub fn toggle_reverse(&self) {
        let mut state = self.state.write().expect("IP matcher poisoned");
        state.reverse = !state.reverse;
        state.matcher.toggle_reverse();
    }
    pub fn set_reverse(&self, reverse: bool) {
        let mut state = self.state.write().expect("IP matcher poisoned");
        state.reverse = reverse;
        state.reverse_set = true;
        state.matcher.set_reverse(reverse);
    }
}
