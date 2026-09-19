use std::{collections::HashMap, net::IpAddr, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;

use super::{
    Cidr, Domain, DomainRule, GeoDataStore, IpRule, domain, domain_rule, ip_from_bytes, ip_rule,
};

/// Compiled domain rules. Matching is case-sensitive, as in the Go geodata API;
/// router callers can use `match_host`, which lowercases the input first.
/// Rule indices are zero-based. Duplicate indices are allowed, order is unspecified.
#[derive(Clone, Debug, Default)]
pub struct DomainMatcher {
    full: HashMap<String, Vec<u32>>,
    suffix: HashMap<String, Vec<u32>>,
    substr: Vec<(String, u32)>,
    regex: Vec<(Regex, u32)>,
}

impl DomainMatcher {
    pub(super) fn build(store: &GeoDataStore, rules: &[DomainRule]) -> Result<Self> {
        ensure!(!rules.is_empty(), "empty domain rule list");
        let mut matcher = Self::default();
        for (index, rule) in rules.iter().enumerate() {
            let index = u32::try_from(index).context("too many domain rules")?;
            match rule.value.as_ref().context("missing domain rule value")? {
                domain_rule::Value::Custom(domain) => matcher.add(domain, index)?,
                domain_rule::Value::Geosite(rule) => {
                    for (entry_index, domain) in store
                        .load_geosite(&rule.file, &rule.code, &rule.attrs)?
                        .iter()
                        .enumerate()
                    {
                        if let Err(error) = matcher.add(domain, index) {
                            // Go ignores invalid entries in asset datasets but rejects invalid custom rules.
                            tracing::warn!(file = %rule.file, code = %rule.code, entry_index, %error, "ignoring invalid geosite entry");
                        }
                    }
                }
            }
        }
        Ok(matcher)
    }

    fn add(&mut self, domain: &Domain, index: u32) -> Result<()> {
        match domain::Type::try_from(domain.r#type).context("unknown domain type")? {
            domain::Type::Full => self
                .full
                .entry(domain.value.to_lowercase())
                .or_default()
                .push(index),
            domain::Type::Domain => self
                .suffix
                .entry(domain.value.to_lowercase())
                .or_default()
                .push(index),
            domain::Type::Substr => self.substr.push((domain.value.to_lowercase(), index)),
            domain::Type::Regex => self.regex.push((
                Regex::new(&domain.value).context("invalid domain regex")?,
                index,
            )),
        }
        Ok(())
    }

    pub fn match_any(&self, input: &str) -> bool {
        self.full.contains_key(input)
            || self.suffix.contains_key(input)
            || input
                .match_indices('.')
                .any(|(index, _)| self.suffix.contains_key(&input[index + 1..]))
            || self
                .substr
                .iter()
                .any(|(pattern, _)| input.contains(pattern))
            || self
                .regex
                .iter()
                .any(|(pattern, _)| pattern.is_match(input))
    }

    /// Router-facing helper, including Go router's lowercase normalization.
    /// A trailing dot is retained because the source router retains it too.
    pub fn match_host(&self, input: &str) -> bool {
        self.match_any(&input.to_lowercase())
    }

    pub fn matching_rules(&self, input: &str) -> Vec<u32> {
        let mut result = Vec::new();
        if let Some(indices) = self.full.get(input) {
            result.extend(indices);
        }
        if let Some(indices) = self.suffix.get(input) {
            result.extend(indices);
        }
        for (index, _) in input.match_indices('.') {
            if let Some(indices) = self.suffix.get(&input[index + 1..]) {
                result.extend(indices);
            }
        }
        result.extend(
            self.substr
                .iter()
                .filter(|(pattern, _)| input.contains(pattern))
                .map(|(_, index)| *index),
        );
        result.extend(
            self.regex
                .iter()
                .filter(|(pattern, _)| pattern.is_match(input))
                .map(|(_, index)| *index),
        );
        result
    }
}

#[derive(Debug, Default)]
struct IpSet {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

impl IpSet {
    fn build(cidrs: &[Cidr]) -> Self {
        let mut set = Self::default();
        for cidr in cidrs {
            let Some(ip) = ip_from_bytes(&cidr.ip) else {
                tracing::warn!(
                    length = cidr.ip.len(),
                    "ignoring invalid geoip address length"
                );
                continue;
            };
            let (address, width, ranges) = match ip {
                IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32, &mut set.v4),
                IpAddr::V6(ip) => (u128::from(ip), 128, &mut set.v6),
            };
            if cidr.prefix > width {
                tracing::warn!(prefix = cidr.prefix, width, "ignoring invalid geoip prefix");
                continue;
            }
            let host_bits = width - cidr.prefix;
            let host_mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1_u128 << host_bits) - 1
            };
            ranges.push((address & !host_mask, address | host_mask));
        }
        merge_ranges(&mut set.v4);
        merge_ranges(&mut set.v6);
        set
    }

    fn matches(&self, ip: IpAddr, reverse: bool) -> bool {
        // Equivalent to netipx.FromStdIP: mapped addresses match IPv4 sets.
        let (number, ranges) = match ip {
            IpAddr::V4(ip) => (u128::from(u32::from(ip)), &self.v4),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => (u128::from(u32::from(ip)), &self.v4),
                None => (u128::from(ip), &self.v6),
            },
        };
        // Reversal never creates an address family missing from the original set.
        if ranges.is_empty() {
            return false;
        }
        let end = ranges.partition_point(|(start, _)| *start <= number);
        let contained = end > 0 && number <= ranges[end - 1].1;
        contained != reverse
    }
}

fn merge_ranges(ranges: &mut Vec<(u128, u128)>) {
    ranges.sort_unstable();
    let mut count = 0;
    for index in 0..ranges.len() {
        let (start, end) = ranges[index];
        if count != 0 && start <= ranges[count - 1].1.saturating_add(1) {
            ranges[count - 1].1 = ranges[count - 1].1.max(end);
        } else {
            ranges[count] = (start, end);
            count += 1;
        }
    }
    ranges.truncate(count);
}

#[derive(Clone, Debug)]
struct IpGroup {
    set: Arc<IpSet>,
    reverse: bool,
}

/// Native IPv4/IPv6 matcher preserving source grouping and inversion semantics.
/// CIDRs union into four independent groups: custom positive/negative and geodata
/// positive/negative. The groups are ORed; a negative group complements its union.
#[derive(Clone, Debug)]
pub struct IpMatcher {
    groups: Vec<IpGroup>,
}

impl IpMatcher {
    pub(super) fn build(store: &GeoDataStore, rules: &[IpRule]) -> Result<Self> {
        let mut cidrs: [Vec<Cidr>; 4] = std::array::from_fn(|_| Vec::new());
        let mut present = [false; 4];
        for rule in rules {
            match rule.value.as_ref().context("missing IP rule value")? {
                ip_rule::Value::Custom(rule) => {
                    let group = usize::from(rule.reverse_match);
                    present[group] = true;
                    if let Some(cidr) = &rule.cidr {
                        cidrs[group].push(cidr.clone());
                    }
                }
                ip_rule::Value::Geoip(rule) => {
                    let group = 2 + usize::from(rule.reverse_match);
                    present[group] = true;
                    cidrs[group].extend(store.load_geoip(&rule.file, &rule.code)?.iter().cloned());
                }
            }
        }
        let groups: Vec<_> = cidrs
            .into_iter()
            .enumerate()
            .filter(|(index, _)| present[*index])
            .map(|(index, cidrs)| IpGroup {
                set: Arc::new(IpSet::build(&cidrs)),
                reverse: index % 2 == 1,
            })
            .collect();
        if groups.is_empty() {
            bail!("no valid IP matcher");
        }
        Ok(Self { groups })
    }

    pub fn match_ip(&self, ip: IpAddr) -> bool {
        self.groups
            .iter()
            .any(|group| group.set.matches(ip, group.reverse))
    }

    /// Invalid byte lengths always fail, including for reversed matchers.
    pub fn match_bytes(&self, ip: &[u8]) -> bool {
        ip_from_bytes(ip).is_some_and(|ip| self.match_ip(ip))
    }

    pub fn any_match(&self, ips: &[IpAddr]) -> bool {
        ips.iter().any(|ip| self.match_ip(*ip))
    }

    /// All addresses must match the SAME group, as in Go's multi-matcher `Matches`.
    /// Empty input returns false. This is deliberately stronger than calling
    /// `match_ip` independently on every address.
    pub fn matches(&self, ips: &[IpAddr]) -> bool {
        !ips.is_empty()
            && self
                .groups
                .iter()
                .any(|group| ips.iter().all(|ip| group.set.matches(*ip, group.reverse)))
    }

    /// Preserve caller order and duplicates in each partition.
    pub fn filter_ips(&self, ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
        ips.iter().copied().partition(|ip| self.match_ip(*ip))
    }

    pub fn any_match_bytes(&self, ips: &[Vec<u8>]) -> bool {
        ips.iter().any(|ip| self.match_bytes(ip))
    }

    pub fn matches_bytes(&self, ips: &[Vec<u8>]) -> bool {
        match ips
            .iter()
            .map(|ip| ip_from_bytes(ip))
            .collect::<Option<Vec<_>>>()
        {
            Some(ips) => self.matches(&ips),
            None => false,
        }
    }

    /// Invalid addresses are silently excluded from both output partitions.
    pub fn filter_ip_bytes(&self, ips: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        ips.iter()
            .filter(|ip| ip_from_bytes(ip).is_some())
            .cloned()
            .partition(|ip| self.match_bytes(ip))
    }

    /// Toggle each group independently, preserving the source multi-matcher API.
    pub fn toggle_reverse(&mut self) {
        for group in &mut self.groups {
            group.reverse = !group.reverse;
        }
    }

    pub fn set_reverse(&mut self, reverse: bool) {
        for group in &mut self.groups {
            group.reverse = reverse;
        }
    }
}
