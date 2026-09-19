//! Native readers and matchers for `common/geodata/geodat.proto`.
//!
//! A store is a snapshot: files and decoded entries remain cached until
//! [`GeoDataStore::clear_cache`] or a registry reload. Relative asset names follow
//! the Go asset resolver, including `xray.location.asset` / `XRAY_LOCATION_ASSET`.
//! Use [`GeoDataRegistry`] when already constructed matchers must observe reloads.
//! There is deliberately no implicit network download or Go subprocess here.

mod matcher;
mod registry;

pub use matcher::{DomainMatcher, IpMatcher};
pub use registry::{DynamicDomainMatcher, DynamicIpMatcher, GeoDataRegistry};
pub use xray_proto::xray::common::geodata::{
    Cidr, CidrRule, Domain, DomainRule, GeoIp, GeoIpRule, GeoSite, GeoSiteRule, IpRule, domain,
    domain_rule, ip_rule,
};

use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail, ensure};
use prost::Message;

pub const DEFAULT_GEOIP_FILE: &str = "geoip.dat";
pub const DEFAULT_GEOSITE_FILE: &str = "geosite.dat";

type EntryKey = (PathBuf, String);

#[derive(Debug, Default)]
struct Cache {
    files: HashMap<PathBuf, Arc<IndexedFile>>,
    ips: HashMap<EntryKey, Arc<Vec<Cidr>>>,
    sites: HashMap<EntryKey, Arc<Vec<Domain>>>,
}

#[derive(Debug)]
struct IndexedFile {
    bytes: Vec<u8>,
    entries: HashMap<String, Range<usize>>,
}

/// Thread-safe file and protobuf-entry cache, with deterministic asset roots.
#[derive(Debug)]
pub struct GeoDataStore {
    roots: Vec<PathBuf>,
    cache: Mutex<Cache>,
}

impl GeoDataStore {
    /// Restrict lookup to one explicit asset directory (useful for embedders).
    pub fn new(asset_dir: impl Into<PathBuf>) -> Self {
        Self {
            roots: vec![asset_dir.into()],
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Resolve the environment exactly once; Linux/Unix also use Go's fallback roots.
    pub fn from_env() -> Result<Self> {
        let configured = std::env::var_os("xray.location.asset")
            .or_else(|| std::env::var_os("XRAY_LOCATION_ASSET"))
            .map(PathBuf::from);
        let root = match configured {
            Some(root) => root,
            None => std::env::current_exe()?
                .parent()
                .unwrap_or(Path::new(""))
                .to_owned(),
        };
        #[allow(unused_mut)]
        let mut roots = vec![root];
        #[cfg(not(windows))]
        roots.extend(
            [
                "/usr/local/share/xray",
                "/usr/share/xray",
                "/opt/share/xray",
            ]
            .map(PathBuf::from),
        );
        Ok(Self {
            roots,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Clear future loads. Previously returned data and matchers remain valid snapshots.
    pub fn clear_cache(&self) {
        *self.cache.lock().expect("geodata cache poisoned") = Cache::default();
    }

    pub(super) fn fresh(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Asset names use slash-separated relative paths, never absolute paths or `..`.
    pub fn resolve_asset(&self, file: &str) -> Result<PathBuf> {
        validate_asset_name(file)?;
        for root in &self.roots {
            let path = root.join(file);
            match fs::metadata(&path) {
                Ok(meta) => {
                    ensure!(
                        meta.is_file(),
                        "asset is not a regular file: {}",
                        path.display()
                    );
                    return Ok(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("stat asset {}", path.display()));
                }
            }
        }
        bail!("asset {file:?} not found in {:?}", self.roots)
    }

    fn indexed_file(&self, path: &Path) -> Result<Arc<IndexedFile>> {
        let mut cache = self.cache.lock().expect("geodata cache poisoned");
        if let Some(file) = cache.files.get(path) {
            return Ok(file.clone());
        }
        let bytes = fs::read(path).with_context(|| format!("read geodata {}", path.display()))?;
        let file = Arc::new(
            IndexedFile::new(bytes).with_context(|| format!("index geodata {}", path.display()))?,
        );
        cache.files.insert(path.to_owned(), file.clone());
        Ok(file)
    }

    /// Verify an exact (normally uppercase) dataset code without decoding its records.
    pub fn check_code(&self, file: &str, code: &str) -> Result<()> {
        ensure!(!code.is_empty(), "empty geodata code");
        let path = self.resolve_asset(file)?;
        let data = self.indexed_file(&path)?;
        ensure!(
            data.entries.contains_key(code),
            "geodata code {code:?} not found in {file:?}"
        );
        Ok(())
    }

    /// Load CIDRs, ignoring the legacy `GeoIP.reverse_match` field like the Go loader.
    /// Inversion belongs to the rule, not the on-disk dataset.
    pub fn load_geoip(&self, file: &str, code: &str) -> Result<Arc<Vec<Cidr>>> {
        let path = self.resolve_asset(file)?;
        let key = (path.clone(), code.to_owned());
        if let Some(value) = self
            .cache
            .lock()
            .expect("geodata cache poisoned")
            .ips
            .get(&key)
        {
            return Ok(value.clone());
        }
        let data = self.indexed_file(&path)?;
        let entry = data
            .entry(code)
            .with_context(|| format!("load IP {file}:{code}"))?;
        let value = Arc::new(
            GeoIp::decode(entry)
                .with_context(|| format!("decode IP {file}:{code}"))?
                .cidr,
        );
        let mut cache = self.cache.lock().expect("geodata cache poisoned");
        Ok(cache.ips.entry(key).or_insert(value).clone())
    }

    /// Filter by AND of exact attribute key presence; values (including false) are ignored.
    /// `!cn` is a literal attribute name, not a logical NOT operator.
    pub fn load_geosite(&self, file: &str, code: &str, attrs: &str) -> Result<Arc<Vec<Domain>>> {
        let path = self.resolve_asset(file)?;
        let key = (path.clone(), code.to_owned());
        let cached = self
            .cache
            .lock()
            .expect("geodata cache poisoned")
            .sites
            .get(&key)
            .cloned();
        let domains = if let Some(value) = cached {
            value
        } else {
            let data = self.indexed_file(&path)?;
            let entry = data
                .entry(code)
                .with_context(|| format!("load site {file}:{code}"))?;
            let value = Arc::new(
                GeoSite::decode(entry)
                    .with_context(|| format!("decode site {file}:{code}"))?
                    .domain,
            );
            self.cache
                .lock()
                .expect("geodata cache poisoned")
                .sites
                .entry(key)
                .or_insert(value)
                .clone()
        };
        if attrs.is_empty() {
            return Ok(domains);
        }
        Ok(Arc::new(
            domains
                .iter()
                .filter(|domain| {
                    attrs
                        .split('@')
                        .all(|attr| domain.attribute.iter().any(|a| a.key == attr))
                })
                .cloned()
                .collect(),
        ))
    }

    /// Parse source-compatible `geoip`, `ext`, `ext-ip`, CIDR and repeated `!` syntax.
    /// External codes are checked now, matching Go's configuration validation.
    pub fn parse_ip_rules(&self, rules: &[String]) -> Result<Vec<IpRule>> {
        rules
            .iter()
            .map(|rule| {
                self.parse_ip_rule(rule)
                    .with_context(|| format!("illegal IP rule {rule:?}"))
            })
            .collect()
    }

    pub fn parse_ip_rule(&self, rule: &str) -> Result<IpRule> {
        let (rule, reverse) = cut_reverse(rule);
        let external = if let Some(code) = rule.strip_prefix("geoip:") {
            Some((DEFAULT_GEOIP_FILE, code))
        } else if let Some(value) = rule
            .strip_prefix("ext:")
            .or_else(|| rule.strip_prefix("ext-ip:"))
        {
            Some(
                value
                    .split_once(':')
                    .context("external IP rule requires file:code")?,
            )
        } else {
            None
        };
        let value = if let Some((file, code)) = external {
            let (code, code_reverse) = cut_reverse(code);
            let code = code.to_uppercase();
            self.check_code(file, &code)?;
            ip_rule::Value::Geoip(GeoIpRule {
                file: file.into(),
                code,
                reverse_match: reverse ^ code_reverse,
            })
        } else {
            ip_rule::Value::Custom(CidrRule {
                cidr: Some(parse_cidr(rule)?),
                reverse_match: reverse,
            })
        };
        Ok(IpRule { value: Some(value) })
    }

    /// Parse geosite/ext[-site/-domain], regexp/domain/full/keyword/dotless rules.
    /// Router callers should pass [`domain::Type::Substr`] as the default type.
    pub fn parse_domain_rules(
        &self,
        rules: &[String],
        default_type: domain::Type,
    ) -> Result<Vec<DomainRule>> {
        rules
            .iter()
            .map(|rule| {
                self.parse_domain_rule(rule, default_type)
                    .with_context(|| format!("illegal domain rule {rule:?}"))
            })
            .collect()
    }

    pub fn parse_domain_rule(&self, rule: &str, default_type: domain::Type) -> Result<DomainRule> {
        let external = if let Some(code) = rule.strip_prefix("geosite:") {
            Some((DEFAULT_GEOSITE_FILE, code))
        } else if let Some(value) = ["ext:", "ext-domain:", "ext-site:"]
            .iter()
            .find_map(|prefix| rule.strip_prefix(prefix))
        {
            Some(
                value
                    .split_once(':')
                    .context("external site rule requires file:code")?,
            )
        } else {
            None
        };
        let value = if let Some((file, code_attrs)) = external {
            ensure!(
                !code_attrs.ends_with('@') && !code_attrs.contains("@@"),
                "empty geosite attribute"
            );
            let (code, attrs) = code_attrs.split_once('@').unwrap_or((code_attrs, ""));
            let code = code.to_uppercase();
            self.check_code(file, &code)?;
            domain_rule::Value::Geosite(GeoSiteRule {
                file: file.into(),
                code,
                attrs: attrs.to_lowercase(),
            })
        } else {
            let (kind, value) = if let Some(value) = rule.strip_prefix("regexp:") {
                (domain::Type::Regex, value.to_owned())
            } else if let Some(value) = rule.strip_prefix("domain:") {
                (domain::Type::Domain, value.to_owned())
            } else if let Some(value) = rule.strip_prefix("full:") {
                (domain::Type::Full, value.to_owned())
            } else if let Some(value) = rule.strip_prefix("keyword:") {
                (domain::Type::Substr, value.to_owned())
            } else if let Some(value) = rule.strip_prefix("dotless:") {
                ensure!(
                    !value.contains('.'),
                    "substring in dotless rule must not contain a dot"
                );
                (
                    domain::Type::Regex,
                    if value.is_empty() {
                        "^[^.]*$".into()
                    } else {
                        format!("^[^.]*{value}[^.]*$")
                    },
                )
            } else {
                (default_type, rule.to_owned())
            };
            domain_rule::Value::Custom(Domain {
                r#type: kind as i32,
                value,
                attribute: vec![],
            })
        };
        Ok(DomainRule { value: Some(value) })
    }

    pub fn build_ip_matcher(&self, rules: &[IpRule]) -> Result<IpMatcher> {
        IpMatcher::build(self, rules)
    }

    pub fn build_domain_matcher(&self, rules: &[DomainRule]) -> Result<DomainMatcher> {
        DomainMatcher::build(self, rules)
    }
}

fn validate_asset_name(file: &str) -> Result<()> {
    ensure!(
        !file.is_empty() && !file.contains(['\\', ':', '\0']),
        "asset path must stay in asset directory"
    );
    ensure!(
        file.split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "asset path must stay in asset directory"
    );
    #[cfg(windows)]
    for part in file.split('/') {
        let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            !matches!(
                base.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) && !(base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && matches!(base.as_bytes()[3], b'1'..=b'9')),
            "reserved Windows asset name"
        );
    }
    Ok(())
}

fn cut_reverse(input: &str) -> (&str, bool) {
    let rest = input.trim_start_matches('!');
    (rest, !(input.len() - rest.len()).is_multiple_of(2))
}

fn parse_cidr(input: &str) -> Result<Cidr> {
    let (address, prefix) = input.split_once('/').unwrap_or((input, ""));
    let mut ip: IpAddr = address.parse().context("invalid IP address")?;
    // Go net.IP.To4 treats IPv4-mapped IPv6 literals as IPv4.
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        ip = IpAddr::V4(v4);
    }
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    let prefix: u32 = if prefix.is_empty() {
        max_prefix
    } else {
        ensure!(
            prefix.bytes().all(|b| b.is_ascii_digit()),
            "invalid IP prefix"
        );
        prefix.parse().context("invalid IP prefix")?
    };
    ensure!(prefix <= max_prefix, "IP prefix exceeds address width");
    let bytes = match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    Ok(Cidr { ip: bytes, prefix })
}

pub(super) fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        16 => Some(IpAddr::V6(<[u8; 16]>::try_from(bytes).ok()?.into())),
        _ => None,
    }
}

impl IndexedFile {
    fn new(bytes: Vec<u8>) -> Result<Self> {
        let mut entries = HashMap::new();
        let mut cursor = 0;
        while cursor < bytes.len() {
            let (field, value) = next_field(&bytes, &mut cursor)?;
            if field != 1 {
                continue;
            }
            let range = value.context("geodata list entry is not a length-delimited message")?;
            let body = &bytes[range.clone()];
            let mut inner = 0;
            let mut code = None;
            while inner < body.len() {
                let (field, value) = next_field(body, &mut inner)?;
                if field == 1 {
                    let value = value.context("geodata code is not a string")?;
                    code = Some(
                        std::str::from_utf8(&body[value])
                            .context("geodata code is not UTF-8")?
                            .to_owned(),
                    );
                }
            }
            if let Some(code) = code {
                entries.entry(code).or_insert(range);
            }
        }
        Ok(Self { bytes, entries })
    }

    fn entry(&self, code: &str) -> Result<&[u8]> {
        ensure!(!code.is_empty(), "empty geodata code");
        let range = self
            .entries
            .get(code)
            .with_context(|| format!("geodata code {code:?} not found"))?;
        Ok(&self.bytes[range.clone()])
    }
}

fn varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor).context("truncated protobuf varint")?;
        *cursor += 1;
        ensure!(shift != 63 || byte <= 1, "protobuf varint overflow");
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint overflow")
}

/// Return a length-delimited payload range, skipping other supported wire types.
fn next_field(bytes: &[u8], cursor: &mut usize) -> Result<(u64, Option<Range<usize>>)> {
    let key = varint(bytes, cursor)?;
    let field = key >> 3;
    ensure!(
        field != 0 && field <= 0x1fff_ffff,
        "invalid protobuf field number"
    );
    let (length, delimited) = match key & 7 {
        0 => {
            varint(bytes, cursor)?;
            return Ok((field, None));
        }
        1 => (8, false),
        2 => (
            usize::try_from(varint(bytes, cursor)?).context("protobuf length overflow")?,
            true,
        ),
        5 => (4, false),
        wire => bail!("unsupported protobuf wire type {wire}"),
    };
    let end = cursor
        .checked_add(length)
        .context("protobuf length overflow")?;
    ensure!(end <= bytes.len(), "truncated protobuf field");
    let range = *cursor..end;
    *cursor = end;
    Ok((field, delimited.then_some(range)))
}

#[cfg(test)]
mod tests;
