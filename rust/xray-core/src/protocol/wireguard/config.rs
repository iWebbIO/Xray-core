use std::{fmt, net::IpAddr, net::SocketAddr};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de};
use zeroize::Zeroizing;

use super::{DEFAULT_MTU, MAX_INNER_PACKET_SIZE};

/// Parse the hexadecimal, standard Base64, or URL-safe Base64 key encodings
/// accepted by infra/conf/wireguard.go, validating the eventual device key size.
/// Errors deliberately never contain key text.
pub fn parse_key(value: &str) -> Result<[u8; 32]> {
    ensure!(!value.is_empty(), "WireGuard key must not be empty");
    if value.len() == 64 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        let mut valid = true;
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = (pair[0] as char).to_digit(16);
            let low = (pair[1] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                bytes[index] = ((high << 4) | low) as u8;
            } else {
                valid = false;
                break;
            }
        }
        if valid {
            return Ok(*bytes);
        }
    }
    // Go trims one trailing '=' and its Base64 decoder ignores CR/LF.
    let value = value.strip_suffix('=').unwrap_or(value);
    let cleaned = Zeroizing::new(value.replace(['\r', '\n'], ""));
    let decoder = if cleaned.contains(['+', '/']) {
        general_purpose::STANDARD_NO_PAD
    } else {
        general_purpose::URL_SAFE_NO_PAD
    };
    let decoded = Zeroizing::new(
        decoder
            .decode(cleaned.as_bytes())
            .context("invalid WireGuard key encoding")?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard key must contain exactly 32 bytes"))
}

/// Secret storage has a redacted Debug implementation and clears bytes on drop.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(Self::from_bytes(parse_key(value)?))
    }

    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public_key(&self) -> [u8; 32] {
        let private = boringtun::x25519::StaticSecret::from(*self.bytes());
        *boringtun::x25519::PublicKey::from(&private).as_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainStrategy {
    ForceIp,
    ForceIpv4,
    ForceIpv6,
    ForceIpv4v6,
    ForceIpv6v4,
}

impl DomainStrategy {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "" | "forceip" => Self::ForceIp,
            "forceipv4" => Self::ForceIpv4,
            "forceipv6" => Self::ForceIpv6,
            "forceipv4v6" => Self::ForceIpv4v6,
            "forceipv6v4" => Self::ForceIpv6v4,
            _ => bail!("unsupported WireGuard domain strategy"),
        })
    }

    /// Select the source resolver's candidate set. A preferred family falls
    /// back only when that family's DNS answer set is empty. The runtime owns
    /// DNS, TTL caching, random choice among candidates, and socket policy.
    pub fn select_addresses(&self, addresses: &[IpAddr]) -> Vec<IpAddr> {
        let want_v4 = match self {
            Self::ForceIp => return addresses.to_vec(),
            Self::ForceIpv4 => true,
            Self::ForceIpv6 => false,
            Self::ForceIpv4v6 => addresses.iter().any(IpAddr::is_ipv4),
            Self::ForceIpv6v4 => !addresses.iter().any(IpAddr::is_ipv6),
        };
        addresses
            .iter()
            .copied()
            .filter(|address| address.is_ipv4() == want_v4)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteDns {
    Local,
    Servers(Vec<IpAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            ensure!(
                address.port() != 0,
                "WireGuard peer endpoint port must be nonzero"
            );
            return Ok(Self {
                host: address.ip().to_string(),
                port: address.port(),
            });
        }
        let (host, port) = value
            .rsplit_once(':')
            .context("WireGuard endpoint requires host:port")?;
        ensure!(
            !host.is_empty()
                && !host.contains([':', '[', ']'])
                && !host.chars().any(char::is_whitespace),
            "invalid WireGuard endpoint host"
        );
        let port: u16 = port.parse().context("invalid WireGuard endpoint port")?;
        ensure!(port != 0, "WireGuard peer endpoint port must be nonzero");
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.host
            .parse()
            .ok()
            .map(|ip| SocketAddr::new(ip, self.port))
    }
}

/// Input JSON settings. Deliberately has no Debug implementation: strings may
/// contain private key material. Call build and then drop this raw settings value.
#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WireGuardConfig {
    #[serde(deserialize_with = "deserialize_null_default")]
    pub no_kernel_tun: bool,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub secret_key: String,
    pub address: Option<Vec<String>>,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub mtu: i32,
    #[serde(deserialize_with = "deserialize_reserved")]
    pub reserved: Vec<u8>,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub domain_strategy: String,
    #[serde(rename = "remoteDNS", deserialize_with = "deserialize_null_default")]
    pub remote_dns: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WireGuardPeerConfig {
    #[serde(deserialize_with = "deserialize_null_default")]
    pub public_key: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub pre_shared_key: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub endpoint: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub keep_alive: u32,
    #[serde(rename = "allowedIPs")]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub level: u32,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub email: String,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_reserved<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Input {
        Bytes(Vec<u8>),
        Encoded(String),
        Null(()),
    }
    match Input::deserialize(deserializer)? {
        Input::Bytes(bytes) => Ok(bytes),
        Input::Encoded(value) => general_purpose::STANDARD
            .decode(value.replace(['\r', '\n'], ""))
            .map_err(de::Error::custom),
        Input::Null(()) => Ok(Vec::new()),
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<SecretKey>,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive: Option<u16>,
    pub allowed_ips: Vec<IpNet>,
    pub level: u32,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub role: Role,
    pub private_key: SecretKey,
    pub addresses: Vec<IpAddr>,
    pub peers: Vec<PeerConfig>,
    pub mtu: usize,
    pub reserved: [u8; 3],
    pub domain_strategy: DomainStrategy,
    pub remote_dns: RemoteDns,
    /// Retained for a future platform backend; this packet engine is userspace.
    pub no_kernel_tun: bool,
}

impl WireGuardConfig {
    pub fn build(&self, role: Role) -> Result<DeviceConfig> {
        let private_key = SecretKey::parse(&self.secret_key)?;
        let defaults = vec!["10.0.0.1".to_owned(), "fd59:7153:2388:b5fd::1".to_owned()];
        let addresses = self
            .address
            .as_ref()
            .unwrap_or(&defaults)
            .iter()
            .map(|value| {
                value
                    .parse::<IpAddr>()
                    .or_else(|_| value.parse::<IpNet>().map(|prefix| prefix.addr()))
                    .context("invalid WireGuard interface address")
            })
            .collect::<Result<Vec<_>>>()?;
        let mtu = if self.mtu == 0 {
            DEFAULT_MTU
        } else {
            usize::try_from(self.mtu).context("WireGuard MTU must be positive")?
        };
        ensure!(
            mtu > 0 && mtu <= MAX_INNER_PACKET_SIZE,
            "WireGuard MTU exceeds portable UDP packet bounds"
        );
        ensure!(
            self.reserved.is_empty() || self.reserved.len() == 3,
            "WireGuard reserved must be empty or three bytes"
        );
        // server.go deliberately constructs its bind without a reserved marker.
        let reserved = if self.reserved.is_empty() || role == Role::Server {
            [0; 3]
        } else {
            self.reserved
                .as_slice()
                .try_into()
                .expect("length validated")
        };
        let domain_strategy = DomainStrategy::parse(&self.domain_strategy)?;
        let remote_dns = if self.remote_dns.len() == 1 && self.remote_dns[0] == "local" {
            RemoteDns::Local
        } else {
            let defaults = [
                "1.1.1.1",
                "1.0.0.1",
                "2606:4700:4700::1111",
                "2606:4700:4700::1001",
            ];
            let values: Vec<&str> = if self.remote_dns.is_empty() {
                defaults.to_vec()
            } else {
                self.remote_dns.iter().map(String::as_str).collect()
            };
            RemoteDns::Servers(
                values
                    .into_iter()
                    .map(|value| {
                        value
                            .parse()
                            .context("invalid WireGuard remote DNS address")
                    })
                    .collect::<Result<_>>()?,
            )
        };
        ensure!(
            role == Role::Server || !self.peers.is_empty(),
            "WireGuard client requires at least one peer"
        );
        let peers = self
            .peers
            .iter()
            .map(|peer| peer.build(role))
            .collect::<Result<Vec<_>>>()?;
        Ok(DeviceConfig {
            role,
            private_key,
            addresses,
            peers,
            mtu,
            reserved,
            domain_strategy,
            remote_dns,
            no_kernel_tun: self.no_kernel_tun,
        })
    }
}

impl WireGuardPeerConfig {
    fn build(&self, role: Role) -> Result<PeerConfig> {
        let public_key = parse_key(&self.public_key)?;
        let preshared_key = if self.pre_shared_key.is_empty() {
            None
        } else {
            Some(SecretKey::parse(&self.pre_shared_key)?)
        };
        // Inbound users become MemoryAccount values, which carry no endpoint.
        let endpoint = if role == Role::Server {
            None
        } else if self.endpoint.is_empty() {
            ensure!(
                role == Role::Server,
                "WireGuard client peer requires an endpoint"
            );
            None
        } else {
            Some(Endpoint::parse(&self.endpoint)?)
        };
        let interval = u16::try_from(self.keep_alive)
            .context("WireGuard persistent keepalive exceeds 65535 seconds")?;
        let defaults = vec!["0.0.0.0/0".to_owned(), "::0/0".to_owned()];
        let allowed_ips = self
            .allowed_ips
            .as_ref()
            .unwrap_or(&defaults)
            .iter()
            .map(|value| {
                value
                    .parse::<IpNet>()
                    .map(|network| network.trunc())
                    .context("invalid WireGuard allowed IP prefix")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PeerConfig {
            public_key,
            preshared_key,
            endpoint,
            persistent_keepalive: (interval != 0).then_some(interval),
            allowed_ips,
            level: if role == Role::Server { self.level } else { 0 },
            email: if role == Role::Server {
                self.email.clone()
            } else {
                String::new()
            },
        })
    }
}
