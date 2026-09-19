use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

impl Address {
    pub fn parse(host: &str) -> Result<Self> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        ensure!(
            !host.is_empty() && host.len() <= 255,
            "domain must contain 1..255 bytes"
        );
        ensure!(
            !host
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace()),
            "invalid domain name"
        );
        Ok(Self::Domain(host.to_owned()))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Domain(name) => name.fmt(f),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
}

impl Destination {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        ensure!(port != 0, "destination port must be nonzero");
        Ok(Self {
            address: Address::parse(host)?,
            port,
        })
    }

    pub fn parse_authority(authority: &str, default_port: Option<u16>) -> Result<Self> {
        ensure!(
            !authority.contains(['@', '/', '?', '#']),
            "invalid target authority"
        );
        if authority.starts_with('[') {
            let end = authority.find(']').context("unclosed IPv6 address")?;
            let ip: Ipv6Addr = authority[1..end].parse().context("invalid IPv6 address")?;
            let port = match &authority[end + 1..] {
                "" => default_port.context("missing target port")?,
                suffix if suffix.starts_with(':') => {
                    suffix[1..].parse().context("invalid target port")?
                }
                _ => bail!("invalid IPv6 target authority"),
            };
            return Self::new(&ip.to_string(), port);
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                ensure!(!host.contains(':'), "IPv6 authorities must use brackets");
                Self::new(host, port.parse().context("invalid target port")?)
            }
            None => Self::new(authority, default_port.context("missing target port")?),
        }
    }

    /// SOCKS5/Trojan address encoding: family, host, big-endian port.
    pub async fn read_socks<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let address = match reader.read_u8().await? {
            1 => {
                let mut ip = [0; 4];
                reader.read_exact(&mut ip).await?;
                Address::Ip(Ipv4Addr::from(ip).into())
            }
            4 => {
                let mut ip = [0; 16];
                reader.read_exact(&mut ip).await?;
                Address::Ip(Ipv6Addr::from(ip).into())
            }
            3 => {
                let len = reader.read_u8().await? as usize;
                let mut host = vec![0; len];
                reader.read_exact(&mut host).await?;
                Address::parse(std::str::from_utf8(&host).context("domain is not UTF-8")?)?
            }
            value => bail!("unsupported address family {value}"),
        };
        Ok(Self {
            address,
            port: reader.read_u16().await?,
        })
    }

    pub async fn write_socks<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        match &self.address {
            Address::Ip(IpAddr::V4(ip)) => {
                writer.write_u8(1).await?;
                writer.write_all(&ip.octets()).await?;
            }
            Address::Ip(IpAddr::V6(ip)) => {
                writer.write_u8(4).await?;
                writer.write_all(&ip.octets()).await?;
            }
            Address::Domain(host) => {
                ensure!(
                    !host.is_empty() && host.len() <= 255,
                    "invalid domain length"
                );
                writer.write_all(&[3, host.len() as u8]).await?;
                writer.write_all(host.as_bytes()).await?;
            }
        }
        writer.write_u16(self.port).await?;
        Ok(())
    }
}

impl From<SocketAddr> for Destination {
    fn from(value: SocketAddr) -> Self {
        Self {
            address: Address::Ip(value.ip()),
            port: value.port(),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.address {
            Address::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            address => write!(f, "{address}:{}", self.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn address_wire_fixtures() {
        for (host, wire) in [
            ("127.0.0.1", vec![1, 127, 0, 0, 1, 1, 187]),
            (
                "example.org",
                [vec![3, 11], b"example.org".to_vec(), vec![1, 187]].concat(),
            ),
            ("::1", [vec![4], vec![0; 15], vec![1, 1, 187]].concat()),
        ] {
            let dest = Destination::new(host, 443).unwrap();
            let mut encoded = Vec::new();
            dest.write_socks(&mut encoded).await.unwrap();
            assert_eq!(encoded, wire);
            assert_eq!(
                Destination::read_socks(&mut wire.as_slice()).await.unwrap(),
                dest
            );
            for len in 0..wire.len() {
                assert!(Destination::read_socks(&mut &wire[..len]).await.is_err());
            }
        }
    }

    #[test]
    fn parses_authorities_without_confusing_ipv6_and_ports() {
        assert_eq!(
            Destination::parse_authority("[::1]:443", None)
                .unwrap()
                .to_string(),
            "[::1]:443"
        );
        assert_eq!(
            Destination::parse_authority("example.org", Some(80))
                .unwrap()
                .port,
            80
        );
        for value in [
            "::1:443",
            "[host]:80",
            "user@host:80",
            "host:0",
            "host:65536",
            "host:80/path",
        ] {
            assert!(
                Destination::parse_authority(value, None).is_err(),
                "{value}"
            );
        }
    }
}
