//! Native TUN packet and lifecycle components derived from `proxy/tun`.
//!
//! Packet codecs, route transactions and source-keyed UDP sessions are portable.
//! The optional `native-tun` feature adds a Linux device/ TCP stack adapter in
//! `native` module. Its runtime is separate from Xray's dispatcher: the
//! caller supplies routing, outbound-interface binding, policy and statistics.
//! Unsupported configuration is rejected before device creation.

pub mod packet;
pub mod route;
pub mod session;

#[cfg(feature = "native-tun")]
pub mod native;

use std::{
    io,
    net::IpAddr,
    time::{Duration, Instant},
};

pub use route::IpPrefix;

/// `gateway` values are interface addresses, not next-hop router addresses.
#[derive(Clone, Debug)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
    pub gateway: Vec<IpPrefix>,
    pub dns: Vec<IpAddr>,
    pub auto_system_routing_table: Vec<IpPrefix>,
    pub auto_outbounds_interface: Option<String>,
    pub description: Option<String>,
    pub udp_idle_timeout: Duration,
    pub max_udp_sessions: usize,
    pub event_capacity: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "xray0".into(),
            mtu: 1500,
            gateway: Vec::new(),
            dns: Vec::new(),
            auto_system_routing_table: Vec::new(),
            auto_outbounds_interface: None,
            description: None,
            udp_idle_timeout: Duration::from_secs(300),
            max_udp_sessions: 4096,
            event_capacity: 1024,
        }
    }
}

impl TunConfig {
    pub fn validate(&self) -> io::Result<()> {
        // Linux IFNAMSIZ includes the terminating NUL. Restrict to a literal
        // name: '%' templates can attach an unexpected interface.
        if self.name.is_empty()
            || matches!(self.name.as_str(), "." | "..")
            || self.name.len() > 15
            || self
                .name
                .bytes()
                .any(|b| b == 0 || b == b'/' || b == b'%' || b.is_ascii_whitespace())
        {
            return Err(invalid(
                "TUN name must be a literal interface name of 1..=15 bytes",
            ));
        }
        if self.mtu < 1280 {
            return Err(invalid("dual-stack TUN MTU must be at least 1280"));
        }
        if self.udp_idle_timeout.is_zero() || self.max_udp_sessions == 0 || self.event_capacity == 0
        {
            return Err(invalid("TUN timeouts and capacity limits must be nonzero"));
        }
        if Instant::now().checked_add(self.udp_idle_timeout).is_none() {
            return Err(invalid(
                "TUN idle timeout exceeds the monotonic clock range",
            ));
        }
        // Tokio's channel permit ceiling is smaller than usize::MAX. Use the
        // same limit here so all settings are validated before OS creation.
        if self.event_capacity > usize::MAX >> 3 {
            return Err(invalid("TUN event capacity exceeds channel permit range"));
        }
        Ok(())
    }

    /// Validate the implemented Linux adapter's settings before any OS change.
    pub fn validate_native(&self) -> io::Result<()> {
        self.validate()?;
        if !self.dns.is_empty() {
            return Err(unsupported(
                "native TUN system DNS configuration is not implemented",
            ));
        }
        if !self.auto_system_routing_table.is_empty() {
            return Err(unsupported(
                "native TUN automatic OS route installation is not implemented",
            ));
        }
        if self
            .auto_outbounds_interface
            .as_deref()
            .is_some_and(|s| !s.is_empty())
        {
            return Err(unsupported(
                "native TUN outbound-interface binding must be integrated by the dispatcher",
            ));
        }
        if self.description.as_deref().is_some_and(|s| !s.is_empty()) {
            return Err(unsupported(
                "native TUN interface description is not implemented",
            ));
        }
        if self
            .gateway
            .iter()
            .filter(|p| p.address().is_ipv4())
            .count()
            > 1
        {
            return Err(unsupported(
                "native TUN adapter currently supports one IPv4 interface address",
            ));
        }
        Ok(())
    }
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unsupported(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_settings_fail_before_device_creation() {
        let mut config = TunConfig::default();
        assert!(config.validate_native().is_ok());
        config.dns.push("1.1.1.1".parse().unwrap());
        assert_eq!(
            config.validate_native().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        config.dns.clear();
        config
            .auto_system_routing_table
            .push("0.0.0.0/0".parse().unwrap());
        assert!(config.validate_native().is_err());
        config.auto_system_routing_table.clear();
        config.gateway = vec![
            "192.0.2.1/24".parse().unwrap(),
            "198.51.100.1/24".parse().unwrap(),
        ];
        assert_eq!(
            config.validate_native().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        config.gateway.clear();
        config.name = "tun%d".into();
        assert!(config.validate_native().is_err());
    }
}
