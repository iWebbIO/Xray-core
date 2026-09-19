use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail, ensure};
use ipnet::IpNet;

/// Longest-prefix cryptokey routing. An exact prefix assigned again is owned by
/// the last peer, matching WireGuard's allowed-IP trie replacement semantics.
#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    routes: Vec<(IpNet, usize)>,
}

impl RouteTable {
    pub fn insert(&mut self, network: IpNet, peer: usize) {
        let network = network.trunc();
        if let Some(route) = self
            .routes
            .iter_mut()
            .find(|(existing, _)| *existing == network)
        {
            route.1 = peer;
        } else {
            self.routes.push((network, peer));
            self.routes
                .sort_by_key(|(network, _)| std::cmp::Reverse(network.prefix_len()));
        }
    }

    pub fn lookup(&self, address: IpAddr) -> Option<usize> {
        self.routes
            .iter()
            .find(|(network, _)| network.contains(&address))
            .map(|(_, peer)| *peer)
    }
}

/// Validated IP header metadata. This checks framing, not transport checksums;
/// TCP/UDP/ICMP validation belongs to the receiving TCP/IP stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub length: usize,
}

impl IpPacket {
    pub fn parse(packet: &[u8]) -> Result<Self> {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => {
                ensure!(packet.len() >= 20, "truncated IPv4 packet");
                let header_length = usize::from(packet[0] & 0x0f) * 4;
                let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
                ensure!(
                    header_length >= 20 && length >= header_length && length <= packet.len(),
                    "invalid IPv4 packet length"
                );
                Ok(Self {
                    source: IpAddr::V4(Ipv4Addr::new(
                        packet[12], packet[13], packet[14], packet[15],
                    )),
                    destination: IpAddr::V4(Ipv4Addr::new(
                        packet[16], packet[17], packet[18], packet[19],
                    )),
                    length,
                })
            }
            Some(6) => {
                ensure!(packet.len() >= 40, "truncated IPv6 packet");
                let length = usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40;
                ensure!(length <= packet.len(), "invalid IPv6 packet length");
                Ok(Self {
                    source: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&packet[8..24]).expect("header checked"),
                    )),
                    destination: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&packet[24..40]).expect("header checked"),
                    )),
                    length,
                })
            }
            _ => bail!("WireGuard payload must be an IPv4 or IPv6 packet"),
        }
    }
}
