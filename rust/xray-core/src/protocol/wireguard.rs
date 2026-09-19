//! Native WireGuard configuration, cryptokey routing, and userspace packet engine.
//!
//! [`WireGuardDevice`] consumes/produces complete IP packets and encrypted UDP
//! payloads. Its caller owns UDP sockets, endpoint DNS resolution, timer polling,
//! and the TCP/IP stack or platform TUN device. This is not a stream proxy by
//! itself; no Go process, FFI, or privileged interface is used here.

mod config;
mod engine;
mod routes;

pub use config::{
    DeviceConfig, DomainStrategy, Endpoint, PeerConfig, RemoteDns, Role, SecretKey,
    WireGuardConfig, WireGuardPeerConfig, parse_key,
};
pub use engine::{PacketAction, PeerStats, TimerEvents, WireGuardDevice};
pub use routes::{IpPacket, RouteTable};

/// Maximum portable UDP payload (IPv4's 65,535-byte packet minus IP/UDP headers).
pub const MAX_DATAGRAM_SIZE: usize = 65_507;
/// WireGuard data header plus authentication tag.
pub const DATA_OVERHEAD: usize = 32;
pub const MAX_INNER_PACKET_SIZE: usize = MAX_DATAGRAM_SIZE - DATA_OVERHEAD;
pub const DEFAULT_MTU: usize = 1420;

#[cfg(test)]
mod tests;
