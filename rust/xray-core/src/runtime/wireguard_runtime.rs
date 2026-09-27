//! CONTRACT (fixed by the integrator): the WireGuard outbound engine pool.
//!
//! OWNER: wiring batch agent A-WG. `connect` lazily builds one
//! `wireguard_netstack::WgNet` per outbound settings value (cache by the
//! compiled `DeviceConfig`), spawns its `run` pumps under the server
//! cancellation, and dials the target through the netstack's TCP path,
//! returning the dialed stream and the locally bound address the runtime's
//! accounting expects. The transport is the real-socket `WgUdpTransport`;
//! the userspace netstack and Noise engine are the batch components in
//! `protocol/wireguard_netstack.rs` and `protocol/wireguard`.

#![allow(dead_code)] // stub until the wiring batch lands

use std::net::SocketAddr;

use super::Dispatcher;
use crate::address::Destination;
use crate::protocol::wireguard::WireGuardConfig;
use crate::transport::BoxStream;

pub(super) struct WireguardPool {
    _private: (),
}

impl WireguardPool {
    pub(super) fn new() -> Self {
        Self { _private: () }
    }

    /// Dial one target through the lazily-built WireGuard netstack. Must fail
    /// explicitly while unwired.
    pub(super) async fn connect(
        &self,
        dispatcher: &Dispatcher,
        settings: &WireGuardConfig,
        target: &Destination,
    ) -> anyhow::Result<(BoxStream, SocketAddr)> {
        let _ = (dispatcher, settings, target);
        anyhow::bail!("WireGuard outbound engine is not wired yet")
    }
}
