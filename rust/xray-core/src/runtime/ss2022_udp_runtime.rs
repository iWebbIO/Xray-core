//! CONTRACT (fixed by the integrator): the Shadowsocks-2022 UDP listener.
//!
//! OWNER: wiring batch agent A-UDP. One UDP socket per `network: "tcp,udp"`
//! 2022 inbound, bound on the same address:port as the TCP listener. Drive
//! `protocol::ss2022_udp::UdpServer` exactly as its module doc prescribes:
//! callers serialize access to one `UdpServer` per listener, supply clocks
//! and randomness explicitly, and route only admitted datagrams. Inbound
//! datagrams go through `dispatcher.udp` (the `udp::UdpDispatcher`), replies
//! return through `UdpServer::encode_reply`, and a periodic
//! `UdpServer::expire` sweep bounds session state.

use std::{net::SocketAddr, sync::Arc};

use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::protocol::shadowsocks2022::Account;

pub(super) struct Ss2022UdpListener {
    _private: (),
}

impl Ss2022UdpListener {
    /// Bind the UDP socket and build the single-user `UdpServer`. Must fail
    /// explicitly while unwired so a `tcp,udp` inbound never starts without
    /// its UDP half.
    pub(super) fn bind(address: SocketAddr, account: &Account) -> anyhow::Result<Self> {
        let _ = (address, account);
        anyhow::bail!("SS2022 UDP listener is not wired yet")
    }

    pub(super) async fn run(
        self,
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let _ = (dispatcher, cancel);
        unreachable!("SS2022 UDP listener construction fails until the wiring lands")
    }
}
