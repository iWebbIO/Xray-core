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
//!
//! Implementation notes (proxy/wireguard client.go is the reference):
//!
//! * One engine per distinct outbound settings value, keyed by a hash of the
//!   raw settings (`settings_key`); two outbounds with identical settings
//!   share one engine, and the engine is never rebuilt per dial. Dropping the
//!   pool aborts every engine's pump task, which drops its `run` future and
//!   stops the pumps (the component's documented lifecycle) when the
//!   dispatcher is released at shutdown.
//! * Peer endpoint hostnames are resolved through the dispatcher's DNS app
//!   (or the system resolver when no app is configured) before the engine is
//!   built, filtered by the settings' `domainStrategy` and picked randomly
//!   among the candidates, mirroring Go's `resolveLocal`.
//! * Domain targets are resolved through the tunnel with the configured
//!   `remoteDNS` servers, like Go's gVisor netstack resolver created by
//!   `CreateNetTUN`; `remoteDNS: ["local"]` uses the host resolver instead.
//!   Resolutions are serialized per engine because the netstack exposes one
//!   UDP datagram stream.
//! * Without the `native-tun` feature `connect` fails explicitly instead of
//!   degrading (the feature is in the workspace default set).

#![allow(dead_code)] // the dispatcher's pool field is read by R-RUNTIME

use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
};

#[cfg(not(feature = "native-tun"))]
use anyhow::bail;

use super::Dispatcher;
use crate::address::Destination;
use crate::protocol::wireguard::WireGuardConfig;
use crate::transport::BoxStream;

#[cfg(feature = "native-tun")]
use anyhow::Context;

pub(super) struct WireguardPool {
    /// One lazily-built engine per outbound settings value, alive for as long
    /// as the pool (and therefore the dispatcher) lives.
    #[cfg(feature = "native-tun")]
    engines: tokio::sync::Mutex<HashMap<u64, std::sync::Arc<wired::EngineEntry>>>,
}

impl WireguardPool {
    pub(super) fn new() -> Self {
        Self {
            #[cfg(feature = "native-tun")]
            engines: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Dial one target through the lazily-built WireGuard netstack.
    pub(super) async fn connect(
        &self,
        dispatcher: &Dispatcher,
        settings: &WireGuardConfig,
        target: &Destination,
    ) -> anyhow::Result<(BoxStream, SocketAddr)> {
        #[cfg(not(feature = "native-tun"))]
        {
            let _ = (dispatcher, settings, target);
            bail!(
                "the WireGuard outbound requires the native-tun build feature; \
                 rebuild with the default feature set"
            );
        }
        #[cfg(feature = "native-tun")]
        {
            let dns = dispatcher.dns.as_deref();
            self.dial(dns, settings, target)
                .await
                .with_context(|| format!("WireGuard outbound dial to {target}"))
        }
    }
}

/// Cache key over every settings field that feeds `WireGuardConfig::build`:
/// two settings values build the same engine exactly when their keys match.
/// `None` and `Some(empty)` address lists stay distinct because `build`
/// treats them differently (defaults versus no interface address).
fn settings_key(settings: &WireGuardConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    settings.secret_key.hash(&mut hasher);
    settings.no_kernel_tun.hash(&mut hasher);
    settings.mtu.hash(&mut hasher);
    settings.reserved.hash(&mut hasher);
    settings.domain_strategy.hash(&mut hasher);
    settings.remote_dns.hash(&mut hasher);
    settings.address.hash(&mut hasher);
    for peer in &settings.peers {
        peer.public_key.hash(&mut hasher);
        peer.pre_shared_key.hash(&mut hasher);
        peer.endpoint.hash(&mut hasher);
        peer.keep_alive.hash(&mut hasher);
        peer.allowed_ips.hash(&mut hasher);
        peer.level.hash(&mut hasher);
        peer.email.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(feature = "native-tun")]
mod wired {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use anyhow::{Context, anyhow, bail, ensure};
    use tokio::{
        sync::Mutex as AsyncMutex,
        task::JoinHandle,
        time::{Instant, timeout},
    };

    use crate::address::{Address, Destination};
    use crate::dns::QueryOptions;
    use crate::dns::wire::{Question, RecordData, RecordType, decode, encode_query};
    use crate::protocol::wireguard::{
        DeviceConfig, DomainStrategy, Endpoint, RemoteDns, Role, WireGuardConfig,
    };
    use crate::protocol::wireguard_netstack::{WgNet, WgUdpSocket};
    use crate::transport::BoxStream;

    use super::{WireguardPool, settings_key};

    /// Per-candidate tunnel TCP dial budget, matching the runtime's dial
    /// timeout (`establish` is additionally wrapped in the runtime's overall
    /// timeout).
    const TUNNEL_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(16);
    /// Source port for through-tunnel DNS queries. Resolutions are
    /// serialized per engine (one netstack UDP stream), so a fixed port is
    /// unambiguous.
    const TUNNEL_DNS_PORT: u16 = 40_000;
    /// Bounded wait per DNS server and family, like a resolver retransmit
    /// window; every configured server is tried once, in order.
    const TUNNEL_DNS_TIMEOUT: Duration = Duration::from_secs(2);

    /// One cached engine: the shared userspace WireGuard device, the settings
    /// the through-tunnel resolver needs, and the pump task keeping it alive.
    pub(super) struct EngineEntry {
        net: Arc<WgNet<WgUdpSocket>>,
        dns: RemoteDns,
        /// The device's tunnel addresses; the family-matching one is the TCP
        /// dial source and the inner DNS query source.
        addresses: Vec<IpAddr>,
        strategy: DomainStrategy,
        /// Serializes through-tunnel DNS resolutions: the netstack exposes a
        /// single UDP datagram stream, so concurrent queries would interleave.
        resolve_guard: AsyncMutex<()>,
        pumps: JoinHandle<()>,
    }

    impl Drop for EngineEntry {
        fn drop(&mut self) {
            // Deterministic shutdown: aborting the task drops the engine's
            // `run` future, which stops the pumps (the component contract)
            // and releases the engine once the last dial-side clone is gone.
            self.pumps.abort();
        }
    }

    impl EngineEntry {
        /// The netstack TCP bind for a remote: the device's tunnel address of
        /// the remote's family (the address the peer must authorize), falling
        /// back to the unspecified address for empty interface configs.
        fn dial_bind(&self, remote: SocketAddr) -> SocketAddr {
            let address = self
                .addresses
                .iter()
                .copied()
                .find(|address| address.is_ipv4() == remote.is_ipv4())
                .unwrap_or_else(|| unspecified(remote.is_ipv4()));
            SocketAddr::new(address, 0)
        }
    }

    fn unspecified(is_ipv4: bool) -> IpAddr {
        if is_ipv4 {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        }
    }

    impl WireguardPool {
        /// The dial path `connect` delegates to. `dns` is the dispatcher's
        /// configured DNS app, when one exists (Go's wireguard client always
        /// resolves endpoint hostnames through the app's DNS client).
        pub(super) async fn dial(
            &self,
            dns: Option<&crate::dns::app::DnsApp>,
            settings: &WireGuardConfig,
            target: &Destination,
        ) -> anyhow::Result<(BoxStream, SocketAddr)> {
            let entry = self.engine(dns, settings).await?;
            let candidates: Vec<SocketAddr> = match &target.address {
                Address::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
                Address::Domain(name) => {
                    let addresses = resolve_target(&entry, name)
                        .await
                        .with_context(|| format!("resolving WireGuard target {name}"))?;
                    let selected = entry.strategy.select_addresses(&addresses);
                    ensure!(
                        !selected.is_empty(),
                        "WireGuard domainStrategy {:?} left no address for target {name}",
                        entry.strategy
                    );
                    selected
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, target.port))
                        .collect()
                }
            };
            let mut last = None;
            for remote in candidates {
                let bind = entry.dial_bind(remote);
                let attempt = timeout(
                    TUNNEL_DIAL_TIMEOUT,
                    entry.net.netstack().dial_tcp(bind, remote),
                )
                .await;
                match attempt {
                    Ok(Ok(stream)) => {
                        let bound = stream.local_addr();
                        return Ok((Box::new(stream), bound));
                    }
                    Ok(Err(error)) => {
                        last = Some(
                            anyhow::Error::new(error)
                                .context(format!("WireGuard tunnel dial to {remote} failed")),
                        );
                    }
                    Err(_) => {
                        last = Some(anyhow!("WireGuard tunnel dial to {remote} timed out"));
                    }
                }
            }
            Err(last.unwrap_or_else(|| {
                anyhow!("WireGuard target {target} resolved to no dialable address")
            }))
        }

        /// Lazily build (or fetch) the engine for one outbound settings value.
        /// The map lock spans the build so concurrent first dials share one
        /// engine per settings value instead of racing to spawn pumps.
        async fn engine(
            &self,
            dns: Option<&crate::dns::app::DnsApp>,
            settings: &WireGuardConfig,
        ) -> anyhow::Result<Arc<EngineEntry>> {
            let key = settings_key(settings);
            let mut engines = self.engines.lock().await;
            if let Some(entry) = engines.get(&key) {
                return Ok(entry.clone());
            }
            let config = settings
                .build(Role::Client)
                .context("WireGuard outbound settings")?;
            let config = resolve_peer_endpoints(dns, config).await?;
            let bind = transport_bind(&config)?;
            let transport =
                WgUdpSocket::bind(bind).context("bind the WireGuard UDP transport socket")?;
            let addresses = config.addresses.clone();
            let dns_servers = config.remote_dns.clone();
            let strategy = config.domain_strategy;
            let net = Arc::new(WgNet::new(config, transport).context("build WireGuard engine")?);
            let pumps = spawn_pumps(net.clone());
            let entry = Arc::new(EngineEntry {
                net,
                dns: dns_servers,
                addresses,
                strategy,
                resolve_guard: AsyncMutex::new(()),
                pumps,
            });
            engines.insert(key, entry.clone());
            Ok(entry)
        }

        /// Number of live engines (the cache identity check).
        #[cfg(test)]
        pub(super) async fn engine_count(&self) -> usize {
            self.engines.lock().await.len()
        }
    }

    /// Run the engine's pumps for as long as the entry (and the pool) lives.
    fn spawn_pumps(net: Arc<WgNet<WgUdpSocket>>) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(error) = net.run().await {
                tracing::warn!(%error, "WireGuard engine pumps stopped");
            }
        })
    }

    /// The transport socket family follows the first peer's endpoint, like
    /// Go's `listenFunc` dialing `Peers[0].Endpoint`; the OS picks the port.
    fn transport_bind(config: &DeviceConfig) -> anyhow::Result<SocketAddr> {
        let endpoint = config
            .peers
            .first()
            .and_then(|peer| peer.endpoint.as_ref())
            .context("WireGuard client peer requires an endpoint")?;
        let address = endpoint
            .socket_addr()
            .context("WireGuard peer endpoint was not resolved to an address")?;
        Ok(SocketAddr::new(unspecified(address.is_ipv4()), 0))
    }

    /// Resolve hostname peer endpoints before the engine is built (Go's
    /// `bind.ParseEndpoint` resolves through the DNS client); literal
    /// addresses pass through untouched.
    async fn resolve_peer_endpoints(
        dns: Option<&crate::dns::app::DnsApp>,
        mut config: DeviceConfig,
    ) -> anyhow::Result<DeviceConfig> {
        let strategy = config.domain_strategy;
        for peer in &mut config.peers {
            let Some(endpoint) = peer.endpoint.clone() else {
                continue;
            };
            if endpoint.socket_addr().is_some() {
                continue;
            }
            let address = resolve_endpoint(dns, strategy, &endpoint.host).await?;
            peer.endpoint = Some(Endpoint {
                host: address.to_string(),
                port: endpoint.port,
            });
        }
        Ok(config)
    }

    /// Go's `resolveLocal`: lookup with both families, filter by the
    /// domain strategy, pick randomly (`dice.Roll`) among the candidates.
    async fn resolve_endpoint(
        dns: Option<&crate::dns::app::DnsApp>,
        strategy: DomainStrategy,
        host: &str,
    ) -> anyhow::Result<IpAddr> {
        let addresses = match dns {
            Some(app) => {
                app.lookup_ip(
                    host,
                    QueryOptions {
                        ipv4: true,
                        ipv6: true,
                    },
                )
                .await
                .with_context(|| format!("WireGuard endpoint DNS lookup for {host}"))?
                .ips
            }
            None => tokio::net::lookup_host((host, 0))
                .await
                .with_context(|| format!("WireGuard endpoint system lookup for {host}"))?
                .map(|address| address.ip())
                .collect(),
        };
        let selected = strategy.select_addresses(&addresses);
        ensure!(
            !selected.is_empty(),
            "WireGuard domainStrategy {strategy:?} produced no address for endpoint {host}"
        );
        Ok(selected[rand::random::<usize>() % selected.len()])
    }

    /// Resolve one target name. `remoteDNS` servers are queried through the
    /// tunnel (Go's `CreateNetTUN` resolver); `local` resolves on the host
    /// while the connection itself still crosses the tunnel.
    async fn resolve_target(entry: &EngineEntry, name: &str) -> anyhow::Result<Vec<IpAddr>> {
        match &entry.dns {
            RemoteDns::Local => tokio::net::lookup_host((name, 0))
                .await
                .with_context(|| format!("WireGuard host DNS lookup for {name}"))
                .map(|addresses| addresses.map(|address| address.ip()).collect()),
            RemoteDns::Servers(servers) => resolve_in_tunnel(entry, servers, name).await,
        }
    }

    /// Query every configured server once (in order, like the Go resolver's
    /// fallback), every address family the strategy allows, and merge the
    /// answers of the first server that responds with records.
    async fn resolve_in_tunnel(
        entry: &EngineEntry,
        servers: &[IpAddr],
        name: &str,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let _serialized = entry.resolve_guard.lock().await;
        let (want_v4, want_v6) = match entry.strategy {
            DomainStrategy::ForceIp | DomainStrategy::ForceIpv4v6 | DomainStrategy::ForceIpv6v4 => {
                (true, true)
            }
            DomainStrategy::ForceIpv4 => (true, false),
            DomainStrategy::ForceIpv6 => (false, true),
        };
        let queries: Vec<RecordType> = [(want_v4, RecordType::A), (want_v6, RecordType::AAAA)]
            .into_iter()
            .filter(|(wanted, _)| *wanted)
            .map(|(_, record)| record)
            .collect();
        ensure!(
            !queries.is_empty(),
            "WireGuard domainStrategy {:?} requests no address family",
            entry.strategy
        );
        for server in servers {
            let mut resolved = Vec::new();
            for record in &queries {
                if let Ok(answers) = query_server(entry, *server, *record, name).await {
                    resolved.extend(answers);
                }
            }
            if !resolved.is_empty() {
                return Ok(resolved);
            }
        }
        bail!(
            "WireGuard tunnel DNS produced no address for {name} after querying {} server(s)",
            servers.len()
        )
    }

    /// One bounded query/response exchange through the netstack's UDP path.
    async fn query_server(
        entry: &EngineEntry,
        server: IpAddr,
        record: RecordType,
        name: &str,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let source_ip = entry
            .addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == server.is_ipv4())
            .with_context(|| {
                format!(
                    "WireGuard interface has no {} address for tunnel DNS server {server}",
                    if server.is_ipv4() { "IPv4" } else { "IPv6" }
                )
            })?;
        let source = SocketAddr::new(source_ip, TUNNEL_DNS_PORT);
        let destination = SocketAddr::new(server, 53);
        let id: u16 = rand::random();
        let question = Question::new(name, record)?;
        let query = encode_query(id, &question, None)?;
        let netstack = entry.net.netstack();
        netstack
            .udp_send(source, destination, &query)
            .await
            .context("send the WireGuard tunnel DNS query")?;
        let deadline = Instant::now() + TUNNEL_DNS_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("WireGuard tunnel DNS server {server} timed out");
            }
            let datagram = match timeout(remaining, netstack.udp_recv()).await {
                Ok(Ok(datagram)) => datagram,
                Ok(Err(error)) => {
                    return Err(
                        anyhow::Error::new(error).context("WireGuard tunnel DNS receive failed")
                    );
                }
                Err(_) => bail!("WireGuard tunnel DNS server {server} timed out"),
            };
            // Skip strays: only a datagram answering our source port and
            // transaction id completes the exchange.
            if datagram.destination != source {
                continue;
            }
            let message = match decode(&datagram.payload) {
                Ok(message) => message,
                Err(_) => continue,
            };
            if message.header.id != id || !message.header.is_response() {
                continue;
            }
            // An error response answers with no records; the next configured
            // server is then tried like the Go resolver fallback.
            if message.response_code() != 0 {
                return Ok(Vec::new());
            }
            return Ok(message
                .answers
                .into_iter()
                .filter_map(|answer| match answer.data {
                    RecordData::A(address) => Some(IpAddr::V4(address)),
                    RecordData::Aaaa(address) => Some(IpAddr::V6(address)),
                    RecordData::Cname(_) | RecordData::Other(_) => None,
                })
                .collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::settings_key;
    use crate::protocol::wireguard::{WireGuardConfig, WireGuardPeerConfig};

    // Key fixtures from protocol/wireguard/tests.rs, which took them from
    // testing/scenarios/wireguard_test.go.
    const SERVER_PRIVATE: &str = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=";
    const SERVER_PUBLIC: &str = "MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw=";
    const CLIENT_PRIVATE: &str = "CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=";
    const CLIENT_PUBLIC: &str = "osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0=";

    fn settings(
        secret: &str,
        peer_public: &str,
        endpoint: &str,
        allowed_ips: &[&str],
    ) -> WireGuardConfig {
        WireGuardConfig {
            secret_key: secret.to_owned(),
            peers: vec![WireGuardPeerConfig {
                public_key: peer_public.to_owned(),
                endpoint: endpoint.to_owned(),
                allowed_ips: Some(
                    allowed_ips
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// The engine cache key follows every settings field that `build` reads.
    #[test]
    fn settings_key_distinguishes_distinct_outbounds() {
        let base = settings(
            CLIENT_PRIVATE,
            SERVER_PUBLIC,
            "127.0.0.1:51820",
            &["0.0.0.0/0"],
        );
        assert_eq!(settings_key(&base), settings_key(&base.clone()));
        let mut other = base.clone();
        other.secret_key = SERVER_PRIVATE.to_owned();
        assert_ne!(settings_key(&base), settings_key(&other));
        let mut other = base.clone();
        other.peers[0].keep_alive = 25;
        assert_ne!(settings_key(&base), settings_key(&other));
        let mut other = base.clone();
        other.peers[0].allowed_ips = Some(vec!["::/0".to_owned()]);
        assert_ne!(settings_key(&base), settings_key(&other));
        let mut other = base.clone();
        other.mtu = 1280;
        assert_ne!(settings_key(&base), settings_key(&other));
        let mut other = base.clone();
        other.remote_dns = vec!["1.1.1.1".to_owned()];
        assert_ne!(settings_key(&base), settings_key(&other));
        let mut other = base.clone();
        other.address = Some(Vec::new());
        assert_ne!(settings_key(&base), settings_key(&other));
    }

    #[cfg(feature = "native-tun")]
    mod tunnel {
        use std::{
            net::{IpAddr, Ipv4Addr, SocketAddr},
            sync::Arc,
            time::Duration,
        };

        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            task::JoinHandle,
            time::timeout,
        };

        use crate::address::{Address, Destination};
        use crate::protocol::wireguard::Role;
        use crate::protocol::wireguard_netstack::{NetTcpStream, WgNet, WgUdpSocket};

        use super::super::WireguardPool;
        use super::{CLIENT_PRIVATE, CLIENT_PUBLIC, SERVER_PRIVATE, SERVER_PUBLIC, settings};

        /// Aborts the spawned pump task on unwind or scope exit, so every
        /// test leaves no engine behind.
        struct AbortOnDrop<T>(JoinHandle<T>);

        impl<T> Drop for AbortOnDrop<T> {
            fn drop(&mut self) {
                self.0.abort();
            }
        }

        fn tunnel_v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }

        async fn echo_once(conn: NetTcpStream) -> u64 {
            let (mut reader, mut writer) = tokio::io::split(conn);
            tokio::io::copy(&mut reader, &mut writer)
                .await
                .expect("echo copy")
        }

        /// A server engine on a real loopback UDP socket, with its pump task
        /// guarded for the test's lifetime. The server's allowed IPs cover the
        /// client's default tunnel addresses so both families are authorized.
        async fn echo_server() -> anyhow::Result<(
            Arc<WgNet<WgUdpSocket>>,
            SocketAddr,
            AbortOnDrop<anyhow::Result<()>>,
        )> {
            let transport = WgUdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
            let endpoint = transport.local_addr()?;
            let server = Arc::new(WgNet::new(
                settings(
                    SERVER_PRIVATE,
                    CLIENT_PUBLIC,
                    "",
                    &["10.0.0.1/32", "fd59:7153:2388:b5fd::1/128"],
                )
                .build(Role::Server)?,
                transport,
            )?);
            let runner = {
                let server = server.clone();
                AbortOnDrop(tokio::spawn(async move { server.run().await }))
            };
            Ok((server, endpoint, runner))
        }

        #[tokio::test]
        async fn pool_dials_and_echoes_over_real_udp_sockets() {
            let (server, endpoint, mut runner) = echo_server().await.unwrap();
            let work = async {
                let bind = SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_002);
                let mut listener = server.netstack().listen_tcp(bind).await?;
                let pool = WireguardPool::new();
                let client = settings(
                    CLIENT_PRIVATE,
                    SERVER_PUBLIC,
                    &endpoint.to_string(),
                    &["0.0.0.0/0", "::/0"],
                );
                let target = Destination {
                    address: Address::Ip(tunnel_v4(10, 0, 0, 2)),
                    port: 40_002,
                };
                let (mut stream, bound) = pool.dial(None, &client, &target).await?;
                // The dial source is the device's tunnel address, like Go's
                // netstack dial from the interface address.
                assert_eq!(bound.ip(), tunnel_v4(10, 0, 0, 1));
                assert_ne!(bound.port(), 0);
                let (conn, remote) = listener.accept().await?;
                assert_eq!(remote.ip(), tunnel_v4(10, 0, 0, 1));
                let echo = tokio::spawn(echo_once(conn));
                // Larger than the MTU so the echo exercises segmentation.
                let payload: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
                stream.write_all(&payload).await?;
                let mut echoed = vec![0u8; payload.len()];
                stream.read_exact(&mut echoed).await?;
                assert_eq!(echoed, payload);
                drop(stream);
                let copied = timeout(Duration::from_secs(2), echo)
                    .await
                    .expect("echo finished")
                    .expect("echo task alive");
                assert_eq!(copied as usize, payload.len());
                anyhow::Ok(())
            };
            timeout(Duration::from_secs(5), async {
                tokio::select! {
                    result = &mut runner.0 => Err(anyhow::anyhow!(
                        "WireGuard server pumps ended early: {result:?}"
                    )),
                    result = work => result,
                }
            })
            .await
            .expect("dial test finished within the deadline")
            .unwrap();
        }

        #[tokio::test]
        async fn pool_reuses_one_engine_across_dials() {
            let (server, endpoint, mut runner) = echo_server().await.unwrap();
            let work = async {
                let bind = SocketAddr::new(tunnel_v4(10, 0, 0, 2), 40_002);
                let mut listener = server.netstack().listen_tcp(bind).await?;
                let pool = WireguardPool::new();
                let client = settings(
                    CLIENT_PRIVATE,
                    SERVER_PUBLIC,
                    &endpoint.to_string(),
                    &["0.0.0.0/0", "::/0"],
                );
                let target = Destination {
                    address: Address::Ip(tunnel_v4(10, 0, 0, 2)),
                    port: 40_002,
                };
                for round in 0..2u8 {
                    let (mut stream, bound) = pool.dial(None, &client, &target).await?;
                    assert_eq!(bound.ip(), tunnel_v4(10, 0, 0, 1));
                    let (conn, remote) = listener.accept().await?;
                    assert_eq!(remote.ip(), tunnel_v4(10, 0, 0, 1));
                    let echo = tokio::spawn(echo_once(conn));
                    let payload = vec![0x41 + round; 1024];
                    stream.write_all(&payload).await?;
                    let mut echoed = vec![0u8; payload.len()];
                    stream.read_exact(&mut echoed).await?;
                    assert_eq!(echoed, payload);
                    drop(stream);
                    timeout(Duration::from_secs(2), echo)
                        .await
                        .expect("echo finished")
                        .expect("echo task alive");
                }
                // Two dials through identical settings stayed on one engine;
                // the second dial rode the first one's established session.
                assert_eq!(pool.engine_count().await, 1);
                anyhow::Ok(())
            };
            timeout(Duration::from_secs(5), async {
                tokio::select! {
                    result = &mut runner.0 => Err(anyhow::anyhow!(
                        "WireGuard server pumps ended early: {result:?}"
                    )),
                    result = work => result,
                }
            })
            .await
            .expect("reuse test finished within the deadline")
            .unwrap();
        }

        #[tokio::test]
        async fn pool_rejects_unresolvable_domain_targets_explicitly() {
            let (server, endpoint, mut runner) = echo_server().await.unwrap();
            let _ = server;
            let work = async {
                let pool = WireguardPool::new();
                let mut client = settings(
                    CLIENT_PRIVATE,
                    SERVER_PUBLIC,
                    &endpoint.to_string(),
                    &["0.0.0.0/0"],
                );
                // 127.0.0.1 is a tunnel-side address here: nothing answers
                // there inside the tunnel, so the bounded resolver must
                // reject the dial explicitly instead of hanging.
                client.remote_dns = vec!["127.0.0.1".to_owned()];
                client.domain_strategy = "forceipv4".to_owned();
                let target = Destination {
                    address: Address::Domain("echo.invalid".to_owned()),
                    port: 80,
                };
                // `BoxStream` carries no `Debug`, so match instead of
                // `expect_err`.
                let error = match pool.dial(None, &client, &target).await {
                    Ok(_) => panic!("domain dial must fail"),
                    Err(error) => error,
                };
                assert!(
                    format!("{error:#}").contains("tunnel DNS"),
                    "unexpected error: {error:#}"
                );
                anyhow::Ok(())
            };
            timeout(Duration::from_secs(5), async {
                tokio::select! {
                    result = &mut runner.0 => Err(anyhow::anyhow!(
                        "WireGuard server pumps ended early: {result:?}"
                    )),
                    result = work => result,
                }
            })
            .await
            .expect("rejection test finished within the deadline")
            .unwrap();
        }
    }
}
