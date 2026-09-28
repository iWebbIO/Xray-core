// P26 sockopt: port of infra/conf/transport_sockopt.go (JSON surface and
// validation) plus transport/internet/sockopt_{linux,windows}.go /
// system_dialer.go / system_listener.go (per-platform application).
#![allow(dead_code)]
//! Xray's `sockopt` configuration, compiled and applied per platform.
//!
//! The JSON surface is `infra/conf/transport_sockopt.go`'s `SocketConfig`
//! (every Go field, exact camelCase key names, unknown keys rejected).
//! `compile()` mirrors `SocketConfig.Build()` for validation, then applies the
//! MIGRATION.md doctrine: an option this build cannot honor is a NAMED error,
//! never a silent downgrade. Go's per-platform files silently ignore options
//! such as `mark` or `tcpUserTimeout` on Windows; this build fails them at
//! compile time with the option name and the reason.
//!
//! Per-option classification for this build (socket2 0.5 default features,
//! tokio 1.53, `unsafe` forbidden by workspace lint, no libc dependency):
//!
//! | option | classification | where applied |
//! |---|---|---|
//! | `mark` | unsupported (SO_MARK) | compile error: Linux-only in Go; socket2 `set_mark` needs the `all` feature |
//! | `tcpFastOpen` true/positive | unsupported | compile error: no TCP_FASTOPEN setter in socket2 0.5 defaults |
//! | `tcpFastOpen` false/0/negative | applicable no-op | OS default for this build's sockets is TFO-off, matching the requested disable (Go quirk: explicit 0 skips like unset) |
//! | `tproxy` | unsupported | compile error: IP_TRANSPARENT is Linux-only; socket2 `set_ip_transparent` is `all`-feature + Linux |
//! | `acceptProxyProtocol` | applicable | runtime-level: `transport::proxy_protocol_runtime::accept_proxy_protocol` before the transport accept chain |
//! | `domainStrategy` | applicable | dial-level: validated enum exposed for the dialer's DNS resolution (admission) |
//! | `dialerProxy` | unsupported | compile error: needs the tagged-dialer runtime (dial through another outbound handler) |
//! | `tcpKeepAliveInterval` / `tcpKeepAliveIdle` | applicable | `apply_outbound` (Chrome 45s/45s defaults like Go's dialer), `apply_inbound` (default disabled like Go's listener), `apply_keepalive` per accepted connection |
//! | `tcpCongestion` | unsupported | compile error: TCP_CONGESTION is Linux-only in Go; no socket2 setter |
//! | `tcpWindowClamp` | unsupported | compile error: Linux-only in Go; no socket2 setter |
//! | `tcpMaxSeg` | unsupported | compile error: Linux-only in Go; socket2's setter is `all`-feature gated |
//! | `penetrate` | applicable | XHTTP dialer-level: download settings inherit the main sockopt (delegated to the XHTTP dialer) |
//! | `tcpUserTimeout` | unsupported | compile error: Linux-only in Go (Windows never applies it); socket2 `set_tcp_user_timeout` is `all`-feature gated |
//! | `v6only` | applicable | `apply_inbound` on an IPv6 socket via socket2 `set_only_v6`, BEFORE bind (Go's Control hook runs pre-bind) |
//! | `interface` | unsupported | compile error: needs SO_BINDTODEVICE (Linux) or IP_UNICAST_IF (Windows); socket2 exposes neither in defaults |
//! | `tcpMptcp` | unsupported | compile error: Go uses net SetMultipathTCP; neither socket2 nor tokio exposes a toggle |
//! | `customSockopt` | unsupported | compile error per system-matching entry: raw setsockopt needs libc; `unsafe` is forbidden |
//! | `customSockopt` system mismatch | applicable skip | Go's filter: debug-log and skip entries whose `system` is not this OS |
//! | `addressPortStrategy` | applicable | DNS-level: validated enum exposed for the resolver (SRV/TXT strategies) |
//! | `happyEyeballs` | applicable | dial-level: validated config with Go defaults (interleave 1, maxConcurrentTry 4) for the racing dialer |
//! | `trustedXForwardedFor` | applicable | hub-level: exposed for gRPC/HTTPUpgrade/XHTTP to derive the remote address |
//!
//! Go applies socket options in the dialer/listener Control hook and only
//! LOGS failures (`failed to apply socket options`); `apply_*` here returns
//! `io::Result` and the caller decides whether to log (integration contract).

use std::{io, time::Duration};

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use socket2::{SockRef, TcpKeepalive};

/// The error Go returns for a mistyped `tcpFastOpen` value
/// (infra/conf/transport_sockopt.go).
const TFO_TYPE_ERROR: &str = "tcpFastOpen: only boolean and integer value is acceptable";

/// Go's outbound keepalive default (system_dialer.go "Chrome defaults"),
/// applied whenever the sockopt does not override or disable it.
const OUTBOUND_KEEPALIVE_DEFAULT: Duration = Duration::from_secs(45);

// ---------------------------------------------------------------------------
// JSON surface
// ---------------------------------------------------------------------------

/// `tcpFastOpen` after Go's parsing: a bool becomes a queue size (true = 256,
/// false = disable); a number is quantized through
/// `int32(math.Min(v, math.MaxInt32))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TfoSetting {
    /// Explicit 0 (or a fraction quantizing to 0): Go lands on the same
    /// `tfo == 0` sentinel as "unset" and never calls setsockopt.
    Skip,
    /// false or a negative number: TCP_FASTOPEN explicitly disabled.
    Disable,
    /// true (queue 256) or a positive number: the queue depth.
    Enable(i32),
}

/// `happyEyeballs`, matching Go's custom `UnmarshalJSON` that starts from the
/// defaults `PrioritizeIPv6: false, Interleave: 1, TryDelayMs: 0,
/// MaxConcurrentTry: 4`. Like Go's anonymous inner struct, unknown keys are
/// tolerated here (the leniency is Go's, not ours).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HappyEyeballs {
    /// Go's json tag is `prioritizeIPv6` (capital V6) — serde's camelCase
    /// would produce `prioritizeIpv6`, so the exact key is pinned here.
    #[serde(default, rename = "prioritizeIPv6")]
    pub prioritize_ipv6: bool,
    #[serde(default)]
    pub try_delay_ms: u64,
    #[serde(default = "default_interleave")]
    pub interleave: u32,
    #[serde(default = "default_max_concurrent_try")]
    pub max_concurrent_try: u32,
}

fn default_interleave() -> u32 {
    1
}

fn default_max_concurrent_try() -> u32 {
    4
}

impl Default for HappyEyeballs {
    fn default() -> Self {
        Self {
            prioritize_ipv6: false,
            try_delay_ms: 0,
            interleave: default_interleave(),
            max_concurrent_try: default_max_concurrent_try(),
        }
    }
}

/// One `customSockopt` entry, exactly Go's `CustomSockoptConfig` keys. Go's
/// json decoding tolerates unknown keys here, so this struct does too.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CustomSockopt {
    pub system: String,
    pub network: String,
    pub level: String,
    pub opt: String,
    pub value: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// The `sockopt` JSON object: every field of Go's `SocketConfig`
/// (infra/conf/transport_sockopt.go) with its exact key names. Unknown keys
/// are rejected; the nested `happyEyeballs`/`customSockopt` objects keep Go's
/// per-key leniency.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SockoptSettings {
    pub mark: i32,
    #[serde(default, deserialize_with = "parse_tcp_fast_open")]
    pub tcp_fast_open: Option<TfoSetting>,
    /// Raw string; `compile()` maps it case-insensitively, and an unknown
    /// value silently becomes `Off` exactly like Go's default switch arm.
    pub tproxy: String,
    pub accept_proxy_protocol: bool,
    /// Raw string; validated by `compile()` (Go validates in `Build`).
    pub domain_strategy: String,
    pub dialer_proxy: String,
    pub tcp_keep_alive_interval: i32,
    pub tcp_keep_alive_idle: i32,
    pub tcp_congestion: String,
    pub tcp_window_clamp: i32,
    pub tcp_max_seg: i32,
    pub penetrate: bool,
    pub tcp_user_timeout: i32,
    pub v6only: bool,
    pub interface: String,
    pub tcp_mptcp: bool,
    pub custom_sockopt: Vec<CustomSockopt>,
    /// Raw string; validated by `compile()` (Go validates in `Build`).
    pub address_port_strategy: String,
    pub happy_eyeballs: Option<HappyEyeballs>,
    pub trusted_x_forwarded_for: Vec<String>,
}

fn parse_tcp_fast_open<'de, D>(deserializer: D) -> Result<Option<TfoSetting>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::Bool(true) => Ok(Some(TfoSetting::Enable(256))),
        Value::Bool(false) => Ok(Some(TfoSetting::Disable)),
        Value::Number(number) => {
            let raw = number
                .as_f64()
                .ok_or_else(|| serde::de::Error::custom(TFO_TYPE_ERROR))?;
            // Go: int32(math.Min(v, math.MaxInt32)); out-of-range and
            // fractional conversions truncate/overflow the same way the
            // int32 cast does.
            let quantized = raw.min(i32::MAX as f64) as i32;
            Ok(Some(match quantized {
                0 => TfoSetting::Skip,
                i32::MIN..=-1 => TfoSetting::Disable,
                queue => TfoSetting::Enable(queue),
            }))
        }
        _ => Err(serde::de::Error::custom(TFO_TYPE_ERROR)),
    }
}

impl SockoptSettings {
    /// The single entry point the config layer calls with the `sockopt`
    /// JSON object (Go: json.Unmarshal into conf.SocketConfig).
    pub fn from_value(value: &Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value.clone())?)
    }

    /// Validate exactly like Go's `SocketConfig.Build()`, then reject every
    /// configured option this build cannot honor with an error naming the
    /// option and the reason (MIGRATION.md: never silently downgrade).
    pub fn compile(&self) -> anyhow::Result<CompiledSockopt> {
        let tfo = self.tcp_fast_open.unwrap_or(TfoSetting::Skip);
        let tproxy = TProxyMode::parse(&self.tproxy);
        let domain_strategy = DomainStrategy::parse(&self.domain_strategy)?;
        let address_port_strategy = AddressPortStrategy::parse(&self.address_port_strategy)?;
        if i64::from(self.tcp_keep_alive_idle) * i64::from(self.tcp_keep_alive_interval) < 0 {
            anyhow::bail!(
                "invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: {} {}",
                self.tcp_keep_alive_idle,
                self.tcp_keep_alive_interval
            );
        }

        let mut custom_sockopt = Vec::with_capacity(self.custom_sockopt.len());
        for (index, entry) in self.custom_sockopt.iter().enumerate() {
            if !entry.system.is_empty() && entry.system != go_os() {
                // Go: LogDebug "CustomSockopt system not match: want ... got
                // ..." and skip the entry.
                tracing::debug!(
                    "customSockopt[{index}] system not match: want {} got {}, skipping",
                    entry.system,
                    go_os()
                );
                continue;
            }
            custom_sockopt.push(ParsedCustomSockopt::parse(entry)?);
        }

        // Explicitly-unsupported options, in Go's field order. Each error
        // names the option and why it cannot be honored on this build.
        if self.mark != 0 {
            return Err(unsupported(
                "mark",
                "SO_MARK is Linux-only in the Go reference (sockopt_linux.go) and this \
                 build's socket2 (0.5, default features) exposes no set_mark",
            ));
        }
        if matches!(tfo, TfoSetting::Enable(_)) {
            return Err(unsupported(
                "tcpFastOpen",
                "TCP_FASTOPEN (listener) / TCP_FASTOPEN_CONNECT (dialer) has no setter in \
                 socket2 0.5 default features on any platform of this workspace",
            ));
        }
        if tproxy != TProxyMode::Off {
            return Err(unsupported(
                "tproxy",
                "IP_TRANSPARENT is Linux-only in the Go reference and socket2's \
                 set_ip_transparent needs both the `all` feature and Linux",
            ));
        }
        if !self.dialer_proxy.is_empty() {
            return Err(unsupported(
                "dialerProxy",
                "it requires the tagged-dialer runtime (Go transport/internet/tagged: \
                 dial through another registered outbound handler), which this dial path \
                 does not provide",
            ));
        }
        if !self.tcp_congestion.is_empty() {
            return Err(unsupported(
                "tcpCongestion",
                "TCP_CONGESTION is Linux-only in the Go reference and socket2 0.5 default \
                 features exposes no setter",
            ));
        }
        if self.tcp_window_clamp > 0 {
            return Err(unsupported(
                "tcpWindowClamp",
                "TCP_WINDOW_CLAMP is Linux-only in the Go reference and socket2 0.5 \
                 default features exposes no setter",
            ));
        }
        if self.tcp_max_seg > 0 {
            return Err(unsupported(
                "tcpMaxSeg",
                "TCP_MAXSEG is Linux-only in the Go reference and socket2's setter is \
                 gated behind its `all` feature",
            ));
        }
        if self.tcp_user_timeout > 0 {
            return Err(unsupported(
                "tcpUserTimeout",
                "TCP_USER_TIMEOUT is Linux-only in the Go reference (Go never applies it \
                 on Windows) and socket2's set_tcp_user_timeout is `all`-feature gated",
            ));
        }
        if !self.interface.is_empty() {
            return Err(unsupported(
                "interface",
                "it needs SO_BINDTODEVICE (Linux) or IP_UNICAST_IF/IPV6_UNICAST_IF \
                 (Windows); socket2 0.5 default features exposes neither setter",
            ));
        }
        if self.tcp_mptcp {
            return Err(unsupported(
                "tcpMptcp",
                "Go uses net Dialer/ListenConfig SetMultipathTCP and neither socket2 0.5 \
                 default features nor tokio 1.53 exposes an MPTCP toggle",
            ));
        }
        if let Some(entry) = custom_sockopt.first() {
            return Err(unsupported(
                "customSockopt[0]",
                &format!(
                    "raw setsockopt (level {}, opt {}) needs libc, which is not a \
                     workspace dependency, and `unsafe` is a forbidden workspace lint",
                    entry.level, entry.opt
                ),
            ));
        }

        let (idle, interval) = (self.tcp_keep_alive_idle, self.tcp_keep_alive_interval);
        let keepalive = if idle < 0 || interval < 0 {
            KeepalivePlan {
                disable: true,
                ..KeepalivePlan::default()
            }
        } else if idle > 0 || interval > 0 {
            KeepalivePlan {
                time: (idle > 0).then(|| Duration::from_secs(idle as u64)),
                interval: (interval > 0).then(|| Duration::from_secs(interval as u64)),
                disable: false,
            }
        } else {
            KeepalivePlan::default()
        };

        Ok(CompiledSockopt {
            tfo,
            tproxy,
            accept_proxy_protocol: self.accept_proxy_protocol,
            domain_strategy,
            dialer_proxy: self.dialer_proxy.clone(),
            keepalive,
            penetrate: self.penetrate,
            v6only: self.v6only,
            happy_eyeballs: self.happy_eyeballs.unwrap_or_default(),
            custom_sockopt,
            address_port_strategy,
            trusted_x_forwarded_for: self.trusted_x_forwarded_for.clone(),
        })
    }
}

fn unsupported(option: &str, why: &str) -> anyhow::Error {
    anyhow::anyhow!("sockopt `{option}` is explicitly unsupported on this build: {why}")
}

// ---------------------------------------------------------------------------
// Validated enums (Go's proto enums reached through SocketConfig.Build)
// ---------------------------------------------------------------------------

/// `internet.SocketConfig_TProxyMode`. Go's parser maps every unrecognized
/// string to `Off` (default switch arm); `compile()` mirrors that.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TProxyMode {
    #[default]
    Off,
    TProxy,
    Redirect,
}

impl TProxyMode {
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "tproxy" => Self::TProxy,
            "redirect" => Self::Redirect,
            _ => Self::Off,
        }
    }
}

/// `internet.DomainStrategy` with Go's case-insensitive switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainStrategy {
    AsIs,
    UseIp,
    UseIp4,
    UseIp6,
    UseIp46,
    UseIp64,
    ForceIp,
    ForceIp4,
    ForceIp6,
    ForceIp46,
    ForceIp64,
}

impl DomainStrategy {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        Ok(match value.to_lowercase().as_str() {
            "" | "asis" => Self::AsIs,
            "useip" => Self::UseIp,
            "useipv4" => Self::UseIp4,
            "useipv6" => Self::UseIp6,
            "useipv4v6" => Self::UseIp46,
            "useipv6v4" => Self::UseIp64,
            "forceip" => Self::ForceIp,
            "forceipv4" => Self::ForceIp4,
            "forceipv6" => Self::ForceIp6,
            "forceipv4v6" => Self::ForceIp46,
            "forceipv6v4" => Self::ForceIp64,
            // Go reports the original (not lowercased) value.
            _ => anyhow::bail!("unsupported domain strategy: {value}"),
        })
    }
}

/// `internet.AddressPortStrategy` with Go's case-insensitive switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressPortStrategy {
    None,
    SrvPortOnly,
    SrvAddressOnly,
    SrvPortAndAddress,
    TxtPortOnly,
    TxtAddressOnly,
    TxtPortAndAddress,
}

impl AddressPortStrategy {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        Ok(match value.to_lowercase().as_str() {
            "" | "none" => Self::None,
            "srvportonly" => Self::SrvPortOnly,
            "srvaddressonly" => Self::SrvAddressOnly,
            "srvportandaddress" => Self::SrvPortAndAddress,
            "txtportonly" => Self::TxtPortOnly,
            "txtaddressonly" => Self::TxtAddressOnly,
            "txtportandaddress" => Self::TxtPortAndAddress,
            _ => anyhow::bail!("unsupported address and port strategy: {value}"),
        })
    }
}

// ---------------------------------------------------------------------------
// customSockopt parsing (Go's apply-time strconv semantics)
// ---------------------------------------------------------------------------

/// `customSockopt` after Go's parse loop: `strconv.Atoi` errors are IGNORED
/// (garbage becomes 0), an empty `opt` is a config error, and the level
/// defaults to 0x6 (IPPROTO_TCP) when empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCustomSockopt {
    pub system: String,
    pub network: String,
    pub level: i32,
    pub opt: i32,
    pub value: CustomSockoptValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomSockoptValue {
    Int(i32),
    Str(String),
}

/// Go's `strconv.Atoi` with the error dropped: `+5` parses, garbage and
/// out-of-range values become 0.
fn atoi_lenient(value: &str) -> i32 {
    value.parse().unwrap_or_default()
}

impl ParsedCustomSockopt {
    fn parse(entry: &CustomSockopt) -> anyhow::Result<Self> {
        if entry.opt.is_empty() {
            // Go: errors.New("No opt!")
            anyhow::bail!("No opt!");
        }
        let level = if entry.level.is_empty() {
            0x6
        } else {
            atoi_lenient(&entry.level)
        };
        let opt = atoi_lenient(&entry.opt);
        let value = match entry.kind.as_str() {
            "int" => CustomSockoptValue::Int(atoi_lenient(&entry.value)),
            "str" => CustomSockoptValue::Str(entry.value.clone()),
            other => anyhow::bail!("unknown CustomSockopt type: {other}"),
        };
        Ok(Self {
            system: entry.system.clone(),
            network: entry.network.clone(),
            level,
            opt,
            value,
        })
    }

    /// Go's network filter (`strings.HasPrefix(network, custom.Network)`,
    /// where the runtime network is tcp4/tcp6/udp4/udp6): an empty filter
    /// matches everything and "tcp" matches "tcp4"/"tcp6".
    pub fn matches_network(&self, network: SocketNet) -> bool {
        network.as_str().starts_with(&self.network)
    }
}

/// `runtime.GOOS` naming for the customSockopt `system` filter (Go says
/// "darwin" where Rust's std says "macos").
pub fn go_os() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        "darwin"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "solaris") {
        "solaris"
    } else {
        std::env::consts::OS
    }
}

// ---------------------------------------------------------------------------
// Compiled sockopt and socket application
// ---------------------------------------------------------------------------

/// Keepalive plan derived from `tcpKeepAliveIdle`/`tcpKeepAliveInterval`:
/// positive values configure, negative values disable, zero leaves the plan
/// absent (which still means "enabled 45s/45s" outbound and "disabled"
/// inbound, mirroring Go's dialer and listener defaults).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeepalivePlan {
    pub time: Option<Duration>,
    pub interval: Option<Duration>,
    pub disable: bool,
}

/// The network stack the socket was created with, mirroring the `network`
/// parameter Go passes into `applyOutbound/InboundSocketOptions` (Go warns
/// that it must carry tcp4/tcp6/udp4/udp6, not just tcp/udp).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketNet {
    Tcp,
    Tcp4,
    Tcp6,
    Udp,
    Udp4,
    Udp6,
}

impl SocketNet {
    /// Go transport/internet/sockopt.go `isTCPSocket`.
    pub const fn is_tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::Tcp4 | Self::Tcp6)
    }

    /// Go transport/internet/sockopt.go `isUDPSocket`.
    pub const fn is_udp(self) -> bool {
        matches!(self, Self::Udp | Self::Udp4 | Self::Udp6)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tcp4 => "tcp4",
            Self::Tcp6 => "tcp6",
            Self::Udp => "udp",
            Self::Udp4 => "udp4",
            Self::Udp6 => "udp6",
        }
    }

    /// The concrete network for a socket about to be created for an address
    /// of this family (Go dials tcp4/tcp6 from the resolved address).
    pub const fn tcp_for(ipv6: bool) -> Self {
        if ipv6 { Self::Tcp6 } else { Self::Tcp4 }
    }

    /// The UDP counterpart of [`SocketNet::tcp_for`].
    pub const fn udp_for(ipv6: bool) -> Self {
        if ipv6 { Self::Udp6 } else { Self::Udp4 }
    }
}

/// `sockopt` after validation: only options this build can honor remain,
/// everything else failed `compile()` with a named error.
#[derive(Clone, Debug)]
pub struct CompiledSockopt {
    /// Always `Skip` or `Disable`; enabling fails `compile()`.
    pub tfo: TfoSetting,
    /// Always `Off`; tproxy/redirect fail `compile()`.
    pub tproxy: TProxyMode,
    pub accept_proxy_protocol: bool,
    pub domain_strategy: DomainStrategy,
    /// Always empty; a tag fails `compile()`.
    pub dialer_proxy: String,
    pub keepalive: KeepalivePlan,
    pub penetrate: bool,
    pub v6only: bool,
    pub happy_eyeballs: HappyEyeballs,
    /// Always empty: every system-matching entry fails `compile()`.
    pub custom_sockopt: Vec<ParsedCustomSockopt>,
    pub address_port_strategy: AddressPortStrategy,
    pub trusted_x_forwarded_for: Vec<String>,
}

impl CompiledSockopt {
    /// Apply to a dialed (connected) socket, mirroring Go's
    /// `applyOutboundSocketOptions` from the dialer's Control hook. Applying
    /// to the connected socket is equivalent for every option portable here.
    /// Go only logs failures at the dial site; this returns them.
    pub fn apply_outbound(&self, network: SocketNet, socket: &SockRef) -> io::Result<()> {
        if network.is_tcp() {
            self.apply_tcp_keepalive_outbound(socket)?;
        }
        Ok(())
    }

    /// Apply to a listening socket, mirroring Go's
    /// `applyInboundSocketOptions` from the listener's Control hook
    /// (sockopt_linux.go / sockopt_windows.go).
    ///
    /// ORDERING (Go parity): Go's Control hook runs on the socket fd AFTER
    /// creation but BEFORE `bind()`. When `v6only` is configured, call this
    /// on the socket before binding it — on Windows `IPV6_V6ONLY` is only
    /// settable pre-bind (10022 WSAEINVAL afterwards), and on Linux it is
    /// only effective pre-bind. The keepalive half works on both bound and
    /// unbound listening sockets. Like Go's per-socket application, a v4
    /// socket with `v6only` configured is an error (Go's setsockopt would
    /// fail and be logged; here it is explicit).
    pub fn apply_inbound(&self, network: SocketNet, socket: &SockRef) -> io::Result<()> {
        if network.is_tcp() {
            self.apply_tcp_keepalive_inbound(socket)?;
        }
        if self.v6only {
            match network {
                SocketNet::Tcp4 | SocketNet::Udp4 => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "sockopt `v6only` (IPV6_V6ONLY) applies only to IPv6 sockets",
                    ));
                }
                _ => socket.set_only_v6(true)?,
            }
        }
        Ok(())
    }

    /// Replay the keepalive values on an ACCEPTED connection. This mirrors
    /// Go's `net.ListenConfig.KeepAliveConfig`, which the listener carries
    /// and reapplies to every accepted socket (on Windows SIO_KEEPALIVE_VALS
    /// is an ioctl and is not inherited from the listening socket).
    pub fn apply_keepalive(&self, socket: &SockRef) -> io::Result<()> {
        if self.keepalive.disable {
            return socket.set_keepalive(false);
        }
        if self.keepalive.time.is_none() && self.keepalive.interval.is_none() {
            // No configured values: the listener's default-disable state
            // already governs the accepted socket, like Go's KeepAlive = -1.
            return Ok(());
        }
        let mut keepalive = TcpKeepalive::new();
        if let Some(time) = self.keepalive.time {
            keepalive = keepalive.with_time(time);
        }
        if let Some(interval) = self.keepalive.interval {
            keepalive = keepalive.with_interval(interval);
        }
        socket.set_tcp_keepalive(&keepalive)
    }

    /// Outbound keepalive: Go's DefaultSystemDialer always dials with the
    /// "Chrome defaults" (45s idle / 45s interval) unless the sockopt
    /// overrides the values or disables keepalive with a negative one.
    fn apply_tcp_keepalive_outbound(&self, socket: &SockRef) -> io::Result<()> {
        if self.keepalive.disable {
            return socket.set_keepalive(false);
        }
        let time = self.keepalive.time.unwrap_or(OUTBOUND_KEEPALIVE_DEFAULT);
        let interval = self
            .keepalive
            .interval
            .unwrap_or(OUTBOUND_KEEPALIVE_DEFAULT);
        socket.set_tcp_keepalive(&TcpKeepalive::new().with_time(time).with_interval(interval))
    }

    /// Inbound keepalive: Go's listener defaults to DISABLED
    /// (`lc.KeepAlive = -1`), enables SO_KEEPALIVE when idle/interval is
    /// positive, and unsets it when either is negative. On Linux the
    /// KEEPIDLE/KEEPINTVL values are also set on the listening fd (accepted
    /// sockets inherit them); on Windows Go's fd hook only flips
    /// SO_KEEPALIVE and the values ride KeepAliveConfig per accepted
    /// connection — see `apply_keepalive`.
    fn apply_tcp_keepalive_inbound(&self, socket: &SockRef) -> io::Result<()> {
        if self.keepalive.disable {
            return socket.set_keepalive(false);
        }
        if self.keepalive.time.is_some() || self.keepalive.interval.is_some() {
            #[cfg(unix)]
            socket.set_tcp_keepalive(&self.keepalive_values())?;
            socket.set_keepalive(true)?;
        } else {
            socket.set_keepalive(false)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn keepalive_values(&self) -> TcpKeepalive {
        let mut keepalive = TcpKeepalive::new();
        if let Some(time) = self.keepalive.time {
            keepalive = keepalive.with_time(time);
        }
        if let Some(interval) = self.keepalive.interval {
            keepalive = keepalive.with_interval(interval);
        }
        keepalive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings(value: serde_json::Value) -> SockoptSettings {
        SockoptSettings::from_value(&value).expect("sockopt JSON must parse")
    }

    fn compile(value: serde_json::Value) -> anyhow::Result<CompiledSockopt> {
        settings(value).compile()
    }

    fn unsupported_message(value: serde_json::Value) -> String {
        compile(value)
            .expect_err("compile must reject the unsupported option")
            .to_string()
    }

    #[test]
    fn parses_every_go_key() {
        let parsed = settings(json!({
            "mark": 5,
            "tcpFastOpen": true,
            "tproxy": "tproxy",
            "acceptProxyProtocol": true,
            "domainStrategy": "UseIP",
            "dialerProxy": "wireguard",
            "tcpKeepAliveInterval": 15,
            "tcpKeepAliveIdle": 30,
            "tcpCongestion": "bbr",
            "tcpWindowClamp": 1024,
            "tcpMaxSeg": 536,
            "penetrate": true,
            "tcpUserTimeout": 3000,
            "v6only": true,
            "interface": "eth0",
            "tcpMptcp": true,
            "customSockopt": [{
                "system": "", "network": "tcp", "level": "6",
                "opt": "1", "value": "1", "type": "int"
            }],
            "addressPortStrategy": "SrvPortOnly",
            "happyEyeballs": {
                "prioritizeIPv6": true, "tryDelayMs": 100,
                "interleave": 2, "maxConcurrentTry": 8
            },
            "trustedXForwardedFor": ["10.0.0.1", "127.0.0.1"]
        }));
        assert_eq!(parsed.mark, 5);
        assert_eq!(parsed.tcp_fast_open, Some(TfoSetting::Enable(256)));
        assert_eq!(parsed.tproxy, "tproxy");
        assert!(parsed.accept_proxy_protocol);
        assert_eq!(parsed.domain_strategy, "UseIP");
        assert_eq!(parsed.dialer_proxy, "wireguard");
        assert_eq!(parsed.tcp_keep_alive_interval, 15);
        assert_eq!(parsed.tcp_keep_alive_idle, 30);
        assert_eq!(parsed.tcp_congestion, "bbr");
        assert_eq!(parsed.tcp_window_clamp, 1024);
        assert_eq!(parsed.tcp_max_seg, 536);
        assert!(parsed.penetrate);
        assert_eq!(parsed.tcp_user_timeout, 3000);
        assert!(parsed.v6only);
        assert_eq!(parsed.interface, "eth0");
        assert!(parsed.tcp_mptcp);
        assert_eq!(parsed.custom_sockopt.len(), 1);
        assert_eq!(parsed.address_port_strategy, "SrvPortOnly");
        assert_eq!(
            parsed.happy_eyeballs,
            Some(HappyEyeballs {
                prioritize_ipv6: true,
                try_delay_ms: 100,
                interleave: 2,
                max_concurrent_try: 8
            })
        );
        assert_eq!(
            parsed.trusted_x_forwarded_for,
            vec!["10.0.0.1", "127.0.0.1"]
        );
    }

    #[test]
    fn denies_unknown_keys_and_defaults_to_go_zero_values() {
        let error = SockoptSettings::from_value(&json!({"unknownKey": 1}))
            .expect_err("unknown keys must be rejected");
        assert!(error.to_string().contains("unknownKey"), "{error}");
        let empty = settings(json!({}));
        assert_eq!(empty.mark, 0);
        assert_eq!(empty.tcp_fast_open, None);
        assert_eq!(empty.tproxy, "");
        assert!(!empty.accept_proxy_protocol);
        assert_eq!(empty.domain_strategy, "");
        assert_eq!(empty.dialer_proxy, "");
        assert_eq!(empty.tcp_keep_alive_interval, 0);
        assert_eq!(empty.tcp_keep_alive_idle, 0);
        assert_eq!(empty.custom_sockopt, Vec::new());
        assert_eq!(empty.happy_eyeballs, None);
    }

    #[test]
    fn tcp_fast_open_parses_go_bool_and_number_shapes() {
        assert_eq!(settings(json!({})).tcp_fast_open, None);
        assert_eq!(settings(json!({"tcpFastOpen": null})).tcp_fast_open, None);
        assert_eq!(
            settings(json!({"tcpFastOpen": true})).tcp_fast_open,
            Some(TfoSetting::Enable(256))
        );
        assert_eq!(
            settings(json!({"tcpFastOpen": false})).tcp_fast_open,
            Some(TfoSetting::Disable)
        );
        assert_eq!(
            settings(json!({"tcpFastOpen": 7})).tcp_fast_open,
            Some(TfoSetting::Enable(7))
        );
        // Go quirk: an explicit 0 lands on the same sentinel as "unset".
        assert_eq!(
            settings(json!({"tcpFastOpen": 0})).tcp_fast_open,
            Some(TfoSetting::Skip)
        );
        // int32(math.Min(v, math.MaxInt32)) clamps huge values.
        assert_eq!(
            settings(json!({"tcpFastOpen": 1e18})).tcp_fast_open,
            Some(TfoSetting::Enable(i32::MAX))
        );
        assert_eq!(
            settings(json!({"tcpFastOpen": -5})).tcp_fast_open,
            Some(TfoSetting::Disable)
        );
        let error = SockoptSettings::from_value(&json!({"tcpFastOpen": "yes"}))
            .expect_err("string values must be rejected");
        assert!(error.to_string().contains(TFO_TYPE_ERROR), "{error}");
        let error = SockoptSettings::from_value(&json!({"tcpFastOpen": [1]}))
            .expect_err("array values must be rejected");
        assert!(error.to_string().contains(TFO_TYPE_ERROR), "{error}");
    }

    #[test]
    fn domain_strategy_accepts_go_values_case_insensitively() {
        for (value, expected) in [
            ("", DomainStrategy::AsIs),
            ("AsIs", DomainStrategy::AsIs),
            ("USEIP", DomainStrategy::UseIp),
            ("useIPv4", DomainStrategy::UseIp4),
            ("useipv6", DomainStrategy::UseIp6),
            ("useIPv4v6", DomainStrategy::UseIp46),
            ("useIPv6v4", DomainStrategy::UseIp64),
            ("ForceIP", DomainStrategy::ForceIp),
            ("forceipv4", DomainStrategy::ForceIp4),
            ("forceipv6", DomainStrategy::ForceIp6),
            ("forceipv4v6", DomainStrategy::ForceIp46),
            ("forceipv6v4", DomainStrategy::ForceIp64),
        ] {
            assert_eq!(DomainStrategy::parse(value).unwrap(), expected, "{value}");
        }
        let error = DomainStrategy::parse("NoIP").unwrap_err().to_string();
        assert_eq!(error, "unsupported domain strategy: NoIP");
    }

    #[test]
    fn address_port_strategy_accepts_go_values_case_insensitively() {
        for (value, expected) in [
            ("", AddressPortStrategy::None),
            ("None", AddressPortStrategy::None),
            ("SrvPortOnly", AddressPortStrategy::SrvPortOnly),
            ("srvaddressonly", AddressPortStrategy::SrvAddressOnly),
            ("SRVPORTANDADDRESS", AddressPortStrategy::SrvPortAndAddress),
            ("txtportonly", AddressPortStrategy::TxtPortOnly),
            ("TxtAddressOnly", AddressPortStrategy::TxtAddressOnly),
            ("txtportandaddress", AddressPortStrategy::TxtPortAndAddress),
        ] {
            assert_eq!(
                AddressPortStrategy::parse(value).unwrap(),
                expected,
                "{value}"
            );
        }
        let error = AddressPortStrategy::parse("SrvAll")
            .unwrap_err()
            .to_string();
        assert_eq!(error, "unsupported address and port strategy: SrvAll");
    }

    #[test]
    fn tproxy_maps_unknown_values_to_off_like_go() {
        assert_eq!(TProxyMode::parse("tproxy"), TProxyMode::TProxy);
        assert_eq!(TProxyMode::parse("TPROXY"), TProxyMode::TProxy);
        assert_eq!(TProxyMode::parse("redirect"), TProxyMode::Redirect);
        assert_eq!(TProxyMode::parse("Redirect"), TProxyMode::Redirect);
        assert_eq!(TProxyMode::parse("garbage"), TProxyMode::Off);
        assert_eq!(TProxyMode::parse(""), TProxyMode::Off);
    }

    #[test]
    fn happy_eyeballs_defaults_match_go_unmarshaljson() {
        assert_eq!(
            settings(json!({"happyEyeballs": {}})).happy_eyeballs,
            Some(HappyEyeballs::default())
        );
        assert_eq!(
            HappyEyeballs::default(),
            HappyEyeballs {
                prioritize_ipv6: false,
                try_delay_ms: 0,
                interleave: 1,
                max_concurrent_try: 4
            }
        );
        // Individual keys keep the defaults for the absent ones.
        assert_eq!(
            settings(json!({"happyEyeballs": {"interleave": 3}})).happy_eyeballs,
            Some(HappyEyeballs {
                interleave: 3,
                ..HappyEyeballs::default()
            })
        );
        // Compile materializes the defaults when the key is absent.
        let compiled = compile(json!({})).unwrap();
        assert_eq!(compiled.happy_eyeballs, HappyEyeballs::default());
    }

    #[test]
    fn keepalive_sign_validation_matches_go_dialer() {
        let error = compile(json!({
            "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": -1
        }))
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: 30 -1"
        );
        // Both negative (product positive) is a valid disable request.
        let compiled =
            compile(json!({"tcpKeepAliveIdle": -1, "tcpKeepAliveInterval": -1})).unwrap();
        assert!(compiled.keepalive.disable);
        // Positive pair configures both values.
        let compiled = compile(json!({"tcpKeepAliveIdle": 20, "tcpKeepAliveInterval": 5})).unwrap();
        assert_eq!(
            compiled.keepalive,
            KeepalivePlan {
                time: Some(Duration::from_secs(20)),
                interval: Some(Duration::from_secs(5)),
                disable: false,
            }
        );
        // Interval only: time stays absent (Go leaves Idle at the platform
        // default on the dialer and only sets KEEPINTVL on Linux).
        let compiled = compile(json!({"tcpKeepAliveInterval": 5})).unwrap();
        assert_eq!(compiled.keepalive.time, None);
        assert_eq!(compiled.keepalive.interval, Some(Duration::from_secs(5)));
        assert!(!compiled.keepalive.disable);
    }

    #[test]
    fn custom_sockopt_parses_go_atoi_semantics() {
        let entry = CustomSockopt {
            system: String::new(),
            network: "tcp".to_owned(),
            level: String::new(),
            opt: "1".to_owned(),
            value: "42".to_owned(),
            kind: "int".to_owned(),
        };
        assert_eq!(
            ParsedCustomSockopt::parse(&entry).unwrap(),
            ParsedCustomSockopt {
                system: String::new(),
                network: "tcp".to_owned(),
                level: 0x6, // default IPPROTO_TCP when empty
                opt: 1,
                value: CustomSockoptValue::Int(42),
            }
        );
        // strconv.Atoi errors are ignored: garbage becomes 0, "+5" parses.
        let garbage = CustomSockopt {
            level: "abc".to_owned(),
            opt: "opt".to_owned(),
            value: "x".to_owned(),
            kind: "int".to_owned(),
            ..entry.clone()
        };
        let parsed = ParsedCustomSockopt::parse(&garbage).unwrap();
        assert_eq!(parsed.level, 0);
        assert_eq!(parsed.opt, 0);
        assert_eq!(parsed.value, CustomSockoptValue::Int(0));
        let plus = CustomSockopt {
            level: "+5".to_owned(),
            opt: "+7".to_owned(),
            value: "+9".to_owned(),
            kind: "int".to_owned(),
            ..entry.clone()
        };
        let parsed = ParsedCustomSockopt::parse(&plus).unwrap();
        assert_eq!(
            (parsed.level, parsed.opt, parsed.value),
            (5, 7, CustomSockoptValue::Int(9))
        );
        // Empty opt is Go's "No opt!" error.
        let no_opt = CustomSockopt {
            opt: String::new(),
            ..entry.clone()
        };
        assert_eq!(
            ParsedCustomSockopt::parse(&no_opt).unwrap_err().to_string(),
            "No opt!"
        );
        // Unknown type is Go's error, reported with the raw value.
        let bad_type = CustomSockopt {
            kind: "u32".to_owned(),
            ..entry.clone()
        };
        assert_eq!(
            ParsedCustomSockopt::parse(&bad_type)
                .unwrap_err()
                .to_string(),
            "unknown CustomSockopt type: u32"
        );
        // str values keep the string.
        let as_str = CustomSockopt {
            kind: "str".to_owned(),
            value: "mptcp".to_owned(),
            ..entry
        };
        assert_eq!(
            ParsedCustomSockopt::parse(&as_str).unwrap().value,
            CustomSockoptValue::Str("mptcp".to_owned())
        );
    }

    #[test]
    fn custom_sockopt_filters_match_go_prefix_and_system_rules() {
        let parse = |system: &str, network: &str| ParsedCustomSockopt {
            system: system.to_owned(),
            network: network.to_owned(),
            level: 6,
            opt: 1,
            value: CustomSockoptValue::Int(1),
        };
        // strings.HasPrefix(network, custom.Network): empty matches all,
        // "tcp" matches tcp4 and tcp6 (but never udp), "tcp6" does not
        // match tcp4, and "udp" does not match tcp.
        assert!(parse("", "tcp").matches_network(SocketNet::Tcp4));
        assert!(parse("tcp", "").matches_network(SocketNet::Tcp6));
        assert!(!parse("", "tcp").matches_network(SocketNet::Udp));
        assert!(!parse("", "tcp6").matches_network(SocketNet::Tcp4));
        assert!(!parse("", "udp").matches_network(SocketNet::Tcp));
    }

    #[test]
    fn custom_sockopt_with_mismatched_system_is_skipped_like_go() {
        // On any given build exactly one of the two entries matches the OS;
        // the mismatched one is skipped (debug log in Go) and the matching
        // one fails compile with a named customSockopt error.
        let mismatched = if cfg!(windows) { "linux" } else { "windows" };
        let compiled = compile(json!({
            "customSockopt": [
                {"system": mismatched, "opt": "1", "value": "1", "type": "int"}
            ]
        }))
        .expect("mismatched system entries are skipped");
        assert!(compiled.custom_sockopt.is_empty());
    }

    #[test]
    fn each_unsupported_option_fails_compile_with_a_named_error() {
        for (key, option) in [
            (json!({"mark": 5}), "mark"),
            (json!({"tcpFastOpen": true}), "tcpFastOpen"),
            (json!({"tcpFastOpen": 10}), "tcpFastOpen"),
            (json!({"tproxy": "tproxy"}), "tproxy"),
            (json!({"tproxy": "redirect"}), "tproxy"),
            (json!({"dialerProxy": "wg"}), "dialerProxy"),
            (json!({"tcpCongestion": "bbr"}), "tcpCongestion"),
            (json!({"tcpWindowClamp": 1024}), "tcpWindowClamp"),
            (json!({"tcpMaxSeg": 536}), "tcpMaxSeg"),
            (json!({"tcpUserTimeout": 3000}), "tcpUserTimeout"),
            (json!({"interface": "eth0"}), "interface"),
            (json!({"tcpMptcp": true}), "tcpMptcp"),
            (
                json!({"customSockopt": [{"opt": "1", "value": "1", "type": "int"}]}),
                "customSockopt[0]",
            ),
        ] {
            let message = unsupported_message(key.clone());
            assert!(message.contains(&format!("`{option}`")), "{key}: {message}");
            assert!(
                message.contains("explicitly unsupported on this build"),
                "{key}: {message}"
            );
        }
    }

    #[test]
    fn zero_valued_platform_options_stay_applicable() {
        // Defaults and zero/empty values must not trip the unsupported
        // errors, exactly like Go treats them as "not configured".
        let compiled = compile(json!({
            "mark": 0,
            "tcpFastOpen": false,
            "tproxy": "off",
            "dialerProxy": "",
            "tcpCongestion": "",
            "tcpWindowClamp": 0,
            "tcpMaxSeg": 0,
            "tcpUserTimeout": 0,
            "interface": "",
            "tcpMptcp": false,
            "customSockopt": []
        }))
        .unwrap();
        assert_eq!(compiled.tfo, TfoSetting::Disable);
        assert_eq!(compiled.tproxy, TProxyMode::Off);
        assert_eq!(compiled.domain_strategy, DomainStrategy::AsIs);
        assert_eq!(compiled.address_port_strategy, AddressPortStrategy::None);
        assert!(compiled.custom_sockopt.is_empty());
        assert_eq!(compiled.keepalive, KeepalivePlan::default());
    }

    #[test]
    fn socket_net_mirrors_go_network_predicates() {
        assert!(SocketNet::Tcp.is_tcp());
        assert!(SocketNet::Tcp4.is_tcp());
        assert!(SocketNet::Tcp6.is_tcp());
        assert!(!SocketNet::Udp.is_tcp());
        assert!(SocketNet::Udp4.is_udp());
        assert!(SocketNet::Udp6.is_udp());
        assert!(!SocketNet::Tcp6.is_udp());
        assert_eq!(SocketNet::Tcp.as_str(), "tcp");
        assert_eq!(SocketNet::udp_for(true), SocketNet::Udp6);
        assert_eq!(SocketNet::tcp_for(false), SocketNet::Tcp4);
    }
}
