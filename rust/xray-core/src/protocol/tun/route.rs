//! CIDR, outbound-interface selection, and reversible route application.
//!
//! These functions are OS-independent. An OS backend must implement
//! `RouteBackend`; this module never shells out to route-management commands.

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Retains host bits for Go's `gateway`/interface-address semantics. Call
/// `network()` when using the prefix as a route destination.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpPrefix {
    address: IpAddr,
    prefix: u8,
}

impl IpPrefix {
    pub fn new(address: IpAddr, prefix: u8) -> io::Result<Self> {
        if prefix > if address.is_ipv4() { 32 } else { 128 } {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CIDR prefix length exceeds address family",
            ));
        }
        Ok(Self { address, prefix })
    }

    pub fn address(self) -> IpAddr {
        self.address
    }
    pub fn prefix_len(self) -> u8 {
        self.prefix
    }

    pub fn network(self) -> Self {
        let address = match self.address {
            IpAddr::V4(value) => IpAddr::V4(Ipv4Addr::from(u32::from(value) & mask32(self.prefix))),
            IpAddr::V6(value) => {
                IpAddr::V6(Ipv6Addr::from(u128::from(value) & mask128(self.prefix)))
            }
        };
        Self { address, ..self }
    }

    pub fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.address.is_ipv4()
            && Self {
                address,
                prefix: self.prefix,
            }
            .network()
                == self.network()
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl FromStr for IpPrefix {
    type Err = io::Error;
    fn from_str(value: &str) -> io::Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "CIDR prefix is required")
        })?;
        let address = address
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid CIDR address"))?;
        let prefix = prefix.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid CIDR prefix length")
        })?;
        Self::new(address, prefix)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub loopback: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub destination: IpPrefix,
    pub interface_index: u32,
    pub metric: u32,
}

/// Matches Linux Go selection: IPv4 defaults before IPv6, minimum metric,
/// excluding down/loopback/TUN interfaces. A fixed name cannot select the TUN.
pub fn select_outbound_interface<'a>(
    tun_index: u32,
    fixed_name: Option<&str>,
    interfaces: &'a [Interface],
    routes: &[Route],
) -> io::Result<&'a Interface> {
    if let Some(name) = fixed_name.filter(|name| !name.is_empty() && *name != "auto") {
        let interface = interfaces
            .iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "fixed outbound interface was not found",
                )
            })?;
        if interface.index == tun_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound interface cannot be the TUN interface",
            ));
        }
        return Ok(interface);
    }
    for ipv4 in [true, false] {
        if let Some((_, interface)) = routes
            .iter()
            .filter(|route| {
                route.destination.prefix_len() == 0 && route.destination.address().is_ipv4() == ipv4
            })
            .filter_map(|route| {
                interfaces
                    .iter()
                    .find(|interface| {
                        interface.index == route.interface_index
                            && interface.index != 0
                            && interface.index != tun_index
                            && interface.up
                            && !interface.loopback
                    })
                    .map(|interface| (route.metric, interface))
            })
            .min_by_key(|(metric, _)| *metric)
        {
            return Ok(interface);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no usable default outbound interface was found",
    ))
}

pub fn plan_routes(interface_index: u32, destinations: &[IpPrefix]) -> io::Result<Vec<Route>> {
    if interface_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route requires a nonzero interface index",
        ));
    }
    let mut routes = Vec::new();
    for destination in destinations {
        let route = Route {
            destination: destination.network(),
            interface_index,
            metric: 1,
        };
        if !routes.contains(&route) {
            routes.push(route);
        }
    }
    Ok(routes)
}

pub trait RouteBackend {
    /// Must fail if this route already exists; replacing foreign routes breaks
    /// rollback ownership. Return success only after the OS accepted the route.
    fn add(&mut self, route: &Route) -> io::Result<()>;
    fn remove(&mut self, route: &Route) -> io::Result<()>;
}

#[derive(Debug)]
pub struct RouteFailure {
    pub route: Route,
    pub error: io::Error,
}

#[derive(Debug)]
pub struct RouteApplyError {
    pub cause: RouteFailure,
    pub rollback_failures: Vec<RouteFailure>,
}

impl fmt::Display for RouteApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed adding {}: {}; {} rollback failures",
            self.cause.route.destination,
            self.cause.error,
            self.rollback_failures.len()
        )
    }
}
impl std::error::Error for RouteApplyError {}

/// Tracks only successfully added routes. Call `close()` before releasing the
/// interface. Failed removals remain owned so cleanup can be retried; errors
/// are never converted into successful teardown.
#[derive(Default, Debug)]
pub struct RouteTransaction {
    installed: Vec<Route>,
}

impl RouteTransaction {
    pub fn installed(&self) -> &[Route] {
        &self.installed
    }

    pub fn apply(
        &mut self,
        backend: &mut impl RouteBackend,
        routes: &[Route],
    ) -> Result<(), RouteApplyError> {
        for route in routes {
            // Re-applying our own transaction is harmless; an OS route owned
            // by another process still causes backend.add() to fail.
            if self.installed.contains(route) {
                continue;
            }
            if let Err(error) = backend.add(route) {
                return Err(RouteApplyError {
                    cause: RouteFailure {
                        route: route.clone(),
                        error,
                    },
                    rollback_failures: self.close(backend),
                });
            }
            self.installed.push(route.clone());
        }
        Ok(())
    }

    pub fn close(&mut self, backend: &mut impl RouteBackend) -> Vec<RouteFailure> {
        let mut failures = Vec::new();
        let mut retained = Vec::new();
        for route in self.installed.drain(..).rev() {
            if let Err(error) = backend.remove(&route) {
                retained.push(route.clone());
                failures.push(RouteFailure { route, error });
            }
        }
        retained.reverse();
        self.installed = retained;
        failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_preserve_interface_hosts_and_mask_routes() {
        let prefix: IpPrefix = "192.0.2.9/24".parse().unwrap();
        assert_eq!(prefix.to_string(), "192.0.2.9/24");
        assert_eq!(prefix.network().to_string(), "192.0.2.0/24");
        assert!(prefix.contains("192.0.2.254".parse().unwrap()));
        assert!(!prefix.contains("192.0.3.1".parse().unwrap()));
        assert!(!prefix.contains("2001:db8::1".parse().unwrap()));
        assert_eq!(
            "2001:db8::1/32"
                .parse::<IpPrefix>()
                .unwrap()
                .network()
                .to_string(),
            "2001:db8::/32"
        );
        assert_eq!(
            "192.0.2.9/0"
                .parse::<IpPrefix>()
                .unwrap()
                .network()
                .to_string(),
            "0.0.0.0/0"
        );
        assert!("::1/129".parse::<IpPrefix>().is_err());
        assert!("1.2.3.4/33".parse::<IpPrefix>().is_err());
    }

    #[test]
    fn default_selection_skips_tun_and_prefers_ipv4_before_metric() {
        let interfaces = vec![
            Interface {
                index: 1,
                name: "tun0".into(),
                up: true,
                loopback: false,
            },
            Interface {
                index: 2,
                name: "eth0".into(),
                up: true,
                loopback: false,
            },
            Interface {
                index: 3,
                name: "eth1".into(),
                up: true,
                loopback: false,
            },
        ];
        let mut routes = plan_routes(1, &["0.0.0.0/0".parse().unwrap()]).unwrap();
        routes.push(Route {
            destination: "::/0".parse().unwrap(),
            interface_index: 3,
            metric: 0,
        });
        routes.push(Route {
            destination: "0.0.0.0/0".parse().unwrap(),
            interface_index: 2,
            metric: 100,
        });
        assert_eq!(
            select_outbound_interface(1, None, &interfaces, &routes)
                .unwrap()
                .name,
            "eth0"
        );
        assert!(select_outbound_interface(1, Some("tun0"), &interfaces, &routes).is_err());
    }

    #[derive(Default)]
    struct Backend {
        log: Vec<String>,
        fail_add: Option<IpPrefix>,
        fail_remove: bool,
    }
    impl RouteBackend for Backend {
        fn add(&mut self, route: &Route) -> io::Result<()> {
            self.log.push(format!("add {}", route.destination));
            if self.fail_add == Some(route.destination) {
                return Err(io::Error::other("exists"));
            }
            Ok(())
        }
        fn remove(&mut self, route: &Route) -> io::Result<()> {
            self.log.push(format!("remove {}", route.destination));
            if self.fail_remove {
                return Err(io::Error::other("remove failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn rollback_is_reverse_order_and_preserves_failed_cleanup_for_retry() {
        let routes = plan_routes(
            2,
            &[
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
            ],
        )
        .unwrap();
        let mut backend = Backend {
            fail_add: Some(routes[2].destination),
            fail_remove: true,
            ..Backend::default()
        };
        let mut transaction = RouteTransaction::default();
        let error = transaction.apply(&mut backend, &routes).unwrap_err();
        assert_eq!(error.rollback_failures.len(), 2);
        assert_eq!(
            &backend.log[3..],
            &["remove 172.16.0.0/12", "remove 10.0.0.0/8"]
        );
        assert_eq!(transaction.installed(), &routes[..2]);
        backend.fail_remove = false;
        assert!(transaction.close(&mut backend).is_empty());
        assert!(transaction.installed().is_empty());
        let calls = backend.log.len();
        assert!(transaction.close(&mut backend).is_empty());
        assert_eq!(calls, backend.log.len());
    }
}
