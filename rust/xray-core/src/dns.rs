//! Native DNS wire codec, classic UDP/TCP resolver, cache, and query service.
//!
//! The module mirrors the address-query behavior in `app/dns` and `proxy/dns`.
//! It does not implement encrypted DNS, FakeDNS, geodata server selection, or
//! Xray's dispatcher integration. See `rust/notes/DNS.md` for integration limits.

pub mod app;
mod cache;
pub mod fakedns;
pub mod network;
mod resolver;
mod service;
pub mod wire;

pub use cache::CacheConfig;
pub use resolver::{
    DnsAnswer, HostEntry, LookupResult, QueryOptions, Resolver, ResolverConfig, ServerLink,
    Transport, Upstream, read_tcp_message, write_tcp_message,
};
pub use service::{DnsService, ServiceConfig};
pub use wire::{Question, RecordType};

use std::{fmt, io};

/// Go's `features/dns.DefaultTTL`, used when a response has no answer TTL.
pub const DEFAULT_TTL: u32 = 300;

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Debug)]
pub enum DnsError {
    Io(io::Error),
    Timeout,
    InvalidName(String),
    Malformed(&'static str),
    MismatchedResponse,
    Truncated,
    ResponseCode(u16),
    EmptyResponse,
    InvalidConfig(&'static str),
    Unsupported(String),
    AliasLoop,
    AllServersFailed(Vec<String>),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "DNS I/O: {error}"),
            Self::Timeout => f.write_str("DNS query timed out"),
            Self::InvalidName(name) => write!(f, "invalid DNS name: {name:?}"),
            Self::Malformed(reason) => write!(f, "malformed DNS message: {reason}"),
            Self::MismatchedResponse => f.write_str("DNS response does not match the query"),
            Self::Truncated => f.write_str("DNS response is truncated"),
            Self::ResponseCode(code) => write!(f, "DNS response code {code}"),
            Self::EmptyResponse => f.write_str("DNS response contains no requested addresses"),
            Self::InvalidConfig(reason) => write!(f, "invalid DNS configuration: {reason}"),
            Self::Unsupported(feature) => write!(f, "unsupported DNS feature: {feature}"),
            Self::AliasLoop => f.write_str("DNS host alias cycle or depth greater than five"),
            Self::AllServersFailed(errors) => {
                write!(f, "all DNS servers failed: {}", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DnsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub mod encrypted;
#[cfg(test)]
mod tests;
