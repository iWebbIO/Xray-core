//! Native networking and configuration for the Rust migration of Xray.

pub mod address;
pub mod api;
pub mod config;
pub mod dns;
pub mod features;
pub mod geodata;
pub mod logging;
pub mod mux;
pub mod protocol;
pub mod reverse;
pub mod router;
pub mod runtime;
pub mod transport;
pub mod user;

pub use config::Config;
pub use runtime::Server;
pub use xray_proto as proto;
