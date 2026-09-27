//! Native policy and statistics features.
//!
//! Policy models follow `infra/conf/policy.go` and `features/policy`. Statistics
//! implement counters and connection-refcounted online users from `app/stats`.
//! Runtime timeout enforcement, I/O accounting, statistics RPC transport and
//! event channels must be wired by their owning runtime/management modules.

pub mod metrics;
pub mod observatory;
pub mod observatory_burst;
pub mod policy;
pub mod policy_levels;
pub mod session;
pub mod stats;
pub mod stats_online;

pub use policy::{PolicyConfig, PolicyManager, SessionPolicy};
pub use stats::{Counter, OnlineMap, OnlineSession, StatsManager};
