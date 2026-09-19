//! Honest native-runtime reporting for the Go-compatible system-stat message.
//!
//! Rust has no tracing garbage collector. GC collections and pause time are
//! therefore genuinely zero. The number of live Tokio tasks is the native
//! equivalent of the goroutine field; this substitution is identified in
//! response metadata. Heap allocation counters require allocator instrumentation
//! and are not guessed from RSS/virtual memory, which measure different things.

use tonic::Status;

/// One observation from a runtime/allocator statistics provider.
///
/// `None` means unavailable, not a measured zero. The protobuf has no presence
/// bits, so [`super::StatsService`] lists unavailable field names in the
/// `x-xray-unsupported-fields` response metadata. A caller that requires those
/// fields should reject that partial response. Uptime belongs to the service
/// lifecycle and is measured separately using a monotonic clock.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemStatsSnapshot {
    pub num_goroutine: Option<u32>,
    pub num_gc: Option<u32>,
    pub alloc: Option<u64>,
    pub total_alloc: Option<u64>,
    pub sys: Option<u64>,
    pub mallocs: Option<u64>,
    pub frees: Option<u64>,
    pub live_objects: Option<u64>,
    pub pause_total_ns: Option<u64>,
}

/// Providers must return actual measurements, or `None` for unavailable fields.
/// This permits a runtime with an instrumented allocator to supply all fields
/// without installing a global allocator as a side effect of using this library.
pub trait SystemStatsProvider: Send + Sync + 'static {
    fn snapshot(&self) -> Result<SystemStatsSnapshot, Status>;

    /// A static ASCII identifier sent as `x-xray-system-stats-provider`.
    fn name(&self) -> &'static str;

    /// Semantics of `num_goroutine`; native Tokio tasks are not Go goroutines.
    fn task_kind(&self) -> &'static str {
        "provider-defined"
    }
}

/// Native metrics available without replacing the process allocator.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeSystemStats;

impl SystemStatsProvider for NativeSystemStats {
    fn snapshot(&self) -> Result<SystemStatsSnapshot, Status> {
        let num_goroutine = tokio::runtime::Handle::try_current().ok().map(|handle| {
            handle
                .metrics()
                .num_alive_tasks()
                .try_into()
                .unwrap_or(u32::MAX)
        });
        Ok(SystemStatsSnapshot {
            num_goroutine,
            num_gc: Some(0),
            pause_total_ns: Some(0),
            ..SystemStatsSnapshot::default()
        })
    }

    fn name(&self) -> &'static str {
        "rust-tokio"
    }

    fn task_kind(&self) -> &'static str {
        "tokio-tasks"
    }
}
