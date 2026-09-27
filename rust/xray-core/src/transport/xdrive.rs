//! Native XDRIVE object-storage stream transport.
//!
//! The wire format is the layout and contents of objects in a shared store, not
//! bytes on a network socket. The implementation follows `transport/internet/
//! xdrive/{params,wal,conn,xdrive,local,template}.go`. Local and explicit HTTP
//! template storage are implemented. Google Drive remains unsupported; an
//! unavailable service never silently falls back to local disk.

mod connection;
mod session;
mod storage;
pub mod stream;
pub mod template;
mod wal;
pub mod wire;

use std::{io, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

pub use connection::Connection;
pub use session::{Listener, dial, dial_with_cancel};
pub use storage::{Entry, LocalStorage, Storage, StorageFuture};

pub const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CONCURRENCY: usize = 64;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub remote_folder: String,
    pub service: String,
    pub secrets: Vec<String>,
    pub segment_bytes: u32,
    pub flush_interval_ms: u32,
    pub poll_interval_ms: u32,
    pub max_poll_interval_ms: u32,
    pub session_ttl_seconds: u32,
    pub concurrency: u32,
    pub eager_window_ms: u32,
    pub hole_timeout_ms: u32,
    pub template: Option<serde_json::Value>,
}

impl Config {
    pub fn from_proto(
        config: &xray_proto::xray::transport::internet::xdrive::Config,
    ) -> io::Result<Self> {
        Ok(Self {
            remote_folder: config.remote_folder.clone(),
            service: config.service.clone(),
            secrets: config.secrets.clone(),
            segment_bytes: config.segment_bytes,
            flush_interval_ms: config.flush_interval_ms,
            poll_interval_ms: config.poll_interval_ms,
            max_poll_interval_ms: config.max_poll_interval_ms,
            session_ttl_seconds: config.session_ttl_seconds,
            concurrency: config.concurrency,
            eager_window_ms: config.eager_window_ms,
            hole_timeout_ms: config.hole_timeout_ms,
            template: if config.template.is_empty() {
                None
            } else {
                Some(serde_json::from_str(&config.template).map_err(io::Error::other)?)
            },
        })
    }

    /// Build only a backend that is actually available in this native module.
    pub async fn storage(&self) -> io::Result<Arc<dyn Storage>> {
        match self.service.as_str() {
            "local" => Ok(Arc::new(LocalStorage::new(&self.remote_folder).await?)),
            "template" => Ok(Arc::new(template::TemplateStorage::new(self)?)),
            "Google Drive" => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "native XDRIVE {} storage backend is not implemented",
                    self.service
                ),
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported XDRIVE storage service",
            )),
        }
    }

    pub async fn dial(&self) -> io::Result<Connection> {
        dial(self.storage().await?, Params::from(self)).await
    }

    pub async fn listen(&self) -> io::Result<Listener> {
        Listener::new(self.storage().await?, Params::from(self))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub segment_bytes: usize,
    pub flush_interval: Duration,
    pub min_poll_interval: Duration,
    pub max_poll_interval: Duration,
    pub eager_window: Duration,
    pub hole_timeout: Duration,
    pub session_ttl: Duration,
    pub concurrency: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self::from(&Config::default())
    }
}

impl From<&Config> for Params {
    fn from(config: &Config) -> Self {
        fn value(value: u32, default: u32) -> u32 {
            if value == 0 { default } else { value }
        }
        fn millis(value: u32, default: u32) -> Duration {
            Duration::from_millis(u64::from(if value == 0 { default } else { value }))
        }
        let min_poll_interval = millis(config.poll_interval_ms, 50);
        Self {
            segment_bytes: (value(config.segment_bytes, 512 * 1024) as usize)
                .min(MAX_SEGMENT_BYTES),
            flush_interval: millis(config.flush_interval_ms, 20),
            min_poll_interval,
            max_poll_interval: millis(config.max_poll_interval_ms, 500).max(min_poll_interval),
            eager_window: millis(config.eager_window_ms, 2000),
            hole_timeout: millis(config.hole_timeout_ms, 30_000),
            session_ttl: Duration::from_secs(u64::from(value(config.session_ttl_seconds, 300))),
            concurrency: (value(config.concurrency, 8) as usize).min(MAX_CONCURRENCY),
        }
    }
}

impl Params {
    pub(crate) fn validate(self) -> io::Result<Self> {
        if self.segment_bytes == 0
            || self.segment_bytes > MAX_SEGMENT_BYTES
            || self.concurrency == 0
            || self.concurrency > MAX_CONCURRENCY
            || self.flush_interval.is_zero()
            || self.min_poll_interval.is_zero()
            || self.max_poll_interval < self.min_poll_interval
            || self.hole_timeout.is_zero()
            || self.session_ttl.is_zero()
            || [
                self.flush_interval,
                self.min_poll_interval,
                self.max_poll_interval,
                self.eager_window,
                self.hole_timeout,
                self.session_ttl,
            ]
            .iter()
            .any(|duration| std::time::Instant::now().checked_add(*duration).is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XDRIVE parameters",
            ));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
