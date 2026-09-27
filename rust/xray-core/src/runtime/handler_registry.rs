//! CONTRACT (fixed by the integrator): runtime backing for the HandlerService
//! management API.
//!
//! OWNER: wiring batch agent A-HANDLER. The registry receives the startup
//! inbound snapshot through `seed_inbound` and exposes a
//! `api::handler::HandlerStore` through `store`. Listing and user queries are
//! served from the snapshot; `add_inbound`/`remove_inbound` spawn and stop
//! real listeners through the runtime's own `accept_loop` (this module is a
//! child of `runtime`, so `super::accept_loop` is reachable) with child
//! cancellation tokens linked to the server token. Every operation the
//! runtime genuinely cannot perform must fail explicitly with
//! `HandlerStoreError`, matching the doc contract on the trait.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use super::Dispatcher;
use crate::api::handler::{HandlerStore, HandlerStoreError, InboundOperation};
use crate::config::{Inbound, InboundConfig, OutboundConfig};
use crate::transport::InboundTransport;
use xray_proto::xray::{
    common::protocol::User,
    core::{InboundHandlerConfig, OutboundHandlerConfig},
};

pub(super) struct RuntimeRegistry {
    _dispatcher: Arc<Dispatcher>,
    _cancel: CancellationToken,
    _outbound_configs: Vec<OutboundConfig>,
}

impl RuntimeRegistry {
    pub(super) fn new(dispatcher: Arc<Dispatcher>, cancel: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            _dispatcher: dispatcher,
            _cancel: cancel,
            _outbound_configs: Vec::new(),
        })
    }

    /// Record one startup inbound for listings and dynamic management.
    pub(super) fn seed_inbound(
        &self,
        raw: InboundConfig,
        inbound: Inbound,
        transport: InboundTransport,
    ) {
        let _ = (raw, inbound, transport);
    }

    /// The store backing HandlerService; every operation fails explicitly
    /// until the wiring batch agent implements it.
    pub(super) fn store(&self) -> Arc<dyn HandlerStore> {
        struct NotWired;

        #[tonic::async_trait]
        impl HandlerStore for NotWired {
            async fn add_inbound(
                &self,
                config: InboundHandlerConfig,
            ) -> Result<(), HandlerStoreError> {
                let _ = config;
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn remove_inbound(&self, tag: &str) -> Result<(), HandlerStoreError> {
                let _ = tag;
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn alter_inbound(
                &self,
                tag: &str,
                operation: InboundOperation,
            ) -> Result<(), HandlerStoreError> {
                let _ = (tag, operation);
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn list_inbounds(&self) -> Vec<InboundHandlerConfig> {
                Vec::new()
            }

            async fn get_inbound_users(
                &self,
                tag: &str,
                email: &str,
            ) -> Result<Vec<User>, HandlerStoreError> {
                let _ = (tag, email);
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn get_inbound_users_count(&self, tag: &str) -> Result<i64, HandlerStoreError> {
                let _ = tag;
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn add_outbound(
                &self,
                config: OutboundHandlerConfig,
            ) -> Result<(), HandlerStoreError> {
                let _ = config;
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn remove_outbound(&self, tag: &str) -> Result<(), HandlerStoreError> {
                let _ = tag;
                Err(HandlerStoreError::Message(
                    "HandlerService runtime store is not wired yet".into(),
                ))
            }

            async fn list_outbounds(&self) -> Vec<OutboundHandlerConfig> {
                Vec::new()
            }
        }

        Arc::new(NotWired)
    }
}
