// P34 handler_api: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]

//! Native HandlerService for runtime inbound/outbound management.
//!
//! The source `handlerServer` (`app/proxyman/command/command.go`) forwards every
//! RPC to the instance's inbound/outbound managers. The runtime backing is
//! supplied through [`HandlerStore`]; this module owns request decoding,
//! TypedMessage operation resolution, and the source's status texts. The source
//! registers the service under both the Xray and v2ray names; both routes below
//! share clones of the same service.
//!
//! The source returns plain Go errors from every RPC, so gRPC maps them all to
//! the Unknown status with the Xray error text (including its
//! `outer > inner` chains). Those exact texts are asserted in the tests.

use std::{
    convert::Infallible,
    sync::Arc,
    task::{Context, Poll},
};

use prost::Message as _;
use tonic::{
    Request, Response, Status,
    body::Body,
    codegen::{Service, http},
    server::NamedService,
    service::Routes,
};

use xray_proto::xray::{
    app::proxyman::command as wire,
    common::protocol::User,
    common::serial::TypedMessage,
    core::{InboundHandlerConfig, OutboundHandlerConfig},
};

/// Full proto names of the two operations registered by the source that
/// implement the source's `InboundOperation` interface.
const ADD_USER_OPERATION: &str = "xray.app.proxyman.command.AddUserOperation";
const REMOVE_USER_OPERATION: &str = "xray.app.proxyman.command.RemoveUserOperation";

/// An operation decoded from `AlterInboundRequest.operation`.
///
/// The source resolves the [`TypedMessage`] through the process-wide proto
/// registry and asserts it implements `InboundOperation`; the source repository
/// registers only the two variants below.
#[derive(Debug, Clone, PartialEq)]
pub enum InboundOperation {
    /// Adds the user to the tagged inbound's proxy (its `UserManager`).
    AddUser(wire::AddUserOperation),
    /// Removes the user with this email from the tagged inbound's proxy.
    RemoveUser(wire::RemoveUserOperation),
}

/// Failures a [`HandlerStore`] reports, carrying the source's exact error texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerStoreError {
    /// A tagged handler was already registered:
    /// `existing tag found: {tag}`.
    ExistingTag(String),
    /// The inbound manager has no handler with this tag:
    /// `handler not found: {tag}`.
    HandlerNotFound(String),
    /// `common.ErrNoClue`, which inbound removal returns for empty and
    /// unknown tags: `not enough information for making a decision`.
    NoClue,
    /// The handler does not expose its inbound proxy:
    /// `can't get inbound proxy from handler.`.
    NoInboundProxy,
    /// The inbound proxy does not manage users:
    /// `proxy is not a UserManager`.
    NotAUserManager,
    /// User parsing failed after the handler was resolved:
    /// `failed to parse user > {inner}` (for example `Account is missing`).
    ParseUser(String),
    /// Any other runtime failure; the text must already match the source's
    /// wire format.
    Message(String),
}

impl HandlerStoreError {
    /// The exact status text the source carries for this failure.
    pub fn go_message(&self) -> String {
        match self {
            Self::ExistingTag(tag) => format!("existing tag found: {tag}"),
            Self::HandlerNotFound(tag) => format!("handler not found: {tag}"),
            Self::NoClue => "not enough information for making a decision".to_owned(),
            Self::NoInboundProxy => "can't get inbound proxy from handler.".to_owned(),
            Self::NotAUserManager => "proxy is not a UserManager".to_owned(),
            Self::ParseUser(inner) => format!("failed to parse user > {inner}"),
            Self::Message(text) => text.clone(),
        }
    }
}

/// Runtime backing for [`HandlerService`]: the inbound/outbound manager and
/// proxy-level user-management surfaces the source `handlerServer` consumes.
///
/// Implementations are expected to reproduce the manager semantics the error
/// texts above document: duplicate tags fail registration, inbound removal of
/// an empty or unknown tag fails with [`HandlerStoreError::NoClue`] while
/// outbound removal of an unknown tag succeeds, and inbound handler lookups
/// fail with [`HandlerStoreError::HandlerNotFound`].
#[tonic::async_trait]
pub trait HandlerStore: Send + Sync + 'static {
    /// `core.AddInboundHandler`: build the handler from the config and register
    /// it. An absent request field arrives as the default config, mirroring the
    /// source handing its typed-nil config straight to handler creation.
    async fn add_inbound(&self, config: InboundHandlerConfig) -> Result<(), HandlerStoreError>;

    /// `inbound.Manager.RemoveHandler`.
    async fn remove_inbound(&self, tag: &str) -> Result<(), HandlerStoreError>;

    /// `inbound.Manager.GetHandler` followed by `InboundOperation.ApplyInbound`
    /// on the live handler. User parsing failures
    /// ([`HandlerStoreError::ParseUser`]) may only be reported after the
    /// handler was resolved, matching the source's ordering of the two steps.
    async fn alter_inbound(
        &self,
        tag: &str,
        operation: InboundOperation,
    ) -> Result<(), HandlerStoreError>;

    /// `inbound.Manager.ListHandlers` as active handler configs, untagged
    /// handlers included.
    async fn list_inbounds(&self) -> Vec<InboundHandlerConfig>;

    /// `UserManager` access on the tagged inbound. A non-empty `email`
    /// selects a single user; a miss returns one default user, which is the
    /// wire form of the source's `ToProtoUser(nil)` entry.
    async fn get_inbound_users(
        &self,
        tag: &str,
        email: &str,
    ) -> Result<Vec<User>, HandlerStoreError>;

    /// `UserManager.GetUsersCount` on the tagged inbound.
    async fn get_inbound_users_count(&self, tag: &str) -> Result<i64, HandlerStoreError>;

    /// `core.AddOutboundHandler`.
    async fn add_outbound(&self, config: OutboundHandlerConfig) -> Result<(), HandlerStoreError>;

    /// `outbound.Manager.RemoveHandler`.
    async fn remove_outbound(&self, tag: &str) -> Result<(), HandlerStoreError>;

    /// `outbound.Manager.ListHandlers` minus the management API outbound the
    /// source filters out (its `*commander.Outbound`); only the runtime knows
    /// that handler's identity.
    async fn list_outbounds(&self) -> Vec<OutboundHandlerConfig>;
}

fn unknown_status(error: HandlerStoreError) -> Status {
    Status::unknown(error.go_message())
}

/// The source wraps inbound handler lookup misses as
/// `failed to get handler: {tag} > handler not found: {tag}`.
fn lookup_status(tag: &str, error: HandlerStoreError) -> Status {
    if let HandlerStoreError::HandlerNotFound(missing) = &error {
        return Status::unknown(format!(
            "failed to get handler: {tag} > handler not found: {missing}"
        ));
    }
    unknown_status(error)
}

fn decodes<M: prost::Message + Default>(bytes: &[u8]) -> bool {
    M::decode(bytes).is_ok()
}

/// Every message the command schema declares, with its wire decoder. The
/// source resolves `TypedMessage` types through the process-wide proto
/// registry, which contains at least these; membership decides between the
/// source's `unknown operation` and `not an inbound/outbound operation`
/// errors. Names outside the schema approximate the registry miss, which the
/// source also reports for types not linked into the binary.
type SchemaDecoder = fn(&[u8]) -> bool;
const SCHEMA_MESSAGES: &[(&str, SchemaDecoder)] = &[
    (ADD_USER_OPERATION, decodes::<wire::AddUserOperation>),
    (REMOVE_USER_OPERATION, decodes::<wire::RemoveUserOperation>),
    (
        "xray.app.proxyman.command.AddInboundRequest",
        decodes::<wire::AddInboundRequest>,
    ),
    (
        "xray.app.proxyman.command.AddInboundResponse",
        decodes::<wire::AddInboundResponse>,
    ),
    (
        "xray.app.proxyman.command.RemoveInboundRequest",
        decodes::<wire::RemoveInboundRequest>,
    ),
    (
        "xray.app.proxyman.command.RemoveInboundResponse",
        decodes::<wire::RemoveInboundResponse>,
    ),
    (
        "xray.app.proxyman.command.AlterInboundRequest",
        decodes::<wire::AlterInboundRequest>,
    ),
    (
        "xray.app.proxyman.command.AlterInboundResponse",
        decodes::<wire::AlterInboundResponse>,
    ),
    (
        "xray.app.proxyman.command.ListInboundsRequest",
        decodes::<wire::ListInboundsRequest>,
    ),
    (
        "xray.app.proxyman.command.ListInboundsResponse",
        decodes::<wire::ListInboundsResponse>,
    ),
    (
        "xray.app.proxyman.command.GetInboundUserRequest",
        decodes::<wire::GetInboundUserRequest>,
    ),
    (
        "xray.app.proxyman.command.GetInboundUserResponse",
        decodes::<wire::GetInboundUserResponse>,
    ),
    (
        "xray.app.proxyman.command.GetInboundUsersCountResponse",
        decodes::<wire::GetInboundUsersCountResponse>,
    ),
    (
        "xray.app.proxyman.command.AddOutboundRequest",
        decodes::<wire::AddOutboundRequest>,
    ),
    (
        "xray.app.proxyman.command.AddOutboundResponse",
        decodes::<wire::AddOutboundResponse>,
    ),
    (
        "xray.app.proxyman.command.RemoveOutboundRequest",
        decodes::<wire::RemoveOutboundRequest>,
    ),
    (
        "xray.app.proxyman.command.RemoveOutboundResponse",
        decodes::<wire::RemoveOutboundResponse>,
    ),
    (
        "xray.app.proxyman.command.AlterOutboundRequest",
        decodes::<wire::AlterOutboundRequest>,
    ),
    (
        "xray.app.proxyman.command.AlterOutboundResponse",
        decodes::<wire::AlterOutboundResponse>,
    ),
    (
        "xray.app.proxyman.command.ListOutboundsRequest",
        decodes::<wire::ListOutboundsRequest>,
    ),
    (
        "xray.app.proxyman.command.ListOutboundsResponse",
        decodes::<wire::ListOutboundsResponse>,
    ),
    ("xray.app.proxyman.command.Config", decodes::<wire::Config>),
];

fn schema_lookup(name: &str, value: &[u8]) -> Option<bool> {
    SCHEMA_MESSAGES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, decodes)| decodes(value))
}

/// The source's unmarshal failure for a registered operation type.
fn malformed_operation() -> Status {
    Status::unknown("unknown operation > proto: cannot parse invalid wire-format data")
}

/// Resolve a schema message name the way the source's registry lookup does:
/// decode the payload, then fail the operation-interface assertion.
fn classify_schema_message(kind: &str, name: &str, value: &[u8]) -> Status {
    match schema_lookup(name, value) {
        Some(true) => Status::unknown(format!("not an {kind} operation")),
        Some(false) => malformed_operation(),
        None => Status::unknown("unknown operation > proto: not found"),
    }
}

fn missing_operation() -> Status {
    // The source dereferences the nil operation pointer, which panics and ends
    // the connection; reject the request instead of reproducing the crash.
    Status::internal("alter request carries no operation; the source panics dereferencing nil")
}

/// Resolve `AlterInboundRequest.operation` into an [`InboundOperation`].
fn decode_inbound_operation(message: Option<&TypedMessage>) -> Result<InboundOperation, Status> {
    let Some(message) = message else {
        return Err(missing_operation());
    };
    match message.r#type.as_str() {
        ADD_USER_OPERATION => wire::AddUserOperation::decode(message.value.as_slice())
            .map(InboundOperation::AddUser)
            .map_err(|_| malformed_operation()),
        REMOVE_USER_OPERATION => wire::RemoveUserOperation::decode(message.value.as_slice())
            .map(InboundOperation::RemoveUser)
            .map_err(|_| malformed_operation()),
        name => Err(classify_schema_message("inbound", name, &message.value)),
    }
}

/// No message registered by the source repository implements the source's
/// `OutboundOperation` interface (`ApplyOutbound`); every `AlterOutbound`
/// request therefore fails before any store call, exactly as in the source
/// binary.
fn alter_outbound_status(message: Option<&TypedMessage>) -> Status {
    let Some(message) = message else {
        return missing_operation();
    };
    classify_schema_message("outbound", &message.r#type, &message.value)
}

/// The management service registered by the source over the commander's API
/// listener.
#[derive(Clone)]
pub struct HandlerService {
    store: Arc<dyn HandlerStore>,
}

impl HandlerService {
    /// Supply the runtime-backed store; the service holds no handler state of
    /// its own.
    pub fn new(store: Arc<dyn HandlerStore>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &Arc<dyn HandlerStore> {
        &self.store
    }

    pub fn into_server(self) -> wire::handler_service_server::HandlerServiceServer<Self> {
        wire::handler_service_server::HandlerServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl wire::handler_service_server::HandlerService for HandlerService {
    async fn add_inbound(
        &self,
        request: Request<wire::AddInboundRequest>,
    ) -> Result<Response<wire::AddInboundResponse>, Status> {
        let request = request.into_inner();
        self.store
            .add_inbound(request.inbound.unwrap_or_default())
            .await
            .map_err(unknown_status)?;
        Ok(Response::new(wire::AddInboundResponse {}))
    }

    async fn remove_inbound(
        &self,
        request: Request<wire::RemoveInboundRequest>,
    ) -> Result<Response<wire::RemoveInboundResponse>, Status> {
        let request = request.into_inner();
        self.store
            .remove_inbound(&request.tag)
            .await
            .map_err(unknown_status)?;
        Ok(Response::new(wire::RemoveInboundResponse {}))
    }

    async fn alter_inbound(
        &self,
        request: Request<wire::AlterInboundRequest>,
    ) -> Result<Response<wire::AlterInboundResponse>, Status> {
        let request = request.into_inner();
        // The source resolves the operation before it looks up the handler.
        let operation = decode_inbound_operation(request.operation.as_ref())?;
        self.store
            .alter_inbound(&request.tag, operation)
            .await
            .map_err(|error| lookup_status(&request.tag, error))?;
        Ok(Response::new(wire::AlterInboundResponse {}))
    }

    async fn list_inbounds(
        &self,
        request: Request<wire::ListInboundsRequest>,
    ) -> Result<Response<wire::ListInboundsResponse>, Status> {
        let request = request.into_inner();
        let inbounds = self
            .store
            .list_inbounds()
            .await
            .into_iter()
            .map(|mut config| {
                if request.is_only_tags {
                    config.receiver_settings = None;
                    config.proxy_settings = None;
                }
                config
            })
            .collect();
        Ok(Response::new(wire::ListInboundsResponse { inbounds }))
    }

    async fn get_inbound_users(
        &self,
        request: Request<wire::GetInboundUserRequest>,
    ) -> Result<Response<wire::GetInboundUserResponse>, Status> {
        let request = request.into_inner();
        let users = self
            .store
            .get_inbound_users(&request.tag, &request.email)
            .await
            .map_err(|error| lookup_status(&request.tag, error))?;
        Ok(Response::new(wire::GetInboundUserResponse { users }))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<wire::GetInboundUserRequest>,
    ) -> Result<Response<wire::GetInboundUsersCountResponse>, Status> {
        let request = request.into_inner();
        let count = self
            .store
            .get_inbound_users_count(&request.tag)
            .await
            .map_err(|error| lookup_status(&request.tag, error))?;
        Ok(Response::new(wire::GetInboundUsersCountResponse { count }))
    }

    async fn add_outbound(
        &self,
        request: Request<wire::AddOutboundRequest>,
    ) -> Result<Response<wire::AddOutboundResponse>, Status> {
        let request = request.into_inner();
        self.store
            .add_outbound(request.outbound.unwrap_or_default())
            .await
            .map_err(unknown_status)?;
        Ok(Response::new(wire::AddOutboundResponse {}))
    }

    async fn remove_outbound(
        &self,
        request: Request<wire::RemoveOutboundRequest>,
    ) -> Result<Response<wire::RemoveOutboundResponse>, Status> {
        let request = request.into_inner();
        self.store
            .remove_outbound(&request.tag)
            .await
            .map_err(unknown_status)?;
        Ok(Response::new(wire::RemoveOutboundResponse {}))
    }

    async fn alter_outbound(
        &self,
        request: Request<wire::AlterOutboundRequest>,
    ) -> Result<Response<wire::AlterOutboundResponse>, Status> {
        let request = request.into_inner();
        // No registered operation implements the source's outbound
        // operation interface; see `alter_outbound_status`.
        Err(alter_outbound_status(request.operation.as_ref()))
    }

    async fn list_outbounds(
        &self,
        _: Request<wire::ListOutboundsRequest>,
    ) -> Result<Response<wire::ListOutboundsResponse>, Status> {
        let outbounds = self
            .store
            .list_outbounds()
            .await
            .into_iter()
            .map(|mut config| {
                // The source lists tag, sender and proxy settings only.
                config.expire = 0;
                config.comment.clear();
                config
            })
            .collect();
        Ok(Response::new(wire::ListOutboundsResponse { outbounds }))
    }
}

/// Compatibility route under the original v2ray service name, which the source
/// registers from the same service descriptor.
#[derive(Clone)]
pub struct LegacyHandlerService {
    inner: wire::handler_service_server::HandlerServiceServer<HandlerService>,
}

impl LegacyHandlerService {
    pub fn new(service: HandlerService) -> Self {
        Self {
            inner: service.into_server(),
        }
    }
}

impl NamedService for LegacyHandlerService {
    const NAME: &'static str = "v2ray.core.app.proxyman.command.HandlerService";
}

impl Service<http::Request<Body>> for LegacyHandlerService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = <wire::handler_service_server::HandlerServiceServer<HandlerService> as Service<
        http::Request<Body>,
    >>::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <wire::handler_service_server::HandlerServiceServer<HandlerService> as Service<
            http::Request<Body>,
        >>::poll_ready(&mut self.inner, context)
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        const PREFIX: &str = "/v2ray.core.app.proxyman.command.HandlerService/";
        if let Some(method) = request.uri().path().strip_prefix(PREFIX)
            && let Ok(uri) = format!("/xray.app.proxyman.command.HandlerService/{method}").parse()
        {
            // HTTP path characters came from a valid URI. Unknown method names
            // remain unknown after rewriting and get the generated status 12.
            *request.uri_mut() = uri;
        }
        self.inner.call(request)
    }
}

/// Start a router containing both source service-name aliases.
pub fn handler_routes(service: HandlerService) -> Routes {
    Routes::new(service.clone().into_server()).add_service(LegacyHandlerService::new(service))
}

/// Add both aliases to a router that already contains StatsService or other
/// management services. The caller owns endpoint binding and access policy.
pub fn add_handler_routes(routes: Routes, service: HandlerService) -> Routes {
    routes
        .add_service(service.clone().into_server())
        .add_service(LegacyHandlerService::new(service))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use prost::Message;
    use tokio::time::timeout;
    use tonic::{Code, transport::Channel};

    use super::*;
    use crate::api::ApiServer;
    use wire::handler_service_server::HandlerService as _;

    /// The memory store treats these tags as handlers whose proxy cannot be
    /// reached, simulating the source's proxy-level failures.
    const NO_INBOUND_PROXY_TAG: &str = "opaque-inbound";
    const NOT_A_USER_MANAGER_TAG: &str = "plain-inbound";

    #[derive(Default)]
    struct MemoryState {
        inbounds: Vec<InboundHandlerConfig>,
        outbounds: Vec<OutboundHandlerConfig>,
        users: BTreeMap<String, Vec<User>>,
    }

    /// In-memory [`HandlerStore`] mirroring the source manager semantics.
    #[derive(Default)]
    struct MemoryStore {
        state: Mutex<MemoryState>,
    }

    impl MemoryStore {
        /// Callers hold the state lock; this helper must not take it.
        fn proxy_failure(tag: &str) -> Option<HandlerStoreError> {
            if tag == NO_INBOUND_PROXY_TAG {
                Some(HandlerStoreError::NoInboundProxy)
            } else if tag == NOT_A_USER_MANAGER_TAG {
                Some(HandlerStoreError::NotAUserManager)
            } else {
                None
            }
        }
    }

    #[tonic::async_trait]
    impl HandlerStore for MemoryStore {
        async fn add_inbound(&self, config: InboundHandlerConfig) -> Result<(), HandlerStoreError> {
            let mut state = self.state.lock().unwrap();
            if !config.tag.is_empty()
                && state
                    .inbounds
                    .iter()
                    .any(|existing| existing.tag == config.tag)
            {
                return Err(HandlerStoreError::ExistingTag(config.tag));
            }
            state.inbounds.push(config);
            Ok(())
        }

        async fn remove_inbound(&self, tag: &str) -> Result<(), HandlerStoreError> {
            let mut state = self.state.lock().unwrap();
            if tag.is_empty() || !state.inbounds.iter().any(|config| config.tag == tag) {
                return Err(HandlerStoreError::NoClue);
            }
            state.inbounds.retain(|config| config.tag != tag);
            state.users.remove(tag);
            Ok(())
        }

        async fn alter_inbound(
            &self,
            tag: &str,
            operation: InboundOperation,
        ) -> Result<(), HandlerStoreError> {
            let mut state = self.state.lock().unwrap();
            if !state.inbounds.iter().any(|config| config.tag == tag) {
                return Err(HandlerStoreError::HandlerNotFound(tag.to_owned()));
            }
            if let Some(failure) = Self::proxy_failure(tag) {
                return Err(failure);
            }
            let users = state.users.entry(tag.to_owned()).or_default();
            match operation {
                InboundOperation::AddUser(operation) => {
                    let Some(user) = operation.user else {
                        return Err(HandlerStoreError::ParseUser(
                            "Account is missing".to_owned(),
                        ));
                    };
                    if user.account.is_none() {
                        // The source's ToMemoryUser fails on a missing account.
                        return Err(HandlerStoreError::ParseUser(
                            "Account is missing".to_owned(),
                        ));
                    }
                    users.retain(|existing| existing.email != user.email);
                    users.push(user);
                    Ok(())
                }
                InboundOperation::RemoveUser(operation) => {
                    users.retain(|existing| existing.email != operation.email);
                    Ok(())
                }
            }
        }

        async fn list_inbounds(&self) -> Vec<InboundHandlerConfig> {
            self.state.lock().unwrap().inbounds.clone()
        }

        async fn get_inbound_users(
            &self,
            tag: &str,
            email: &str,
        ) -> Result<Vec<User>, HandlerStoreError> {
            let state = self.state.lock().unwrap();
            if !state.inbounds.iter().any(|config| config.tag == tag) {
                return Err(HandlerStoreError::HandlerNotFound(tag.to_owned()));
            }
            if let Some(failure) = Self::proxy_failure(tag) {
                return Err(failure);
            }
            let users = state.users.get(tag).cloned().unwrap_or_default();
            if !email.is_empty() {
                // The source returns ToProtoUser(nil), which serializes as one
                // default user entry, for a miss by email.
                return Ok(vec![
                    users
                        .into_iter()
                        .find(|user| user.email == email)
                        .unwrap_or_default(),
                ]);
            }
            Ok(users)
        }

        async fn get_inbound_users_count(&self, tag: &str) -> Result<i64, HandlerStoreError> {
            Ok(self.get_inbound_users(tag, "").await?.len() as i64)
        }

        async fn add_outbound(
            &self,
            config: OutboundHandlerConfig,
        ) -> Result<(), HandlerStoreError> {
            let mut state = self.state.lock().unwrap();
            if !config.tag.is_empty()
                && state
                    .outbounds
                    .iter()
                    .any(|existing| existing.tag == config.tag)
            {
                return Err(HandlerStoreError::ExistingTag(config.tag));
            }
            state.outbounds.push(config);
            Ok(())
        }

        async fn remove_outbound(&self, tag: &str) -> Result<(), HandlerStoreError> {
            if tag.is_empty() {
                return Err(HandlerStoreError::NoClue);
            }
            let mut state = self.state.lock().unwrap();
            // The source outbound manager deletes unknown tags without error.
            state.outbounds.retain(|config| config.tag != tag);
            Ok(())
        }

        async fn list_outbounds(&self) -> Vec<OutboundHandlerConfig> {
            self.state.lock().unwrap().outbounds.clone()
        }
    }

    fn service() -> HandlerService {
        HandlerService::new(Arc::new(MemoryStore::default()))
    }

    fn typed(name: &str, value: Vec<u8>) -> TypedMessage {
        TypedMessage {
            r#type: name.to_owned(),
            value,
        }
    }

    fn add_inbound_request(tag: &str) -> Request<wire::AddInboundRequest> {
        Request::new(wire::AddInboundRequest {
            inbound: Some(InboundHandlerConfig {
                tag: tag.to_owned(),
                receiver_settings: Some(typed("xray.transport.internet.tcp.Config", vec![])),
                proxy_settings: Some(typed("xray.proxy.socks.Server", vec![])),
            }),
        })
    }

    fn add_user_operation(email: &str, with_account: bool) -> TypedMessage {
        let operation = wire::AddUserOperation {
            user: Some(User {
                level: 1,
                email: email.to_owned(),
                account: with_account.then(|| typed("xray.proxy.socks.Account", vec![])),
            }),
        };
        TypedMessage {
            r#type: ADD_USER_OPERATION.to_owned(),
            value: operation.encode_to_vec(),
        }
    }

    fn alter_inbound_request(
        tag: &str,
        operation: Option<TypedMessage>,
    ) -> Request<wire::AlterInboundRequest> {
        Request::new(wire::AlterInboundRequest {
            tag: tag.to_owned(),
            operation,
        })
    }

    fn inbound_user_request(tag: &str, email: &str) -> Request<wire::GetInboundUserRequest> {
        Request::new(wire::GetInboundUserRequest {
            tag: tag.to_owned(),
            email: email.to_owned(),
        })
    }

    #[tokio::test]
    async fn inbound_add_alter_list_remove_round_trip() {
        let service = service();
        service
            .add_inbound(add_inbound_request("in-1"))
            .await
            .unwrap();

        service
            .alter_inbound(alter_inbound_request(
                "in-1",
                Some(add_user_operation("user@example.com", true)),
            ))
            .await
            .unwrap();
        let users = service
            .get_inbound_users(inbound_user_request("in-1", ""))
            .await
            .unwrap()
            .into_inner()
            .users;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "user@example.com");
        assert_eq!(users[0].level, 1);
        assert!(users[0].account.is_some());

        // An email lookup of a missing user yields one default entry.
        let miss = service
            .get_inbound_users(inbound_user_request("in-1", "nobody@example.com"))
            .await
            .unwrap()
            .into_inner()
            .users;
        assert_eq!(miss, vec![User::default()]);

        assert_eq!(
            service
                .get_inbound_users_count(inbound_user_request("in-1", ""))
                .await
                .unwrap()
                .into_inner()
                .count,
            1
        );

        service
            .alter_inbound(alter_inbound_request(
                "in-1",
                Some(TypedMessage {
                    r#type: REMOVE_USER_OPERATION.to_owned(),
                    value: wire::RemoveUserOperation {
                        email: "user@example.com".into(),
                    }
                    .encode_to_vec(),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            service
                .get_inbound_users_count(inbound_user_request("in-1", ""))
                .await
                .unwrap()
                .into_inner()
                .count,
            0
        );

        let full = service
            .list_inbounds(Request::new(wire::ListInboundsRequest {
                is_only_tags: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .inbounds;
        assert_eq!(full.len(), 1);
        assert_eq!(full[0].tag, "in-1");
        assert!(full[0].receiver_settings.is_some());
        assert!(full[0].proxy_settings.is_some());

        let tags_only = service
            .list_inbounds(Request::new(wire::ListInboundsRequest {
                is_only_tags: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .inbounds;
        assert_eq!(tags_only.len(), 1);
        assert_eq!(tags_only[0].tag, "in-1");
        assert!(tags_only[0].receiver_settings.is_none());
        assert!(tags_only[0].proxy_settings.is_none());

        service
            .remove_inbound(Request::new(wire::RemoveInboundRequest {
                tag: "in-1".into(),
            }))
            .await
            .unwrap();
        assert_eq!(
            service
                .list_inbounds(Request::new(wire::ListInboundsRequest {
                    is_only_tags: true
                }))
                .await
                .unwrap()
                .into_inner()
                .inbounds
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn inbound_registration_failures_repeat_the_source_error_texts() {
        let service = service();
        service
            .add_inbound(add_inbound_request("dup"))
            .await
            .unwrap();
        let error = service
            .add_inbound(add_inbound_request("dup"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "existing tag found: dup");

        for tag in ["", "missing"] {
            let error = service
                .remove_inbound(Request::new(wire::RemoveInboundRequest { tag: tag.into() }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::Unknown);
            assert_eq!(
                error.message(),
                "not enough information for making a decision"
            );
        }
    }

    #[tokio::test]
    async fn alter_inbound_resolves_operations_like_the_source_registry() {
        let service = service();
        service
            .add_inbound(add_inbound_request("in-1"))
            .await
            .unwrap();

        let error = service
            .alter_inbound(alter_inbound_request(
                "in-1",
                Some(typed("not.a.Proto", vec![])),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "unknown operation > proto: not found");

        // A schema message resolves and decodes, but implements no operation.
        let error = service
            .alter_inbound(alter_inbound_request(
                "in-1",
                Some(typed(
                    "xray.app.proxyman.command.AddInboundRequest",
                    wire::AddInboundRequest::default().encode_to_vec(),
                )),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "not an inbound operation");

        // A registered operation with malformed bytes fails at unmarshal.
        let error = service
            .alter_inbound(alter_inbound_request(
                "in-1",
                Some(typed(ADD_USER_OPERATION, vec![0xFF, 0xFF])),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(
            error.message(),
            "unknown operation > proto: cannot parse invalid wire-format data"
        );

        // The absent operation field panics in the source; rejected here.
        let error = service
            .alter_inbound(alter_inbound_request("in-1", None))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Internal);
    }

    #[tokio::test]
    async fn alter_inbound_lookup_failure_wraps_and_wins_over_parse_errors() {
        let service = service();
        service
            .add_inbound(add_inbound_request("in-1"))
            .await
            .unwrap();

        // The operation resolves before the handler lookup.
        let error = service
            .alter_inbound(alter_inbound_request(
                "ghost",
                Some(add_user_operation("x@example.com", false)),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(
            error.message(),
            "failed to get handler: ghost > handler not found: ghost"
        );

        // With the handler present, the parse failure surfaces with its text.
        let error = service
            .alter_inbound(alter_inbound_request(
                "in-1",
                Some(add_user_operation("x@example.com", false)),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "failed to parse user > Account is missing");
    }

    #[tokio::test]
    async fn user_access_errors_mirror_the_source_proxy_texts() {
        let service = service();
        for tag in [NO_INBOUND_PROXY_TAG, NOT_A_USER_MANAGER_TAG] {
            service.add_inbound(add_inbound_request(tag)).await.unwrap();
        }

        let error = service
            .get_inbound_users(inbound_user_request(NO_INBOUND_PROXY_TAG, ""))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "can't get inbound proxy from handler.");

        for request in [
            inbound_user_request(NOT_A_USER_MANAGER_TAG, ""),
            inbound_user_request(NOT_A_USER_MANAGER_TAG, "x@example.com"),
        ] {
            let error = service.get_inbound_users(request).await.unwrap_err();
            assert_eq!(error.code(), Code::Unknown);
            assert_eq!(error.message(), "proxy is not a UserManager");
        }

        let error = service
            .alter_inbound(alter_inbound_request(
                NOT_A_USER_MANAGER_TAG,
                Some(add_user_operation("x@example.com", true)),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.message(), "proxy is not a UserManager");

        let error = service
            .get_inbound_users_count(inbound_user_request("ghost", ""))
            .await
            .unwrap_err();
        assert_eq!(
            error.message(),
            "failed to get handler: ghost > handler not found: ghost"
        );
    }

    #[tokio::test]
    async fn outbound_round_trip_matches_manager_semantics() {
        let service = service();
        let outbound = || {
            Request::new(wire::AddOutboundRequest {
                outbound: Some(OutboundHandlerConfig {
                    tag: "out-1".into(),
                    sender_settings: Some(typed("xray.transport.internet.tcp.Config", vec![])),
                    proxy_settings: Some(typed("xray.proxy.freedom.Config", vec![])),
                    expire: 42,
                    comment: "never listed".into(),
                }),
            })
        };
        service.add_outbound(outbound()).await.unwrap();
        let error = service.add_outbound(outbound()).await.unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "existing tag found: out-1");

        let listed = service
            .list_outbounds(Request::new(wire::ListOutboundsRequest {}))
            .await
            .unwrap()
            .into_inner()
            .outbounds;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].tag, "out-1");
        assert!(listed[0].sender_settings.is_some());
        // The source response never carries the expire or comment fields.
        assert_eq!(listed[0].expire, 0);
        assert_eq!(listed[0].comment, "");

        service
            .remove_outbound(Request::new(wire::RemoveOutboundRequest {
                tag: "out-1".into(),
            }))
            .await
            .unwrap();
        // Unknown outbound tags delete silently, unlike inbound tags.
        service
            .remove_outbound(Request::new(wire::RemoveOutboundRequest {
                tag: "never-there".into(),
            }))
            .await
            .unwrap();
        // The empty tag still reports the source's ErrNoClue.
        let error = service
            .remove_outbound(Request::new(wire::RemoveOutboundRequest {
                tag: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(
            error.message(),
            "not enough information for making a decision"
        );
        assert_eq!(
            service
                .list_outbounds(Request::new(wire::ListOutboundsRequest {}))
                .await
                .unwrap()
                .into_inner()
                .outbounds
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn alter_outbound_rejects_every_registered_operation() {
        let service = service();
        // The only registered operations are inbound-only in the source.
        let error = service
            .alter_outbound(Request::new(wire::AlterOutboundRequest {
                tag: "out-1".into(),
                operation: Some(add_user_operation("x@example.com", true)),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unknown);
        assert_eq!(error.message(), "not an outbound operation");

        let error = service
            .alter_outbound(Request::new(wire::AlterOutboundRequest {
                tag: "out-1".into(),
                operation: Some(typed("not.a.Proto", vec![])),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.message(), "unknown operation > proto: not found");

        let error = service
            .alter_outbound(Request::new(wire::AlterOutboundRequest {
                tag: "out-1".into(),
                operation: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Internal);
    }

    #[test]
    fn schema_names_match_the_generated_type_names() {
        use prost::Name;
        assert_eq!(ADD_USER_OPERATION, wire::AddUserOperation::full_name());
        assert_eq!(
            REMOVE_USER_OPERATION,
            wire::RemoveUserOperation::full_name()
        );
        for (name, _) in SCHEMA_MESSAGES {
            assert!(name.starts_with("xray.app.proxyman.command."));
        }
    }

    /// Client channel that optionally rewrites requests onto the legacy v2ray
    /// service name, exercising the compatibility route over real HTTP/2.
    #[derive(Clone)]
    struct AliasClientChannel {
        inner: Channel,
        legacy: bool,
    }

    impl Service<http::Request<Body>> for AliasClientChannel {
        type Response = <Channel as Service<http::Request<Body>>>::Response;
        type Error = <Channel as Service<http::Request<Body>>>::Error;
        type Future = <Channel as Service<http::Request<Body>>>::Future;

        fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(context)
        }

        fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
            if self.legacy {
                let mut parts = request.uri().clone().into_parts();
                let path = parts.path_and_query.as_ref().unwrap().as_str().replace(
                    "/xray.app.proxyman.command.HandlerService/",
                    "/v2ray.core.app.proxyman.command.HandlerService/",
                );
                parts.path_and_query = Some(path.parse().unwrap());
                *request.uri_mut() = http::Uri::from_parts(parts).unwrap();
            }
            self.inner.call(request)
        }
    }

    #[tokio::test]
    async fn both_service_aliases_manage_handlers_over_http2() {
        let server = ApiServer::from_routes(handler_routes(service()))
            .bind_tcp("127.0.0.1:0")
            .await
            .unwrap();
        let endpoint = format!("http://{}", server.local_addr().unwrap());
        let channel = timeout(
            Duration::from_secs(5),
            Channel::from_shared(endpoint).unwrap().connect(),
        )
        .await
        .unwrap()
        .unwrap();

        for legacy in [false, true] {
            let mut client =
                wire::handler_service_client::HandlerServiceClient::new(AliasClientChannel {
                    inner: channel.clone(),
                    legacy,
                });
            let tag = format!("in-{legacy}");
            timeout(
                Duration::from_secs(5),
                client.add_inbound(add_inbound_request(&tag)),
            )
            .await
            .unwrap()
            .unwrap();
            timeout(
                Duration::from_secs(5),
                client.alter_inbound(alter_inbound_request(
                    &tag,
                    Some(add_user_operation("alias@example.com", true)),
                )),
            )
            .await
            .unwrap()
            .unwrap();
            let listed = timeout(
                Duration::from_secs(5),
                client.list_inbounds(Request::new(wire::ListInboundsRequest {
                    is_only_tags: true,
                })),
            )
            .await
            .unwrap()
            .unwrap()
            .into_inner()
            .inbounds;
            assert!(listed.iter().any(|config| config.tag == tag));
            timeout(
                Duration::from_secs(5),
                client.remove_inbound(Request::new(wire::RemoveInboundRequest { tag })),
            )
            .await
            .unwrap()
            .unwrap();
        }
        drop(channel);
        timeout(Duration::from_secs(5), server.shutdown())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_legacy_methods_remain_unimplemented() {
        let mut service = LegacyHandlerService::new(service());
        let response = service
            .call(
                http::Request::builder()
                    .uri("/v2ray.core.app.proxyman.command.HandlerService/NotARealMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["grpc-status"], "12");
    }
}
