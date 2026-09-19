use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;

use super::{
    Connection, Params, Storage,
    wal::{ErrorSlot, Failure, stored_error},
    wire::{self, SESSIONS_DIR, STREAMS_DIR},
};

pub async fn dial(storage: Arc<dyn Storage>, params: Params) -> io::Result<Connection> {
    dial_with_cancel(storage, params, CancellationToken::new()).await
}

pub async fn dial_with_cancel(
    storage: Arc<dyn Storage>,
    params: Params,
    cancel: CancellationToken,
) -> io::Result<Connection> {
    let params = params.validate()?;
    let session = wire::new_session_id()?;
    let announce = wire::announcement_name(&session, SystemTime::now())?;
    tokio::select! {
        _ = cancel.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "XDRIVE dial cancelled")),
        result = storage.put(&announce, Vec::new()) => result?,
    }
    Ok(Connection::new(
        session.clone(),
        storage,
        wire::uplink_prefix(&session),
        wire::downlink_prefix(&session),
        params,
        cancel,
        None,
    ))
}

#[derive(Default)]
struct Registry {
    active: HashSet<String>,
    handled: HashMap<String, Instant>,
    idle_since: HashMap<String, Instant>,
}

impl Registry {
    fn claim(&mut self, session: &str) -> bool {
        if self.active.contains(session) || self.handled.contains_key(session) {
            return false;
        }
        self.active.insert(session.to_owned());
        self.handled.insert(session.to_owned(), Instant::now());
        true
    }
}

pub struct Listener {
    accepted: mpsc::Receiver<Connection>,
    storage: Arc<dyn Storage>,
    registry: Arc<Mutex<Registry>>,
    cancel: CancellationToken,
    errors: ErrorSlot,
    tasks: Vec<JoinHandle<()>>,
}

impl Listener {
    pub fn new(storage: Arc<dyn Storage>, params: Params) -> io::Result<Self> {
        let params = params.validate()?;
        let cancel = CancellationToken::new();
        let registry = Arc::new(Mutex::new(Registry::default()));
        let errors = Arc::new(Mutex::new(None));
        let (accepted_tx, accepted_rx) = mpsc::channel(4 * params.concurrency);
        let tasks = vec![
            tokio::spawn(accept_loop(
                storage.clone(),
                params,
                registry.clone(),
                accepted_tx,
                errors.clone(),
                cancel.clone(),
            )),
            tokio::spawn(collect_loop(
                storage.clone(),
                params,
                registry.clone(),
                errors.clone(),
                cancel.clone(),
            )),
        ];
        Ok(Self {
            accepted: accepted_rx,
            storage,
            registry,
            cancel,
            errors,
            tasks,
        })
    }

    pub async fn accept(&mut self) -> io::Result<Connection> {
        self.accepted
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "XDRIVE listener closed"))
    }

    pub fn active_sessions(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active
            .len()
    }
    pub fn last_error(&self) -> Option<io::Error> {
        stored_error(&self.errors)
    }
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub async fn close(mut self) -> io::Result<()> {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.storage.close().await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn record_error(errors: &ErrorSlot, error: io::Error) {
    tracing::warn!(error = %error, "XDRIVE storage polling failed");
    *errors.lock().unwrap_or_else(|error| error.into_inner()) = Some(Failure::new(error));
}

async fn accept_loop(
    storage: Arc<dyn Storage>,
    params: Params,
    registry: Arc<Mutex<Registry>>,
    accepted: mpsc::Sender<Connection>,
    errors: ErrorSlot,
    cancel: CancellationToken,
) {
    let mut delay = params.min_poll_interval;
    let mut active = Instant::now();
    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => return,
            result = accept_pending(&storage, params, &registry, &accepted, &cancel) => result,
        };
        let changed = match result {
            Ok(changed) => changed,
            Err(error) => {
                record_error(&errors, error);
                false
            }
        };
        if changed {
            active = Instant::now();
            delay = params.min_poll_interval;
        } else if active.elapsed() < params.eager_window {
            delay = params.min_poll_interval;
        } else {
            delay = delay.saturating_mul(2).min(params.max_poll_interval);
        }
        tokio::select! { _ = cancel.cancelled() => return, _ = time::sleep(delay) => {} }
    }
}

async fn accept_pending(
    storage: &Arc<dyn Storage>,
    params: Params,
    registry: &Arc<Mutex<Registry>>,
    accepted: &mpsc::Sender<Connection>,
    cancel: &CancellationToken,
) -> io::Result<bool> {
    let announcements = storage.list(SESSIONS_DIR).await?;
    let mut changed = false;
    for entry in announcements {
        // List names are basenames, never nested paths. Enforce this for custom
        // cloud backends as well as the local storage implementation.
        if entry.name.contains(['/', '\\']) {
            continue;
        }
        let name = format!("{SESSIONS_DIR}/{}", entry.name);
        let Some((session, at)) = wire::parse_announcement(&entry.name) else {
            let _ = storage.delete(&name).await;
            continue;
        };
        if SystemTime::now()
            .duration_since(at)
            .is_ok_and(|age| age > params.session_ttl)
        {
            let _ = storage.delete(&name).await;
            let active = registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .active
                .contains(&session);
            if !active {
                let _ = storage.delete(&wire::session_prefix(&session)).await;
            }
            continue;
        }
        if !registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .claim(&session)
        {
            continue;
        }
        let on_close_registry = registry.clone();
        let on_close_session = session.clone();
        let on_close = Box::new(move || {
            on_close_registry
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .active
                .remove(&on_close_session);
        });
        let connection = Connection::new(
            session.clone(),
            storage.clone(),
            wire::downlink_prefix(&session),
            wire::uplink_prefix(&session),
            params,
            cancel.child_token(),
            Some(on_close),
        );
        // Construct the close guard before the next suspension point: cancelling
        // a slow announcement deletion must release the active-session claim.
        let _ = storage.delete(&name).await;
        if accepted.send(connection).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XDRIVE listener receiver closed",
            ));
        }
        changed = true;
    }
    Ok(changed)
}

async fn collect_loop(
    storage: Arc<dyn Storage>,
    params: Params,
    registry: Arc<Mutex<Registry>>,
    errors: ErrorSlot,
    cancel: CancellationToken,
) {
    let interval = (params.session_ttl / 2).max(std::time::Duration::from_nanos(1));
    loop {
        tokio::select! { _ = cancel.cancelled() => return, _ = time::sleep(interval) => {} }
        let result = tokio::select! { _ = cancel.cancelled() => return, result = collect(&storage, params, &registry) => result };
        if let Err(error) = result {
            record_error(&errors, error);
        }
    }
}

async fn collect(
    storage: &Arc<dyn Storage>,
    params: Params,
    registry: &Arc<Mutex<Registry>>,
) -> io::Result<()> {
    let entries = storage.list(STREAMS_DIR).await?;
    let now = Instant::now();
    let mut expired = Vec::new();
    {
        let mut state = registry.lock().unwrap_or_else(|error| error.into_inner());
        let mut present = HashSet::new();
        for entry in entries {
            let session = entry.name;
            if wire::validate_session_id(&session).is_err() {
                continue;
            }
            present.insert(session.clone());
            if state.active.contains(&session) {
                state.idle_since.remove(&session);
                continue;
            }
            match state.idle_since.get(&session) {
                None => {
                    state.idle_since.insert(session, now);
                }
                Some(since) if now.duration_since(*since) >= params.session_ttl => {
                    state.idle_since.remove(&session);
                    expired.push(session);
                }
                _ => {}
            }
        }
        state
            .idle_since
            .retain(|session, _| present.contains(session));
        let active = state.active.clone();
        state.handled.retain(|session, at| {
            active.contains(session) || now.duration_since(*at) < params.session_ttl
        });
    }
    for session in expired {
        storage.delete(&wire::session_prefix(&session)).await?;
    }
    Ok(())
}
