use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::{Arc, Mutex},
};

use tokio::{
    sync::{Notify, mpsc, oneshot},
    task::JoinSet,
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;

use super::{
    Entry, MAX_SEGMENT_BYTES, Params, Storage,
    wire::{ObjectKind, object_name, parse_entry},
};

#[derive(Clone)]
pub(super) struct Failure {
    kind: io::ErrorKind,
    message: String,
}
impl Failure {
    pub(super) fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
    pub(super) fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}
pub(super) type ErrorSlot = Arc<Mutex<Option<Failure>>>;

pub(super) fn stored_error(slot: &ErrorSlot) -> Option<io::Error> {
    slot.lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(Failure::error)
}
fn store_error(slot: &ErrorSlot, error: &io::Error) {
    let mut state = slot.lock().unwrap_or_else(|error| error.into_inner());
    if state.is_none() {
        *state = Some(Failure {
            kind: error.kind(),
            message: error.to_string(),
        });
    }
}

pub(super) enum WriteCommand {
    Data(Vec<u8>),
    Flush(oneshot::Sender<io::Result<()>>),
    Finish(oneshot::Sender<io::Result<()>>),
}

fn joined(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    result.map_err(io::Error::other)?
}

async fn upload_chunk(
    storage: Arc<dyn Storage>,
    prefix: String,
    sequence: u64,
    bytes: Vec<u8>,
) -> io::Result<()> {
    let name = object_name(&prefix, sequence, ObjectKind::Segment)?;
    if let Err(error) = storage.put(&name, bytes).await {
        if let Ok(marker) = object_name(&prefix, sequence, ObjectKind::Error) {
            let _ = storage.put(&marker, Vec::new()).await;
        }
        return Err(io::Error::new(
            error.kind(),
            format!("failed to store XDRIVE segment {sequence}: {error}"),
        ));
    }
    Ok(())
}

async fn queue_chunk(
    uploads: &mut JoinSet<io::Result<()>>,
    storage: &Arc<dyn Storage>,
    prefix: &str,
    sequence: &mut u64,
    bytes: Vec<u8>,
    concurrency: usize,
) -> io::Result<()> {
    while uploads.len() >= concurrency {
        if let Some(result) = uploads.join_next().await {
            joined(result)?;
        }
    }
    let next = sequence
        .checked_add(1)
        .filter(|next| *next <= i64::MAX as u64)
        .ok_or_else(|| io::Error::other("XDRIVE sequence exhausted"))?;
    let task = upload_chunk(storage.clone(), prefix.to_owned(), *sequence, bytes);
    uploads.spawn(task);
    *sequence = next;
    Ok(())
}

async fn flush_buffer(
    buffer: &mut VecDeque<u8>,
    uploads: &mut JoinSet<io::Result<()>>,
    storage: &Arc<dyn Storage>,
    prefix: &str,
    sequence: &mut u64,
    params: Params,
) -> io::Result<()> {
    while !buffer.is_empty() {
        let count = buffer.len().min(params.segment_bytes);
        let bytes = buffer.drain(..count).collect();
        queue_chunk(
            uploads,
            storage,
            prefix,
            sequence,
            bytes,
            params.concurrency,
        )
        .await?;
    }
    while let Some(result) = uploads.join_next().await {
        joined(result)?;
    }
    Ok(())
}

pub(super) async fn run_writer(
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Params,
    mut commands: mpsc::Receiver<WriteCommand>,
    errors: ErrorSlot,
    cancel: CancellationToken,
) {
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => return,
        result = writer_inner(storage, prefix, params, &mut commands, &errors) => result,
    };
    if let Err(error) = result {
        store_error(&errors, &error);
    }
}

async fn writer_inner(
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Params,
    commands: &mut mpsc::Receiver<WriteCommand>,
    errors: &ErrorSlot,
) -> io::Result<()> {
    let mut uploads = JoinSet::new();
    let mut sequence = 0;
    let mut buffer = VecDeque::new();
    let mut last_size = 0;
    let mut held_ticks = 0;
    let mut ticks = time::interval_at(
        Instant::now() + params.flush_interval,
        params.flush_interval,
    );
    ticks.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = uploads.join_next(), if !uploads.is_empty() => { if let Some(result) = result { joined(result)?; } },
            command = commands.recv() => match command {
                Some(WriteCommand::Data(bytes)) => {
                    buffer.extend(bytes);
                    while buffer.len() >= params.segment_bytes {
                        let chunk = buffer.drain(..params.segment_bytes).collect();
                        queue_chunk(&mut uploads, &storage, &prefix, &mut sequence, chunk, params.concurrency).await?;
                        last_size = buffer.len(); held_ticks = 0;
                    }
                }
                Some(WriteCommand::Flush(reply)) => {
                    let result = flush_buffer(&mut buffer, &mut uploads, &storage, &prefix, &mut sequence, params).await;
                    if let Err(error) = &result { store_error(errors, error); }
                    let failed = result.is_err(); let _ = reply.send(result);
                    if failed { return Ok(()); }
                    last_size = 0; held_ticks = 0;
                }
                Some(WriteCommand::Finish(reply)) => {
                    let result = async {
                        flush_buffer(&mut buffer, &mut uploads, &storage, &prefix, &mut sequence, params).await?;
                        storage.put(&object_name(&prefix, sequence, ObjectKind::End)?, Vec::new()).await
                    }.await;
                    if let Err(error) = &result { store_error(errors, error); }
                    let _ = reply.send(result); return Ok(());
                }
                None => return Ok(()),
            },
            _ = ticks.tick(), if !buffer.is_empty() => {
                let grew = buffer.len() > last_size; last_size = buffer.len();
                if grew && held_ticks < 8 { held_ticks += 1; continue; }
                held_ticks = 0;
                let chunk = buffer.drain(..).collect();
                queue_chunk(&mut uploads, &storage, &prefix, &mut sequence, chunk, params.concurrency).await?;
                last_size = 0;
            },
        }
    }
}

struct ReaderState {
    sequence: u64,
    hole_since: Option<Instant>,
}

pub(super) async fn run_reader(
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Params,
    output: mpsc::Sender<io::Result<Vec<u8>>>,
    discards: mpsc::Sender<String>,
    wake: Arc<Notify>,
    cancel: CancellationToken,
) {
    let mut reader = ReaderState {
        sequence: 0,
        hole_since: None,
    };
    let mut delay = params.min_poll_interval;
    let mut active = Instant::now();
    loop {
        let polled = Instant::now();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = reader.poll(&storage, &prefix, params, &output, &discards) => result,
        };
        match result {
            Err(error) => {
                tokio::select! { _ = cancel.cancelled() => {}, _ = output.send(Err(error)) => {} }
                return;
            }
            Ok((_, true)) => return,
            Ok((true, false)) => {
                active = Instant::now();
                delay = params.min_poll_interval;
            }
            Ok((false, false)) if active.elapsed() < params.eager_window => {
                delay = params.min_poll_interval
            }
            Ok((false, false)) => delay = delay.saturating_mul(2).min(params.max_poll_interval),
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = time::sleep(delay) => {},
            _ = wake.notified() => {
                active = Instant::now(); delay = params.min_poll_interval;
                if let Some(rest) = params.min_poll_interval.checked_sub(polled.elapsed()) {
                    tokio::select! { _ = cancel.cancelled() => return, _ = time::sleep(rest) => {} }
                }
            },
        }
    }
}

impl ReaderState {
    async fn poll(
        &mut self,
        storage: &Arc<dyn Storage>,
        prefix: &str,
        params: Params,
        output: &mpsc::Sender<io::Result<Vec<u8>>>,
        discards: &mpsc::Sender<String>,
    ) -> io::Result<(bool, bool)> {
        let listed = storage.list(prefix).await?;
        if listed.is_empty() {
            return Ok((false, false));
        }
        let mut pending = BTreeMap::<u64, (ObjectKind, Entry)>::new();
        let mut ahead = false;
        for entry in listed {
            let Some((sequence, kind)) = parse_entry(&entry.name) else {
                continue;
            };
            if sequence > self.sequence {
                ahead = true;
            }
            // Error markers win over a duplicate segment if a cloud PUT may have
            // committed before reporting a failure. Never hide a peer failure.
            if pending
                .get(&sequence)
                .is_some_and(|(kind, _)| *kind == ObjectKind::Error)
            {
                continue;
            }
            pending.insert(sequence, (kind, entry));
        }
        if !pending.contains_key(&self.sequence) && ahead {
            match self.hole_since {
                Some(since) if since.elapsed() >= params.hole_timeout => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "XDRIVE segment {} never arrived while later ones did",
                            self.sequence
                        ),
                    ));
                }
                None => self.hole_since = Some(Instant::now()),
                _ => {}
            }
        } else {
            self.hole_since = None;
        }
        let mut advanced = false;
        loop {
            if let Some((kind, entry)) = pending.get(&self.sequence) {
                match kind {
                    ObjectKind::Error => {
                        let _ = discards.try_send(format!("{prefix}/{}", entry.name));
                        return Err(io::Error::other(format!(
                            "the peer could not store XDRIVE segment {}",
                            self.sequence
                        )));
                    }
                    ObjectKind::End => {
                        let _ = discards.try_send(format!("{prefix}/{}", entry.name));
                        return Ok((advanced, true));
                    }
                    ObjectKind::Segment => {}
                }
            }
            let mut batch = Vec::new();
            for index in 0..params.concurrency {
                let Some(sequence) = self.sequence.checked_add(index as u64) else {
                    break;
                };
                match pending.get(&sequence) {
                    Some((ObjectKind::Segment, entry)) => batch.push(entry.clone()),
                    _ => break,
                }
            }
            if batch.is_empty() {
                return Ok((advanced, false));
            }
            let chunks = match fetch(storage, prefix, &batch).await {
                Ok(chunks) => chunks,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok((advanced, false));
                }
                Err(error) => return Err(error),
            };
            for (entry, chunk) in batch.into_iter().zip(chunks) {
                if output.send(Ok(chunk)).await.is_err() {
                    return Ok((advanced, true));
                }
                self.sequence = self
                    .sequence
                    .checked_add(1)
                    .filter(|sequence| *sequence <= i64::MAX as u64)
                    .ok_or_else(|| io::Error::other("XDRIVE sequence exhausted"))?;
                advanced = true;
                let _ = discards.try_send(format!("{prefix}/{}", entry.name));
            }
        }
    }
}

async fn fetch(
    storage: &Arc<dyn Storage>,
    prefix: &str,
    batch: &[Entry],
) -> io::Result<Vec<Vec<u8>>> {
    let mut chunks: Vec<Option<Vec<u8>>> = vec![None; batch.len()];
    let mut tasks = JoinSet::new();
    for (index, entry) in batch.iter().enumerate() {
        if let Some(inline) = &entry.inline {
            if inline.len() > MAX_SEGMENT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XDRIVE inline segment is too large",
                ));
            }
            chunks[index] = Some(inline.clone());
        } else {
            let storage = storage.clone();
            let name = format!("{prefix}/{}", entry.name);
            tasks.spawn(async move { (index, storage.get(&name).await) });
        }
    }
    let mut failures: Vec<Option<io::Error>> = (0..batch.len()).map(|_| None).collect();
    while let Some(result) = tasks.join_next().await {
        let (index, result) = result.map_err(io::Error::other)?;
        match result {
            Ok(bytes) if bytes.len() <= MAX_SEGMENT_BYTES => chunks[index] = Some(bytes),
            Ok(_) => {
                failures[index] = Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XDRIVE segment is too large",
                ))
            }
            Err(error) => failures[index] = Some(error),
        }
    }
    if let Some(error) = failures.into_iter().flatten().next() {
        return Err(error);
    }
    chunks
        .into_iter()
        .map(|chunk| chunk.ok_or_else(|| io::Error::other("XDRIVE fetch task produced no result")))
        .collect()
}

pub(super) async fn run_discards(
    storage: Arc<dyn Storage>,
    concurrency: usize,
    mut discards: mpsc::Receiver<String>,
    cancel: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    let mut closed = false;
    loop {
        if closed && tasks.is_empty() {
            return;
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            name = discards.recv(), if !closed && tasks.len() < concurrency => {
                match name {
                    Some(name) => { let storage = storage.clone(); tasks.spawn(async move { let _ = storage.delete(&name).await; }); },
                    None => closed = true,
                }
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}
