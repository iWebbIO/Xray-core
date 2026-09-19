use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant as StdInstant,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Notify, mpsc, oneshot},
    task::JoinHandle,
    time::{self, Sleep},
};
use tokio_util::sync::{CancellationToken, PollSender};

use super::{
    Params, Storage,
    wal::{self, ErrorSlot, Failure, WriteCommand},
};

/// A single XDRIVE session, with independent c2s and s2c WAL directions.
///
/// AsyncWrite shutdown flushes published data and writes the .end marker while
/// leaving reads usable. `close` also cancels reads. Drop aborts pending work;
/// call shutdown/close when a graceful EOF marker is required.
pub struct Connection {
    session_id: String,
    writer: PollSender<WriteCommand>,
    reader: mpsc::Receiver<io::Result<Vec<u8>>>,
    write_error: ErrorSlot,
    read_error: Option<Failure>,
    read_buf: Vec<u8>,
    read_offset: usize,
    read_deadline: Option<Pin<Box<Sleep>>>,
    write_deadline: Option<Pin<Box<Sleep>>>,
    wake: Arc<Notify>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    pending_ack: Option<oneshot::Receiver<io::Result<()>>>,
    ack_finishes: bool,
    closing: bool,
    finished: bool,
    write_chunk_size: usize,
    on_close: Option<Box<dyn FnOnce() + Send>>,
}

impl Connection {
    pub(super) fn new(
        session_id: String,
        storage: Arc<dyn Storage>,
        write_prefix: String,
        read_prefix: String,
        params: Params,
        cancel: CancellationToken,
        on_close: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        let (write_tx, write_rx) = mpsc::channel(params.concurrency);
        let (read_tx, read_rx) = mpsc::channel(params.concurrency);
        let (discard_tx, discard_rx) = mpsc::channel(4 * params.concurrency);
        let write_error = Arc::new(Mutex::new(None));
        let wake = Arc::new(Notify::new());
        let tasks = vec![
            tokio::spawn(wal::run_writer(
                storage.clone(),
                write_prefix,
                params,
                write_rx,
                write_error.clone(),
                cancel.clone(),
            )),
            tokio::spawn(wal::run_reader(
                storage.clone(),
                read_prefix,
                params,
                read_tx,
                discard_tx,
                wake.clone(),
                cancel.clone(),
            )),
            tokio::spawn(wal::run_discards(
                storage,
                params.concurrency,
                discard_rx,
                cancel.clone(),
            )),
        ];
        Self {
            session_id,
            writer: PollSender::new(write_tx),
            reader: read_rx,
            write_error,
            read_error: None,
            read_buf: Vec::new(),
            read_offset: 0,
            read_deadline: None,
            write_deadline: None,
            wake,
            cancel,
            tasks,
            pending_ack: None,
            ack_finishes: false,
            closing: false,
            finished: false,
            write_chunk_size: params.segment_bytes.min(65536),
            on_close,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn set_read_deadline(&mut self, deadline: Option<StdInstant>) {
        self.read_deadline = deadline.map(|deadline| Box::pin(time::sleep_until(deadline.into())));
    }
    pub fn set_write_deadline(&mut self, deadline: Option<StdInstant>) {
        self.write_deadline = deadline.map(|deadline| Box::pin(time::sleep_until(deadline.into())));
    }
    pub fn set_deadline(&mut self, deadline: Option<StdInstant>) {
        self.set_read_deadline(deadline);
        self.set_write_deadline(deadline);
    }

    pub async fn close(mut self) -> io::Result<()> {
        self.shutdown().await
    }

    fn writer_closed(&self) -> io::Error {
        wal::stored_error(&self.write_error)
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "XDRIVE writer is closed"))
    }

    fn poll_control(&mut self, cx: &mut Context<'_>, finish: bool) -> Poll<io::Result<()>> {
        loop {
            if let Some(error) = wal::stored_error(&self.write_error) {
                return Poll::Ready(Err(error));
            }
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            if timed_out(&mut self.write_deadline, cx) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "XDRIVE write deadline exceeded",
                )));
            }
            if let Some(reply) = self.pending_ack.as_mut() {
                match Pin::new(reply).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        self.pending_ack = None;
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => return Poll::Ready(Err(error)),
                            Err(_) => return Poll::Ready(Err(self.writer_closed())),
                        }
                        if self.ack_finishes {
                            self.finished = true;
                            return Poll::Ready(Ok(()));
                        }
                        if !finish {
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
            match self.writer.poll_reserve(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(self.writer_closed())),
                Poll::Ready(Ok(())) => {}
            }
            let (reply, receiver) = oneshot::channel();
            let command = if finish {
                WriteCommand::Finish(reply)
            } else {
                WriteCommand::Flush(reply)
            };
            if self.writer.send_item(command).is_err() {
                return Poll::Ready(Err(self.writer_closed()));
            }
            self.pending_ack = Some(receiver);
            self.ack_finishes = finish;
            self.closing |= finish;
        }
    }
}

fn timed_out(deadline: &mut Option<Pin<Box<Sleep>>>, cx: &mut Context<'_>) -> bool {
    deadline.as_mut().is_some_and(|sleep| {
        // Tokio's timer wheel may round a deadline to a later tick. An already
        // expired deadline must reject immediately even if a flush/receive can
        // complete before that timer tick is dispatched.
        sleep.deadline() <= time::Instant::now() || sleep.as_mut().poll(cx).is_ready()
    })
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..64 {
            if this.read_offset < this.read_buf.len() {
                let n = (this.read_buf.len() - this.read_offset).min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_offset..this.read_offset + n]);
                this.read_offset += n;
                if this.read_offset == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = &this.read_error {
                return Poll::Ready(Err(error.error()));
            }
            if timed_out(&mut this.read_deadline, cx) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "XDRIVE read deadline exceeded",
                )));
            }
            match this.reader.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => {
                    this.read_error = Some(Failure::new(error));
                }
                Poll::Ready(Some(Ok(bytes))) => this.read_buf = bytes,
            }
        }
        // Empty .seg objects advance the WAL but must not become a false EOF.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Some(error) = wal::stored_error(&this.write_error) {
            return Poll::Ready(Err(error));
        }
        if this.closing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XDRIVE write side is closed",
            )));
        }
        if timed_out(&mut this.write_deadline, cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "XDRIVE write deadline exceeded",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.pending_ack.is_some() {
            match this.poll_control(cx, false) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        match this.writer.poll_reserve(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(this.writer_closed())),
            Poll::Ready(Ok(())) => {}
        }
        let n = bytes.len().min(this.write_chunk_size);
        if this
            .writer
            .send_item(WriteCommand::Data(bytes[..n].to_vec()))
            .is_err()
        {
            return Poll::Ready(Err(this.writer_closed()));
        }
        this.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_control(cx, false)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_control(cx, true)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
        if let Some(on_close) = self.on_close.take() {
            on_close();
        }
    }
}
