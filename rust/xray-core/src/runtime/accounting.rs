//! System counters belong outside proxy encoding, at the transport boundary.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{features::stats::TrafficCounters, transport::BoxStream};

pub(super) struct CountedStream {
    inner: BoxStream,
    counters: TrafficCounters,
    inbound: bool,
}

impl CountedStream {
    pub(super) fn wrap(inner: BoxStream, counters: TrafficCounters, inbound: bool) -> BoxStream {
        if counters.uplink.is_none() && counters.downlink.is_none() {
            return inner;
        }
        Box::new(Self {
            inner,
            counters,
            inbound,
        })
    }

    fn read_bytes(&self, bytes: usize) {
        if self.inbound {
            self.counters.add_uplink(bytes);
        } else {
            self.counters.add_downlink(bytes);
        }
    }

    fn written_bytes(&self, bytes: usize) {
        if self.inbound {
            self.counters.add_downlink(bytes);
        } else {
            self.counters.add_uplink(bytes);
        }
    }
}

impl AsyncRead for CountedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        self.read_bytes(buffer.filled().len() - before);
        result
    }
}

impl AsyncWrite for CountedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buffer);
        if let Poll::Ready(Ok(bytes)) = result {
            self.written_bytes(bytes);
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, buffers);
        if let Poll::Ready(Ok(bytes)) = result {
            self.written_bytes(bytes);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
