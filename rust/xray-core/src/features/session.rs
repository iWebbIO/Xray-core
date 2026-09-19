//! Policy-aware, bounded TCP byte-stream relay.
//!
//! Uplink is client -> upstream. After an uplink EOF only downlink remains, so
//! `downlink_only` applies (and conversely for a downlink EOF). Timeouts measure
//! time since the last successful write, reset when entering a half-closed state,
//! and zero means immediate expiry. Unlike Go's periodically sampled activity
//! timer, deadlines here are exact rather than allowing an extra polling period.
//!
//! There is no read-ahead queue: each direction drains its scratch buffer before
//! reading again. Positive buffer policies cap that buffer, zero permits only a
//! 2 KiB transfer chunk (the source pipe also permits one write at zero capacity),
//! and unlimited policies use a bounded 16 KiB chunk. These are byte-stream buffer
//! semantics, not a port of Go's optional MultiBuffer queue/zero-copy optimizations.
//! Handshake timeouts are enforced by the caller before entering this relay.

use std::{io, sync::Mutex, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use super::{
    policy::{BufferPolicy, SessionPolicy},
    stats::{TrafficCounters, UserSessionStats},
};

const MAX_CHUNK: usize = 16 * 1024;
const UNBUFFERED_CHUNK: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayTotals {
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Clone, Copy)]
enum Direction {
    Uplink,
    Downlink,
}

struct ActivityState {
    last: Instant,
    timeout: Duration,
}

struct Activity {
    state: Mutex<ActivityState>,
    changed: Notify,
}

impl Activity {
    fn new(timeout: Duration, last: Instant) -> Self {
        Self {
            state: Mutex::new(ActivityState { last, timeout }),
            changed: Notify::new(),
        }
    }

    fn update(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .last = Instant::now();
        self.changed.notify_one();
    }

    fn set_timeout(&self, timeout: Duration) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.last = Instant::now();
        state.timeout = timeout;
        drop(state);
        self.changed.notify_one();
    }

    async fn expired(&self) -> io::Error {
        loop {
            let deadline = {
                let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                state.last.checked_add(state.timeout)
            };
            let Some(deadline) = deadline else {
                // A duration outside the monotonic clock's representable range
                // cannot expire in this process, but cancellation still works.
                self.changed.notified().await;
                continue;
            };
            tokio::select! {
                _ = self.changed.notified() => (),
                _ = sleep_until(deadline) => {
                    let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                    // A ready timer may race a write or a transition to a new
                    // timeout. Only the latest state can expire the session.
                    if Instant::now().saturating_duration_since(state.last) >= state.timeout {
                        return io::Error::new(io::ErrorKind::TimedOut, "proxy session inactivity timeout");
                    }
                }
            }
        }
    }
}

fn chunk_size(policy: BufferPolicy) -> usize {
    match policy.per_connection {
        0 => UNBUFFERED_CHUNK,
        limit if limit > 0 => (limit as usize).min(MAX_CHUNK),
        _ => MAX_CHUNK,
    }
}

struct Accounting<'a> {
    user: Option<&'a TrafficCounters>,
    traffic: &'a [TrafficCounters],
}

impl Accounting<'_> {
    fn add(&self, direction: Direction, bytes: usize) {
        for counters in self.user.into_iter().chain(self.traffic.iter()) {
            match direction {
                Direction::Uplink => counters.add_uplink(bytes),
                Direction::Downlink => counters.add_downlink(bytes),
            }
        }
    }
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    activity: &Activity,
    remaining_timeout: Duration,
    accounting: &Accounting<'_>,
    capacity: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; capacity];
    let mut total = 0_u64;
    loop {
        let bytes = reader.read(&mut buffer).await?;
        if bytes == 0 {
            activity.set_timeout(remaining_timeout);
            // Preserve the reverse direction after this EOF. Shutdown flushes
            // buffered transports; a blocked shutdown is also timed out.
            writer.shutdown().await?;
            return Ok(total);
        }
        let mut written = 0;
        while written < bytes {
            let count = writer.write(&buffer[written..bytes]).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "proxy stream stopped accepting bytes",
                ));
            }
            written += count;
            total = total.saturating_add(count as u64);
            // Count every successful partial write, before any later write,
            // flush, timeout or cancellation can fail the session.
            accounting.add(direction, count);
            activity.update();
        }
        writer.flush().await?;
        // Custom AsyncRead/AsyncWrite implementations can always be ready;
        // explicitly yield so they cannot starve cancellation or the timer.
        tokio::task::yield_now().await;
    }
}

/// Relay until both directions finish, an I/O error, cancellation or inactivity.
///
/// `session` is owned, so its online-user guard is released on every return path
/// and when this future is dropped, including before its first poll. `traffic`
/// adds optional inbound/outbound accounting; do not repeat the same handles as
/// the user counters. Updates happen during transfer, not only on completion.
///
/// No tasks are spawned. Dropping/cancelling stops both directions immediately;
/// already accepted bytes remain counted and pending scratch data is discarded.
/// The streams are borrowed; the caller should close/drop them after an error.
pub async fn relay<A, B>(
    client: &mut A,
    upstream: &mut B,
    policy: &SessionPolicy,
    session: Option<UserSessionStats>,
    traffic: &[TrafficCounters],
    cancel: &CancellationToken,
) -> io::Result<RelayTotals>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    relay_with_idle_since(
        client,
        upstream,
        policy,
        session,
        traffic,
        cancel,
        Instant::now(),
    )
    .await
}

/// Continue an authenticated session's existing inactivity budget after setup.
/// Successful transfers and half-close transitions start a new full timeout;
/// outbound dialing and proxy handshakes do not extend `idle_since`.
pub async fn relay_with_idle_since<A, B>(
    client: &mut A,
    upstream: &mut B,
    policy: &SessionPolicy,
    session: Option<UserSessionStats>,
    traffic: &[TrafficCounters],
    cancel: &CancellationToken,
    idle_since: Instant,
) -> io::Result<RelayTotals>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "proxy session cancelled",
        ));
    }
    if Instant::now().saturating_duration_since(idle_since) >= policy.timeouts.connection_idle {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "proxy session inactivity timeout",
        ));
    }
    let result = {
        let activity = Activity::new(policy.timeouts.connection_idle, idle_since);
        let accounting = Accounting {
            user: session.as_ref().map(|session| &session.traffic),
            traffic,
        };
        let capacity = chunk_size(policy.buffer);
        let (client_read, client_write) = tokio::io::split(client);
        let (upstream_read, upstream_write) = tokio::io::split(upstream);
        let transfer = async {
            let (uplink, downlink) = tokio::try_join!(
                copy_direction(
                    client_read,
                    upstream_write,
                    Direction::Uplink,
                    &activity,
                    policy.timeouts.downlink_only,
                    &accounting,
                    capacity
                ),
                copy_direction(
                    upstream_read,
                    client_write,
                    Direction::Downlink,
                    &activity,
                    policy.timeouts.uplink_only,
                    &accounting,
                    capacity
                ),
            )?;
            Ok(RelayTotals { uplink, downlink })
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "proxy session cancelled")),
            result = transfer => result,
            error = activity.expired() => Err(error),
        }
    };
    drop(session);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::{
        policy::UserStatsPolicy,
        stats::{Counter, OnlineMap, StatsManager},
    };
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };
    use tokio::io::{ReadBuf, duplex};
    use tokio::time::timeout;

    fn policy() -> SessionPolicy {
        let mut policy = SessionPolicy::default();
        policy.timeouts.connection_idle = Duration::from_secs(2);
        policy.timeouts.uplink_only = Duration::from_millis(20);
        policy.timeouts.downlink_only = Duration::from_millis(20);
        policy
    }

    #[tokio::test]
    async fn half_close_preserves_reply_and_counts_both_directions() {
        let (mut client, mut inbound) = duplex(32);
        let (mut outbound, mut server) = duplex(32);
        let cancel = CancellationToken::new();
        let uplink = Arc::new(Counter::new());
        let downlink = Arc::new(Counter::new());
        let traffic = [TrafficCounters {
            uplink: Some(uplink.clone()),
            downlink: Some(downlink.clone()),
        }];
        let mut config = policy();
        config.timeouts.downlink_only = Duration::from_secs(2);
        let result = timeout(Duration::from_secs(3), async {
            let copy = relay(
                &mut inbound,
                &mut outbound,
                &config,
                None,
                &traffic,
                &cancel,
            );
            let peers = async {
                client.write_all(b"request").await.unwrap();
                client.shutdown().await.unwrap();
                let mut request = Vec::new();
                server.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"request");
                server.write_all(b"response").await.unwrap();
                server.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"response");
            };
            let (result, ()) = tokio::join!(copy, peers);
            result.unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            result,
            RelayTotals {
                uplink: 7,
                downlink: 8
            }
        );
        assert_eq!(uplink.value(), 7);
        assert_eq!(downlink.value(), 8);
    }

    #[tokio::test]
    async fn idle_timeout_releases_online_guard() {
        let (_client, mut inbound) = duplex(8);
        let (mut outbound, _server) = duplex(8);
        let online = Arc::new(OnlineMap::new());
        let session = UserSessionStats {
            traffic: TrafficCounters::default(),
            online: Some(online.track("192.0.2.1")),
        };
        let mut config = policy();
        config.timeouts.connection_idle = Duration::from_millis(10);
        let error = timeout(
            Duration::from_secs(2),
            relay(
                &mut inbound,
                &mut outbound,
                &config,
                Some(session),
                &[],
                &CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(online.count(), 0);
    }

    #[tokio::test]
    async fn eof_uses_timeout_for_remaining_direction() {
        for uplink_eof in [true, false] {
            let (mut client, mut inbound) = duplex(8);
            let (mut outbound, mut server) = duplex(8);
            if uplink_eof {
                client.shutdown().await.unwrap();
            } else {
                server.shutdown().await.unwrap();
            }
            let mut config = policy();
            if uplink_eof {
                config.timeouts.uplink_only = Duration::from_secs(60);
            } else {
                config.timeouts.downlink_only = Duration::from_secs(60);
            }
            let error = timeout(
                Duration::from_secs(1),
                relay(
                    &mut inbound,
                    &mut outbound,
                    &config,
                    None,
                    &[],
                    &CancellationToken::new(),
                ),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test]
    async fn counters_are_live_during_blocked_write_and_cancellation_releases_session() {
        let (mut client, mut inbound) = duplex(16);
        let (mut outbound, _server) = duplex(2);
        let stats = StatsManager::new();
        let session = stats.user_session(
            "user@example.test",
            "192.0.2.1",
            UserStatsPolicy {
                user_uplink: true,
                user_downlink: true,
                user_online: true,
            },
        );
        let counter = session.traffic.uplink.as_ref().unwrap().clone();
        let online = stats
            .get_online_map("user>>>user@example.test>>>online")
            .unwrap();
        let cancel = CancellationToken::new();
        let stopping = cancel.clone();
        let task = tokio::spawn(async move {
            relay(
                &mut inbound,
                &mut outbound,
                &policy(),
                Some(session),
                &[],
                &stopping,
            )
            .await
        });
        client.write_all(b"abcdef").await.unwrap();
        timeout(Duration::from_secs(1), async {
            while counter.value() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(counter.value(), 2);
        assert_eq!(online.count(), 1);
        assert!(!task.is_finished());
        cancel.cancel();
        let error = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(counter.value(), 2);
        assert_eq!(online.count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn successful_writes_reset_inactivity_deadline() {
        let (mut client, mut inbound) = duplex(16);
        let (mut outbound, mut server) = duplex(16);
        let mut config = policy();
        config.timeouts.connection_idle = Duration::from_secs(10);
        let task = tokio::spawn(async move {
            relay(
                &mut inbound,
                &mut outbound,
                &config,
                None,
                &[],
                &CancellationToken::new(),
            )
            .await
        });
        let mut received = [0; 1];
        client.write_all(b"a").await.unwrap();
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, *b"a");
        tokio::time::advance(Duration::from_secs(9)).await;
        client.write_all(b"b").await.unwrap();
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, *b"b");
        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "traffic must extend the original idle deadline"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn dropping_unpolled_future_releases_online_guard() {
        let (_client, mut inbound) = duplex(8);
        let (mut outbound, _server) = duplex(8);
        let online = Arc::new(OnlineMap::new());
        let session = UserSessionStats {
            traffic: TrafficCounters::default(),
            online: Some(online.track("192.0.2.1")),
        };
        let config = policy();
        let cancel = CancellationToken::new();
        let future = relay(
            &mut inbound,
            &mut outbound,
            &config,
            Some(session),
            &[],
            &cancel,
        );
        assert_eq!(online.count(), 1);
        drop(future);
        assert_eq!(online.count(), 0);
    }

    struct FailAfterTwo {
        written: bool,
    }
    impl AsyncRead for FailAfterTwo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for FailAfterTwo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.written {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            } else {
                self.written = true;
                Poll::Ready(Ok(bytes.len().min(2)))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn partial_write_is_counted_before_later_io_error() {
        let (mut client, mut inbound) = duplex(16);
        client.write_all(b"abcdef").await.unwrap();
        let counter = Arc::new(Counter::new());
        let traffic = [TrafficCounters {
            uplink: Some(counter.clone()),
            downlink: None,
        }];
        let error = timeout(
            Duration::from_secs(1),
            relay(
                &mut inbound,
                &mut FailAfterTwo { written: false },
                &policy(),
                None,
                &traffic,
                &CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(counter.value(), 2);
    }

    #[tokio::test]
    async fn zero_idle_policy_expires_without_moving_bytes() {
        let (mut client, mut inbound) = duplex(16);
        let (mut outbound, _server) = duplex(16);
        client.write_all(b"queued").await.unwrap();
        let mut config = policy();
        config.timeouts.connection_idle = Duration::ZERO;
        let counter = Arc::new(Counter::new());
        let traffic = [TrafficCounters {
            uplink: Some(counter.clone()),
            downlink: None,
        }];
        let error = relay(
            &mut inbound,
            &mut outbound,
            &config,
            None,
            &traffic,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(counter.value(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn outbound_setup_consumes_the_initial_inactivity_budget() {
        let (_client, mut inbound) = duplex(16);
        let (mut outbound, _server) = duplex(16);
        let mut config = policy();
        config.timeouts.connection_idle = Duration::from_secs(10);
        let started = Instant::now();
        let error = relay_with_idle_since(
            &mut inbound,
            &mut outbound,
            &config,
            None,
            &[],
            &CancellationToken::new(),
            started - Duration::from_secs(8),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(2));
    }

    #[test]
    fn buffer_policy_bounds_memory_without_read_ahead_queue() {
        assert_eq!(chunk_size(BufferPolicy { per_connection: 1 }), 1);
        assert_eq!(
            chunk_size(BufferPolicy {
                per_connection: 1024
            }),
            1024
        );
        assert_eq!(chunk_size(BufferPolicy { per_connection: 0 }), 2048);
        assert_eq!(chunk_size(BufferPolicy { per_connection: -1 }), MAX_CHUNK);
        assert_eq!(
            chunk_size(BufferPolicy {
                per_connection: i32::MAX
            }),
            MAX_CHUNK
        );
    }
}
