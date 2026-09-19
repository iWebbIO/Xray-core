//! Deterministic Xray KCP reliability and close-state engine. No socket/runtime dependency.
use super::wire::{self, ACK_LIMIT, ACK_OVERHEAD, CLOSE, Command, DATA_OVERHEAD, Segment};
use std::{
    collections::{HashMap, VecDeque},
    io,
};

const HALF: u32 = 0x8000_0000;
fn before(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < HALF
}
fn due(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < HALF
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mtu: usize,
    pub tti_ms: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub cwnd_multiplier: u32,
    pub max_sending_window: usize,
    pub idle_timeout_ms: u32,
    pub close_timeout_ms: u32,
    pub terminate_linger_ms: u32,
    pub max_retransmissions: u32,
    pub max_sessions: usize,
    pub accept_backlog: usize,
    pub datagram_queue: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti_ms: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 1,
            max_sending_window: 2 * 1024 * 1024,
            idle_timeout_ms: 30_000,
            close_timeout_ms: 15_000,
            terminate_linger_ms: 8_000,
            max_retransmissions: 128,
            max_sessions: 1024,
            accept_backlog: 64,
            datagram_queue: 64,
        }
    }
}
impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if !(64..=65_507).contains(&self.mtu) || !(1..=1000).contains(&self.tti_ms) {
            return Err(invalid("KCP MTU must be 64..65507 and TTI 1..1000 ms"));
        }
        if self.uplink_capacity == 0
            || self.downlink_capacity == 0
            || self.uplink_capacity > 4096
            || self.downlink_capacity > 4096
            || !(1..=16).contains(&self.cwnd_multiplier)
        {
            return Err(invalid(
                "KCP capacity or congestion multiplier outside supported bounds",
            ));
        }
        if self.max_sending_window < self.mtu
            || self.max_sending_window > 16 * 1024 * 1024
            || u64::from(self.receive_window()) * self.mtu as u64 > 16 * 1024 * 1024
        {
            return Err(invalid(
                "KCP per-direction buffer must be between one MTU and 16 MiB",
            ));
        }
        for value in [
            self.idle_timeout_ms,
            self.close_timeout_ms,
            self.terminate_linger_ms,
        ] {
            if value == 0 || value >= HALF {
                return Err(invalid(
                    "KCP timeouts must be positive and below 2^31 milliseconds",
                ));
            }
        }
        if !(1..=4096).contains(&self.max_retransmissions)
            || !(1..=16384).contains(&self.max_sessions)
            || !(1..=4096).contains(&self.accept_backlog)
            || !(1..=1024).contains(&self.datagram_queue)
        {
            return Err(invalid("KCP queue/session/retransmission bound invalid"));
        }
        Ok(())
    }
    fn capacity_window(&self, capacity: u32) -> u32 {
        // Same integer arithmetic order as Config.Get*InFlightSize in Go.
        (u64::from(capacity) * 1024 * 1024
            / self.mtu.max(1) as u64
            / (1000 / self.tti_ms.clamp(1, 1000)) as u64)
            .max(8)
            .min(u32::MAX as u64) as u32
    }
    pub fn send_window(&self) -> u32 {
        self.capacity_window(self.uplink_capacity)
    }
    pub fn receive_window(&self) -> u32 {
        self.capacity_window(self.downlink_capacity)
    }
    pub fn mss(&self) -> usize {
        self.mtu - DATA_OVERHEAD
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

#[derive(Debug)]
struct Pending {
    number: u32,
    payload: Vec<u8>,
    timeout: u32,
    transmissions: u32,
}
#[derive(Debug)]
struct Ack {
    number: u32,
    timestamp: u32,
    next_flush: u32,
    fresh: bool,
}
#[derive(Debug)]
struct RoundTrip {
    srtt: u32,
    variation: u32,
    rto: u32,
    updated: u32,
    minimum: u32,
}
impl RoundTrip {
    fn update(&mut self, rtt: u32, now: u32) {
        if rtt >= HALF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            self.variation = (3 * self.variation + self.srtt.abs_diff(rtt)) / 4;
            self.srtt = ((7 * self.srtt + rtt) / 8).max(self.minimum);
        }
        let extra = if self.minimum < 4 * self.variation {
            4 * self.variation
        } else {
            self.variation
        };
        self.rto = ((self.srtt + extra).min(10_000) * 5 / 4).max(1);
        self.updated = now;
    }
}

pub struct Session {
    config: Config,
    conversation: u16,
    state: State,
    state_since: u32,
    last_incoming: u32,
    last_ping: u32,
    send_next: u32,
    receive_next: u32,
    remote_window: u32,
    control_window: u32,
    send: VecDeque<Pending>,
    send_bytes: usize,
    received: HashMap<u32, Vec<u8>>,
    acks: VecDeque<Ack>,
    ack_dirty: bool,
    send_next_dirty: bool,
    acknowledged_bytes: u64,
    roundtrip: RoundTrip,
}

impl Session {
    pub fn new(conversation: u16, config: Config, now: u32) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            conversation,
            control_window: config.send_window(),
            roundtrip: RoundTrip {
                srtt: 0,
                variation: 0,
                rto: 100,
                updated: now,
                minimum: config.tti_ms,
            },
            config,
            state: State::Active,
            state_since: now,
            last_incoming: now,
            last_ping: now.wrapping_sub(3000),
            send_next: 0,
            receive_next: 0,
            remote_window: 32,
            send: VecDeque::new(),
            send_bytes: 0,
            received: HashMap::new(),
            acks: VecDeque::new(),
            ack_dirty: false,
            send_next_dirty: false,
            acknowledged_bytes: 0,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn conversation(&self) -> u16 {
        self.conversation
    }
    pub fn acknowledged_bytes(&self) -> u64 {
        self.acknowledged_bytes
    }
    pub fn pending_bytes(&self) -> usize {
        self.send_bytes
    }
    pub fn rto_ms(&self) -> u32 {
        self.roundtrip.rto
    }
    pub fn has_received(&self) -> bool {
        self.received.contains_key(&self.receive_next)
    }
    pub fn writable_bytes(&self) -> usize {
        if self.state != State::Active {
            return 0;
        }
        let segments = self.config.max_sending_window / self.config.mtu;
        segments.saturating_sub(self.send.len()) * self.config.mss()
    }
    fn first_unacknowledged(&self) -> u32 {
        self.send.front().map_or(self.send_next, |s| s.number)
    }
    fn set_state(&mut self, state: State, now: u32) {
        self.state = state;
        self.state_since = now;
        if matches!(
            state,
            State::PeerClosed | State::PeerTerminating | State::Terminating | State::Terminated
        ) {
            self.send.clear();
            self.send_bytes = 0;
        }
    }
    pub fn close(&mut self, now: u32) {
        match self.state {
            State::Active => self.set_state(State::ReadyToClose, now),
            State::PeerClosed => self.set_state(State::Terminating, now),
            State::PeerTerminating => self.set_state(State::Terminated, now),
            _ => {}
        }
    }
    /// Queue as many complete payload bytes as fit. Backpressure is a short write.
    pub fn queue(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.state != State::Active {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KCP conversation closed for writes",
            ));
        }
        let accepted = bytes.len().min(self.writable_bytes());
        for payload in bytes[..accepted].chunks(self.config.mss()) {
            self.send.push_back(Pending {
                number: self.send_next,
                payload: payload.to_vec(),
                timeout: 0,
                transmissions: 0,
            });
            self.send_next = self.send_next.wrapping_add(1);
        }
        self.send_bytes += accepted;
        Ok(accepted)
    }
    /// Advance the advertised receive window only when the application accepts bytes.
    pub fn pop_received(&mut self) -> Option<Vec<u8>> {
        let bytes = self.received.remove(&self.receive_next)?;
        self.receive_next = self.receive_next.wrapping_add(1);
        self.ack_dirty = true;
        Some(bytes)
    }
    pub fn input_datagram(&mut self, now: u32, bytes: &[u8]) -> io::Result<()> {
        let segments = wire::decode_datagram(bytes, self.config.mtu)?;
        self.input(now, segments)
    }
    fn clear_acks(&mut self, sending_next: u32) {
        self.acks.retain(|ack| !before(ack.number, sending_next));
    }
    fn remove_acknowledged(&mut self, receiving_next: u32, numbers: &[u32]) {
        // Untrusted future cumulative ACKs cannot remove queued, unsent bytes.
        let valid = !before(self.send_next, receiving_next)
            && !self
                .send
                .iter()
                .any(|s| before(s.number, receiving_next) && s.transmissions == 0);
        let first = self.first_unacknowledged();
        let mut removed = 0;
        self.send.retain(|s| {
            let acknowledged = s.transmissions > 0
                && ((valid && before(s.number, receiving_next)) || numbers.contains(&s.number));
            if acknowledged {
                removed += s.payload.len();
            }
            !acknowledged
        });
        self.send_bytes -= removed;
        self.acknowledged_bytes += removed as u64;
        self.send_next_dirty |= self.first_unacknowledged() != first;
    }
    pub fn input(&mut self, now: u32, segments: Vec<Segment>) -> io::Result<()> {
        if segments.is_empty()
            || segments
                .iter()
                .any(|s| s.conversation() != self.conversation || s.option() & !CLOSE != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KCP conversation/options mismatch",
            ));
        }
        if self.state == State::Terminated {
            return Ok(());
        }
        self.last_incoming = now;
        for segment in segments {
            if segment.option() & CLOSE != 0 {
                // Go discards its send window on peer-close. Account for ACKs
                // carried by that same closing segment before discarding the
                // remainder, so a confirmed final flush is not reported lost.
                match &segment {
                    Segment::Ack {
                        receiving_next,
                        numbers,
                        ..
                    } => self.remove_acknowledged(*receiving_next, numbers),
                    Segment::Command { receiving_next, .. } => {
                        self.remove_acknowledged(*receiving_next, &[])
                    }
                    Segment::Data { .. } => {}
                }
                match self.state {
                    State::Active => self.set_state(State::PeerClosed, now),
                    State::ReadyToClose => self.set_state(State::Terminating, now),
                    _ => {}
                }
            }
            match segment {
                Segment::Data {
                    number,
                    sending_next,
                    timestamp,
                    payload,
                    ..
                } => {
                    if matches!(self.state, State::Terminating | State::Terminated) {
                        continue;
                    }
                    if payload.is_empty() || payload.len() > self.config.mss() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "KCP payload exceeds configured MTU",
                        ));
                    }
                    let offset = number.wrapping_sub(self.receive_next);
                    if offset >= self.config.receive_window() {
                        if before(number, self.receive_next) {
                            self.ack_dirty = true;
                        }
                        continue;
                    }
                    self.clear_acks(sending_next);
                    if let Some(ack) = self.acks.iter_mut().find(|ack| ack.number == number) {
                        ack.timestamp = timestamp;
                        ack.fresh = true;
                    } else {
                        // Cumulative ACKs cover already-delivered entries if a peer never
                        // advances SendingNext. Bound retained selective-ACK state as well.
                        if self.acks.len() >= self.config.receive_window() as usize * 2 {
                            self.acks
                                .retain(|ack| !before(ack.number, self.receive_next));
                        }
                        self.acks.push_back(Ack {
                            number,
                            timestamp,
                            next_flush: now,
                            fresh: true,
                        });
                    }
                    self.received.entry(number).or_insert(payload);
                    self.ack_dirty = true;
                }
                Segment::Ack {
                    receiving_window,
                    receiving_next,
                    timestamp,
                    numbers,
                    ..
                } => {
                    if before(self.remote_window, receiving_window) {
                        self.remote_window = receiving_window;
                    }
                    let maxack = self
                        .send
                        .iter()
                        .rev()
                        .find(|s| s.transmissions > 0 && numbers.contains(&s.number))
                        .map(|s| s.number);
                    self.remove_acknowledged(receiving_next, &numbers);
                    if let Some(maxack) = maxack {
                        for pending in &mut self.send {
                            if before(pending.number, maxack) && pending.transmissions > 0 {
                                pending.timeout =
                                    pending.timeout.wrapping_sub(self.roundtrip.rto / 3);
                            }
                        }
                        let rtt = now.wrapping_sub(timestamp);
                        if rtt < 10_000 {
                            self.roundtrip.update(rtt, now);
                        }
                    }
                }
                Segment::Command {
                    command,
                    sending_next,
                    receiving_next,
                    peer_rto,
                    ..
                } => {
                    self.remove_acknowledged(receiving_next, &[]);
                    self.clear_acks(sending_next);
                    if now.wrapping_sub(self.roundtrip.updated) >= 3000 {
                        self.roundtrip.rto = peer_rto.clamp(1, 12_500);
                        self.roundtrip.updated = now;
                    }
                    if command == Command::Terminate {
                        match self.state {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating, now)
                            }
                            State::ReadyToClose => self.set_state(State::Terminating, now),
                            State::Terminating => self.set_state(State::Terminated, now),
                            _ => {}
                        }
                    }
                    // A ping also refreshes the window when no data has been received.
                    self.ack_dirty = true;
                }
            }
        }
        Ok(())
    }
    fn command(&self, command: Command) -> Segment {
        Segment::Command {
            conv: self.conversation,
            option: if self.state == State::ReadyToClose {
                CLOSE
            } else {
                0
            },
            command,
            sending_next: self.first_unacknowledged(),
            receiving_next: self.receive_next,
            peer_rto: self.roundtrip.rto,
        }
    }
    /// Produce each UDP datagram at `now`, a wrapping millisecond clock.
    pub fn poll(&mut self, now: u32) -> io::Result<Vec<Vec<u8>>> {
        if self.state == State::Terminated {
            return Ok(Vec::new());
        }
        if matches!(self.state, State::Active | State::PeerClosed)
            && now.wrapping_sub(self.last_incoming) >= self.config.idle_timeout_ms
        {
            self.set_state(State::Terminated, now);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "KCP peer idle timeout",
            ));
        }
        if self.state == State::ReadyToClose
            && (self.send.is_empty()
                || now.wrapping_sub(self.state_since) >= self.config.close_timeout_ms)
        {
            self.set_state(State::Terminating, now);
            self.last_ping = now.wrapping_sub(1000);
        }
        if self.state == State::PeerTerminating && now.wrapping_sub(self.state_since) >= 4000 {
            self.set_state(State::Terminating, now);
            self.last_ping = now.wrapping_sub(1000);
        }
        if self.state == State::Terminating {
            if now.wrapping_sub(self.state_since) >= self.config.terminate_linger_ms {
                self.set_state(State::Terminated, now);
                return Ok(Vec::new());
            }
            if now.wrapping_sub(self.last_ping) >= 1000 {
                self.last_ping = now;
                return Ok(vec![self.command(Command::Terminate).encode()?]);
            }
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let option = if self.state == State::ReadyToClose {
            CLOSE
        } else {
            0
        };
        let ack_limit = ACK_LIMIT.min((self.config.mtu - ACK_OVERHEAD) / 4);
        let mut numbers = Vec::with_capacity(ack_limit);
        let mut timestamp = 0;
        for ack in &mut self.acks {
            if !ack.fresh && !due(now, ack.next_flush) {
                continue;
            }
            ack.fresh = false;
            ack.next_flush = now.wrapping_add((self.roundtrip.rto / 2).max(20));
            numbers.push(ack.number);
            if numbers.len() == 1 || before(timestamp, ack.timestamp) {
                timestamp = ack.timestamp;
            }
            if numbers.len() == ack_limit {
                output.push(
                    Segment::Ack {
                        conv: self.conversation,
                        option,
                        receiving_window: self
                            .receive_next
                            .wrapping_add(self.config.receive_window()),
                        receiving_next: self.receive_next,
                        timestamp,
                        numbers: std::mem::take(&mut numbers),
                    }
                    .encode()?,
                );
                self.ack_dirty = false;
            }
        }
        if self.ack_dirty || !numbers.is_empty() {
            output.push(
                Segment::Ack {
                    conv: self.conversation,
                    option,
                    receiving_window: self.receive_next.wrapping_add(self.config.receive_window()),
                    receiving_next: self.receive_next,
                    timestamp,
                    numbers,
                }
                .encode()?,
            );
            self.ack_dirty = false;
        }
        let sending_next = self.first_unacknowledged();
        let available = self.remote_window.wrapping_sub(sending_next);
        let available = if available < HALF { available } else { 0 };
        let budget = self
            .config
            .send_window()
            .min(self.control_window)
            .min(available)
            .saturating_mul(self.config.cwnd_multiplier);
        let mut sent = 0;
        let mut lost = 0;
        for pending in &mut self.send {
            if sent >= budget {
                break;
            }
            if !before(pending.number, self.remote_window)
                || (pending.transmissions > 0 && !due(now, pending.timeout))
            {
                continue;
            }
            if pending.transmissions >= self.config.max_retransmissions {
                self.state = State::Terminated;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "KCP retransmission limit exceeded",
                ));
            }
            if pending.transmissions > 0 {
                lost += 1;
            }
            pending.transmissions += 1;
            pending.timeout = now.wrapping_add(self.roundtrip.rto);
            output.push(
                Segment::Data {
                    conv: self.conversation,
                    option,
                    timestamp: now,
                    number: pending.number,
                    sending_next,
                    payload: pending.payload.clone(),
                }
                .encode()?,
            );
            sent += 1;
        }
        if sent > 0 {
            let in_flight = self
                .send
                .iter()
                .filter(|s| s.transmissions > 0)
                .count()
                .max(1) as u32;
            let rate = lost * 100 / in_flight;
            if rate >= 15 {
                self.control_window = self.control_window * 3 / 4;
            }
            if rate <= 5 {
                self.control_window += self.control_window / 4;
            }
            self.control_window = self.control_window.max(16).min(self.config.send_window());
            self.send_next_dirty = false;
        }
        if self.send_next_dirty || now.wrapping_sub(self.last_ping) >= 3000 {
            self.last_ping = now;
            self.send_next_dirty = false;
            output.push(self.command(Command::Ping).encode()?);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn small() -> Config {
        Config {
            mtu: 64,
            uplink_capacity: 1,
            downlink_capacity: 1,
            tti_ms: 1,
            ..Config::default()
        }
    }
    fn data_packets(session: &mut Session, now: u32) -> Vec<Vec<u8>> {
        session
            .poll(now)
            .unwrap()
            .into_iter()
            .filter(|p| p[2] == 1)
            .collect()
    }
    fn feed(from: &mut Session, to: &mut Session, now: u32) {
        for packet in from.poll(now).unwrap() {
            to.input_datagram(now, &packet).unwrap();
        }
    }
    #[test]
    fn defaults_match_go_window_arithmetic() {
        let c = Config::default();
        assert_eq!(c.send_window(), 194);
        assert_eq!(c.receive_window(), 776);
        assert_eq!(c.mss(), 1332);
        c.validate().unwrap();
    }
    #[test]
    fn loss_reorder_duplicates_selective_ack_and_fast_retransmit() {
        let mut a = Session::new(7, small(), 0).unwrap();
        let mut b = Session::new(7, small(), 0).unwrap();
        let bytes: Vec<_> = (0..138).map(|i| i as u8).collect();
        assert_eq!(a.queue(&bytes).unwrap(), 138);
        let packets = data_packets(&mut a, 0);
        assert_eq!(packets.len(), 3);
        b.input_datagram(10, &packets[2]).unwrap();
        b.input_datagram(11, &packets[1]).unwrap();
        b.input_datagram(12, &packets[1]).unwrap();
        assert!(b.pop_received().is_none());
        feed(&mut b, &mut a, 20);
        assert_eq!(a.pending_bytes(), 46);
        assert!(data_packets(&mut a, 60).is_empty());
        let retry = data_packets(&mut a, 67);
        assert_eq!(retry.len(), 1);
        b.input_datagram(68, &retry[0]).unwrap();
        let mut delivered = Vec::new();
        while let Some(part) = b.pop_received() {
            delivered.extend(part);
        }
        assert_eq!(delivered, bytes);
        feed(&mut b, &mut a, 70);
        assert_eq!(a.pending_bytes(), 0);
        assert_eq!(a.acknowledged_bytes(), 138);
    }
    #[test]
    fn lost_ack_is_repeated_until_sending_next_clears_it() {
        let mut a = Session::new(9, small(), 0).unwrap();
        let mut b = Session::new(9, small(), 0).unwrap();
        a.queue(b"hello").unwrap();
        feed(&mut a, &mut b, 0);
        let _lost = b.poll(1).unwrap();
        assert_eq!(b.pop_received().unwrap(), b"hello");
        feed(&mut b, &mut a, 55);
        assert_eq!(a.pending_bytes(), 0);
        feed(&mut a, &mut b, 56);
        assert!(b.acks.is_empty());
    }
    #[test]
    fn receive_window_advances_only_after_read_and_send_is_bounded() {
        let mut cfg = small();
        cfg.max_sending_window = 64 * 10;
        let mut a = Session::new(1, cfg.clone(), 0).unwrap();
        let mut b = Session::new(1, cfg, 0).unwrap();
        assert_eq!(a.queue(&vec![1; 1000]).unwrap(), 460);
        assert_eq!(a.queue(b"x").unwrap(), 0);
        feed(&mut a, &mut b, 0);
        assert_eq!(b.received.len(), 10);
        assert_eq!(b.receive_next, 0);
        for _ in 0..10 {
            assert!(b.pop_received().is_some());
        }
        assert_eq!(b.receive_next, 10);
    }
    #[test]
    fn sequence_and_clock_wrap_work() {
        let start = u32::MAX - 30;
        let mut a = Session::new(1, small(), start).unwrap();
        let mut b = Session::new(1, small(), start).unwrap();
        a.send_next = u32::MAX;
        a.remote_window = 31;
        b.receive_next = u32::MAX;
        a.queue(&vec![7; 92]).unwrap();
        let packets = data_packets(&mut a, start);
        assert_eq!(packets.len(), 2);
        b.input_datagram(start, &packets[1]).unwrap();
        b.input_datagram(5, &packets[0]).unwrap();
        assert_eq!(b.pop_received().unwrap().len(), 46);
        assert_eq!(b.pop_received().unwrap().len(), 46);
        assert_eq!(b.receive_next, 1);
        feed(&mut b, &mut a, 8);
        assert_eq!(a.pending_bytes(), 0);
        assert_eq!(a.first_unacknowledged(), 1);
    }
    #[test]
    fn timeout_and_retransmit_limit_are_errors() {
        let cfg = Config {
            max_retransmissions: 2,
            ..small()
        };
        let mut a = Session::new(1, cfg, 0).unwrap();
        a.queue(b"x").unwrap();
        assert_eq!(data_packets(&mut a, 0).len(), 1);
        assert_eq!(data_packets(&mut a, 100).len(), 1);
        assert_eq!(a.poll(200).unwrap_err().kind(), io::ErrorKind::TimedOut);
        let mut b = Session::new(1, small(), 0).unwrap();
        assert_eq!(b.poll(30_000).unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    #[test]
    fn close_drains_and_termination_has_a_bound() {
        let mut a = Session::new(1, small(), 0).unwrap();
        let mut b = Session::new(1, small(), 0).unwrap();
        a.queue(b"bye").unwrap();
        a.close(0);
        feed(&mut a, &mut b, 1);
        assert_eq!(b.state(), State::PeerClosed);
        assert_eq!(b.pop_received().unwrap(), b"bye");
        feed(&mut b, &mut a, 2);
        let packets = a.poll(3).unwrap();
        assert!(packets.iter().any(|p| p[2] == 2));
        assert_eq!(a.state(), State::Terminating);
        a.poll(8003).unwrap();
        assert_eq!(a.state(), State::Terminated);
    }
    #[test]
    fn forged_ack_cannot_ack_unsent_bytes_and_wrong_conversation_rejected() {
        let mut a = Session::new(1, small(), 0).unwrap();
        a.queue(b"unsent").unwrap();
        a.input(
            0,
            vec![Segment::Ack {
                conv: 1,
                option: 0,
                receiving_window: 32,
                receiving_next: 100,
                timestamp: 0,
                numbers: vec![0],
            }],
        )
        .unwrap();
        assert_eq!(a.pending_bytes(), 6);
        assert!(
            a.input(
                0,
                vec![Segment::Command {
                    conv: 2,
                    option: 0,
                    command: Command::Ping,
                    sending_next: 0,
                    receiving_next: 0,
                    peer_rto: 100
                }]
            )
            .is_err()
        );
    }
    #[test]
    fn invalid_settings_fail_before_allocating() {
        for c in [
            Config { mtu: 0, ..small() },
            Config {
                tti_ms: 0,
                ..small()
            },
            Config {
                max_sending_window: usize::MAX,
                ..small()
            },
            Config {
                downlink_capacity: 4096,
                tti_ms: 1000,
                ..small()
            },
            Config {
                datagram_queue: 0,
                ..small()
            },
        ] {
            assert!(c.validate().is_err());
        }
    }

    #[test]
    fn bidirectional_loss_jitter_and_duplicate_network_converges() {
        let config = Config {
            mtu: 192,
            tti_ms: 10,
            ..small()
        };
        let mut a = Session::new(33, config.clone(), 0).unwrap();
        let mut b = Session::new(33, config, 0).unwrap();
        let left: Vec<_> = (0..50_000).map(|n| (n % 251) as u8).collect();
        let right: Vec<_> = (0..41_000).map(|n| (n % 239) as u8).collect();
        assert_eq!(a.queue(&left).unwrap(), left.len());
        assert_eq!(b.queue(&right).unwrap(), right.len());
        let mut network: Vec<(u32, bool, Vec<u8>)> = Vec::new();
        let (mut at_a, mut at_b) = (Vec::new(), Vec::new());
        let mut serial = 0u32;
        for now in (0..15_000).step_by(5) {
            for (to_b, packets) in [(true, a.poll(now).unwrap()), (false, b.poll(now).unwrap())] {
                for packet in packets {
                    serial += 1;
                    if serial % 5 == 0 {
                        continue;
                    }
                    let deadline = now + (serial * 13) % 80;
                    if serial % 11 == 0 {
                        network.push((deadline + 3, to_b, packet.clone()));
                    }
                    network.push((deadline, to_b, packet));
                }
            }
            for index in (0..network.len()).rev() {
                if network[index].0 > now {
                    continue;
                }
                let (_, to_b, packet) = network.swap_remove(index);
                if to_b {
                    b.input_datagram(now, &packet).unwrap();
                } else {
                    a.input_datagram(now, &packet).unwrap();
                }
            }
            if now % 15 == 0 {
                while let Some(bytes) = a.pop_received() {
                    at_a.extend(bytes);
                }
                while let Some(bytes) = b.pop_received() {
                    at_b.extend(bytes);
                }
            }
            if at_a.len() == right.len()
                && at_b.len() == left.len()
                && a.pending_bytes() == 0
                && b.pending_bytes() == 0
            {
                break;
            }
        }
        assert_eq!(at_a, right);
        assert_eq!(at_b, left);
        assert_eq!(a.pending_bytes(), 0);
        assert_eq!(b.pending_bytes(), 0);
    }

    #[test]
    fn duplicate_stale_acks_do_not_free_twice_or_regress_window() {
        let mut a = Session::new(7, small(), 0).unwrap();
        a.queue(&vec![1; 138]).unwrap();
        let _ = a.poll(0).unwrap();
        let ack = Segment::Ack {
            conv: 7,
            option: 0,
            receiving_window: 64,
            receiving_next: 0,
            timestamp: 0,
            numbers: vec![2, 1, 2],
        };
        a.input(10, vec![ack.clone()]).unwrap();
        assert_eq!(a.acknowledged_bytes(), 92);
        a.input(11, vec![ack]).unwrap();
        assert_eq!(a.acknowledged_bytes(), 92);
        a.input(
            12,
            vec![Segment::Ack {
                conv: 7,
                option: 0,
                receiving_window: 32,
                receiving_next: 0,
                timestamp: 0,
                numbers: vec![0],
            }],
        )
        .unwrap();
        assert_eq!(a.acknowledged_bytes(), 138);
        assert_eq!(a.pending_bytes(), 0);
        assert_eq!(a.remote_window, 64);
    }

    #[test]
    fn retransmit_deadline_crosses_wrapping_millisecond_clock() {
        let start = u32::MAX - 30;
        let mut a = Session::new(1, small(), start).unwrap();
        a.queue(b"retry").unwrap();
        assert_eq!(data_packets(&mut a, start).len(), 1);
        assert!(data_packets(&mut a, 68).is_empty());
        assert_eq!(data_packets(&mut a, 69).len(), 1);
    }

    #[test]
    fn closing_ack_accounts_for_confirmed_bytes_before_discarding_window() {
        let mut a = Session::new(1, small(), 0).unwrap();
        a.queue(b"final").unwrap();
        let _ = a.poll(0).unwrap();
        a.input(
            1,
            vec![Segment::Ack {
                conv: 1,
                option: CLOSE,
                receiving_window: 32,
                receiving_next: 1,
                timestamp: 0,
                numbers: vec![0],
            }],
        )
        .unwrap();
        assert_eq!(a.state(), State::PeerClosed);
        assert_eq!(a.pending_bytes(), 0);
        assert_eq!(a.acknowledged_bytes(), 5);
    }
}
