use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::{
    DnsError, Resolver, Result,
    resolver::{read_tcp_message, write_tcp_message},
    wire::{self, CLASS_IN, MAX_MESSAGE_SIZE, RecordType},
};

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Maximum concurrent UDP requests or TCP connections per serve call.
    pub max_in_flight: usize,
    pub max_udp_payload: u16,
    pub tcp_idle_timeout: Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 256,
            max_udp_payload: 1350,
            tcp_idle_timeout: Duration::from_secs(60),
        }
    }
}

/// Address-query service matching the DNS outbound's default rules: A/AAAA
/// queries resolve locally; other IN queries receive an empty NOERROR reply.
/// Caller-owned sockets make the binding address and routing explicit.
pub struct DnsService {
    resolver: Resolver,
    config: ServiceConfig,
}

impl DnsService {
    pub fn new(resolver: Resolver, config: ServiceConfig) -> Result<Self> {
        if config.max_in_flight == 0 {
            return Err(DnsError::InvalidConfig("service concurrency is zero"));
        }
        if !(512..=65507).contains(&config.max_udp_payload) {
            return Err(DnsError::InvalidConfig("UDP payload must be in 512..65507"));
        }
        if config.tcp_idle_timeout.is_zero() {
            return Err(DnsError::InvalidConfig("TCP idle timeout is zero"));
        }
        Ok(Self { resolver, config })
    }

    /// Process a complete unframed DNS query using the full TCP message limit.
    /// Lookup/network errors remain errors; they are not changed into NXDOMAIN.
    pub async fn handle_query(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.handle(bytes, false).await
    }

    /// Process a datagram, respecting EDNS payload size and setting TC if needed.
    pub async fn handle_udp_query(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.handle(bytes, true).await
    }

    async fn handle(&self, bytes: &[u8], udp: bool) -> Result<Vec<u8>> {
        if bytes.len() < 2 {
            return Err(DnsError::Malformed(
                "query does not contain a transaction ID",
            ));
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        // Do not answer a response packet, even when the rest is malformed.
        if bytes.get(2).is_some_and(|flags| flags & 0x80 != 0) {
            return Err(DnsError::Malformed("response sent to DNS query service"));
        }
        let message = match wire::decode(bytes) {
            Ok(message) => message,
            Err(_) => return Ok(wire::encode_error(id, 1)), // FORMERR
        };
        if message.header.opcode() != 0 {
            return Ok(wire::encode_error(id, 4));
        }
        if message.questions.len() != 1
            || !message.answers.is_empty()
            || !message.authorities.is_empty()
        {
            return Ok(wire::encode_error(id, 1));
        }
        let question = &message.questions[0];
        let payload = self
            .config
            .max_udp_payload
            .min(message.udp_payload_size() as u16);
        let edns = message.has_edns().then_some(payload);
        let limit = if udp {
            usize::from(payload)
        } else {
            MAX_MESSAGE_SIZE
        };
        let edns_version = message
            .additionals
            .iter()
            .find(|record| record.record_type == RecordType::OPT)
            .map_or(0, |record| (record.ttl >> 16) as u8);
        if edns_version != 0 {
            return wire::encode_response(id, question, &[], 0, 16, edns, limit);
        }
        if question.class != CLASS_IN {
            return wire::encode_response(id, question, &[], 0, 5, edns, limit);
        }
        if question.record_type != RecordType::A && question.record_type != RecordType::AAAA {
            return wire::encode_response(id, question, &[], 0, 0, edns, limit);
        }
        let answer = self
            .resolver
            .query(&question.name, question.record_type)
            .await?;
        wire::encode_response(
            id,
            question,
            &answer.ips,
            answer.ttl,
            answer.response_code,
            edns,
            limit,
        )
    }

    pub async fn serve_udp(
        self: Arc<Self>,
        socket: UdpSocket,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let socket = Arc::new(socket);
        let mut buffer = vec![0; MAX_MESSAGE_SIZE];
        let mut workers = JoinSet::new();
        let outcome = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                Some(_) = workers.join_next(), if !workers.is_empty() => {},
                packet = socket.recv_from(&mut buffer) => {
                    let (size, peer) = match packet { Ok(packet) => packet, Err(error) => break Err(error.into()) };
                    // UDP has no backpressure: overload drops requests for client
                    // retry, keeping allocation/task counts bounded.
                    if workers.len() >= self.config.max_in_flight { continue; }
                    let bytes = buffer[..size].to_vec();
                    let service = self.clone();
                    let socket = socket.clone();
                    workers.spawn(async move {
                        if let Ok(response) = service.handle_udp_query(&bytes).await {
                            let _ = socket.send_to(&response, peer).await;
                        }
                    });
                }
            }
        };
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        outcome
    }

    pub async fn serve_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let mut workers = JoinSet::new();
        let outcome = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                Some(_) = workers.join_next(), if !workers.is_empty() => {},
                accepted = listener.accept(), if workers.len() < self.config.max_in_flight => {
                    let (stream, _) = match accepted { Ok(accepted) => accepted, Err(error) => break Err(error.into()) };
                    let service = self.clone();
                    workers.spawn(async move { let _ = service.serve_connection(stream).await; });
                }
            }
        };
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        outcome
    }

    /// Serve an existing stream (including a routed BoxStream). Frames can be
    /// pipelined; replies are processed in request order on each connection.
    pub async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
    ) -> Result<()> {
        loop {
            let bytes =
                match timeout(self.config.tcp_idle_timeout, read_tcp_message(&mut stream)).await {
                    Ok(Ok(Some(bytes))) => bytes,
                    Ok(Ok(None)) => return Ok(()),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(DnsError::Timeout),
                };
            // Like Go's handleIPQuery, network failures produce no synthetic
            // successful answer. The connection survives for subsequent frames.
            if let Ok(response) = self.handle_query(&bytes).await {
                timeout(
                    self.config.tcp_idle_timeout,
                    write_tcp_message(&mut stream, &response),
                )
                .await
                .map_err(|_| DnsError::Timeout)??;
            }
        }
    }
}
