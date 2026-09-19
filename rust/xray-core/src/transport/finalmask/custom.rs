//! Custom TCP/UDP headers: expression evaluation, variable capture, per-peer
//! state, and explicit TCP handshakes. Sources: `header/custom/*.go`.
//!
//! Configuration adapters must select each item's source with Go's precedence:
//! nonzero random length, nonempty packet, variable, expression, then empty.
//! The enum below makes that selection explicit and prevents ambiguous items.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use rand::{CryptoRng, Rng};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{SampleRange, UDP_SIZE, invalid, random_bytes};

pub const MAX_HEADER_SIZE: usize = 65_536;
pub const MAX_EXPRESSION_DEPTH: usize = 64;
pub const STATE_TTL: Duration = Duration::from_secs(5);
pub const MAX_STATE_PEERS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Op {
    Concat,
    Slice,
    Xor16,
    Xor32,
    Be16,
    Be32,
    Le16,
    Le32,
    Le64,
    Pad,
    Truncate,
    Add,
    Sub,
    And,
    Or,
    Shl,
    Shr,
}

impl Op {
    pub fn parse(name: &str) -> io::Result<Self> {
        Ok(match name {
            "concat" => Self::Concat,
            "slice" => Self::Slice,
            "xor16" => Self::Xor16,
            "xor32" => Self::Xor32,
            "be16" => Self::Be16,
            "be32" => Self::Be32,
            "le16" => Self::Le16,
            "le32" => Self::Le32,
            "le64" => Self::Le64,
            "pad" => Self::Pad,
            "truncate" => Self::Truncate,
            "add" => Self::Add,
            "sub" => Self::Sub,
            "and" => Self::And,
            "or" => Self::Or,
            "shl" => Self::Shl,
            "shr" => Self::Shr,
            _ => {
                return Err(invalid(format!(
                    "unsupported custom-header expression: {name}"
                )));
            }
        })
    }
}

#[derive(Clone, Debug)]
pub enum Expr {
    Bytes(Vec<u8>),
    U64(u64),
    Variable(String),
    Metadata(String),
    Call(Op, Vec<Expr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Bytes(Vec<u8>),
    U64(u64),
}

impl Value {
    pub fn into_bytes(self) -> io::Result<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(invalid("expression value is not bytes")),
        }
    }
    pub fn as_u64(&self) -> io::Result<u64> {
        match self {
            Self::U64(value) => Ok(*value),
            _ => Err(invalid("expression value is not u64")),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Context {
    pub variables: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, Value>,
}

impl Context {
    pub fn with_addresses(local: SocketAddr, remote: SocketAddr) -> Self {
        let mut ctx = Self::default();
        ctx.load_address("local", "dst", local);
        ctx.load_address("remote", "src", remote);
        ctx
    }

    fn load_address(&mut self, prefix: &str, alias: &str, addr: SocketAddr) {
        let port = Value::U64(u64::from(addr.port()));
        self.metadata.insert(format!("{prefix}_port"), port.clone());
        self.metadata.insert(format!("{alias}_port_u16"), port);
        let ipv4 = match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(ip) => ip.to_ipv4_mapped(),
        };
        if let Some(ip) = ipv4 {
            let value = Value::U64(u64::from(u32::from_be_bytes(ip.octets())));
            self.metadata
                .insert(format!("{prefix}_ip4_u32"), value.clone());
            self.metadata.insert(format!("{alias}_ip4_u32"), value);
        }
    }

    fn sizes(&self) -> HashMap<String, usize> {
        self.variables
            .iter()
            .map(|(name, bytes)| (name.clone(), bytes.len()))
            .collect()
    }
}

fn bounded_size(n: u64) -> io::Result<usize> {
    let size = usize::try_from(n).map_err(|_| invalid("custom-header size overflows usize"))?;
    if size > MAX_HEADER_SIZE {
        return Err(invalid("custom header exceeds size limit"));
    }
    Ok(size)
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_HEADER_SIZE.saturating_sub(out.len()) {
        return Err(invalid("custom header exceeds size limit"));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn arity(args: &[Expr], count: usize) -> io::Result<()> {
    if args.len() != count {
        return Err(invalid(format!("expression expects {count} arguments")));
    }
    Ok(())
}

pub fn evaluate(expr: &Expr, ctx: &Context) -> io::Result<Value> {
    eval(expr, ctx, 0)
}

fn eval(expr: &Expr, ctx: &Context, depth: usize) -> io::Result<Value> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(invalid("expression nesting exceeds limit"));
    }
    let (op, args) = match expr {
        Expr::Bytes(bytes) => {
            bounded_size(bytes.len() as u64)?;
            return Ok(Value::Bytes(bytes.clone()));
        }
        Expr::U64(value) => return Ok(Value::U64(*value)),
        Expr::Variable(name) => {
            return ctx
                .variables
                .get(name)
                .cloned()
                .map(Value::Bytes)
                .ok_or_else(|| invalid(format!("unknown variable: {name}")));
        }
        Expr::Metadata(name) => {
            return ctx
                .metadata
                .get(name)
                .cloned()
                .ok_or_else(|| invalid(format!("unknown metadata: {name}")));
        }
        Expr::Call(op, args) => (*op, args),
    };
    let value = |i: usize| eval(&args[i], ctx, depth + 1);
    let bytes = |i: usize| value(i)?.into_bytes();
    let number = |i: usize| value(i)?.as_u64();
    let result = match op {
        Op::Concat => {
            let mut out = Vec::new();
            for arg in args {
                append(&mut out, &eval(arg, ctx, depth + 1)?.into_bytes()?)?;
            }
            Value::Bytes(out)
        }
        Op::Slice => {
            arity(args, 3)?;
            let source = bytes(0)?;
            let offset = number(1)?;
            let length = number(2)?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid("slice index overflow"))?;
            if end > source.len() as u64 {
                return Err(invalid("slice out of bounds"));
            }
            Value::Bytes(source[offset as usize..end as usize].to_vec())
        }
        Op::Be16 | Op::Be32 | Op::Le16 | Op::Le32 | Op::Le64 => {
            arity(args, 1)?;
            let n = number(0)?;
            let out = match op {
                Op::Be16 | Op::Le16 => {
                    let n = u16::try_from(n).map_err(|_| invalid("16-bit packing overflow"))?;
                    if op == Op::Be16 {
                        n.to_be_bytes().to_vec()
                    } else {
                        n.to_le_bytes().to_vec()
                    }
                }
                Op::Be32 | Op::Le32 => {
                    let n = u32::try_from(n).map_err(|_| invalid("32-bit packing overflow"))?;
                    if op == Op::Be32 {
                        n.to_be_bytes().to_vec()
                    } else {
                        n.to_le_bytes().to_vec()
                    }
                }
                Op::Le64 => n.to_le_bytes().to_vec(),
                _ => unreachable!(),
            };
            Value::Bytes(out)
        }
        Op::Pad => {
            arity(args, 3)?;
            let mut out = bytes(0)?;
            let target = bounded_size(number(1)?)?;
            let fill = bytes(2)?;
            if fill.is_empty() {
                return Err(invalid("pad fill must not be empty"));
            }
            if target < out.len() {
                return Err(invalid("pad target shorter than source"));
            }
            while out.len() < target {
                let n = (target - out.len()).min(fill.len());
                out.extend_from_slice(&fill[..n]);
            }
            Value::Bytes(out)
        }
        Op::Truncate => {
            arity(args, 2)?;
            let mut out = bytes(0)?;
            let length = bounded_size(number(1)?)?;
            if length > out.len() {
                return Err(invalid("truncate out of bounds"));
            }
            out.truncate(length);
            Value::Bytes(out)
        }
        Op::Xor16 | Op::Xor32 | Op::Add | Op::Sub | Op::And | Op::Or | Op::Shl | Op::Shr => {
            arity(args, 2)?;
            let a = number(0)?;
            let b = number(1)?;
            let n = match op {
                Op::Xor16 | Op::Xor32 => {
                    let mask = if op == Op::Xor16 { 0xffff } else { 0xffff_ffff };
                    if a > mask || b > mask {
                        return Err(invalid("xor width overflow"));
                    }
                    a ^ b
                }
                Op::Add => a.checked_add(b).ok_or_else(|| invalid("add overflow"))?,
                Op::Sub => a.checked_sub(b).ok_or_else(|| invalid("sub underflow"))?,
                Op::And => a & b,
                Op::Or => a | b,
                Op::Shl | Op::Shr => {
                    if b >= 64 {
                        return Err(invalid("shift out of range"));
                    }
                    if op == Op::Shl {
                        if a > u64::MAX >> b {
                            return Err(invalid("left shift overflow"));
                        }
                        a << b
                    } else {
                        a >> b
                    }
                }
                _ => unreachable!(),
            };
            Value::U64(n)
        }
    };
    Ok(result)
}

fn measure_expr(expr: &Expr, sizes: &HashMap<String, usize>, depth: usize) -> io::Result<usize> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(invalid("expression nesting exceeds limit"));
    }
    let n = match expr {
        Expr::Bytes(bytes) => bytes.len(),
        Expr::Variable(name) => *sizes
            .get(name)
            .ok_or_else(|| invalid(format!("unknown variable: {name}")))?,
        Expr::U64(_) | Expr::Metadata(_) => {
            return Err(invalid("numeric expression has no byte width"));
        }
        Expr::Call(op, args) => match op {
            Op::Concat => {
                let mut total: usize = 0;
                for arg in args {
                    total = total
                        .checked_add(measure_expr(arg, sizes, depth + 1)?)
                        .ok_or_else(|| invalid("header size overflow"))?;
                }
                total
            }
            Op::Be16 | Op::Le16 => {
                arity(args, 1)?;
                2
            }
            Op::Be32 | Op::Le32 => {
                arity(args, 1)?;
                4
            }
            Op::Le64 => {
                arity(args, 1)?;
                8
            }
            Op::Slice | Op::Pad | Op::Truncate => {
                let (count, index) = match op {
                    Op::Slice => (3, 2),
                    Op::Pad => (3, 1),
                    _ => (2, 1),
                };
                arity(args, count)?;
                match &args[index] {
                    Expr::U64(n) => bounded_size(*n)?,
                    _ => {
                        return Err(invalid(
                            "measured slice/pad/truncate length must be a literal u64",
                        ));
                    }
                }
            }
            _ => return Err(invalid("expression does not produce bytes")),
        },
    };
    bounded_size(n as u64)
}

#[derive(Clone, Debug)]
pub enum Source {
    Empty,
    Random { length: usize, min: u8, max: u8 },
    Packet(Vec<u8>),
    Variable(String),
    Expression(Expr),
}

#[derive(Clone, Debug)]
pub struct Item {
    pub source: Source,
    pub save: Option<String>,
    /// TCP only: delay before this item; non-delayed adjacent items are merged.
    pub delay_ms: SampleRange,
}

impl Item {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            save: None,
            delay_ms: SampleRange::fixed(0),
        }
    }

    fn measure(&self, sizes: &mut HashMap<String, usize>) -> io::Result<usize> {
        let size = match &self.source {
            Source::Empty => 0,
            Source::Random { length, .. } => *length,
            Source::Packet(bytes) => bytes.len(),
            Source::Variable(name) => *sizes
                .get(name)
                .ok_or_else(|| invalid(format!("unknown variable: {name}")))?,
            Source::Expression(expr) => measure_expr(expr, sizes, 0)?,
        };
        bounded_size(size as u64)?;
        if let Some(name) = &self.save {
            sizes.insert(name.clone(), size);
        }
        Ok(size)
    }

    fn emit<R: Rng + CryptoRng + ?Sized>(
        &self,
        ctx: &mut Context,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        let bytes = match &self.source {
            Source::Empty => Vec::new(),
            Source::Random { length, min, max } => {
                bounded_size(*length as u64)?;
                let mut bytes = vec![0; *length];
                random_bytes(&mut bytes, *min, *max, rng);
                bytes
            }
            Source::Packet(bytes) => bytes.clone(),
            Source::Variable(name) => ctx
                .variables
                .get(name)
                .cloned()
                .ok_or_else(|| invalid(format!("unknown variable: {name}")))?,
            Source::Expression(expr) => evaluate(expr, ctx)?.into_bytes()?,
        };
        bounded_size(bytes.len() as u64)?;
        if let Some(name) = &self.save {
            ctx.variables.insert(name.clone(), bytes.clone());
        }
        Ok(bytes)
    }

    fn capture(&self, bytes: &[u8], ctx: &mut Context) -> io::Result<()> {
        let matches = match &self.source {
            Source::Empty => bytes.is_empty(),
            // Receive-side random fields are wildcards, not range validators.
            Source::Random { .. } => true,
            Source::Packet(packet) => bytes == packet,
            Source::Variable(name) => ctx.variables.get(name).is_some_and(|value| value == bytes),
            Source::Expression(expr) => evaluate(expr, ctx)?.into_bytes()? == bytes,
        };
        if !matches {
            return Err(invalid("custom-header mismatch"));
        }
        if let Some(name) = &self.save {
            ctx.variables.insert(name.clone(), bytes.to_vec());
        }
        Ok(())
    }
}

pub fn measure_items(items: &[Item], sizes: &mut HashMap<String, usize>) -> io::Result<usize> {
    let mut total: usize = 0;
    for item in items {
        total = total
            .checked_add(item.measure(sizes)?)
            .ok_or_else(|| invalid("header size overflow"))?;
        bounded_size(total as u64)?;
    }
    Ok(total)
}

/// Evaluate one complete header, committing saved variables only on success.
pub fn encode_items<R: Rng + CryptoRng + ?Sized>(
    items: &[Item],
    ctx: &mut Context,
    rng: &mut R,
) -> io::Result<Vec<u8>> {
    let mut next = ctx.clone();
    let mut out = Vec::new();
    for item in items {
        append(&mut out, &item.emit(&mut next, rng)?)?;
    }
    *ctx = next;
    Ok(out)
}

/// Match a header prefix and return its consumed byte count. The remaining bytes
/// are the application datagram. A failed match never changes saved variables.
pub fn match_items(items: &[Item], packet: &[u8], ctx: &mut Context) -> io::Result<usize> {
    let mut next = ctx.clone();
    let mut offset: usize = 0;
    for item in items {
        let length = item.measure(&mut next.sizes())?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("header size overflow"))?;
        bounded_size(end as u64)?;
        let bytes = packet
            .get(offset..end)
            .ok_or_else(|| invalid("truncated custom header"))?;
        item.capture(bytes, &mut next)?;
        offset = end;
    }
    *ctx = next;
    Ok(offset)
}

pub async fn read_sequence<R: AsyncRead + Unpin>(
    reader: &mut R,
    items: &[Item],
    ctx: &mut Context,
) -> io::Result<()> {
    let mut total = 0;
    for item in items {
        let length = item.measure(&mut ctx.sizes())?;
        total += length;
        bounded_size(total as u64)?;
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        item.capture(&bytes, ctx)?;
    }
    Ok(())
}

pub async fn write_sequence<W: AsyncWrite + Unpin, R: Rng + CryptoRng + ?Sized>(
    writer: &mut W,
    items: &[Item],
    ctx: &mut Context,
    rng: &mut R,
) -> io::Result<()> {
    let mut merged = Vec::new();
    let mut total = 0;
    for item in items {
        if item.delay_ms.upper() > 0 {
            if !merged.is_empty() {
                writer.write_all(&merged).await?;
                merged.clear();
            }
            tokio::time::sleep(Duration::from_millis(item.delay_ms.sample(rng))).await;
        }
        let bytes = item.emit(ctx, rng)?;
        total += bytes.len();
        bounded_size(total as u64)?;
        append(&mut merged, &bytes)?;
    }
    if !merged.is_empty() {
        writer.write_all(&merged).await?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct TcpConfig {
    pub clients: Vec<Vec<Item>>,
    pub servers: Vec<Vec<Item>>,
    pub errors: Vec<Vec<Item>>,
}

impl TcpConfig {
    /// Alternating client/server sequences, followed by any remaining server
    /// sequences. Invoke once before releasing application bytes to the stream.
    pub async fn client_handshake<
        S: AsyncRead + AsyncWrite + Unpin,
        R: Rng + CryptoRng + ?Sized,
    >(
        &self,
        stream: &mut S,
        ctx: &mut Context,
        rng: &mut R,
    ) -> io::Result<()> {
        let mut next_server = 0;
        for sequence in &self.clients {
            write_sequence(stream, sequence, ctx, rng).await?;
            if let Some(reply) = self.servers.get(next_server) {
                read_sequence(stream, reply, ctx).await?;
                next_server += 1;
            }
        }
        for sequence in &self.servers[next_server..] {
            read_sequence(stream, sequence, ctx).await?;
        }
        Ok(())
    }

    pub async fn server_handshake<
        S: AsyncRead + AsyncWrite + Unpin,
        R: Rng + CryptoRng + ?Sized,
    >(
        &self,
        stream: &mut S,
        ctx: &mut Context,
        rng: &mut R,
    ) -> io::Result<()> {
        let mut next_server = 0;
        for (i, sequence) in self.clients.iter().enumerate() {
            if let Err(error) = read_sequence(stream, sequence, ctx).await {
                if let Some(reply) = self.errors.get(i) {
                    let _ = write_sequence(stream, reply, ctx, rng).await;
                }
                return Err(error);
            }
            if let Some(reply) = self.servers.get(next_server) {
                write_sequence(stream, reply, ctx, rng).await?;
                next_server += 1;
            }
        }
        for sequence in &self.servers[next_server..] {
            write_sequence(stream, sequence, ctx, rng).await?;
        }
        Ok(())
    }
}

struct StateEntry {
    variables: HashMap<String, Vec<u8>>,
    expires: Instant,
}

/// Per-peer five-second state for regular (header-per-datagram) custom UDP.
/// Standalone UDP authentication/queueing is a separate protocol and is not
/// implemented by this type.
pub struct UdpHeaders {
    outgoing: Vec<Item>,
    incoming: Vec<Item>,
    write_size: usize,
    read_size: usize,
    state: HashMap<SocketAddr, StateEntry>,
}

impl UdpHeaders {
    pub fn new(client: Vec<Item>, server: Vec<Item>, is_server: bool) -> io::Result<Self> {
        let mut sizes = HashMap::new();
        let client_size = measure_items(&client, &mut sizes)?;
        let server_size = measure_items(&server, &mut sizes)?;
        if client_size > UDP_SIZE || server_size > UDP_SIZE {
            return Err(invalid("custom UDP header exceeds packet limit"));
        }
        let (outgoing, incoming, write_size, read_size) = if is_server {
            (server, client, server_size, client_size)
        } else {
            (client, server, client_size, server_size)
        };
        Ok(Self {
            outgoing,
            incoming,
            write_size,
            read_size,
            state: HashMap::new(),
        })
    }

    pub fn write_header_size(&self) -> usize {
        self.write_size
    }
    pub fn read_header_size(&self) -> usize {
        self.read_size
    }

    pub fn expire(&mut self, now: Instant) {
        self.state.retain(|_, entry| now <= entry.expires);
    }
    pub fn forget_peer(&mut self, peer: SocketAddr) {
        self.state.remove(&peer);
    }

    fn save(&mut self, peer: SocketAddr, ctx: Context, now: Instant) {
        if !self.state.contains_key(&peer)
            && self.state.len() >= MAX_STATE_PEERS
            && let Some(oldest) = self
                .state
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| *key)
        {
            self.state.remove(&oldest);
        }
        self.state.insert(
            peer,
            StateEntry {
                variables: ctx.variables,
                expires: now + STATE_TTL,
            },
        );
    }

    pub fn encode_to<R: Rng + CryptoRng + ?Sized>(
        &mut self,
        payload: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        now: Instant,
        rng: &mut R,
    ) -> io::Result<Vec<u8>> {
        if payload.len() > UDP_SIZE - self.write_size {
            return Err(invalid("custom UDP datagram exceeds packet limit"));
        }
        self.expire(now);
        let mut ctx = Context::with_addresses(local, peer);
        if let Some(entry) = self.state.get(&peer) {
            ctx.variables.clone_from(&entry.variables);
        }
        let mut packet = encode_items(&self.outgoing, &mut ctx, rng)?;
        if packet.len() != self.write_size {
            return Err(invalid("custom UDP header size changed"));
        }
        packet.extend_from_slice(payload);
        self.save(peer, ctx, now);
        Ok(packet)
    }

    pub fn decode_from<'a>(
        &mut self,
        packet: &'a [u8],
        peer: SocketAddr,
        now: Instant,
    ) -> io::Result<&'a [u8]> {
        if packet.len() > UDP_SIZE || packet.len() < self.read_size {
            return Err(invalid("invalid custom UDP packet size"));
        }
        self.expire(now);
        // Go's UDP receive matcher deliberately supplies saved vars, but no
        // endpoint metadata. TCP read_sequence does have address metadata.
        let mut ctx = Context::default();
        if let Some(entry) = self.state.get(&peer) {
            ctx.variables.clone_from(&entry.variables);
        }
        let read = match_items(&self.incoming, packet, &mut ctx)?;
        if read != self.read_size {
            return Err(invalid("custom UDP header size changed"));
        }
        self.save(peer, ctx, now);
        Ok(&packet[read..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn num(n: u64) -> Expr {
        Expr::U64(n)
    }
    fn raw(bytes: &[u8]) -> Expr {
        Expr::Bytes(bytes.to_vec())
    }
    fn call(op: Op, args: Vec<Expr>) -> Expr {
        Expr::Call(op, args)
    }
    fn bytes(expr: Expr) -> Vec<u8> {
        evaluate(&expr, &Context::default())
            .unwrap()
            .into_bytes()
            .unwrap()
    }
    fn packet(bytes: &[u8]) -> Item {
        Item::new(Source::Packet(bytes.to_vec()))
    }
    fn captured() -> Item {
        Item {
            source: Source::Random {
                length: 2,
                min: 42,
                max: 42,
            },
            save: Some("txid".into()),
            delay_ms: SampleRange::fixed(0),
        }
    }
    fn reused() -> Item {
        Item::new(Source::Variable("txid".into()))
    }

    #[test]
    fn source_golden_expression_vectors() {
        assert_eq!(
            bytes(call(Op::Slice, vec![raw(&[1, 2, 3, 4]), num(1), num(2)])),
            [2, 3]
        );
        assert_eq!(
            bytes(call(Op::Concat, vec![raw(b"ab"), raw(b"cd"), raw(b"ef")])),
            b"abcdef"
        );
        assert_eq!(
            bytes(call(
                Op::Be16,
                vec![call(Op::Xor16, vec![num(0x1234), num(0xffff)])]
            )),
            [0xed, 0xcb]
        );
        assert_eq!(
            bytes(call(
                Op::Concat,
                vec![
                    call(Op::Le16, vec![num(0x1234)]),
                    call(Op::Le32, vec![num(0xa1b2c3d4)]),
                    call(Op::Le64, vec![num(0x0102030405060708)])
                ]
            )),
            [0x34, 0x12, 0xd4, 0xc3, 0xb2, 0xa1, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(
            bytes(call(
                Op::Pad,
                vec![raw(&[0xaa, 0xbb]), num(5), raw(&[0xcc, 0xdd])]
            )),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xcc]
        );
        assert_eq!(
            bytes(call(Op::Truncate, vec![raw(&[1, 2, 3, 4]), num(2)])),
            [1, 2]
        );
    }

    #[test]
    fn arithmetic_types_bounds_and_expression_depth_are_checked() {
        let ctx = Context::default();
        for expr in [
            call(Op::Add, vec![num(u64::MAX), num(1)]),
            call(Op::Sub, vec![num(0), num(1)]),
            call(Op::Shl, vec![num(u64::MAX), num(1)]),
            call(Op::Shr, vec![num(1), num(64)]),
            call(Op::Xor16, vec![num(0x10000), num(0)]),
            call(Op::Be16, vec![raw(&[1])]),
            call(Op::Slice, vec![raw(b"a"), num(u64::MAX), num(1)]),
            call(Op::Pad, vec![raw(b"a"), num(1_000_000), raw(b"b")]),
        ] {
            assert!(evaluate(&expr, &ctx).is_err(), "{expr:?}");
        }
        assert_eq!(
            evaluate(&call(Op::Add, vec![num(2), num(3)]), &ctx).unwrap(),
            Value::U64(5)
        );
        let mut deep = raw(b"x");
        for _ in 0..66 {
            deep = call(Op::Concat, vec![deep]);
        }
        assert!(evaluate(&deep, &ctx).is_err());
    }

    #[test]
    fn metadata_matches_go_remote_src_local_dst_aliases() {
        let ctx = Context::with_addresses(
            "10.0.0.1:3478".parse().unwrap(),
            "203.0.113.9:54321".parse().unwrap(),
        );
        let expr = call(
            Op::Concat,
            vec![
                call(Op::Be16, vec![Expr::Metadata("src_port_u16".into())]),
                call(Op::Be32, vec![Expr::Metadata("src_ip4_u32".into())]),
                call(Op::Be16, vec![Expr::Metadata("dst_port_u16".into())]),
            ],
        );
        assert_eq!(
            evaluate(&expr, &ctx).unwrap().into_bytes().unwrap(),
            [0xd4, 0x31, 203, 0, 113, 9, 0x0d, 0x96]
        );
        assert!(evaluate(&Expr::Metadata("unknown".into()), &ctx).is_err());
    }

    #[test]
    fn captures_are_wildcards_and_failed_match_does_not_commit() {
        let items = vec![captured(), reused(), packet(b"end")];
        let mut ctx = Context::default();
        let got = encode_items(&items, &mut ctx, &mut StdRng::seed_from_u64(1)).unwrap();
        assert_eq!(got, [42, 42, 42, 42, b'e', b'n', b'd']);
        let mut receiver = Context::default();
        assert_eq!(
            match_items(&items, b"ababendpayload", &mut receiver).unwrap(),
            7
        );
        assert_eq!(receiver.variables["txid"], b"ab");
        assert!(match_items(&items, b"xxxxbad", &mut receiver).is_err());
        assert_eq!(receiver.variables["txid"], b"ab");
        for len in 0..7 {
            assert!(match_items(&items, &got[..len], &mut Context::default()).is_err());
        }
    }

    #[test]
    fn udp_prior_capture_reply_expiry_and_source_isolation() {
        let mut client = UdpHeaders::new(vec![captured()], vec![reused()], false).unwrap();
        let mut server = UdpHeaders::new(vec![captured()], vec![reused()], true).unwrap();
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let other = "127.0.0.1:3".parse().unwrap();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(2);
        let wire = client.encode_to(b"request", a, b, now, &mut rng).unwrap();
        assert_eq!(server.decode_from(&wire, a, now).unwrap(), b"request");
        assert!(server.encode_to(b"reply", b, other, now, &mut rng).is_err());
        let reply = server.encode_to(b"reply", b, a, now, &mut rng).unwrap();
        assert_eq!(client.decode_from(&reply, b, now).unwrap(), b"reply");
        assert!(
            client
                .decode_from(&reply, b, now + Duration::from_secs(6))
                .is_err()
        );
        assert!(
            client
                .encode_to(&vec![0; UDP_SIZE], a, b, now, &mut rng)
                .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_handshake_handles_short_reads_and_leaves_application_bytes() {
        let config = TcpConfig {
            clients: vec![vec![packet(b"cli"), captured()]],
            servers: vec![vec![packet(b"srv"), reused()], vec![packet(b"done")]],
            errors: vec![],
        };
        let (mut client, mut server) = tokio::io::duplex(2);
        let mut cc = Context::default();
        let mut sc = Context::default();
        let mut cr = StdRng::seed_from_u64(3);
        let mut sr = StdRng::seed_from_u64(4);
        let (a, b) = tokio::join!(
            config.client_handshake(&mut client, &mut cc, &mut cr),
            config.server_handshake(&mut server, &mut sc, &mut sr)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(cc.variables, sc.variables);
        let (sent, received) = tokio::join!(client.write_all(b"app"), async {
            let mut bytes = [0; 3];
            server.read_exact(&mut bytes).await.unwrap();
            bytes
        });
        sent.unwrap();
        assert_eq!(received, b"app".as_slice());
    }

    #[tokio::test]
    async fn tcp_error_sequence_is_sent_on_mismatch() {
        let config = TcpConfig {
            clients: vec![vec![packet(b"ok")]],
            servers: vec![],
            errors: vec![vec![packet(b"bad")]],
        };
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(b"no").await.unwrap();
        let mut ctx = Context::default();
        let mut rng = StdRng::seed_from_u64(5);
        assert!(
            config
                .server_handshake(&mut server, &mut ctx, &mut rng)
                .await
                .is_err()
        );
        let mut error = [0; 3];
        client.read_exact(&mut error).await.unwrap();
        assert_eq!(&error, b"bad");
    }
}
