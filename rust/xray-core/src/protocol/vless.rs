//! VLESS version 0 TCP headers, including the Vision flow addon.
//!
//! The wire layout follows `proxy/vless/encoding/encoding.go`: version, UUID,
//! addon length, the protobuf `Addons{string Flow = 1; bytes Seed = 2}`
//! message (`proxy/vless/encoding/addons.proto`), command, port, and address.
//! Reads consume exactly the header so a client may send application bytes
//! in the same packet as its request. VLESS account encryption is a separate
//! session layer in `vless_encryption`.
//!
//! Flow handling follows Go exactly:
//!
//! - the writer marshals the addons message only for the Vision flow; the
//!   client-only `-udp443` spelling is stripped to `xtls-rprx-vision` before
//!   the header is written (`proxy/vless/outbound/outbound.go`);
//! - the reader validates the request flow against the matched account's
//!   flow with Go's exact errors (`proxy/vless/inbound/inbound.go`): a
//!   Vision account that receives no flow addon is rejected with `account
//!   {uuid} is rejected since the client flow is empty. Note that the pure
//!   TLS proxy has certain TLS in TLS characters.`, a mismatched flow with
//!   `account {uuid} is not able to use the flow {flow}`, and any other
//!   request flow with `unknown request flow {flow}`;
//! - the server always answers with an empty addons message (the `Flow` echo
//!   in `inbound.go` is commented out), and the client, like Go's
//!   `DecodeHeaderAddons`, accepts any well-formed addons message without
//!   validating its flow — the verification switch is empty. The vestigial
//!   `Seed` field is decoded and carried, never rejected: nothing in
//!   `proxy/vless` reads `Addons.Seed`.
//!
//! ## Vision runtime contract (for the runtime wiring)
//!
//! Go wraps the connection body with the Vision reader/writer only after the
//! header exchange (`proxy/vless/inbound/inbound.go`,
//! `proxy/vless/outbound/outbound.go`):
//!
//! 1. Exchange the base headers over the raw (optionally `vless_encryption`
//!    wrapped) stream: `write_request` then read the response
//!    (`VlessStream`) on the client, `read_request` then `write_response` on
//!    the server.
//! 2. When the validated flow is `xtls-rprx-vision` — the client account's
//!    flow (either Vision spelling) or the server's `Accepted.flow` — wrap
//!    the stream body with `vless_vision::VisionStream::client(inner,
//!    account.id)` / `VisionStream::server(inner, accepted.id)`. The Vision
//!    frame codec seeds itself with the account UUID, exactly like Go's
//!    `proxy.NewTrafficState(user UUID bytes)`.
//! 3. On the client, when no early payload follows the request header
//!    within Go's 500 ms read window, call `queue_header_camo` to insert the
//!    empty-content long-padding camouflage frame before the first payload
//!    frame ("Insert padding with empty content to camouflage VLESS
//!    header").

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context, Result, bail, ensure};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{Reply, Request};
use crate::address::{Address, Destination};

const VERSION: u8 = 0;
const TCP_COMMAND: u8 = 1;

/// `vless.XRV` (`proxy/vless/vless.go`): the Vision flow, the only request
/// flow Go's inbound accepts beyond the empty flow.
pub const XRV_FLOW: &str = "xtls-rprx-vision";

/// The client-only UDP/443 spelling (`vless.XRV + "-udp443"`,
/// `proxy/vless/outbound/outbound.go`): allowed in outbound account configs
/// and stripped to [`XRV_FLOW`] before the request header is written.
pub const XRV_UDP443_FLOW: &str = "xtls-rprx-vision-udp443";

#[derive(Clone, Debug)]
pub struct Account {
    pub id: [u8; 16],
    pub email: String,
    /// Per-user flow: empty, or one of the two Vision spellings
    /// (`xtls-rprx-vision`, `xtls-rprx-vision-udp443`).
    pub flow: String,
}

/// One authenticated inbound request plus the validated flow addon and the
/// matched account's UUID (the Vision codec's per-user seed, like Go's
/// `proxy.NewTrafficState(userSentID)`).
pub struct Accepted {
    pub request: Request,
    /// The validated request flow: empty for plaintext accounts, otherwise
    /// exactly `xtls-rprx-vision`.
    pub flow: String,
    /// The UUID of the matched account; `vless_vision::VisionStream::server`
    /// seeds its frame codec with these bytes.
    pub id: [u8; 16],
}

/// The protobuf `Addons{string Flow = 1; bytes Seed = 2}` message
/// (`proxy/vless/encoding/addons.proto`), carried after the UUID in requests
/// and after the version byte in responses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Addons {
    pub flow: String,
    pub seed: Vec<u8>,
}

/// Authenticate and read one base VLESS TCP request. The success response must
/// be sent through `Request::reply` after the destination connection succeeds.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    accounts: &[Account],
) -> Result<Accepted> {
    let version = reader.read_u8().await.context("read VLESS version")?;
    ensure!(version == VERSION, "unsupported VLESS version {version}");

    let mut id = [0; 16];
    reader
        .read_exact(&mut id)
        .await
        .context("read VLESS UUID")?;
    let mut authenticated = None;
    for account in accounts {
        if bool::from(account.id.ct_eq(&id)) {
            authenticated = Some(account);
        }
    }
    let account = authenticated.context("invalid VLESS user")?;

    let addons = read_addons(reader)
        .await
        .context("decode VLESS request addons")?;
    let command = reader.read_u8().await.context("read VLESS command")?;
    ensure!(
        command == TCP_COMMAND,
        "unsupported VLESS command {command}; only TCP is implemented"
    );
    let destination = read_destination(reader)
        .await
        .context("read VLESS destination")?;

    // Flow validation mirrors the switch over `requestAddons.Flow` in
    // `proxy/vless/inbound/inbound.go` Process, which runs after the full
    // header decode. Only the TCP command reaches this point, so Go's
    // `isMuxAndNotXUDP` clause reduces to "always".
    match addons.flow.as_str() {
        "" => {
            // Go rejects the empty client flow only for accounts whose flow
            // is exactly XRV; the `-udp443` spelling does not match it.
            if account.flow == XRV_FLOW {
                bail!(
                    "account {} is rejected since the client flow is empty. \
                     Note that the pure TLS proxy has certain TLS in TLS characters.",
                    uuid_string(&account.id)
                );
            }
        }
        XRV_FLOW => {
            ensure!(
                account.flow == addons.flow,
                "account {} is not able to use the flow {}",
                uuid_string(&account.id),
                addons.flow
            );
        }
        // Any other flow on the wire — including the `-udp443` spelling,
        // which Go clients strip before encoding — is unknown to the server.
        other => bail!("unknown request flow {other}"),
    }

    Ok(Accepted {
        request: Request {
            destination,
            user: account.email.clone(),
            initial_payload: Vec::new(),
            reply: Reply::Vless,
        },
        flow: addons.flow,
        id: account.id,
    })
}

/// Write the base TCP request. Application data can be written immediately;
/// waiting for the response header before sending it can deadlock a peer.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    account: &Account,
    destination: &Destination,
) -> Result<()> {
    // Encode before touching the socket so invalid addresses send no partial
    // authentication header. The largest valid base header is 278 bytes; a
    // flow addon adds at most 255 more.
    //
    // `proxy/vless/outbound/outbound.go` normalizes the client-only
    // `-udp443` spelling away before encoding, and `EncodeHeaderAddons`
    // (`proxy/vless/encoding/addons.go`) marshals the protobuf message only
    // for the Vision flow; every other flow carries a zero-length addon.
    // The config layer admits only the three Go spellings; anything else
    // fails explicitly instead of silently downgrading to a flow-less
    // request.
    let wire_flow = match account.flow.as_str() {
        "" => None,
        XRV_FLOW => Some(XRV_FLOW),
        XRV_UDP443_FLOW => Some(XRV_FLOW),
        other => bail!(
            "VLESS flow {other:?} is not supported (Go accepts only \"\", \
             \"xtls-rprx-vision\" and \"xtls-rprx-vision-udp443\")"
        ),
    };
    let mut addons = Vec::new();
    if let Some(flow) = wire_flow {
        addons = encode_addons(&Addons {
            flow: flow.to_owned(),
            seed: Vec::new(),
        });
        ensure!(addons.len() <= 255, "VLESS flow addon exceeds 255 bytes");
    }
    let mut header = Vec::with_capacity(533);
    header.push(VERSION);
    header.extend_from_slice(&account.id);
    header.push(addons.len() as u8);
    header.extend_from_slice(&addons);
    header.push(TCP_COMMAND);
    header.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.address {
        Address::Ip(IpAddr::V4(ip)) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        Address::Domain(host) => {
            ensure!(
                !host.is_empty() && host.len() <= 255,
                "invalid VLESS domain length"
            );
            header.extend_from_slice(&[2, host.len() as u8]);
            header.extend_from_slice(host.as_bytes());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            header.push(3);
            header.extend_from_slice(&ip.octets());
        }
    }
    writer
        .write_all(&header)
        .await
        .context("write VLESS request")
}

pub async fn write_response<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    // Go's server always answers with an empty addons message: the `Flow:
    // requestAddons.Flow` echo in `inbound.go` is commented out, so
    // `EncodeHeaderAddons` writes a zero length for every account.
    writer
        .write_all(&[VERSION, 0])
        .await
        .context("write VLESS response")
}

/// Read the base TCP response header and return its addons. Like Go's
/// `DecodeResponseHeader` (`proxy/vless/encoding/encoding.go`), the version
/// must match and the addons must be well-formed protobuf; the flow inside
/// the addons is accepted without validation (Go's verification switch is
/// empty and its client never reads the response flow).
pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Addons> {
    let version = reader
        .read_u8()
        .await
        .context("read VLESS response version")?;
    ensure!(
        version == VERSION,
        "unexpected VLESS response version {version}"
    );
    read_addons(reader)
        .await
        .context("decode VLESS response addons")
}

/// Read the one-byte addon length and the `Addons` message it frames, per
/// `DecodeHeaderAddons` in `proxy/vless/encoding/addons.go`.
async fn read_addons<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Addons> {
    let length = reader.read_u8().await.context("read VLESS addon length")?;
    let mut bytes = vec![0u8; length as usize];
    reader
        .read_exact(&mut bytes)
        .await
        .context("read VLESS addons value")?;
    Ok(decode_addons(&bytes)?)
}

fn invalid_addons(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid VLESS addons protobuf: {reason}"),
    )
}

/// Decode one protobuf varint (a tag or a length); returns the value and the
/// number of bytes consumed.
fn read_varint(bytes: &[u8]) -> io::Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        if index >= 10 {
            return Err(invalid_addons("varint exceeds 10 bytes"));
        }
        let low = u64::from(byte & 0x7f);
        if shift >= 64 || (shift == 63 && low > 1) {
            return Err(invalid_addons("varint overflows 64 bits"));
        }
        value |= low << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
    }
    Err(invalid_addons("truncated varint"))
}

/// Skip one unknown field value by wire type. Go's tag-matching decoder
/// treats a known field with an unexpected wire type as unknown and skips
/// it, so this path covers those tags too. Groups (wire types 3/4) and the
/// reserved types 6/7 are rejected: `Addons` has no groups and no real sender
/// emits them.
fn skip_field(bytes: &[u8], position: &mut usize, wire: u8) -> io::Result<()> {
    match wire {
        0 => {
            let (_, consumed) = read_varint(&bytes[*position..])?;
            *position += consumed;
        }
        1 | 5 => {
            let size = if wire == 1 { 8 } else { 4 };
            if bytes.len() - *position < size {
                return Err(invalid_addons("field value runs past the message"));
            }
            *position += size;
        }
        2 => {
            let (length, consumed) = read_varint(&bytes[*position..])?;
            *position += consumed;
            if length > (bytes.len() - *position) as u64 {
                return Err(invalid_addons("field value runs past the message"));
            }
            *position += length as usize;
        }
        _ => return Err(invalid_addons("unsupported wire type")),
    }
    Ok(())
}

/// Decode the `Addons` message exactly like Go's `proto.Unmarshal`: field 1
/// (`Flow`) and field 2 (`Seed`) are length-delimited with the last value
/// winning, unknown fields are skipped per protobuf rules, and a malformed
/// message is an error. The vestigial `Seed` is carried, not rejected —
/// nothing in `proxy/vless` reads it.
fn decode_addons(bytes: &[u8]) -> io::Result<Addons> {
    let mut addons = Addons::default();
    let mut position = 0usize;
    while position < bytes.len() {
        let (tag, consumed) = read_varint(&bytes[position..])?;
        position += consumed;
        let field = tag >> 3;
        let wire = (tag & 0x7) as u8;
        if field == 0 {
            return Err(invalid_addons("field number 0 is reserved"));
        }
        match (field, wire) {
            (1, 2) | (2, 2) => {
                let (length, consumed) = read_varint(&bytes[position..])?;
                position += consumed;
                if length > (bytes.len() - position) as u64 {
                    return Err(invalid_addons(
                        "length-delimited field runs past the message",
                    ));
                }
                let end = position + length as usize;
                let value = &bytes[position..end];
                position = end;
                if field == 1 {
                    addons.flow = String::from_utf8(value.to_vec())
                        .map_err(|_| invalid_addons("Flow is not valid UTF-8"))?;
                } else {
                    addons.seed = value.to_vec();
                }
            }
            _ => skip_field(bytes, &mut position, wire)?,
        }
    }
    Ok(addons)
}

/// Encode the `Addons` message exactly like Go's `proto.Marshal`: field 1
/// (`Flow`) then field 2 (`Seed`), proto3 omitting empty values. Go's writers
/// only ever set `Flow`.
fn encode_addons(addons: &Addons) -> Vec<u8> {
    let mut out = Vec::new();
    if !addons.flow.is_empty() {
        out.push(0x0A);
        append_varint(&mut out, addons.flow.len() as u64);
        out.extend_from_slice(addons.flow.as_bytes());
    }
    if !addons.seed.is_empty() {
        out.push(0x12);
        append_varint(&mut out, addons.seed.len() as u64);
        out.extend_from_slice(&addons.seed);
    }
    out
}

fn append_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Format the account bytes like Go's `uuid.UUID.String()` for the flow
/// validation errors (8-4-4-4-12 lowercase hex).
fn uuid_string(id: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (index, byte) in id.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn read_destination<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Destination> {
    let port = reader.read_u16().await?;
    let address = match reader.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            Address::Ip(Ipv4Addr::from(bytes).into())
        }
        2 => {
            let length = reader.read_u8().await? as usize;
            ensure!(length != 0, "empty VLESS domain");
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).await?;
            let host = std::str::from_utf8(&bytes).context("invalid VLESS domain encoding")?;
            // Go's address parser accepts IP literals encoded as domains,
            // including bracketed IPv6, then checks the ASCII domain alphabet.
            let ip_host = host
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(host);
            if let Ok(ip) = ip_host.parse::<IpAddr>() {
                Address::Ip(ip)
            } else {
                ensure!(
                    host.bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
                    "invalid VLESS domain name"
                );
                Address::Domain(host.to_owned())
            }
        }
        3 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            Address::Ip(Ipv6Addr::from(bytes).into())
        }
        family => bail!("unsupported VLESS address family {family}"),
    };
    Ok(Destination { address, port })
}

/// A VLESS outbound stream that removes the response header — the version
/// byte, the addon length byte, and the addons message — on its first read,
/// then passes bytes through. Writes pass through immediately, including
/// before a response is available.
pub struct VlessStream<S> {
    inner: S,
    /// Fixed response prefix: version byte, addon length byte.
    header: [u8; 2],
    header_read: usize,
    /// The addon region, sized once the length byte arrives.
    addons: Vec<u8>,
    addons_read: usize,
    /// Set once the version check passed and the addons decoded; afterwards
    /// reads pass straight through to the inner stream.
    header_done: bool,
    failure: Option<(io::ErrorKind, &'static str)>,
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 2],
            header_read: 0,
            addons: Vec::new(),
            addons_read: 0,
            header_done: false,
            failure: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Record the first failure; every later read repeats it (Go's client
    /// fails the response decode once and the connection is torn down).
    fn fail(&mut self, kind: io::ErrorKind, message: &'static str) -> io::Error {
        self.failure = Some((kind, message));
        io::Error::new(kind, message)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some((kind, message)) = this.failure {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        while !this.header_done {
            if this.header_read < 2 {
                let mut prefix = ReadBuf::new(&mut this.header[this.header_read..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut prefix) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let count = prefix.filled().len();
                        if count == 0 {
                            return Poll::Ready(Err(this.fail(
                                io::ErrorKind::UnexpectedEof,
                                "truncated VLESS response header",
                            )));
                        }
                        this.header_read += count;
                        if this.header[0] != VERSION {
                            return Poll::Ready(Err(this.fail(
                                io::ErrorKind::InvalidData,
                                "unexpected VLESS response version",
                            )));
                        }
                        if this.header_read == 2 {
                            this.addons = vec![0; this.header[1] as usize];
                        }
                    }
                }
            } else {
                let mut region = ReadBuf::new(&mut this.addons[this.addons_read..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut region) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let count = region.filled().len();
                        if count == 0 {
                            return Poll::Ready(Err(this.fail(
                                io::ErrorKind::UnexpectedEof,
                                "truncated VLESS response addons",
                            )));
                        }
                        this.addons_read += count;
                    }
                }
            }
            if this.header_read == 2 && this.addons_read == this.addons.len() {
                // Go `DecodeHeaderAddons`: unmarshal the addons, then run the
                // (empty) verification switch — any well-formed message is
                // accepted and its flow ignored, exactly like the request
                // side.
                if decode_addons(&this.addons).is_err() {
                    return Poll::Ready(Err(this.fail(
                        io::ErrorKind::InvalidData,
                        "invalid VLESS response addons protobuf",
                    )));
                }
                this.header_done = true;
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const ID_STRING: &str = "00112233-4455-6677-8899-aabbccddeeff";

    fn account() -> Account {
        Account {
            id: ID,
            email: "test@example.com".to_owned(),
            flow: String::new(),
        }
    }

    // Fixed version, UUID, no addons, TCP command and port 443, as emitted by
    // Go EncodeRequestHeader; address suffixes use VLESS's family bytes 1/2/3.
    fn request_fixture(address: &[u8]) -> Vec<u8> {
        let mut wire = vec![
            0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0, 1, 0x01, 0xbb,
        ];
        wire.extend_from_slice(address);
        wire
    }

    /// A request fixture whose addons region is exactly `addons`.
    fn request_with_addons(addons: &[u8]) -> Vec<u8> {
        let mut wire = vec![0];
        wire.extend_from_slice(&ID);
        wire.push(addons.len() as u8);
        wire.extend_from_slice(addons);
        wire.push(1);
        wire.extend_from_slice(&[0x01, 0xbb]);
        wire.extend_from_slice(&[2, 11]);
        wire.extend_from_slice(b"example.com");
        wire
    }

    /// The addons message Go's proto.Marshal emits for one flow string.
    fn flow_addon(flow: &str) -> Vec<u8> {
        let mut addons = vec![0x0A, flow.len() as u8];
        addons.extend_from_slice(flow.as_bytes());
        addons
    }

    #[tokio::test]
    async fn go_wire_fixtures_and_all_truncations() {
        let cases = [
            ("127.0.0.1", vec![1, 127, 0, 0, 1]),
            (
                "www.example.com",
                [vec![2, 15], b"www.example.com".to_vec()].concat(),
            ),
            ("::1", [vec![3], vec![0; 15], vec![1]].concat()),
        ];
        for (host, address) in cases {
            let fixture = request_fixture(&address);
            let destination = Destination::new(host, 443).unwrap();
            let mut encoded = Vec::new();
            write_request(&mut encoded, &account(), &destination)
                .await
                .unwrap();
            assert_eq!(encoded, fixture);

            let accepted = read_request(&mut fixture.as_slice(), &[account()])
                .await
                .unwrap();
            assert_eq!(accepted.request.destination, destination);
            assert_eq!(accepted.request.user, "test@example.com");
            assert!(matches!(accepted.request.reply, Reply::Vless));
            assert_eq!(accepted.flow, "");
            for length in 0..fixture.len() {
                assert!(
                    read_request(&mut &fixture[..length], &[account()])
                        .await
                        .is_err(),
                    "accepted truncated {host} request of length {length}"
                );
            }
        }
    }

    #[tokio::test]
    async fn vision_flow_addons_round_trip_both_spellings() {
        // Exactly Go's proto.Marshal(&Addons{Flow: "xtls-rprx-vision"}):
        // field 1, length-delimited — 0x0A, 0x10, then the 16 flow bytes.
        let destination = Destination::new("example.com", 443).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(&ID);
        expected.push(2 + 16); // addon length: tag, length byte, 16-byte flow
        expected.extend_from_slice(&[0x0A, 16]);
        expected.extend_from_slice(b"xtls-rprx-vision");
        expected.push(1);
        expected.extend_from_slice(&[0x01, 0xbb]);
        expected.extend_from_slice(&[2, 11]);
        expected.extend_from_slice(b"example.com");

        let mut vision = account();
        vision.flow = "xtls-rprx-vision".into();
        let mut encoded = Vec::new();
        write_request(&mut encoded, &vision, &destination)
            .await
            .unwrap();
        assert_eq!(encoded, expected);
        let accepted = read_request(&mut encoded.as_slice(), &[vision.clone()])
            .await
            .unwrap();
        assert_eq!(accepted.flow, "xtls-rprx-vision");
        assert_eq!(accepted.id, ID);
        assert_eq!(accepted.request.destination, destination);

        // The `-udp443` spelling is a client-only option: the wire addon is
        // the bare Vision flow, which Go's outbound strips before encoding.
        let mut udp443 = account();
        udp443.flow = "xtls-rprx-vision-udp443".into();
        let mut encoded = Vec::new();
        write_request(&mut encoded, &udp443, &destination)
            .await
            .unwrap();
        assert_eq!(encoded, expected);

        // Flows Go never accepts fail explicitly; they are never silently
        // downgraded to a flow-less (zero-length) addon.
        let mut bogus = account();
        bogus.flow = "xtls-rprx-direct".into();
        assert!(
            write_request(&mut Vec::new(), &bogus, &destination)
                .await
                .is_err()
        );

        // Every truncation of the Vision request still fails.
        for length in 0..expected.len() {
            assert!(
                read_request(&mut &expected[..length], &[vision.clone()])
                    .await
                    .is_err(),
                "accepted truncated vision request of length {length}"
            );
        }
    }

    #[tokio::test]
    async fn request_flow_validation_follows_go_inbound() {
        // (account flow, request flow, expected error fragment) per the
        // switch over requestAddons.Flow in proxy/vless/inbound/inbound.go.
        let rejects = [
            (
                "xtls-rprx-vision",
                "",
                "rejected since the client flow is empty",
            ),
            (
                "",
                "xtls-rprx-vision",
                "is not able to use the flow xtls-rprx-vision",
            ),
            (
                "xtls-rprx-vision-udp443",
                "xtls-rprx-vision",
                "is not able to use the flow xtls-rprx-vision",
            ),
            (
                "",
                "xtls-rprx-vision-udp443",
                "unknown request flow xtls-rprx-vision-udp443",
            ),
            (
                "",
                "xtls-rprx-direct",
                "unknown request flow xtls-rprx-direct",
            ),
            (
                "xtls-rprx-vision",
                "xtls-rprx-direct",
                "unknown request flow xtls-rprx-direct",
            ),
        ];
        for (account_flow, request_flow, expected) in rejects {
            let wire = request_with_addons(&flow_addon(request_flow));
            let mut account = account();
            account.flow = account_flow.into();
            let error = read_request(&mut wire.as_slice(), &[account])
                .await
                .err()
                .unwrap();
            let text = format!("{error:#}");
            assert!(
                text.contains(expected),
                "account {account_flow:?} vs request {request_flow:?}: {text}"
            );
            // Go names the account by its UUID in the account-check errors;
            // the `default:` unknown-flow arm carries no account ID.
            if expected.starts_with("account") {
                assert!(text.contains(ID_STRING), "{text}");
            }
        }

        // Go quirk: the empty client flow is rejected only for accounts whose
        // flow is exactly xtls-rprx-vision — a `-udp443` account accepts it.
        let wire = request_with_addons(&[]);
        let mut udp443 = account();
        udp443.flow = "xtls-rprx-vision-udp443".into();
        let accepted = read_request(&mut wire.as_slice(), &[udp443]).await.unwrap();
        assert_eq!(accepted.flow, "");
    }

    #[tokio::test]
    async fn addons_protobuf_decode_follows_go_rules() {
        // Seed is decoded and carried but never rejected: Go's verification
        // switch is empty and nothing in proxy/vless reads Addons.Seed.
        let mut vision = account();
        vision.flow = "xtls-rprx-vision".into();
        let mut addons = flow_addon("xtls-rprx-vision");
        addons.extend_from_slice(&[0x12, 4]); // field 2 (Seed), length 4
        addons.extend_from_slice(b"seed");
        let accepted = read_request(&mut request_with_addons(&addons).as_slice(), &[vision])
            .await
            .unwrap();
        assert_eq!(accepted.flow, "xtls-rprx-vision");

        // Unknown fields are skipped per protobuf rules, including field 1
        // with a non-length wire type (tag 0x08) which Go's tag-matching
        // decoder also treats as unknown: 0x38 0x2A (field 7, varint),
        // 0x08 0x2A (field 1, varint), 0x7A 0x03 b"abc" (field 15, LEN).
        let unknown = [0x38, 0x2A, 0x08, 0x2A, 0x7A, 0x03, b'a', b'b', b'c'];
        let accepted = read_request(&mut request_with_addons(&unknown).as_slice(), &[account()])
            .await
            .unwrap();
        assert_eq!(accepted.flow, "");

        // Malformed messages are rejected: field 0, reserved wire types,
        // values running past the region, truncated varints, invalid UTF-8.
        for bad in [
            &[0x00][..],             // field number 0
            &[0x0F][..],             // wire type 7
            &[0x13][..],             // wire type 3 (group)
            &[0x0A][..],             // flow length missing
            &[0x0A, 0x05, b'a'][..], // flow runs past the region
            &[0x12, 0x02, 0x11][..], // seed runs past the region
            &[0x38][..],             // unknown varint missing its value
            &[0x0A, 0x01, 0xff][..], // flow not valid UTF-8
            &[0x15][..],             // fixed32 without its 4 bytes
        ] {
            assert!(decode_addons(bad).is_err(), "{bad:?}");
        }

        // The encoder emits proto.Marshal bytes: field 1 then field 2, with
        // proto3 omitting empty values.
        assert!(encode_addons(&Addons::default()).is_empty());
        assert_eq!(
            encode_addons(&Addons {
                flow: "xtls-rprx-vision".into(),
                seed: Vec::new()
            }),
            [vec![0x0A, 16], b"xtls-rprx-vision".to_vec()].concat()
        );
        assert_eq!(
            encode_addons(&Addons {
                flow: "x".into(),
                seed: b"s".to_vec()
            }),
            [0x0A, 0x01, b'x', 0x12, 0x01, b's']
        );
        let bytes = encode_addons(&Addons {
            flow: "f".into(),
            seed: b"sz".to_vec(),
        });
        assert_eq!(
            decode_addons(&bytes).unwrap(),
            Addons {
                flow: "f".into(),
                seed: b"sz".to_vec()
            }
        );
    }

    #[tokio::test]
    async fn rejects_bad_credentials_versions_addons_commands_and_addresses() {
        let fixture = request_fixture(&[1, 127, 0, 0, 1]);
        assert!(read_request(&mut fixture.as_slice(), &[]).await.is_err());
        for (offset, value, expected) in [
            (0, 1, "version"),
            (1, 1, "invalid VLESS user"),
            (17, 1, "addons"),
            (18, 2, "command 2"),
            (18, 3, "command 3"),
            (18, 4, "command 4"),
            (18, 255, "command 255"),
            (21, 4, "address family"),
        ] {
            let mut wire = fixture.clone();
            wire[offset] = value;
            let error = read_request(&mut wire.as_slice(), &[account()])
                .await
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        for address in [&[2, 0][..], &[2, 1, b'/'][..], &[2, 1, 0xff][..]] {
            assert!(
                read_request(&mut request_fixture(address).as_slice(), &[account()])
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn response_addons_decode_like_go_client() {
        // Go's server always answers with empty addons (the Flow echo in
        // inbound.go is commented out), and its client accepts any
        // well-formed addons message without validating the flow.
        let mut wire = vec![0, 3, 0x0A, 0x01, b'v'];
        wire.extend_from_slice(b"payload");
        let mut reader = wire.as_slice();
        let addons = read_response(&mut reader).await.unwrap();
        assert_eq!(
            addons,
            Addons {
                flow: "v".into(),
                seed: Vec::new()
            }
        );
        assert_eq!(reader, b"payload");

        for mut wire in [
            &[][..],
            &[0][..],
            &[1, 0][..],
            &[0, 1][..],             // addon value truncated
            &[0, 1, 0x00][..],       // field number 0
            &[0, 2, 0x0A, 0x05][..], // flow runs past the region
        ] {
            assert!(read_response(&mut wire).await.is_err(), "{wire:?}");
        }
    }

    #[tokio::test]
    async fn request_and_response_preserve_early_payload() {
        let mut wire = request_fixture(&[1, 127, 0, 0, 1]);
        wire.extend_from_slice(b"early application bytes");
        let mut reader = wire.as_slice();
        let accepted = read_request(&mut reader, &[account()]).await.unwrap();
        assert!(accepted.request.initial_payload.is_empty());
        assert_eq!(reader, b"early application bytes");

        let mut response = Vec::new();
        write_response(&mut response).await.unwrap();
        assert_eq!(response, [0, 0]);
        response.extend_from_slice(b"early reply bytes");
        let mut reader = response.as_slice();
        read_response(&mut reader).await.unwrap();
        assert_eq!(reader, b"early reply bytes");
        for mut wire in [&[][..], &[0][..], &[1, 0][..], &[0, 1][..]] {
            assert!(read_response(&mut wire).await.is_err());
        }
    }

    #[tokio::test]
    async fn lazy_stream_sends_payload_before_waiting_for_response() {
        tokio::time::timeout(Duration::from_secs(3), async {
            // One-byte capacity splits every header and exercises Pending in
            // the response parser. The server deliberately waits for payload.
            let (mut client, mut server) = tokio::io::duplex(1);
            let client_task = async {
                let destination = Destination::new("example.com", 443).unwrap();
                write_request(&mut client, &account(), &destination)
                    .await
                    .unwrap();
                let mut stream = VlessStream::new(client);
                stream.write_all(b"hello").await.unwrap();
                stream.flush().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"world");
            };
            let server_task = async {
                let accepted = read_request(&mut server, &[account()]).await.unwrap();
                assert_eq!(accepted.request.destination.to_string(), "example.com:443");
                let mut payload = [0; 5];
                server.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"hello");
                write_response(&mut server).await.unwrap();
                server.write_all(b"world").await.unwrap();
                server.shutdown().await.unwrap();
            };
            tokio::join!(client_task, server_task);
        })
        .await
        .expect("VLESS handshake blocked before sending client payload");
    }

    #[tokio::test]
    async fn lazy_stream_decodes_response_addons_across_partial_reads() {
        tokio::time::timeout(Duration::from_secs(3), async {
            // One-byte capacity splits the version, addon length, addon
            // bytes, and payload across separate polls.
            let (client, mut server) = tokio::io::duplex(1);
            let mut stream = VlessStream::new(client);
            let writer = async {
                server.write_all(&[0, 3, 0x0A, 0x01, b'v']).await.unwrap();
                server.write_all(b"payload").await.unwrap();
                server.shutdown().await.unwrap();
            };
            let reader = async {
                let mut payload = Vec::new();
                stream.read_to_end(&mut payload).await.unwrap();
                assert_eq!(payload, b"payload");
            };
            tokio::join!(writer, reader);
        })
        .await
        .expect("VLESS response with addons blocked the lazy stream");
    }

    #[tokio::test]
    async fn lazy_stream_rejects_invalid_or_truncated_headers_permanently() {
        for (wire, kind) in [
            (&[][..], io::ErrorKind::UnexpectedEof),
            (&[0][..], io::ErrorKind::UnexpectedEof),
            (&[0, 2, 0x0A][..], io::ErrorKind::UnexpectedEof),
            (&[1, 0, 42][..], io::ErrorKind::InvalidData),
            // 0x42 is field 8, length-delimited, without its length byte: a
            // complete one-byte addon region that fails the protobuf decode.
            (&[0, 1, 42][..], io::ErrorKind::InvalidData),
            (&[0, 1, 0x00][..], io::ErrorKind::InvalidData),
            (&[0, 2, 0x0A, 0x05][..], io::ErrorKind::InvalidData),
        ] {
            let mut stream = VlessStream::new(wire);
            let mut payload = [0; 1];
            for _ in 0..2 {
                assert_eq!(stream.read(&mut payload).await.unwrap_err().kind(), kind);
            }
        }
        let mut stream = VlessStream::new(&[0, 0, 42][..]);
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, [42]);
        assert!(stream.into_inner().is_empty());
        // Well-formed response addons decode like Go's client; the flow is
        // accepted, never validated.
        let mut stream = VlessStream::new(&[0, 3, 0x0A, 0x01, b'v', 42][..]);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, [42]);
        assert!(stream.into_inner().is_empty());
    }
}
