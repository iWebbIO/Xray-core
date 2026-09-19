# Native XDRIVE transport

The native implementation is in `xray-core/src/transport/xdrive.rs` and
`xray-core/src/transport/xdrive/`. It follows the repository's Go
`transport/internet/xdrive/{xdrive,params,wal,conn,storage,local}.go` sources.
XDRIVE transports a byte stream through objects in shared storage. It is not a
TCP framing protocol and does not add payload encryption of its own.

## Implemented

- Storage-neutral, ordered, bidirectional WAL sessions with bounded concurrent
  uploads, fetches, and best-effort deletes.
- Session announcements, listener deduplication, stale-announcement cleanup, and
  idle-session garbage collection that preserves active sessions.
- The `local` backend with atomic temporary-file publication, idempotent
  recursive deletes, and immediate-child directory listings.
- An HTTP-template backend with explicit static, Basic, and OAuth authentication,
  token refresh, bounded streaming bodies, retries, and flattened listings.
- A Tokio `AsyncRead + AsyncWrite` connection with backpressure, independent
  write shutdown, read/write deadlines, cancellation, and sticky peer/storage
  failures.
- Configuration conversion from the generated XDRIVE protobuf, with Go's zero
  defaults and upper bounds. Configuration does not derive `Debug`, avoiding
  accidental credential logging.

`Config::storage`, `Config::dial`, and `Config::listen` construct a local
transport. Custom backends can implement the object-safe `Storage` trait and
use `dial`, `dial_with_cancel`, or `Listener::new`. `Storage::list` returns
immediate child names and optional inline bytes: `Some(Vec::new())` means an
empty inline object; `None` requires a separate fetch. A missing fetch must
return `io::ErrorKind::NotFound` so the reader can retry eventual visibility
without delivering a batch twice. A successful `put` must publish a whole
object atomically.

## Wire compatibility

An announcement is an empty object named
`sessions/<UnixNano>-<session>`. New session identifiers contain 16 random bytes
encoded as 32 lowercase hexadecimal characters. Timestamps use nonnegative
nanoseconds within the Go `int64` range.

The client writes to `streams/<session>/c2s` and reads from
`streams/<session>/s2c`; the server reverses these directions. Each direction
contains objects named `<sequence>.seg`, `<sequence>.end`, or
`<sequence>.err`. Sequence numbers are decimal with at least nine digits and
remain within signed `int64` range. Segment bodies contain unmodified stream
bytes; end and error markers are empty. The writer publishes the end marker
only after all preceding uploads finish. Failed segment uploads attempt to
publish an error marker at the same sequence number.

| Setting | Default | Bound or behavior |
| --- | --- | --- |
| Segment size | 512 KiB | Maximum 16 MiB |
| Flush interval | 20 ms | Growing small buffer held for up to eight ticks |
| Minimum poll | 50 ms | Writes wake polling while respecting this minimum |
| Maximum poll | 500 ms | Raised to minimum poll if configured lower |
| Eager window | 2 seconds | Poll at minimum interval after activity |
| Hole timeout | 30 seconds | Applies only when later objects reveal a gap |
| Session TTL | 5 minutes | GC runs every half TTL; idle age starts on first sight |
| Concurrent operations | 8 | Maximum 64 |

Idle streams have no implicit read timeout. A listed segment that is not yet
available through `get` is retried. Out-of-order uploads are delivered in
sequence, and empty segments advance the sequence without producing a false
EOF. Logical path flattening helpers preserve Google Drive's `/` to `~`
mapping for future backend integration.

## Lifecycle and intentional edge differences

Call `AsyncWriteExt::shutdown` to flush the outgoing direction and publish
its end marker while continuing to read. `Connection::close` consumes the
connection, attempts the same flush, then cancels remaining work. Dropping a
connection aborts its tasks and does not promise a graceful flush. Listener
cancellation propagates to accepted sessions; session claims are released even
if cancellation interrupts announcement deletion.

Error markers take precedence if a backend lists both a segment and an error
at the same sequence. This prevents an ambiguously successful upload from
hiding the peer's reported failure. A stale duplicate announcement cannot
delete an active session's storage.

Like the Go local backend, `..` components are normalized and clamped inside
the configured root. Rust additionally rejects platform escape syntax, reserved
device/temp names, symlinks, and Windows reparse points below that root. The
owner must control the storage directory; path checks are not a defense against
a hostile process concurrently replacing filesystem entries. Non-UTF-8
unrelated filenames are ignored when listing protocol objects.

## HTTP-template backend

`template::TemplateStorage::new(&Config)` builds the HTTP(S) provider. Templates
use the Go fields `put`, `get`, `delete`, `list`, `auth`, `retry`, `flatten`, and
`concurrency`. All four operation URLs and a list `namesRegex` capture group
are required. Missing operation methods default to GET, including put/delete,
just as in Go. A put sends raw bytes unless `put.body` is set; then `{data}` is
standard base64. Body fields on get/delete/list are ignored by Go and Rust.
Folder, name/prefix, explicit secrets, and OAuth token substitutions are raw,
without automatic URL or form escaping. Unknown placeholders remain intact.

Auth modes are none, static header substitution, Basic, and OAuth2. OAuth token
requests use only the explicitly configured token URL and raw form fields;
dotted JSON object paths select token and expiry. Successful tokens are cached
with Go's 60-second expiry margin. A 401 invalidates the rejected cached token.
No ambient environment proxy or cookie credentials are acquired. HTTP(S) URL
userinfo, where supplied, is explicit configuration. HTTPS uses the reqwest
Rustls trust store; `with_client` accepts a deliberately configured HTTP client.

Requests use a 60-second timeout, ten-redirect limit, 32 concurrent operations
by default (capped at 256), and eight attempts. Retry delays start at 200 ms,
double up to eight seconds, and use half-to-full jitter. Configured status codes
and nonempty dotted `retry.rateReason` values on 403 trigger retries. Network
failures are retried; invalid requests and oversized responses fail immediately.
Get 404 maps to NotFound; delete 404 succeeds; list 404 yields an empty listing.
Operation headers override authentication headers. Errors omit response bodies
and credential-bearing request URLs.

The provider streams and checks bodies rather than accepting unbounded reads.
Default caps are 16 MiB per operation response, 1 MiB per token response, and
32 MiB per request body. `TemplateLimits` and `with_limits` let callers select
explicit caps. Oversized Content-Length, chunked, and decoded gzip bodies return
errors; no clipped content is reported as successful storage. Config templates
are capped at 1 MiB, and outgoing segment data remains capped at 16 MiB.
The concurrency permit remains held until the whole body is consumed.
Cancelling/dropping an operation releases its token lock, HTTP response, and
permit. Closing the backend cancels pending requests and retry/semaphore waits.

Intentional bounded differences from Go are explicit body/template limits and
deterministic substitution order (Go's map iteration can vary recursive
substitution order). Rust's regex engine supports the intended capture-based
listing templates but is not a byte-for-byte copy of Go's regexp dialect.
Custom Xray HTTP/TLS/REALITY fronting is still outside this provider.

## Validation

The module includes unit/regression coverage for defaults and protobuf fields,
wire naming and timestamps, bidirectional sessions and half-close, concurrent
upload ordering, flush coalescing, missing segments versus idle streams,
eventual visibility, inline/empty objects, error markers, clearable deadlines,
listener cancellation/deduplication/GC, and the local filesystem backend.
Fourteen local scripted HTTP tests cover template authentication and refresh,
request/list semantics, retries, error mapping, bounded content-length/chunked/
gzip/token/request bodies, cancellation, permit/token-lock cleanup, redirects,
and invalid inputs. Those tests are written and pending centralized Rust
validation at this handoff.

`go test ./rust/xray-core/src/transport/xdrive/interop` passed on September 19,
2026. This compiles the independent Go fixture; it is not the interoperability
run itself. Rust compilation and tests are delegated to the root agent's
centralized validation queue. The first shared run compiled the local backend
and exposed two Windows-specific regressions: SystemTime fixture precision and
an expired deadline racing Tokio's rounded timer tick. Both are fixed, with
full-nanosecond parsing and immediate-deadline regression coverage. A rebuilt
run, including the newly wired template provider, remains pending at this
handoff.

The ignored test
`pinned_go_xdrive_local_interoperability_in_both_directions` exercises both
Rust-client/Go-server and Go-client/Rust-server operation. It exchanges a
131,071-byte payload using unequal peer segment sizes and checks clean EOF.
Build `xdrive/interop/main.go` as a separate executable and set
`XRAY_XDRIVE_GO_FIXTURE` to its absolute path before running that ignored test.
The Go process is only a test peer; the Rust transport never delegates runtime
work to Go.

## Remaining scope

The Google Drive-specific credential adapter and Drive REST storage remain
unimplemented. Selecting `Google Drive` returns `Unsupported`; there is no
silent local-storage fallback. Generic OAuth2 is implemented for explicit HTTP
templates. Xray-specific HTTP/TLS/REALITY fronting and shared runtime/configuration
wiring are handled separately by the root agent. These limitations must not be
represented as complete Go XDRIVE parity.
