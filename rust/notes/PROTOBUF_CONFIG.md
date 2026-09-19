# Native protobuf configuration

`config::protobuf::from_bytes(&[u8]) -> anyhow::Result<Config>` decodes the
reference `xray.core.Config` with generated Prost bindings. It does not invoke
Go, start listeners, or open logs. As with `Config::from_json`, callers must run
the normal native validation/startup path afterward. Runtime limitations (for
example supported policy levels and security fingerprints) therefore apply to
both input formats.

Supported conversions include:

- SOCKS, HTTP, dokodemo-door, VLESS, VMess, Trojan, classic Shadowsocks, and
  single-user Shadowsocks 2022
  inbounds; corresponding proxy outbounds plus freedom and blackhole.
- TCP, WebSocket, HTTPUpgrade, gRPC, KCP, and supported XHTTP transport settings.
  WebSocket/HTTPUpgrade protobuf early-data fields convert to the native `ed`
  query convention without sending an additional query parameter on the wire.
- Supported TLS settings and REALITY client settings. Binary certificate/key
  fields must contain UTF-8 PEM text. REALITY binary keys convert to URL-safe
  base64 and short IDs to hexadecimal.
- Dispatcher/handler-manager app markers, logging, policy, stats, ordinary
  observatory, StatsService, LoggerService, ObservatoryService, supported routing
  rules, and freedom final admission rules. Observatory intervals retain their
  exact signed nanosecond value through the Go-duration string representation.

Each typed message is unpacked through `TypedMessage::unpack`, which validates
the exact protobuf full name. After consuming represented fields, the converter
compares the remaining generated message against its default. A nondefault
unconsumed field is an error; unknown apps, handlers, transports, security types,
or services are also errors. Duplicate apps and ambiguous transport/security
settings fail instead of selecting a value by accident. Protobuf wire fields
unknown to the checked-in schemas retain Prost's standard unknown-field
discard behavior; this is not a descriptor-based future-schema validator.

Presence and defaults matter:

- Missing policy seconds inherit defaults; present zero seconds remain zero.
- Protobuf policy buffers are bytes, while the JSON model uses KiB. Only `-1`
  or exact nonnegative multiples of 1024 can be represented. Other values fail
  instead of being rounded or assigned a new meaning.
- An absent inbound listen address becomes `0.0.0.0`. Exactly one receiver port
  is supported. Empty lists, ranges, domain/unix listeners, and overflowing ports
  fail rather than producing multiple independently tagged handlers.
- An empty protobuf log app disables access and error destinations. It does not
  become the JSON empty log object, which would enable console logging. Unknown
  severity with an active error logger is rejected because the native JSON
  logger cannot express that threshold independently from access logging.
- XHTTP ranges whose upper endpoint is zero use the reference getter defaults.
  Explicit negative stream-up keepalive ranges retain their disabled meaning.
- The Go VLESS handler's empty encryption/decryption values normalize to the
  equivalent explicit `none` required by native JSON validation.
- Disabled sender mux options have no behavior and are accepted; enabled mux
  is rejected. Outbound `expire` and `comment` are source-declared unused
  metadata and do not influence runtime configuration.

Unsupported conversions currently include extensions, DNS and other app
integrations, version constraints, arbitrary API services, sniffing, original
destination interception, source binding, socket options, masks, QUIC, REALITY
inbounds, proxy-protocol headers, nondefault protocol encryption/fallback/test
options, HTTP outbound custom headers, Shadowsocks IV checking, and routing
balancing/process/local/protocol/webhook fields. TLS ECH, certificate pins and
name overrides, and XHTTP xmux/downloadSettings/custom-session-ID settings are
explicit errors. A protobuf WebSocket/HTTPUpgrade query whose native normalization
would change its bytes or early-data meaning is rejected. This includes literal
or encoded `ed` keys and unsorted query pairs when inserting an early-data option.

The CLI accepts `-format pb`, `-format protobuf`, `.pb`/`.protobuf` file
extensions, and explicit binary stdin input. It reads bytes before selecting a
decoder. Auto stdin remains JSON. Like Go, any combination containing protobuf
must have exactly one input, and rejection happens before opening files or
consuming stdin. Config-directory filtering and default filename discovery
remain text-only, following `main/run.go`. `-dump` projects the supported native
configuration to JSON; it is not the Go protobuf-debug JSON representation or a
lossless protobuf re-encoder.

Unit fixtures cover a hand-authored core/outbound wire message and every
truncation, invalid wire bytes, typed-message mismatches, unsupported settings,
logging presence, policy zero/value-unit semantics, all supported proxy families,
routing selectors, early-data conversion, KCP fields, and XHTTP signed/default
ranges. CLI tests exercise binary files, stdin, format overrides, JSON dumping,
and malformed/multiple-input rejection.

`rust/fixtures/protobuf/basic.pb` was produced from the adjacent JSON fixture
with the existing reference executable (`Xray 26.9.9`, revision
`dcdfc57-dirty`, Go 1.27.0, Windows/amd64) using:

```powershell
target/reference-xray.exe convert pb -outpbfile rust/fixtures/protobuf/basic.pb rust/fixtures/protobuf/basic.json
target/reference-xray.exe run -test -c rust/fixtures/protobuf/basic.pb
```

The reference executable reported `Configuration OK.`. The binary includes
invalid-UTF-8 custom blackhole response bytes, ensuring tests catch accidental
text decoding. Its SHA-256 is
`6a4c7a0a909af315df9253a5ffbf78af66869d53a3f0a85c6fcb07f8ca611dab`.
The parent agent owns Rust Cargo compilation and execution of the new tests.
