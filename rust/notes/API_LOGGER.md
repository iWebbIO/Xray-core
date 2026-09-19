# Logger and observatory management services

`api/logger.rs` implements the generated LoggerService RPC using a clone of
the runtime's actual `logging::Logger`. Cloning the logger shares its writers
and lifecycle. The service does not construct an independent logger from the
same configuration.

Integration APIs:

- `LoggerService::new(logger)` and `into_server()`.
- `LoggerService::from_optional_logger(None)` preserves the source's gRPC
  UNKNOWN `unable to get logger instance` failure.
- `logger_routes(service)` creates a router with both aliases.
- `add_logger_routes(routes, service)` adds both aliases to existing routes.
- Canonical service: `xray.app.log.command.LoggerService`.
- Legacy source alias: `v2ray.core.app.log.command.LoggerService`.

`RestartLogger` calls the existing `Logger::restart` on a Tokio blocking
worker so filesystem operations do not block an asynchronous network worker.
Success is returned only after the restart completes. Reopening errors become
gRPC UNKNOWN with their underlying IO error; task failures become INTERNAL.
Unknown methods retain the generated gRPC UNIMPLEMENTED response.

The native logger atomically replaces its writers after new files are opened.
Unlike the Go Close/Start sequence, a failed reopen of an active logger keeps
its previous writers available. Its single restart error cannot distinguish
the Go command's separate `failed to close logger` and `failed to start logger`
phrases. This is an explicit lifecycle/diagnostic difference, not a claim of
exact failure-state parity. A dispatched blocking restart can finish after a
client cancels its RPC, matching the fact that the underlying restart itself
does not take a cancellation context.

`api/observatory.rs` implements the generated
`xray.core.app.observatory.command.ObservatoryService` using an explicit
`Arc<dyn ObservationProvider>`. There is no legacy service alias in the Go
source. `get_observation()` returns the real `ObservationResult` protobuf or
a `tonic::Status`; the service forwards both unchanged, wrapping successful
observations in `GetOutboundStatusResponse.status`.

`ObservatoryService::new(provider)`, `observatory_routes(service)` and
`add_observatory_routes(routes, service)` require the caller to supply a real
observer. There is deliberately no empty/default provider. The native runtime
does not yet contain the ordinary/burst observation scheduler and probe state,
so this service must not be advertised as working runtime observability until
that provider is connected. Delay values remain milliseconds, and the burst
health-ping duration fields remain nanoseconds as in the source. This module
does not synthesize metrics from counters or guess outbound health.

Tests cover logger clone/lifecycle sharing, missing logger and reopen errors,
both service aliases over native HTTP/2 gRPC, unknown methods, live observation
provider calls and unit preservation, provider errors, and the generated
observatory client against a loopback gRPC server. Shared listener wiring,
service configuration and runtime observation collection remain parent-owned.
