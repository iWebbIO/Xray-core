# Rust migration documentation

**PAUSED at the user's request. The project is not fully converted to Rust.**

Pause checkpoint: **September 19, 2026, 21:34:47 BST (UTC+01:00)**.
Implementation, builds, tests, and new migration assignments are stopped.
Work after that checkpoint is documentation only. Resume only on a new request.

| Document | Purpose |
|---|---|
| [RUST_MIGRATION_HANDOFF.md](RUST_MIGRATION_HANDOFF.md) | Workspace, architecture, delivered functionality, ownership and exact stopping state |
| [VALIDATION.md](VALIDATION.md) | Actual evidence, pending tests, reference artifacts and future commands |
| [REMAINING_WORK.md](REMAINING_WORK.md) | Known defects, next priorities and remaining full-parity work |
| [TRANSPORT_PLATFORM_HANDOFF.md](TRANSPORT_PLATFORM_HANDOFF.md) | Transport/platform/packaging coordinator's detailed handoff |
| [PROTOCOL_SECURITY_HANDOFF.md](PROTOCOL_SECURITY_HANDOFF.md) | Protocol and REALITY/VLESS security coordinator's handoff |
| [HELPER_COORDINATION_HANDOFF.md](HELPER_COORDINATION_HANDOFF.md) | DNS/UDP/observatory, reviews and audit handoff |
| [WORKSPACE_SNAPSHOT.md](WORKSPACE_SNAPSHOT.md) | Repository state, source counts/hashes, artifacts and pause verification |
| [rust-file-inventory.json](rust-file-inventory.json) | Machine-readable source inventory with SHA-256 hashes |

The final tree has **not** passed a complete build/test/lint run. Historical
passes apply to earlier snapshots. The last workspace check failed on a
protobuf HTTP Upgrade type name. That name was subsequently corrected, but
the correction and final TLS/protobuf changes have not been compiled.

Original Go code and Go releases are preserved. The Rust implementation does
not invoke Go through subprocesses or FFI. Go executables listed here are
test references only.

Detailed module notes remain in [rust/notes](../rust/notes). Some older notes
predate the pause. Use these handoffs to resolve status differences.

