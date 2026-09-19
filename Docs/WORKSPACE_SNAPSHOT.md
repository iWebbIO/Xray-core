# Workspace snapshot

Documentation checkpoint for the user-requested pause on September 19, 2026.

## Repository state

- Root: C:/Users/W/Documents/iwebbio/Xray-core
- Branch: main
- HEAD: dcdfc57ccdad496e192344788a7d14a8d4c88573
- Reference source version: 26.9.9
- Source inventory captured: 2026-09-19 21:41:45 BST
- Changes are uncommitted; no migration commit or PR was created.

Tracked modifications:
- .github/dependabot.yml
- .gitignore
- README.md

New/untracked paths:
- .github/workflows/rust.yml
- .github/workflows/rust-release.yml
- Cargo.toml
- Cargo.lock
- rust/
- Docs/

Git's short status collapses the untracked Rust tree. The inventory expands
that tree so work does not disappear behind a single directory entry.

## Inventory and integrity

[rust-file-inventory.json](rust-file-inventory.json) records:

- **236 migration/source/metadata files**, including **159 Rust source files**.
- **3,347,021 bytes** of recorded source/metadata.
- Per-file relative path, size and SHA-256.
- Full Git HEAD, branch and pause status.
- Five reference executables, with sizes and SHA-256.

Selection is `rg --files rust` plus root Cargo/README/.gitignore/Dependabot
and the two new Rust workflows. Ignored build caches, temporary validation
directories and the Docs files themselves are not part of the source inventory.
Original unchanged Go files are not recopied into this manifest; Git HEAD
identifies that baseline.

A second read-only hash verification found **zero mismatches** across all 236
recorded files. This checks snapshot integrity only, not code correctness.
The basic protobuf fixture's actual hash is preserved in the manifest.

The inventory should be regenerated only after an explicitly authorized resume
changes source. It is a pause checkpoint, not an automatic watcher.

## Runtime/build state at pause

- At 21:34:47 BST no cargo, rustc, go or link process was present.
- The parent had no active Cargo/Go execution session.
- The parent goal API returned null; no replacement goal was created.
- Parent implementation agents were completed/stopped; logging was explicitly
  interrupted after its final handoff.
- Helper coordinators stopped their implementation workers. Documentation-only
  handoff work continued in Docs and then stopped.
- Generic processes of unknown ownership were not terminated.
- No new build, test, cleanup, implementation edit, publication or deployment
  was performed after the pause.

Approximately 3.77 GB of C: space was free at the first pause check, and 3.26 GB
at inventory verification. Disk space changes independently of this snapshot;
recheck before later builds.

## Retained artifacts

Five ignored Go reference executables are listed with hashes in the inventory.
Their sources and future-use commands are in VALIDATION.md.

Other retained diagnostics include:
- target/fmt-check.log: earlier failed formatting dry run.
- target/xhttp-wire-diag.py: XHTTP diagnostic helper.
- xhttp-diag-* temporary directories reported by the XHTTP owner.
- compiled Cargo test executables in target/debug/deps, tied to earlier source.

The protected geodata validation directory and target/debug cleanup have prior
automatic approval rejections. They were not removed during pause. Preserve
their recorded restrictions.

## Documentation completeness

The main status/validation/remaining-work documents are accompanied by the
three coordinator handoffs. Original detailed module notes remain in rust/notes
and are linked from those handoffs. The interrupted PARITY_AUDIT.md update is
explicitly identified as a draft.

The latest TLS/protobuf patch and certificate-location issue are recorded even
though the older module note does not yet include them. Historical passing
tests and current unrun source are kept separate throughout the handoff.

