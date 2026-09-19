# Native Rust migration packaging

These packages contain the **partial native Rust migration**. They are not the
existing Go release and do not establish full protocol, configuration, CLI or
operating-system parity. `rust/MIGRATION.md` is the source-level completion
checklist. No Go executable, Go subprocess or Go FFI is used to build the Rust
binary. Existing Go release workflows and Docker image definitions are preserved.

## Native build and archives

Requirements: Python 3.11+, Rust at least the workspace `rust-version` (currently
1.88), Cargo, the native platform linker/C toolchain, and the checked-in
`Cargo.lock`. Cargo may fetch locked dependencies. Protobuf generation uses the
workspace's vendored `protoc` dependency; the packaging script adds no dependencies.

From the repository root, inspect the build commands without starting external
processes or writing output:

```sh
python rust/packaging/package.py matrix
python rust/packaging/package.py build --dry-run --target x86_64-unknown-linux-gnu
```

Build on a configured native host, or explicitly name its matching Rust target:

```sh
python rust/packaging/package.py build
python rust/packaging/package.py build --target x86_64-pc-windows-msvc --output target/rust-dist
```

The command selects only the `xray` binary, uses Cargo's release profile and
`--locked`, and builds under `target/rust-packaging`. It rejects a target different
from `rustc -vV`'s host and rejects unconfigured targets. It does not install a
toolchain, linker or sysroot. The default Cargo feature selection is used; the
optional `native-tun` feature is **not enabled**.

Before writing an archive it executes `xray version` and validates the bundled
SOCKS config with `xray run --config ... --test`. These checks do not open listeners
or establish interoperability. Failures stop packaging; build or smoke failures
are never represented as successful artifacts. Existing archives are not replaced.

Archives are named `Xray-rust-partial-<version>-<target>.zip` on Windows and
`.tar.gz` elsewhere, with a `.sha256` sidecar, under `target/rust-dist` by default.
Each archive has a single directory containing the executable, repository license,
Rust README, migration checklist, this note, target inventory, example config and
`BUILD-INFO.json`. Build metadata records the native target, source revision,
compiler/Cargo versions, selected feature policy, executable digest and actual
smoke checks. A Git checkout's modified/untracked state adds `-dirty` to its
revision. `--revision` supplies provenance for source copies without `.git`.

`SOURCE_DATE_EPOCH` fixes archive timestamps (Unix seconds, 0 through 4294967295).
Absent that variable, packaging uses the current time. Identical staging bytes and
epoch produce identical archive bytes; this is **not a claim of reproducible Cargo
builds**. ZIP timestamps are clamped to its representable range. Archives preserve
the executable bit, and staged symlinks are rejected.

## Configured CI targets and pending Go release targets

`rust/packaging/targets.json` is the workflow's matrix source. Its `native_ci` entries
describe configured jobs, **not successful builds or platform certification**:

| Rust target | Native GitHub runner |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `x86_64-pc-windows-msvc` | `windows-2022` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `aarch64-apple-darwin` | `macos-15` |

Runner availability depends on the repository's Actions entitlement. An unavailable
runner leaves its job pending; there is no fallback to a different architecture.
Linux archives use the selected runner's libc and are not static or advertised as
compatible with older Linux distributions. Windows archives are unsigned and have
no installer or Windows service. macOS archives are unsigned and not notarized;
the runner build does not establish an older macOS deployment baseline.

The inventory also covers every OS/architecture combination in the Go
`.github/workflows/release.yml`, including additional MIPS soft-float binaries.
The pending entries record candidate Rust triples and concrete missing validation.
They include 32-bit targets, Windows ARM64, other Linux CPUs, Android, FreeBSD and
OpenBSD. Some need a custom/build-std toolchain or have no corresponding validated
Rust target. An existing Rust target triple does not imply downloadable standard
libraries, compatible native dependencies, or equivalence to Go's CPU/float ABI.
The inventory does not map the separate Go Windows 7 legacy release workflow.

`.github/workflows/rust-release.yml` checks the packaging fixtures and builds the
five native targets on relevant pushes, pull requests, or manual dispatch. It uses
the stable toolchain available at execution and records the actual version. It
retains workflow artifacts for seven days. Its token has only `contents: read`;
it does not create releases, upload release assets, push images or replace the Go
workflow. Broader Rust checks remain in the existing `rust.yml` workflow.

## Container build

From the repository root:

```sh
docker build -f rust/packaging/Dockerfile --build-arg SOURCE_REVISION=<commit> -t xray-rust:partial .
docker run --rm --network none xray-rust:partial version
docker run --rm --network none xray-rust:partial run --config /opt/xray-rust/examples/socks-direct.json --test
```

Replace `<commit>` with the source revision. The default builder image is
`rust:bookworm`; `--build-arg RUST_IMAGE=rust:bookworm@sha256:<digest>` allows a
deliberately pinned builder. Both stages use Debian Bookworm. Native compilation
and executable smoke checks happen in the builder. The runtime includes CA
certificates and `libgcc-s1`, uses UID/GID 65532, and defaults to the `version`
command. Proxy startup requires an explicit `run --config ...` command and a
readable mounted config; no default listener or successful tunnel is invented.

The Dockerfile-specific ignore file excludes host Cargo outputs and `.git`, so a
host binary cannot accidentally replace the container build. The repository root
must be the build context because protobuf files outside `rust/` are required.
No geodata, Wintun library, installer, service definition, route changes or TUN
capabilities are included. TLS certificates use the image's system trust store.
The packaged loopback-only example is suitable for validation; exposing a proxy
requires a deliberate config and Docker port mapping.

The default local build uses the Docker engine's native platform. Linux amd64 and
arm64 match the inventory, but only a manually requested amd64 container job is
configured in CI. Multi-architecture manifests, QEMU/emulated builds, musl/static
images, other CPU targets and container runtime feature parity are unvalidated.
The manual `build_container` workflow input builds, runs two offline smoke checks,
and saves a Docker image archive plus SHA-256; it never pushes to a registry.

## Verification and remaining validation

Packaging-only tests do not invoke Cargo or a proxy:

```sh
python -B -m unittest discover -s rust/packaging -p 'test_*.py' -v
```

They cover dry-run side effects, target and host rejection, minimum compiler
rejection, smoke-failure propagation, archive contents/modes, digest correctness,
overwrite rejection, empty executables and deterministic fixture archives. Release
compilation, native runner execution, Docker builds and Docker execution still
require integration validation. These packaging files do not certify any of them.

Protocol/transport parity, native TUN and host networking privileges, service
lifecycle, platform socket behavior, geodata distribution, signing/notarization,
third-party license distribution requirements and supported OS-version baselines
need separate completion before replacing Go release artifacts.

Reference sources used for the configuration (reviewed September 19, 2026):

- Existing `.github/workflows/release.yml`, `.github/docker/Dockerfile`, workspace
  manifests, CLI source and migration notes in this repository.
- GitHub's `actions/runner-images` README for explicit runner labels/architectures:
  https://github.com/actions/runner-images#available-images
- Rust's platform support and cross-compilation requirements:
  https://doc.rust-lang.org/rustc/platform-support.html
  https://rust-lang.github.io/rustup/cross-compilation.html
- Docker's Dockerfile-specific context exclusion and native multi-platform builds:
  https://docs.docker.com/build/building/context/#dockerignore-files
  https://docs.docker.com/build/building/multi-platform/
- Action versions are pinned to commit IDs resolved from the official
  `actions/checkout` v4, `actions/setup-python` v5 and `actions/upload-artifact` v4
  repositories. They are selected versions, not a claim to be the latest releases.
