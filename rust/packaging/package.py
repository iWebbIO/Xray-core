#!/usr/bin/env python3
"""Build and package a native, explicitly partial Rust migration (Python 3.11+)."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = Path(__file__).with_name("targets.json")


def inventory() -> dict:
    data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if data["schema_version"] != 1:
        raise ValueError("unsupported target inventory schema")
    return data


def workspace() -> dict:
    with (ROOT / "Cargo.toml").open("rb") as source:
        return tomllib.load(source)["workspace"]["package"]


def capture(command: list[str]) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def source_revision() -> str:
    try:
        revision = capture(["git", "rev-parse", "HEAD"])
        dirty = capture(["git", "status", "--porcelain", "--untracked-files=normal"])
        return revision + ("-dirty" if dirty else "")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unknown"


def compiler_host(details: str) -> str:
    for line in details.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ").strip()
    raise ValueError("rustc -vV did not identify its native host")


def numeric_version(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        raise ValueError(f"invalid compiler version: {value}")
    return tuple(int(part or 0) for part in match.groups())


def native_target(target: str) -> dict:
    for entry in inventory()["native_ci"]:
        if entry["rust_target"] == target:
            return entry
    raise ValueError(f"{target}: no configured native package; see targets.json for pending targets")


def build_plan(target: str, output: Path) -> dict:
    entry = native_target(target)
    version = workspace()["version"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", version):
        raise ValueError("workspace version is not safe for an archive filename")
    name = f"Xray-rust-partial-{version}-{target}"
    suffix = ".zip" if "windows" in target else ".tar.gz"
    build_dir = ROOT / "target" / "rust-packaging"
    return {
        "status": "configured-not-yet-executed",
        "migration_status": "partial",
        "target": target,
        "runner": entry["runner"],
        "name": name,
        "archive": str(output / (name + suffix)),
        "binary": str(build_dir / target / "release" / ("xray.exe" if "windows" in target else "xray")),
        "command": ["cargo", "build", "--release", "--locked", "--package", "xray", "--bin", "xray", "--target", target, "--target-dir", str(build_dir)],
        "feature_selection": "Cargo defaults; optional native-tun is not enabled",
    }


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def create_archive(stage: Path, destination: Path, epoch: int) -> None:
    """Store regular files only, preserving the executable bit on every platform."""
    files = sorted(path for path in stage.rglob("*") if path.is_file())
    if any(path.is_symlink() for path in stage.rglob("*")):
        raise ValueError("package staging directory contains a symlink")
    executable = {"xray", "xray.exe"}
    if destination.name.endswith(".zip"):
        # ZIP cannot represent dates before 1980 or after 2107.
        zip_date = time.gmtime(min(max(epoch, 315532800), 4354819198))[:6]
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                member = zipfile.ZipInfo(f"{stage.name}/{path.relative_to(stage).as_posix()}", zip_date)
                member.create_system = 3
                mode = 0o755 if path.name in executable else 0o644
                member.external_attr = (stat.S_IFREG | mode) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, path.read_bytes())
    else:
        with destination.open("xb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for path in files:
                        info = archive.gettarinfo(str(path), arcname=f"{stage.name}/{path.relative_to(stage).as_posix()}")
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mode = 0o755 if path.name in executable else 0o644
                        info.mtime = epoch
                        with path.open("rb") as source:
                            archive.addfile(info, source)


def package_binary(plan: dict, metadata: dict, epoch: int) -> Path:
    archive = Path(plan["archive"])
    checksum = archive.with_name(archive.name + ".sha256")
    if archive.exists() or checksum.exists():
        raise ValueError(f"refusing to overwrite existing package: {archive}")
    binary = Path(plan["binary"])
    if not binary.is_file() or binary.is_symlink() or binary.stat().st_size == 0:
        raise ValueError("built executable is missing, empty, or a symlink")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xray-rust-package-", dir=archive.parent) as temp:
        stage = Path(temp) / plan["name"]
        stage.mkdir()
        shutil.copyfile(binary, stage / binary.name)
        (stage / binary.name).chmod(0o755)
        for source, name in [
            (ROOT / "LICENSE", "LICENSE"),
            (ROOT / "rust" / "README.md", "RUST-README.md"),
            (ROOT / "rust" / "MIGRATION.md", "MIGRATION.md"),
            (ROOT / "rust" / "notes" / "PACKAGING.md", "PACKAGING.md"),
            (INVENTORY, "targets.json"),
            (ROOT / "rust" / "examples" / "socks-direct.json", "examples/socks-direct.json"),
        ]:
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        metadata = {**metadata, "binary_sha256": sha256(binary)}
        (stage / "BUILD-INFO.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        temporary_archive = Path(temp) / archive.name
        create_archive(stage, temporary_archive, epoch)
        # The completed archive is moved only after all files were copied successfully.
        temporary_archive.replace(archive)
    with checksum.open("x", encoding="utf-8", newline="\n") as destination:
        destination.write(f"{sha256(archive)}  {archive.name}\n")
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["matrix", "build"])
    parser.add_argument("--target", help="must match rustc's host; required for --dry-run")
    parser.add_argument("--output", type=Path, default=ROOT / "target" / "rust-dist")
    parser.add_argument("--revision", help="source revision for builds without .git")
    parser.add_argument("--dry-run", action="store_true", help="print a build plan without invoking any external commands")
    args = parser.parse_args(argv)
    if args.command == "matrix":
        print(json.dumps({"include": inventory()["native_ci"]}, separators=(",", ":")))
        return 0
    if args.dry_run:
        if not args.target:
            parser.error("--dry-run requires --target; no compiler is invoked to guess it")
        print(json.dumps(build_plan(args.target, args.output.resolve()), indent=2))
        return 0
    details = capture(["rustc", "-vV"])
    host = compiler_host(details)
    target = args.target or host
    if target != host:
        raise ValueError(f"cross-compilation is not validated: requested {target}, rustc host is {host}")
    package = workspace()
    compiler_version = details.splitlines()[0].split()[1]
    if numeric_version(compiler_version) < numeric_version(package["rust-version"]):
        raise ValueError(f"Rust {package['rust-version']} or newer is required")
    plan = build_plan(target, args.output.resolve())
    if Path(plan["archive"]).exists() or Path(plan["archive"] + ".sha256").exists():
        raise ValueError("output package already exists; choose a new --output directory")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", int(time.time())))
    if not 0 <= epoch <= 4294967295:
        raise ValueError("SOURCE_DATE_EPOCH must be between 0 and 4294967295")
    revision = args.revision or source_revision()
    cargo_version = capture(["cargo", "--version"])
    subprocess.run(plan["command"], cwd=ROOT, check=True)
    binary = plan["binary"]
    # Validate local execution and config parsing without opening listeners.
    version_output = capture([binary, "version"])
    if "Rust" not in version_output:
        raise ValueError("the packaged executable did not identify itself as Rust")
    capture([binary, "run", "--config", str(ROOT / "rust/examples/socks-direct.json"), "--test"])
    metadata = {
        "implementation": "native-rust",
        "migration_status": "partial",
        "full_go_parity": False,
        "version": package["version"],
        "source_revision": revision,
        "target": target,
        "host": host,
        "rustc": details,
        "cargo": cargo_version,
        "feature_selection": plan["feature_selection"],
        "epoch": epoch,
        "smoke_checks": ["version", "run --config examples/socks-direct.json --test"],
        "version_output": version_output,
        "notes": "Native compilation and CLI smoke checks do not establish protocol or platform parity. No geodata, Wintun, installer, or system service is bundled.",
    }
    print(package_binary(plan, metadata, epoch))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"packaging failed: {error}", file=sys.stderr)
        sys.exit(1)
