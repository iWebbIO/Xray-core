"""Packaging contract checks using fixture bytes, never Cargo or a live proxy."""

import contextlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

import package


class PackagingTests(unittest.TestCase):
    def test_dry_run_never_runs_tools_or_creates_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "not-created"
            for entry in package.inventory()["native_ci"]:
                with self.subTest(target=entry["rust_target"]):
                    stream = io.StringIO()
                    with mock.patch.object(package, "capture", side_effect=AssertionError("external tool")):
                        with mock.patch.object(package.subprocess, "run", side_effect=AssertionError("build")):
                            with contextlib.redirect_stdout(stream):
                                self.assertEqual(package.main(["build", "--dry-run", "--target", entry["rust_target"], "--output", str(output)]), 0)
                    plan = json.loads(stream.getvalue())
                    self.assertIn("--locked", plan["command"])
                    self.assertIn("partial", plan["name"])
            self.assertFalse(output.exists())

    def test_unvalidated_target_cannot_be_packaged(self):
        for entry in package.inventory()["unvalidated"]:
            if entry["rust_target"]:
                with self.subTest(target=entry["rust_target"]):
                    with self.assertRaisesRegex(ValueError, "no configured native package"):
                        package.build_plan(entry["rust_target"], Path("unused"))

    def test_cross_build_is_rejected_before_cargo(self):
        with mock.patch.object(package, "capture", return_value="rustc 1.95.0\nhost: x86_64-pc-windows-msvc"):
            with mock.patch.object(package.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "cross-compilation is not validated"):
                    package.main(["build", "--target", "x86_64-unknown-linux-gnu"])
                run.assert_not_called()

    def test_old_compiler_is_rejected_before_cargo(self):
        with mock.patch.object(package, "capture", return_value="rustc 1.87.0\nhost: x86_64-unknown-linux-gnu"):
            with mock.patch.object(package.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "or newer is required"):
                    package.main(["build"])
                run.assert_not_called()

    def test_smoke_failure_prevents_packaging(self):
        responses = ["rustc 1.95.0\nhost: x86_64-unknown-linux-gnu", "cargo 1.95.0", "Go executable"]
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(package, "capture", side_effect=responses):
                with mock.patch.object(package.subprocess, "run") as build:
                    with mock.patch.object(package, "package_binary") as archive:
                        with self.assertRaisesRegex(ValueError, "did not identify itself as Rust"):
                            package.main(["build", "--output", temp, "--revision", "fixture"])
                        build.assert_called_once()
                        archive.assert_not_called()

    def test_archives_include_notice_metadata_hash_and_executable(self):
        for target in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                binary = root / ("xray.exe" if "windows" in target else "xray")
                binary.write_bytes(b"fixture executable, not runnable\x00\xff")
                plan = package.build_plan(target, root / "dist")
                plan["binary"] = str(binary)
                archive = package.package_binary(plan, {"migration_status": "partial", "full_go_parity": False}, 1700000000)
                prefix = plan["name"] + "/"
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as content:
                        names = content.namelist()
                        data = content.read(prefix + "BUILD-INFO.json")
                        mode = content.getinfo(prefix + binary.name).external_attr >> 16
                        self.assertTrue(mode & stat.S_IXUSR)
                        self.assertEqual(content.read(prefix + binary.name), binary.read_bytes())
                else:
                    with tarfile.open(archive, "r:gz") as content:
                        names = content.getnames()
                        data = content.extractfile(prefix + "BUILD-INFO.json").read()
                        self.assertEqual(content.getmember(prefix + binary.name).mode, 0o755)
                        self.assertEqual(content.extractfile(prefix + binary.name).read(), binary.read_bytes())
                for name in ["LICENSE", "PACKAGING.md", "MIGRATION.md", "RUST-README.md", "targets.json", "examples/socks-direct.json"]:
                    self.assertIn(prefix + name, names)
                metadata = json.loads(data)
                self.assertFalse(metadata["full_go_parity"])
                self.assertEqual(metadata["binary_sha256"], package.sha256(binary))
                self.assertEqual(archive.with_name(archive.name + ".sha256").read_text().strip(), f"{package.sha256(archive)}  {archive.name}")
                previous = archive.read_bytes()
                with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                    package.package_binary(plan, {}, 1700000000)
                self.assertEqual(archive.read_bytes(), previous)

    def test_archive_bytes_repeat_for_fixed_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stage = root / "fixture"
            stage.mkdir()
            (stage / "xray").write_bytes(b"not a real executable")
            for suffix in [".tar.gz", ".zip"]:
                first, second = root / ("one" + suffix), root / ("two" + suffix)
                package.create_archive(stage, first, 1700000000)
                package.create_archive(stage, second, 1700000000)
                self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_empty_binary_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "xray"
            binary.touch()
            plan = package.build_plan("x86_64-unknown-linux-gnu", Path(temp) / "dist")
            plan["binary"] = str(binary)
            with self.assertRaisesRegex(ValueError, "missing, empty, or a symlink"):
                package.package_binary(plan, {}, 1700000000)


if __name__ == "__main__":
    unittest.main()
