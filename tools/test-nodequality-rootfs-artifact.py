#!/usr/bin/env python3
"""Exercise offline derivation using explicitly supplied canonical source files."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import signal
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
import nodequality_rootfs_artifact as artifact
import release


def module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


def inert_rootfs(runner, arch="amd64", provenance_edits=None):
    fixture = module("rootfs_artifact_inert_fixture", artifact.ROOT / "tools/test-nodequality-rootfs.py")
    prefix = "usr/share/sinan-rootfs/"
    builder = {"image_sha256": "1" * 64, "arch": arch, "tools": []}
    inventory = {"inputs-lock.json": (json.dumps({"schema": 1, "arch": arch, "source_epoch": 1,
                                                    "builder": builder, "TEST_ONLY": True}) + "\n").encode(),
                 "source-inventory.json": (json.dumps({"schema": 1, "arch": arch, "TEST_ONLY": True}) + "\n").encode(),
                 "license-inventory.json": b'{"schema":1,"reviewed":false,"TEST_ONLY":true}\n'}
    provenance = {"schema": 1, "kind": "sinan-nodequality-debian12-preparation", "arch": arch,
                  "full_ready": False, "source_authenticated": True, "reproducibility_verified": False,
                  "source_epoch": 1, "builder": builder,
                  "inputs_lock_sha256": artifact.digest(inventory["inputs-lock.json"]),
                  "source_inventory_sha256": artifact.digest(inventory["source-inventory.json"]),
                  "license_inventory_sha256": artifact.digest(inventory["license-inventory.json"]),
                  "build_tool_sha256": "0" * 64, "pending_capabilities": ["TEST_ONLY inert fixture; never distribute"]}
    provenance.update(provenance_edits or {})
    inventory["provenance.json"] = (json.dumps(provenance, sort_keys=True) + "\n").encode()
    rows = fixture.inventory() + [
        {"path": "usr/share", "type": "dir", "mode": 0o755},
        {"path": "usr/share/sinan-rootfs", "type": "dir", "mode": 0o755},
    ]
    for name, content in inventory.items():
        rows.append({"path": prefix + name, "type": "file", "mode": 0o644,
                     "size": len(content), "sha256": artifact.digest(content)})
    rows.sort(key=lambda row: row["path"])
    archive, raw = fixture.pack(rows, {prefix + name: content for name, content in inventory.items()})
    manifest = fixture.manifest(rows, archive, len(raw))
    manifest["arch"] = arch
    return {artifact.BINARY: runner, "rootfs.tar.gz": archive,
            "rootfs-manifest.json": (json.dumps(manifest, sort_keys=True) + "\n").encode()}


class DerivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("SINAN_NODEQUALITY_CANONICAL_SOURCES")
        if not path:
            raise unittest.SkipTest("requires offline canonical sources matching the committed source lock")
        specification = importlib.util.spec_from_file_location("rootfs_artifact_source", artifact.PLUGIN / "source-helper.py")
        helper = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(helper)
        lock = helper.decode(helper.ordinary(artifact.PLUGIN / "source-lock.json", 65536))
        cls.bundle = helper.pack(lock, Path(path))
        cls.legacy = artifact.canonical_runner(cls.bundle)
        cls.runner = artifact.offline_runner(cls.legacy)

    def test_exact_canonical_sources_and_full_licenses_are_retained(self):
        self.assertEqual(artifact.embedded(self.legacy, "SINAN_NODEQUALITY_REPORT_HELPER"),
                         artifact.history.source("report.py"))
        self.assertEqual(artifact.embedded(self.runner, "SINAN_NODEQUALITY_ROOTFS_HELPER"),
                         artifact.history.source("rootfs.py"))
        self.assertEqual(artifact.embedded(self.runner, artifact.MARKERS["PINNED_CHAIN"]), self.bundle)
        self.assertEqual(artifact.embedded(self.runner, artifact.MARKERS["NODEQUALITY_LICENSE"]),
                         artifact.embedded(self.legacy, artifact.MARKERS["NODEQUALITY_LICENSE"]))
        entry = artifact.embedded(self.legacy, artifact.MARKERS["NODEQUALITY_SOURCE"])
        self.assertEqual(hashlib.sha256(entry).hexdigest(), artifact.ENTRY_SHA256)
        self.assertEqual(artifact.embedded(self.runner, "SINAN_NODEQUALITY_EXECUTION_ADMISSION"),
                         artifact.embedded(self.legacy, "SINAN_NODEQUALITY_EXECUTION_ADMISSION"))
        self.assertEqual(artifact.embedded(self.runner, "SINAN_OFFICIAL_IP_HELPER"),
                         artifact.embedded(self.legacy, "SINAN_OFFICIAL_IP_HELPER"))
        self.assertIn(artifact.LOCAL_ROOTFS, self.runner)
        self.assertNotIn(artifact.LOAD_ROOTFS, self.runner)
        self.assertNotIn(b'exec "$SINAN_REAL_CURL" --connect-timeout 15 --max-time 900', self.runner)

    def test_version_is_distinct_and_full_is_refused_before_any_prerequisite_or_io(self):
        with tempfile.TemporaryDirectory(prefix="sinan-rootfs-wrapper-") as temporary:
            script = Path(temporary) / "nodequality"
            script.write_bytes(self.runner)
            environment = dict(os.environ, PATH="/nonexistent", BASH_ENV="", ENV="")
            bash = "/bin/bash"
            version = subprocess.run([bash, str(script), "--version"], env=environment,
                                     capture_output=True, timeout=3)
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout.decode().strip(), "nodequality " + artifact.VERSION)
            nonexistent = Path(temporary) / "never-created"
            full = subprocess.run([bash, str(script), "--workspace", str(nonexistent), "--mode", "full"],
                                  env=environment, capture_output=True, timeout=3)
            self.assertNotEqual(full.returncode, 0)
            self.assertIn(b"new full diagnostics are paused", full.stderr)
            self.assertFalse(nonexistent.exists())

    def test_changed_legacy_wrapper_entry_bundle_and_license_cannot_be_derived(self):
        changes = [self.legacy + b"\nprintf changed\n",
                   self.legacy.replace(b"-r19\n", b"-r22\n", 1),
                   self.legacy.replace(b"umask 077", b"umask 022", 1),
                   self.legacy.replace(artifact.LOAD_ROOTFS, artifact.LOAD_ROOTFS + b"# changed\n", 1)]
        bundle = json.loads(self.bundle)
        bundle["files"]["LICENSE.ip"] = bundle["files"]["LICENSE.net"][:-4]
        changed = (json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n").encode()
        changes.append(self.legacy.replace(self.bundle, changed, 1))
        for content in changes:
            with self.subTest(digest=hashlib.sha256(content).hexdigest()):
                with self.assertRaises((ValueError, KeyError)):
                    artifact.offline_runner(content)

    def test_missing_or_duplicate_embedded_boundaries_are_refused(self):
        sentinel = artifact.MARKERS["PINNED_CHAIN"]
        begin = ("<<'" + sentinel + "'\n").encode()
        for content in (self.legacy.replace(begin, b"<<'missing'\n", 1),
                        self.legacy + begin + b"duplicate\n" + sentinel.encode() + b"\n"):
            with self.assertRaises(ValueError):
                artifact.offline_runner(content)
        for content in (b"null", b"[]", b'"string"'):
            with self.assertRaises(ValueError):
                artifact.canonical_runner(content)

    def test_preparation_artifact_roundtrip_and_inner_manifest_are_both_validated(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                files = inert_rootfs(self.runner, arch)
                self.assertEqual(artifact.validate_files(files, artifact.VERSION, arch)["arch"], arch)
                data = artifact.pack(files)
                self.assertEqual(artifact.archive_files(data), files)
                auxiliary = {name: {"size": len(content), "sha256": artifact.digest(content)}
                             for name, content in files.items() if name != artifact.BINARY}
                self.assertEqual(release.binary_bytes(data, "tar.gz", artifact.BINARY, auxiliary), self.runner)

    def test_missing_inventory_wrong_arch_tampering_and_full_ready_are_rejected(self):
        files = inert_rootfs(self.runner)
        changed_rootfs = dict(files, **{"rootfs.tar.gz": files["rootfs.tar.gz"][:-1] + b"!"})
        changed_runner = dict(files, nodequality=self.runner + b"\nprintf changed\n")
        missing = dict(files)
        missing.pop("rootfs-manifest.json")
        for changed in (changed_rootfs, changed_runner, missing,
                        inert_rootfs(self.runner, provenance_edits={"full_ready": True}),
                        inert_rootfs(self.runner, provenance_edits={"source_inventory_sha256": "0" * 64})):
            with self.subTest(files=sorted(changed)):
                with self.assertRaises((ValueError, KeyError)):
                    artifact.validate_files(changed, artifact.VERSION, "amd64")
        with self.assertRaises(ValueError):
            artifact.validate_files(files, artifact.VERSION, "arm64")

    def prepare_cli(self, root):
        command = module("offline_cli_fixture", artifact.ROOT / "tools/build-nodequality-offline.py")
        fixture = module("offline_cli_archive_fixture", artifact.ROOT / "tools/test-nodequality-rootfs.py")
        rootfs_directory = root / "export"
        rootfs_directory.mkdir()
        files = inert_rootfs(self.runner)
        for name in ("rootfs.tar.gz", "rootfs-manifest.json"):
            (rootfs_directory / name).write_bytes(files[name])
        archive, _ = fixture.pack([{"path": "nodequality", "type": "file", "mode": 0o755,
                                   "size": len(self.legacy), "sha256": artifact.digest(self.legacy)}],
                                 {"nodequality": self.legacy})
        legacy = root / "legacy"
        legacy.write_bytes(archive)
        approved = "1" * 64
        prepared = {"TEST_ONLY": "source verifier is covered by its separate tests"}
        receipt = {"archive": {"sha256": artifact.digest(files["rootfs.tar.gz"]), "size": len(files["rootfs.tar.gz"])},
                   "manifest": {"sha256": artifact.digest(files["rootfs-manifest.json"]), "size": len(files["rootfs-manifest.json"])}}
        builder = SimpleNamespace(verify_prepared=mock.Mock(return_value=prepared),
                                  verify_export=mock.Mock(return_value=receipt))
        arguments = SimpleNamespace(arch="amd64", legacy_artifact=legacy, rootfs_directory=rootfs_directory,
                                    prepared_directory=root / "prepared", approved_builder_image_sha256=approved,
                                    output=root / "output")
        actual_module = artifact.module
        def load(name, path):
            return builder if name == "sinan_rootfs_preparation" else actual_module(name, path)
        return command, builder, arguments, mock.patch.object(artifact, "module", side_effect=load)

    def test_cli_rechecks_preparation_and_export_and_preserves_immutable_artifact(self):
        with tempfile.TemporaryDirectory(prefix="sinan-rootfs-cli-") as temporary:
            root = Path(temporary).resolve()
            command, builder, arguments, loading = self.prepare_cli(root)
            with loading:
                target = command.build(arguments)
                original = target.read_bytes()
                sums = target.parent / "SHA256SUMS"
                original_sums = sums.read_bytes()
                builder.verify_prepared.assert_called_with(arguments.prepared_directory, arguments.approved_builder_image_sha256)
                builder.verify_export.assert_called_with(arguments.rootfs_directory, builder.verify_prepared.return_value, "amd64")
                with self.assertRaisesRegex(ValueError, "immutable"):
                    command.build(arguments)
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(sums.read_bytes(), original_sums)
            self.assertFalse((target.parent / ".build.lock").exists())
            self.assertEqual(artifact.archive_files(original)["nodequality"], self.runner)

    def test_cli_refuses_export_mutation_after_source_verification(self):
        with tempfile.TemporaryDirectory(prefix="sinan-rootfs-cli-tamper-") as temporary:
            root = Path(temporary).resolve()
            command, builder, arguments, loading = self.prepare_cli(root)
            builder.verify_export.return_value["archive"]["sha256"] = "0" * 64
            with loading, self.assertRaisesRegex(ValueError, "changed after"):
                command.build(arguments)
            self.assertFalse(arguments.output.exists())

    def test_cli_refuses_symlink_ancestors_and_never_writes_their_target(self):
        with tempfile.TemporaryDirectory(prefix="sinan-rootfs-cli-path-") as temporary:
            root = Path(temporary).resolve()
            command, _, arguments, loading = self.prepare_cli(root)
            outside = root / "outside"
            outside.mkdir()
            arguments.output.symlink_to(outside, target_is_directory=True)
            with loading, self.assertRaises((ValueError, OSError)):
                command.build(arguments)
            self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(hasattr(signal, "pthread_sigmask"), "requires POSIX signal publication control")
    def test_cli_interruptions_do_not_leave_checksum_inventory_inconsistent(self):
        for phase in ("link", "replace"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="sinan-rootfs-cli-signal-") as temporary:
                root = Path(temporary).resolve()
                command, _, arguments, loading = self.prepare_cli(root)
                real = getattr(command.os, phase)
                def interrupted(*args, **kwargs):
                    result = real(*args, **kwargs)
                    os.kill(os.getpid(), signal.SIGTERM)
                    return result
                with loading, command.cli_signals(), mock.patch.object(command.os, phase, side_effect=interrupted):
                    with self.assertRaises(SystemExit) as captured:
                        command.build(arguments)
                self.assertEqual(captured.exception.code, 143)
                directory = arguments.output / "nodequality" / artifact.VERSION
                self.assertFalse((directory / ".build.lock").exists())
                self.assertFalse(any(path.name.startswith((".artifact-", ".sums-")) for path in directory.iterdir()))
                if phase == "link":
                    self.assertFalse((directory / "amd64").exists())
                    self.assertFalse((directory / "SHA256SUMS").exists())
                else:
                    self.assertEqual((directory / "SHA256SUMS").read_text(),
                                     artifact.digest((directory / "amd64").read_bytes()) + "  amd64\n")

    @unittest.skipUnless(hasattr(signal, "pthread_sigmask"), "requires POSIX signal publication control")
    def test_cli_interruptions_during_lock_or_temporary_creation_remove_owned_paths(self):
        for phase in ("lock", "temporary"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="sinan-rootfs-cli-create-") as temporary:
                root = Path(temporary).resolve()
                command, _, arguments, loading = self.prepare_cli(root)
                if phase == "lock":
                    real = Path.mkdir
                    def interrupted(path, *args, **kwargs):
                        result = real(path, *args, **kwargs)
                        if path.name == ".build.lock":
                            os.kill(os.getpid(), signal.SIGTERM)
                        return result
                    mutation = mock.patch.object(Path, "mkdir", interrupted)
                else:
                    real = command.tempfile.NamedTemporaryFile
                    def interrupted(*args, **kwargs):
                        result = real(*args, **kwargs)
                        os.kill(os.getpid(), signal.SIGTERM)
                        return result
                    mutation = mock.patch.object(command.tempfile, "NamedTemporaryFile", side_effect=interrupted)
                with loading, command.cli_signals(), mutation:
                    with self.assertRaises(SystemExit) as captured:
                        command.build(arguments)
                self.assertEqual(captured.exception.code, 143)
                directory = arguments.output / "nodequality" / artifact.VERSION
                self.assertEqual(list(directory.iterdir()), [])

    @unittest.skipUnless(shutil.which("minisign"), "requires actual minisign TEST_ONLY interoperability")
    def test_release_signs_exact_aux_inventory_and_refuses_an_incomplete_signed_identity(self):
        with tempfile.TemporaryDirectory(prefix="sinan-rootfs-release-") as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            for arch in ("amd64", "arm64"):
                directory = source / "nodequality" / artifact.VERSION
                directory.mkdir(parents=True, exist_ok=True)
                (directory / arch).write_bytes(artifact.pack(inert_rootfs(self.runner, arch)))
                directory = source / "agent" / "0.3.0"
                directory.mkdir(parents=True, exist_ok=True)
                (directory / arch).write_bytes(b"TEST_ONLY nonexecutable Agent")
                directory = source / "sing-box" / "1.14.2"
                directory.mkdir(parents=True, exist_ok=True)
                fixture = module("rootfs_signing_fixture", artifact.ROOT / "tools/test-nodequality-rootfs.py")
                payload, _ = fixture.pack([{"path": "sing-box", "type": "file", "mode": 0o755,
                                            "size": 4, "sha256": artifact.digest(b"TEST")}], {"sing-box": b"TEST"})
                (directory / arch).write_bytes(payload)
            installer = root / "install.sh"
            installer.write_bytes(b"#!/bin/sh\nexit 0\n")
            output = root / "release"
            release.assemble(SimpleNamespace(source=source, output=output, agent_version="0.3.0",
                runtime_version="1.14.2", nodequality_version=artifact.VERSION, arch=None,
                tag="agent-v0.3.0", installer=installer))
            fixtures = artifact.ROOT / "crates/protocol/tests/fixtures"
            def sign():
                result = subprocess.run(["minisign", "-S", "-q", "-m", str(output / "SHA256SUMS"),
                                         "-s", str(fixtures / "TEST_ONLY.key"), "-t", "Sinan TEST ONLY offline rootfs"],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            sign()
            roots = release.load_roots(fixtures / "public-keys.json")
            metadata = release.verify_bundle(output, roots, "minisign", "agent-v0.3.0")
            for entry in metadata["artifacts"]:
                if entry["name"] == "nodequality":
                    self.assertEqual(set(entry["auxiliary_files"]), artifact.FILES - {artifact.BINARY})
            # A newly signed but wrong identity must still fail the explicit
            # offline r20 file-set contract, independent of a valid test signature.
            for entry in metadata["artifacts"]:
                if entry["name"] == "nodequality":
                    entry["auxiliary_files"].pop("rootfs-manifest.json")
            (output / "release.json").write_bytes((json.dumps(metadata, sort_keys=True) + "\n").encode())
            sums = output / "SHA256SUMS"
            sums.write_text("\n".join(artifact.digest((output / "release.json").read_bytes()) + "  release.json"
                           if line.endswith("  release.json") else line for line in sums.read_text().splitlines()) + "\n")
            sign()
            with self.assertRaisesRegex(ValueError, "incomplete offline"):
                release.verify_manifest(output, roots, "minisign", "agent-v0.3.0")


if __name__ == "__main__":
    unittest.main()
