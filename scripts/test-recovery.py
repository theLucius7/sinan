#!/usr/bin/env python3
"""Exercise backup integrity, ownership and retention without Docker or networking."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from urllib.parse import unquote, urlsplit

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("recovery.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def backup(self, base, name="latest", *, member="artifacts/releases/example", days=0):
        destination = base / name
        destination.mkdir(mode=0o700)
        (destination / "environment").write_text("SINAN_DB_PASSWORD=example-only\n")
        (destination / "database.dump").write_bytes(b"explicit-test-dump")
        with tarfile.open(destination / "panel-data.tar.gz", "w:gz") as archive:
            info = tarfile.TarInfo(member)
            info.size = 7
            archive.addfile(info, io.BytesIO(b"payload"))
        manifest = {"format": 2, "complete": True, "image": "sha256:" + "a" * 64,
                    "created_at": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
                    "sha256": {name: recovery.sha256(destination / name) for name in recovery.FILES}}
        (destination / "manifest.json").write_text(json.dumps(manifest))
        return destination, manifest

    def test_backup_digest_binds_exact_material(self):
        with tempfile.TemporaryDirectory() as directory:
            destination, _ = self.backup(Path(directory))
            self.assertTrue(recovery.verify(destination)["complete"])
            (destination / "database.dump").write_bytes(b"changed")
            with self.assertRaises(recovery.Failure):
                recovery.verify(destination)

    def test_archive_traversal_rejected_even_with_matching_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            destination, _ = self.backup(Path(directory), member="../../outside")
            with self.assertRaises(recovery.Failure):
                recovery.verify(destination)

    def test_symbolic_material_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            destination, _ = self.backup(Path(directory))
            (destination / "database.dump").unlink()
            (destination / "database.dump").symlink_to(destination / "environment")
            with self.assertRaises(recovery.Failure):
                recovery.verify(destination)

    def test_retention_keeps_latest_dependency_and_active_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            latest, manifest = self.backup(base, "latest")
            dependency, old = self.backup(base, "dependency", days=90)
            active, _ = self.backup(base, "active", days=80)
            removable, _ = self.backup(base, "removable", days=70)
            manifest["dependency_manifest_sha256"] = [hashlib.sha256(recovery.canonical(old)).hexdigest()]
            (latest / "manifest.json").write_text(json.dumps(manifest))
            (active / ".restore-in-use").write_text("test")
            args = argparse.Namespace(backup=base, keep_count=1, keep_days=30, confirm=False)
            self.assertEqual(recovery.retention(args)["paths"], [str(removable)])
            self.assertTrue(removable.exists())
            args.confirm = True
            recovery.retention(args)
            self.assertTrue(latest.exists())
            self.assertTrue(dependency.exists())
            self.assertTrue(active.exists())
            self.assertFalse(removable.exists())

    def test_isolated_restore_generates_credentials_without_source_login_material(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for source in [
                "SINAN_DATABASE_URL=postgres://sinan:TEST_ONLY_userinfo@postgres/sinan?password=TEST_ONLY_query_override\n",
                "SINAN_DATABASE_URL=postgres://sinan@postgres/sinan\n",
                "SINAN_DB_PASSWORD=TEST_ONLY_explicit_legacy\n",
                "SINAN_DATABASE_URL=postgres://sinan:TEST_ONLY_encoded%40password@postgres/sinan\n",
            ]:
                with self.subTest(source=source):
                    (base / "environment").write_text(source)
                    before = recovery.sha256(base / "environment")
                    first = recovery.env_values(base)["SINAN_DB_PASSWORD"]
                    second = recovery.env_values(base)["SINAN_DB_PASSWORD"]
                    self.assertRegex(first, r"^[A-Za-z0-9_-]{43}$")
                    self.assertNotEqual(first, second)
                    self.assertNotIn("TEST_ONLY", first)
                    self.assertNotIn(first, source)
                    self.assertEqual(recovery.sha256(base / "environment"), before)

    def test_restore_uses_the_same_private_destination_password_for_database_and_panel(self):
        class ControlledRestore(recovery.Restore):
            def __init__(self, args, manifest):
                super().__init__(args, manifest)
                self.environments = {}
                self.arguments = []

            def fresh(self):
                return "sha256:" + "b" * 64

            def docker(self, *arguments, **kwargs):
                self.arguments.append(arguments)
                if "--env-file" in arguments:
                    path = Path(arguments[arguments.index("--env-file") + 1])
                    self.environments[arguments[arguments.index("--name") + 1]] = {
                        key: value for key, _, value in (line.partition("=") for line in path.read_text().splitlines())
                    }
                    self_test.assertEqual(path.stat().st_mode & 0o777, 0o600)
                if arguments[-1] == "SHOW server_version_num":
                    return "160000"
                if "_sqlx_migrations" in arguments[-1]:
                    return "[]"
                return ""

            def healthy(self):
                return True

        self_test = self
        with tempfile.TemporaryDirectory() as directory:
            backup, manifest = self.backup(Path(directory))
            source = "SINAN_DATABASE_URL=postgres://source:TEST_ONLY_old@source.example/panel?password=TEST_ONLY_actual\n"
            (backup / "environment").write_text(source)
            args = argparse.Namespace(backup=backup, project=None, port=18080, keyring_file=None)
            controlled = ControlledRestore(args, manifest)
            before = recovery.sha256(backup / "environment")
            controlled.restore()
            password = controlled.environments[controlled.postgres]["POSTGRES_PASSWORD"]
            panel = controlled.environments[controlled.panel]
            destination = urlsplit(panel["SINAN_DATABASE_URL"])
            self.assertEqual(unquote(destination.password), password)
            self.assertEqual(destination.hostname, "postgres")
            self.assertEqual(destination.path, "/sinan")
            self.assertNotIn("TEST_ONLY", password)
            self.assertFalse(any("TEST_ONLY_old" in str(arguments) or "TEST_ONLY_actual" in str(arguments) or password in str(arguments) for arguments in controlled.arguments))
            self.assertEqual(recovery.sha256(backup / "environment"), before)
            self.assertTrue(controlled.checks["database_restore"])
            self.assertTrue(controlled.checks["panel_health"])


if __name__ == "__main__":
    unittest.main()
