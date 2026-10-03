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

    def test_native_environment_reads_encoded_database_password(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "environment").write_text("SINAN_DATABASE_URL=postgres://sinan:example%40password@postgres/sinan\n")
            self.assertEqual(recovery.env_values(base)["SINAN_DB_PASSWORD"], "example@password")


if __name__ == "__main__":
    unittest.main()
