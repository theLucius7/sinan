#!/usr/bin/env python3
"""Exercise the real management CLI with an isolated Docker command fixture."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/panel.py"
FAKE_DOCKER = r'''
import json, os, sys
args = sys.argv[1:]
assert "SINAN_ADMIN_PASSWORD" not in os.environ
with open(os.environ["PANEL_TEST_LOG"], "a") as output:
    output.write(json.dumps(args) + "\n")
if "ps" in args and "--services" in args:
    print("postgres\npanel")
elif args[:2] == ["ps", "-aq"]:
    print("existing-project-container" if os.environ.get("PANEL_TEST_PROJECT_CONTAINER") else "")
elif "ps" in args and "-aq" in args:
    print("existing" if os.environ.get("PANEL_TEST_EXISTING") else "")
elif "volume" in args:
    print("existing-volume" if os.environ.get("PANEL_TEST_VOLUME") or os.environ.get("PANEL_TEST_PANEL_VOLUME") and "label=com.docker.compose.volume=postgres-data" not in args else "")
elif "pg_dump" in args:
    if os.environ.get("PANEL_TEST_FAIL"):
        print("private-database-password", file=sys.stderr)
        sys.exit(7)
    sys.stdout.buffer.write(b"PGDMP-fixture")
elif "psql" in args:
    statement = args[-1]
    if "FROM _sqlx_migrations WHERE success" in statement:
        print(json.dumps([{"version": 1, "checksum": "a" * 96},
                          {"version": 54, "checksum": "b" * 96}]))
    elif statement == "SHOW server_version_num":
        print("160015")
    elif "FROM credential_entries" in statement:
        print(os.environ.get("PANEL_TEST_KEY_IDS", "[]"))
    else:
        raise SystemExit("fixture rejects unexpected database statement")
elif "stop" in args and os.environ.get("PANEL_TEST_STOP_FAIL"):
    sys.exit(9)
elif "run" in args:
    sys.stdout.buffer.write(b"fixture-archive")
elif "images" in args:
    print("sha256:test-image")
'''


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.log = self.root / "commands.jsonl"
        binary = self.root / "docker"
        binary.write_text(f"#!{sys.executable}\n" + FAKE_DOCKER)
        binary.chmod(0o700)
        self.env_file = self.root / ".env"
        self.backups = self.root / "backups"
        self.env = {**os.environ, "PATH": f"{self.root}{os.pathsep}{os.environ['PATH']}",
                    "PANEL_TEST_LOG": str(self.log), "SINAN_ADMIN_PASSWORD": "must-not-override-file"}

    def run_cli(self, action, *arguments, **overrides):
        return subprocess.run([sys.executable, str(SCRIPT), action, "--env-file", str(self.env_file),
                               "--backup-dir", str(self.backups), *arguments],
                              env={**self.env, **overrides}, capture_output=True, text=True)

    def init(self):
        result = self.run_cli("init", "--public-url", "https://panel.example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.env_file.read_bytes()

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_init_is_private_repeatable_and_uses_pinned_public_roots(self):
        content = self.init()
        result = self.run_cli("init", "--public-url", "https://other.example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.env_file.read_bytes(), content)
        values = dict(line.split("=", 1) for line in content.decode().splitlines())
        self.assertEqual(json.loads(values["SINAN_RELEASE_PUBLIC_KEYS"]), json.loads((ROOT / "deploy/release-public-keys.json").read_text()))
        self.assertNotIn(values["SINAN_ADMIN_PASSWORD"], result.stdout + result.stderr)
        self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.commands(), [])

    def test_upgrade_backs_up_before_build_and_preserves_credentials(self):
        content = self.init()
        result = self.run_cli("upgrade")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        index = lambda word: next(i for i, command in enumerate(commands) if word in command)
        self.assertLess(index("stop"), index("pg_dump"))
        self.assertLess(index("pg_dump"), index("run"))
        self.assertLess(index("run"), index("start"))
        self.assertLess(index("start"), index("build"))
        self.assertLess(index("build"), index("up"))
        destination, = self.backups.iterdir()
        manifest = json.loads((destination / "manifest.json").read_text())
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["format"], 2)
        self.assertEqual(manifest["postgres_version_num"], 160015)
        self.assertEqual(manifest["schema_migrations"], [
            {"version": 1, "checksum": "a" * 96},
            {"version": 54, "checksum": "b" * 96},
        ])
        self.assertEqual(manifest["required_key_ids"], [])
        self.assertFalse(manifest["keyring_included"])
        self.assertFalse(manifest["node_data_included"])
        for filename, digest in manifest["sha256"].items():
            path = destination / filename
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((destination / "environment").read_bytes(), content)
        self.assertEqual(self.env_file.read_bytes(), content)
        self.assertFalse(any("--volumes" in command for command in commands))

    def test_backup_keeps_required_key_id_and_independent_reference_without_copying_keyring(self):
        self.init()
        private = 'SINAN_CREDENTIAL_KEYS={"TEST_ONLY-key":"TEST_ONLY private master key sentinel"}\nSINAN_CREDENTIAL_CURRENT_KEY=TEST_ONLY-key\n'
        reference = "TEST_ONLY independent offline keyring location"
        with self.env_file.open("a") as environment:
            environment.write(private + f"SINAN_BACKUP_KEYRING_REFERENCE={reference}\n")
        content = self.env_file.read_bytes()
        result = self.run_cli("backup", PANEL_TEST_KEY_IDS='["TEST_ONLY-key"]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.env_file.read_bytes(), content)
        destination, = self.backups.iterdir()
        manifest = json.loads((destination / "manifest.json").read_text())
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["required_key_ids"], ["TEST_ONLY-key"])
        self.assertEqual(manifest["keyring_reference"], reference)
        self.assertFalse(manifest["keyring_included"])
        backup_environment = (destination / "environment").read_text()
        self.assertNotIn("SINAN_CREDENTIAL_KEYS", backup_environment)
        self.assertNotIn("SINAN_CREDENTIAL_CURRENT_KEY", backup_environment)
        self.assertNotIn("TEST_ONLY private master key sentinel", backup_environment)
        self.assertEqual(backup_environment, content.decode().replace(private, ""))
        for filename, digest in manifest["sha256"].items():
            self.assertEqual(hashlib.sha256((destination / filename).read_bytes()).hexdigest(), digest)
            self.assertEqual((destination / filename).stat().st_mode & 0o777, 0o600)
        self.assertNotIn("TEST_ONLY private master key sentinel", result.stdout + result.stderr)
        self.assertFalse(any("build" in command or "up" in command for command in self.commands()))

    def test_required_backup_keys_without_independent_reference_block_upgrade_and_restore_service(self):
        self.init()
        private = "SINAN_CREDENTIAL_KEYS=TEST_ONLY private master key sentinel\nSINAN_CREDENTIAL_CURRENT_KEY=TEST_ONLY-key\n"
        with self.env_file.open("a") as environment:
            environment.write(private)
        content = self.env_file.read_bytes()
        result = self.run_cli("upgrade", PANEL_TEST_KEY_IDS='["TEST_ONLY-key"]')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SINAN_BACKUP_KEYRING_REFERENCE", result.stderr)
        self.assertEqual(self.env_file.read_bytes(), content)
        destination, = self.backups.iterdir()
        self.assertFalse((destination / "manifest.json").exists())
        self.assertNotIn("TEST_ONLY private master key sentinel", (destination / "environment").read_text())
        self.assertNotIn("TEST_ONLY private master key sentinel", result.stdout + result.stderr)
        commands = self.commands()
        self.assertTrue(any("start" in command for command in commands))
        self.assertFalse(any("build" in command or "up" in command for command in commands))

    def test_failed_backup_restarts_original_service_and_prevents_upgrade(self):
        self.init()
        result = self.run_cli("upgrade", PANEL_TEST_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("private-database-password", result.stdout + result.stderr)
        commands = self.commands()
        self.assertTrue(any("start" in command for command in commands))
        self.assertFalse(any("build" in command or "up" in command for command in commands))
        destination, = self.backups.iterdir()
        self.assertFalse((destination / "manifest.json").exists())

    def test_repeat_install_backs_up_and_orphan_database_volume_blocks_new_install(self):
        content = self.init()
        result = self.run_cli("install", PANEL_TEST_EXISTING="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("pg_dump" in command for command in self.commands()))
        self.assertEqual(self.env_file.read_bytes(), content)
        self.log.write_text("")
        result = self.run_cli("install", PANEL_TEST_VOLUME="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("build" in command or "up" in command for command in self.commands()))

    def test_missing_environment_refuses_existing_project_before_creating_credentials(self):
        for override in ("PANEL_TEST_PROJECT_CONTAINER", "PANEL_TEST_VOLUME"):
            with self.subTest(override=override):
                self.env_file.unlink(missing_ok=True)
                if self.backups.exists():
                    shutil.rmtree(self.backups)
                self.log.write_text("")
                result = self.run_cli("install", "--public-url", "https://panel.example.com", **{override: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.env_file.exists())
                self.assertFalse(self.backups.exists())
                self.assertFalse(any("build" in command or "up" in command for command in self.commands()))

    def test_fresh_install_initializes_only_after_read_only_project_discovery(self):
        result = self.run_cli("install", "--public-url", "https://panel.example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        container = next(command for command in commands if command[:2] == ["ps", "-aq"])
        volumes = next(command for command in commands if command[:2] == ["volume", "ls"])
        self.assertIn("label=com.docker.compose.project=sinan", container)
        self.assertIn("label=com.docker.compose.project=sinan", volumes)
        self.assertFalse(any("com.docker.compose.volume=" in argument for argument in volumes))
        self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)

    def test_orphan_panel_data_with_preserved_environment_requires_recovery(self):
        content = self.init()
        result = self.run_cli("install", PANEL_TEST_PANEL_VOLUME="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.env_file.read_bytes(), content)
        self.assertFalse(any("build" in command or "up" in command for command in self.commands()))

    def test_failed_stop_still_attempts_to_restore_original_service(self):
        self.init()
        result = self.run_cli("backup", PANEL_TEST_STOP_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any("start" in command for command in self.commands()))
        self.assertFalse(any("pg_dump" in command for command in self.commands()))

    def test_doctor_is_read_only_and_start_cannot_implicitly_build(self):
        content = self.init()
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("pg_isready" in command for command in self.commands()))
        self.assertTrue(any("curl" in command for command in self.commands()))
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.env_file.read_bytes(), content)
        result = self.run_cli("start")
        self.assertEqual(result.returncode, 0, result.stderr)
        command = next(command for command in self.commands() if "up" in command)
        self.assertIn("--no-build", command)
        self.assertIn("--no-recreate", command)

    def test_symlink_and_public_environment_are_rejected_before_docker(self):
        content = self.init()
        target = self.root / "actual-env"
        self.env_file.rename(target)
        self.env_file.symlink_to(target)
        self.assertNotEqual(self.run_cli("install").returncode, 0)
        self.assertEqual(target.read_bytes(), content)
        self.env_file.unlink()
        target.rename(self.env_file)
        self.env_file.chmod(0o644)
        self.assertNotEqual(self.run_cli("upgrade").returncode, 0)
        self.assertEqual(self.commands(), [])


if __name__ == "__main__":
    unittest.main()
