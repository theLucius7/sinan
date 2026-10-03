#!/usr/bin/env python3
"""Verify local recovery and typed node/observer CLI failure contracts."""

import argparse
import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


node = load("node_backup", "node-backup.py")
recovery = load("recovery", "recovery.py")
observer = load("observe_panel", "observe-panel.py")
panel = load("panel", "panel.py")


class OperationsCliTests(unittest.TestCase):
    def node_args(self, base):
        session = base / "session"
        session.write_text("test_session_" + "a" * 48)
        session.chmod(0o600)
        return argparse.Namespace(origin="http://127.0.0.1:18080", session_file=session,
                                  recipient="age1" + "a" * 58, server=1,
                                  file=["/etc/example/config.json"], output=base / "node.age", timeout=30)

    def backup(self, base):
        destination = base / "backup"
        destination.mkdir(mode=0o700)
        (destination / "environment").write_text("SINAN_DB_PASSWORD=TEST_ONLY\n")
        (destination / "database.dump").write_bytes(b"TEST_ONLY database")
        with tarfile.open(destination / "panel-data.tar.gz", "w:gz") as archive:
            member = tarfile.TarInfo("artifacts/test")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"test"))
        manifest = {"format": 2, "complete": True, "image": "sha256:" + "a" * 64,
                    "sha256": {name: recovery.sha256(destination / name) for name in recovery.FILES}}
        (destination / "manifest.json").write_text(json.dumps(manifest))
        return destination

    def test_uncertain_node_receipt_never_resubmits(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.node_args(Path(temp))
            for status in ("unknown", "reconciled", "expired", "cancelled"):
                with self.subTest(status=status), patch.object(node.shutil, "which", return_value="age"), \
                        patch.object(node, "api", side_effect=[{"id": "TEST_ONLY operation"}, {"status": status}]) as api:
                    with self.assertRaises(node.Failure):
                        node.capture(args)
                    self.assertEqual(api.call_count, 2)
                    self.assertEqual(sum("body" in call.kwargs for call in api.call_args_list), 1)
                    self.assertFalse(args.output.exists())

    def test_node_hash_mismatch_is_rejected_before_encryption(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.node_args(Path(temp))
            receipt = {"status": "succeeded", "result": {"result": {
                "content": base64.b64encode(b"TEST_ONLY").decode(), "sha256": "0" * 64}}}
            with patch.object(node.shutil, "which", return_value="age"), \
                    patch.object(node, "api", side_effect=[{"id": "TEST_ONLY"}, receipt]), \
                    patch.object(node.subprocess, "run") as encrypt:
                with self.assertRaises(node.Failure):
                    node.capture(args)
                encrypt.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_node_success_captures_exact_bytes_and_private_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.node_args(Path(temp))
            payload = b"TEST_ONLY managed configuration\x00\xff"
            receipt = {"status": "succeeded", "result": {"result": {
                "content": base64.b64encode(payload).decode(), "sha256": hashlib.sha256(payload).hexdigest()}}}
            captured = {}

            def encrypt(command, *, stdout, stderr, timeout):
                with tarfile.open(command[-1], "r:gz") as archive:
                    captured["bytes"] = archive.extractfile("file-000").read()
                    captured["manifest"] = json.load(archive.extractfile("manifest.json"))
                stdout.write(b"TEST_ONLY encrypted fixture")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(node.shutil, "which", return_value="age"), \
                    patch.object(node, "api", side_effect=[{"id": "TEST_ONLY"}, receipt]), \
                    patch.object(node.subprocess, "run", side_effect=encrypt):
                result = node.capture(args)
            self.assertEqual(captured["bytes"], payload)
            self.assertEqual(captured["manifest"]["files"][0]["source_path"], args.file[0])
            self.assertFalse(captured["manifest"]["agent_identity_auto_copied"])
            self.assertFalse(result["multi_file_snapshot"])
            self.assertEqual(args.output.stat().st_mode & 0o777, 0o600)

    def test_node_failed_encryption_removes_only_owned_output(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.node_args(Path(temp))
            payload = b"TEST_ONLY"
            receipt = {"status": "succeeded", "result": {"result": {
                "content": base64.b64encode(payload).decode(), "sha256": hashlib.sha256(payload).hexdigest()}}}
            with patch.object(node.shutil, "which", return_value="age"), \
                    patch.object(node, "api", side_effect=[{"id": "TEST_ONLY"}, receipt]), \
                    patch.object(node.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaises(node.Failure):
                    node.capture(args)
                self.assertFalse(args.output.exists())
            args.output.write_bytes(b"existing independent output")
            with patch.object(node.shutil, "which", return_value="age"), \
                    patch.object(node, "api", side_effect=[{"id": "TEST_ONLY"}, receipt]):
                with self.assertRaises(FileExistsError):
                    node.capture(args)
            self.assertEqual(args.output.read_bytes(), b"existing independent output")

    def test_node_rejects_remote_http_and_api_token_before_request(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.node_args(Path(temp))
            with patch.object(node, "api") as api:
                args.origin = "http://panel.example.com"
                with self.assertRaises(node.Failure):
                    node.capture(args)
                args.origin = "https://panel.example.com"
                args.session_file.write_text("sinan_api_" + "a" * 48)
                with self.assertRaises(node.Failure):
                    node.capture(args)
                api.assert_not_called()

    def test_recovery_invalid_manifest_shape_is_a_controlled_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            backup = self.backup(Path(temp))
            manifest = json.loads((backup / "manifest.json").read_text())
            for value in ([], {"format": 2, "complete": True, "sha256": []},
                          {**manifest, "image": []},
                          {**manifest, "required_key_ids": ["duplicated", "duplicated"]},
                          {**manifest, "required_key_ids": [{}]},
                          {**manifest, "sha256": {**manifest["sha256"], "database.dump": []}}):
                (backup / "manifest.json").write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(recovery.Failure):
                    recovery.verify(backup)

    def test_recovery_keyring_checks_shape_versions_and_real_key_size(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "keyring.json"
            valid = {"current": "fixture", "keys": {"fixture": base64.b64encode(b"x" * 32).decode()}}
            path.write_text(json.dumps(valid))
            path.chmod(0o600)
            self.assertEqual(recovery.recovery_keyring(path, ["fixture"]), valid)
            values = [[], {"current": "fixture", "keys": []},
                      {"current": "missing", "keys": valid["keys"]},
                      {"current": "fixture", "keys": {"fixture": "TEST_ONLY not base64"}},
                      {"current": "fixture", "keys": {"fixture": base64.b64encode(b"short").decode()}},
                      {"current": "injected\nSINAN_LISTEN=x", "keys": {"injected\nSINAN_LISTEN=x": valid["keys"]["fixture"]}}]
            for value in values:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(recovery.Failure):
                        recovery.recovery_keyring(path, ["fixture"])
            path.write_text(json.dumps(valid))
            with self.assertRaises(recovery.Failure):
                recovery.recovery_keyring(path, ["missing"])
            encoded = valid["keys"]["fixture"]
            for duplicate in ('{"current":"fixture","current":"fixture","keys":{"fixture":"' + encoded + '"}}',
                              '{"current":"fixture","keys":{"fixture":"' + encoded + '","fixture":"' + encoded + '"}}'):
                path.write_text(duplicate)
                with self.assertRaises(recovery.Failure):
                    recovery.recovery_keyring(path, ["fixture"])
            excessive = {str(index): encoded for index in range(17)}
            path.write_text(json.dumps({"current": "0", "keys": excessive}))
            with self.assertRaises(recovery.Failure):
                recovery.recovery_keyring(path, ["0"])
            path.write_text(json.dumps(valid))
            path.chmod(0o644)
            with self.assertRaises(recovery.Failure):
                recovery.recovery_keyring(path, ["fixture"])

    def test_recovery_process_start_failure_cleans_owned_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            args = argparse.Namespace(backup=self.backup(base), recipient="age1" + "a" * 58,
                                      output=base / "backup.age")
            with patch.object(recovery.shutil, "which", return_value="age"), \
                    patch.object(recovery.subprocess, "Popen", side_effect=OSError("TEST_ONLY start failure")):
                with self.assertRaises(OSError):
                    recovery.encrypt(args)
                self.assertFalse(args.output.exists())
                args.output = base / "decrypted"
                args.identity = base / "identity"
                args.identity.write_text("TEST_ONLY age identity")
                args.identity.chmod(0o600)
                with self.assertRaises(OSError):
                    recovery.decrypt(args)
                self.assertFalse(args.output.exists())

    def test_existing_restore_marker_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            backup = self.backup(Path(temp))
            marker = backup / ".restore-in-use"
            marker.write_text("another active restore")
            with patch.object(sys, "argv", ["recovery.py", "drill", "--backup", str(backup)]), \
                    patch.object(recovery, "Restore") as restore, redirect_stdout(io.StringIO()):
                self.assertEqual(recovery.main(), 1)
                restore.assert_not_called()
            self.assertEqual(marker.read_text(), "another active restore")

    def test_isolated_health_does_not_claim_host_reachability(self):
        operation = recovery.Restore(argparse.Namespace(project="sinan-recovery-TEST_ONLY".lower(), port=18080), {})
        with patch.object(recovery.urllib.request, "build_opener") as opener, \
                patch.object(operation, "docker", return_value="ok") as docker:
            opener.return_value.open.side_effect = urllib.error.URLError("TEST_ONLY unreachable mapped port")
            self.assertTrue(operation.healthy())
            self.assertFalse(operation.checks["host_loopback_reachable"])
            self.assertEqual(operation.health_source, "isolated_container_loopback")
            self.assertIn(operation.panel, docker.call_args.args)
        with patch.object(recovery.urllib.request, "build_opener") as opener, \
                patch.object(operation, "docker", side_effect=recovery.Failure("TEST_ONLY unavailable app")):
            opener.return_value.open.side_effect = urllib.error.URLError("TEST_ONLY unreachable mapped port")
            self.assertFalse(operation.healthy())

    def test_live_health_cannot_substitute_for_encrypted_material_authentication(self):
        class Health(BaseHTTPRequestHandler):
            acknowledged = False

            def do_GET(self):
                self.send_response(200)
                if self.acknowledged:
                    self.send_header("x-sinan-recovery-material-verified", "true")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Health)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        operation = recovery.Restore(argparse.Namespace(project="sinan-recovery-key-auth", port=server.server_port),
                                     {"required_key_ids": ["same-ID-content-must-be-authenticated"]})
        try:
            with patch.object(operation, "docker", side_effect=recovery.Failure("TEST_ONLY unused fallback")):
                with self.assertRaises(recovery.Failure):
                    operation.healthy()
                self.assertFalse(operation.checks.get("keyring_authenticated", False))
                Health.acknowledged = True
                self.assertTrue(operation.healthy())
                self.assertTrue(operation.checks["keyring_authenticated"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        fallback = recovery.Restore(argparse.Namespace(project="sinan-recovery-key-fallback", port=18080),
                                    {"required_key_ids": ["fixture"]})
        with patch.object(recovery.urllib.request, "build_opener") as opener, \
                patch.object(fallback, "docker", return_value="HTTP/1.1 200 OK\r\n\r\nok"):
            opener.return_value.open.side_effect = urllib.error.URLError("TEST_ONLY host unavailable")
            with self.assertRaises(recovery.Failure):
                fallback.healthy()
        with patch.object(recovery.urllib.request, "build_opener") as opener, \
                patch.object(fallback, "docker", return_value="HTTP/1.1 200 OK\r\nx-sinan-recovery-material-verified: true\r\n\r\nok"):
            opener.return_value.open.side_effect = urllib.error.URLError("TEST_ONLY host unavailable")
            self.assertTrue(fallback.healthy())
            self.assertTrue(fallback.checks["keyring_authenticated"])
            self.assertFalse(fallback.checks["host_loopback_reachable"])

    def test_created_panel_is_tracked_when_start_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            backup = self.backup(Path(temp))
            args = argparse.Namespace(project="sinan-recovery-start-failure", backup=backup,
                                      keyring_file=None, port=18080)
            manifest = {"image": "sha256:" + "a" * 64, "schema_migrations": [], "postgres_version_num": 160015}
            operation = recovery.Restore(args, manifest)
            calls = []

            def docker(*arguments, **kwargs):
                calls.append(arguments)
                if arguments[:2] == ("start", operation.panel) or (arguments[0] == "run" and operation.panel in arguments):
                    raise recovery.Failure("TEST_ONLY container creation succeeded but start failed")
                if "inspect" in arguments:
                    return operation.project
                if "SHOW server_version_num" in arguments:
                    return "160015"
                if any("FROM _sqlx_migrations" in value for value in arguments):
                    return "[]"
                return "TEST_ONLY"

            with patch.object(operation, "fresh", return_value="sha256:" + "b" * 64), \
                    patch.object(operation, "docker", side_effect=docker):
                with self.assertRaises(recovery.Failure):
                    operation.restore()
                self.assertIn(operation.panel, operation.created["containers"])
                self.assertTrue(operation.cleanup())
            self.assertIn(("rm", "-f", operation.panel), calls)

    def test_observer_redirect_does_not_forward_management_token(self):
        self.assertIsNone(observer.NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://outside.example.com"))

    def test_panel_backup_quiesces_and_restores_same_container_after_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            env_file = base / "environment"
            env_file.write_text("SINAN_DB_PASSWORD=TEST_ONLY\nSINAN_CREDENTIAL_KEYS=TEST_ONLY_DO_NOT_BACKUP\nSINAN_CREDENTIAL_CURRENT_KEY=TEST_ONLY\n")
            args = argparse.Namespace(env_file=env_file, backup_dir=base / "backups", project="TEST_ONLY")
            operation = panel.Panel(args)
            calls = []

            def compose(*arguments, **kwargs):
                calls.append(arguments)
                if arguments[:1] == ("ps",):
                    return "postgres\npanel"
                if "pg_dump" in arguments:
                    kwargs["output"].write(b"TEST_ONLY database")
                if arguments[:1] == ("run",):
                    raise panel.Failure("TEST_ONLY data capture failure")
                return ""

            with patch.object(operation, "compose", side_effect=compose), redirect_stdout(io.StringIO()):
                with self.assertRaises(panel.Failure):
                    operation.backup()
            self.assertIn(("stop", "panel"), calls)
            self.assertEqual(calls[-1], ("start", "panel"))
            backup = next(args.backup_dir.iterdir())
            self.assertNotIn("SINAN_CREDENTIAL_", (backup / "environment").read_text())
            self.assertFalse((backup / "manifest.json").exists())

    def test_node_api_blocks_real_loopback_redirect(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers.get("Cookie")))
                self.send_response(302)
                self.send_header("Location", "/would_receive_token")
                self.end_headers()

            def log_message(self, *arguments):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(node.Failure):
                node.api(f"http://127.0.0.1:{server.server_port}", "TEST_ONLY", "/initial")
            self.assertEqual(requests, [("/initial", "sinan_session=TEST_ONLY")])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    @unittest.skipUnless(shutil.which("openssl"), "local TLS fixture needs openssl")
    def test_observer_tls_fixture_preserves_observation_and_blocks_redirect(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            certificate, key = base / "certificate.pem", base / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(certificate), "-days", "1",
                            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            requests = []
            mode = {"redirect": False}

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    requests.append(("GET", self.path, self.headers.get("Authorization")))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

                def do_POST(self):
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    requests.append(("POST", self.path, self.headers.get("Authorization"), body))
                    if mode["redirect"]:
                        self.send_response(302)
                        self.send_header("Location", "/would_receive_token")
                        self.end_headers()
                    else:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"id":"TEST_ONLY receipt"}')

                def log_message(self, *arguments):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            token = "sinan_api_" + "a" * 48
            argv = ["observe-panel.py", "--panel-origin", f"https://127.0.0.1:{server.server_port}",
                    "--observer-name", "TEST_ONLY loopback TLS"]
            try:
                with patch.dict(os.environ, {"SSL_CERT_FILE": str(certificate), "NO_PROXY": "127.0.0.1",
                                             "SINAN_OBSERVER_API_TOKEN": token}), patch.object(sys, "argv", argv):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        observer.main()
                    value = json.loads(output.getvalue())
                    self.assertTrue(value["observation"]["available"])
                    self.assertTrue(value["observation"]["evidence"]["tls_verification"])
                    self.assertIsNone(requests[0][2])
                    self.assertEqual(requests[1][2], "Bearer " + token)
                    mode["redirect"] = True
                    output = io.StringIO()
                    with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
                        observer.main()
                    self.assertEqual(stopped.exception.code, 2)
                    failed = json.loads(output.getvalue())
                    self.assertTrue(failed["observation"]["available"])
                    self.assertEqual(failed["delivery"], "failed")
                    self.assertNotIn("receipt", failed)
                    self.assertFalse(any(request[1] == "/would_receive_token" for request in requests))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    @unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "real age roundtrip needs official tools")
    def test_actual_age_roundtrip_and_wrong_key_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            identity = base / "identity"
            subprocess.run(["age-keygen", "-o", str(identity)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            identity.chmod(0o600)
            recipient = next(line.removeprefix("# public key: ") for line in identity.read_text().splitlines()
                             if line.startswith("# public key: "))
            backup = self.backup(base)
            args = argparse.Namespace(backup=backup, recipient=recipient, output=base / "backup.age")
            result = recovery.encrypt(args)
            self.assertTrue(result["encrypted"])
            self.assertEqual(args.output.stat().st_mode & 0o777, 0o600)
            decrypted = base / "decrypted"
            recovery.decrypt(argparse.Namespace(backup=args.output, identity=identity, output=decrypted))
            for name in (*recovery.FILES, "manifest.json"):
                self.assertEqual((backup / name).read_bytes(), (decrypted / name).read_bytes())
            wrong_identity = base / "wrong-identity"
            subprocess.run(["age-keygen", "-o", str(wrong_identity)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            wrong_identity.chmod(0o600)
            wrong_output = base / "wrong-decrypted"
            with self.assertRaises((recovery.Failure, tarfile.TarError)):
                recovery.decrypt(argparse.Namespace(backup=args.output, identity=wrong_identity, output=wrong_output))
            self.assertFalse(wrong_output.exists())

    @unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "typed REST backup fixture needs official age tools")
    def test_actual_node_http_receipt_and_encrypted_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            args = self.node_args(base)
            identity = base / "identity"
            subprocess.run(["age-keygen", "-o", str(identity)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            args.recipient = next(line.removeprefix("# public key: ") for line in identity.read_text().splitlines()
                                  if line.startswith("# public key: "))
            payload = b"TEST_ONLY real REST and age fixture\x00\xff"
            requests = []

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    requests.append(("POST", self.path, body, self.headers.get("Origin"), self.headers.get("Cookie")))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"id":"TEST_ONLY"}')

                def do_GET(self):
                    requests.append(("GET", self.path))
                    result = {"status": "succeeded", "result": {"result": {
                        "content": base64.b64encode(payload).decode(), "sha256": hashlib.sha256(payload).hexdigest()}}}
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps(result).encode())

                def log_message(self, *arguments):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            args.origin = f"http://127.0.0.1:{server.server_port}"
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = node.capture(args)
                self.assertTrue(result["passed"])
                self.assertEqual(len(requests), 2)
                self.assertEqual(requests[0][2], {"kind": "file_read", "path": args.file[0]})
                self.assertEqual(requests[0][3], args.origin)
                self.assertEqual(requests[0][4], "sinan_session=" + args.session_file.read_text())
                plain = subprocess.run(["age", "--decrypt", "--identity", str(identity), str(args.output)],
                                       capture_output=True, check=True, timeout=30).stdout
                with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as archive:
                    self.assertEqual(archive.extractfile("file-000").read(), payload)
                    manifest = json.load(archive.extractfile("manifest.json"))
                    self.assertEqual(manifest["files"][0]["operation_id"], "TEST_ONLY")
                    self.assertFalse(manifest["agent_identity_auto_copied"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
