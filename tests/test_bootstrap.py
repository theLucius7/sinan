#!/usr/bin/env python3
"""Bootstrap network boundaries and independently provisioned trust file tests."""

import io
import importlib.util
import http.server
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/protocol/tests/fixtures"
if not FIXTURES.is_dir():
    FIXTURES = ROOT / "fixtures"
sys.path.insert(0, str(ROOT / "tools"))
import bootstrap
import release

RENDER_SPEC = importlib.util.spec_from_file_location("render_bootstrap", ROOT / "tools/render-bootstrap.py")
RENDER = importlib.util.module_from_spec(RENDER_SPEC)
RENDER_SPEC.loader.exec_module(RENDER)


class Response(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url
        self.status = 200
        self.headers = {}


class BootstrapTests(unittest.TestCase):
    def test_actual_platform_detection_uses_cpu_os_and_libc(self):
        for system, machine, libc, target in (
                ("Linux", "x86_64", "glibc", "linux-gnu-amd64"),
                ("Linux", "aarch64", "musl", "linux-musl-arm64"),
                ("Darwin", "arm64", "", "macos-arm64"),
                ("FreeBSD", "amd64", "", "freebsd-amd64"),
                ("FreeBSD", "aarch64", "", "freebsd-arm64")):
            with self.subTest(target=target), patch.object(bootstrap.platform, "system", return_value=system), \
                    patch.object(bootstrap.platform, "machine", return_value=machine), \
                    patch.object(bootstrap.platform, "libc_ver", return_value=(libc, "")):
                self.assertEqual(bootstrap.host_target(), target)
        for system, machine in (("Darwin", "x86_64"), ("Linux", "riscv64"), ("Windows", "amd64")):
            with self.subTest(system=system), patch.object(bootstrap.platform, "system", return_value=system), \
                    patch.object(bootstrap.platform, "machine", return_value=machine), self.assertRaises(ValueError):
                bootstrap.host_target()

    def test_abi_selection_never_installs_gnu_on_musl_or_another_cpu(self):
        self.assertEqual(bootstrap.compatible_targets("linux-musl-arm64"), ["linux-musl-arm64", "arm64"])
        self.assertEqual(bootstrap.compatible_targets("linux-gnu-amd64", "linux-gnu-amd64"),
                         ["linux-gnu-amd64", "linux-musl-amd64", "amd64"])
        for actual, requested in (("linux-musl-arm64", "linux-gnu-arm64"),
                                  ("linux-gnu-arm64", "linux-musl-amd64"),
                                  ("macos-arm64", "freebsd-arm64")):
            with self.subTest(actual=actual, requested=requested), self.assertRaises(ValueError):
                bootstrap.compatible_targets(actual, requested)

    def test_native_selection_rejects_prerelease_before_enrollment(self):
        for actual in ("macos-arm64", "freebsd-amd64"):
            with self.subTest(target=actual), self.assertRaises(bootstrap.IncompatibleRelease):
                bootstrap.select_artifact({}, "0.3.0-rc.1", actual)

    def test_signed_selection_requires_real_platform_version_and_protocol(self):
        metadata = {"tag": "agent-v0.3.0", "protocol_min": 1, "protocol_max": 2, "artifacts": [
            {"name": "agent", "version": "0.3.0", "arch": "linux-gnu-arm64", "format": "raw",
             "binary_name": "sinan-agent", "archive_size": 1, "binary_size": 1},
            {"name": "agent", "version": "0.3.0", "arch": "macos-arm64", "format": "raw",
             "binary_name": "sinan-agent", "archive_size": 1, "binary_size": 1},
        ]}
        self.assertEqual(bootstrap.select_artifact(metadata, "0.3.0", "macos-arm64")["arch"], "macos-arm64")
        with self.assertRaises(bootstrap.IncompatibleRelease):
            bootstrap.select_artifact(metadata, "0.3.0", "linux-musl-arm64")
        metadata["protocol_min"] = 2
        with self.assertRaises(bootstrap.IncompatibleRelease):
            bootstrap.select_artifact(metadata, "0.3.0", "macos-arm64")
        metadata["protocol_min"] = 1
        with self.assertRaises(ValueError):
            bootstrap.select_artifact(metadata, "0.4.0", "macos-arm64")

    def test_newly_signed_historical_bytes_do_not_gain_missing_installation_commands(self):
        for version in ("0.1.0", "0.2.0"):
            metadata = {"tag":"agent-v" + version, "protocol_min":1, "protocol_max":1,
                        "artifacts":[{"name":"agent", "version":version, "arch":"amd64", "format":"raw",
                                      "binary_name":"sinan-agent", "archive_size":1, "binary_size":1}]}
            with self.subTest(version=version), patch.object(bootstrap.subprocess, 'run') as execute, \
                    self.assertRaisesRegex(bootstrap.IncompatibleRelease, "历史 Agent 不支持当前标准安装与服务合同"):
                bootstrap.select_artifact(metadata, version, "linux-gnu-amd64")
            execute.assert_not_called()
        # An independent supported version remains selectable regardless of the
        # panel package version. Execution still requires normal proof/CLI checks.
        metadata = {"tag":"agent-v0.4.0", "protocol_min":1, "protocol_max":1,
                    "artifacts":[{"name":"agent", "version":"0.4.0", "arch":"amd64", "format":"raw",
                                  "binary_name":"sinan-agent", "archive_size":1, "binary_size":1}]}
        self.assertEqual(bootstrap.select_artifact(metadata, "0.4.0", "linux-gnu-amd64")["version"], "0.4.0")

    def test_latest_catalog_is_data_only_and_uses_numeric_stable_order(self):
        versions = [{"version": v, "tag": "agent-v" + v, "targets": ["arm64"],
                     "protocol_min": 9, "protocol_max": 9}
                    for v in ("0.9.0", "0.10.0", "2.0.0-beta")]
        url = "https://panel.example.com/api/bootstrap/versions?token=fixture&target=linux-musl-arm64"
        with patch.object(bootstrap, "panel_opener") as opener:
            opener.return_value.open.return_value = Response(json.dumps({"versions": versions}).encode(), url)
            candidates = bootstrap.catalog("https://panel.example.com", "fixture", "linux-musl-arm64", "latest")
        self.assertEqual([item["version"] for item in candidates], ["0.10.0", "0.9.0"])
        self.assertEqual(opener.return_value.open.call_args.args[0], url)

    def test_explicit_catalog_failure_distinguishes_compatibility_without_exposing_panel_data(self):
        private = "PRIVATE_TOKEN@private-panel.example.test/install?token=secret"
        for code, message, expected in (
                (409, "所选 Agent 版本尚未导入已校验的签名 Release", "尚未导入"),
                (409, "所选 Agent 版本与当前面板协议不兼容，请选择兼容的已签名版本", "协议不兼容"),
                (409, "所选历史 Agent 不支持当前标准安装与服务合同：" + private, "历史 Agent 不支持"),
                (409, "所选 Agent 版本不包含该平台可安装的制品，请核对平台、架构及稳定版本要求", "本机平台"),
                (401, private, "令牌无效或已过期"),
                (500, private, "无法获取接入版本"),
                (409, private, "无法获取接入版本"),
                (409, {"private": private}, "无法获取接入版本")):
            error = urllib.error.HTTPError("https://" + private, code, private, {},
                                           io.BytesIO(json.dumps({"error": message}).encode()))
            with self.subTest(code=code, expected=expected), patch.object(bootstrap, "panel_opener") as opener:
                opener.return_value.open.side_effect = error
                with self.assertRaisesRegex(ValueError, expected) as refusal:
                    bootstrap.catalog("https://panel.example.com", "TEST_ONLY token", "linux-musl-amd64", "0.1.0")
                self.assertNotIn(private, str(refusal.exception))
                self.assertIsNone(refusal.exception.__cause__)
                self.assertEqual(opener.return_value.open.call_count, 1)

    def test_catalog_refusal_body_shares_deadline_and_has_a_size_limit(self):
        for payload in (b"{" + b"x" * 8192, b"not-json", b'[]'):
            error = urllib.error.HTTPError("https://panel.example.com", 409, "refused", {}, io.BytesIO(payload))
            self.assertIn("无法获取接入版本", bootstrap.catalog_refusal(error, time.monotonic() + 1))
        error = urllib.error.HTTPError("https://panel.example.com", 409, "refused", {},
                                       io.BytesIO(b'{"error":"private"}'))
        self.assertIn("无法获取接入版本", bootstrap.catalog_refusal(error, time.monotonic() - 1))

    def test_slow_private_catalog_cannot_renew_its_total_deadline(self):
        payload = json.dumps({"versions": [{"version": "0.3.0", "tag": "agent-v0.3.0",
                                          "targets": ["arm64"]}]}).encode()
        stop = threading.Event()

        class SlowCatalog(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    for byte in payload:
                        if stop.wait(0.01):
                            break
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_arguments):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowCatalog)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        started = time.monotonic()
        try:
            with patch.object(bootstrap, "CATALOG_BUDGET_SECONDS", 0.15), \
                    self.assertRaises((ValueError, OSError)) as refusal:
                bootstrap.catalog(f"http://127.0.0.1:{server.server_port}",
                                  "TEST_ONLY_catalog_token", "linux-musl-arm64", "latest")
            self.assertLess(time.monotonic() - started, 1)
            self.assertNotIn("TEST_ONLY_catalog_token", str(refusal.exception))
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_agent_download_is_bounded_github_only_and_rejects_tampering_before_execution(self):
        item = {"version": "0.3.0", "arch": "freebsd-arm64", "archive_size": 3,
                "binary_size": 3, "format": "raw", "asset_name": "agent-0.3.0-freebsd-arm64",
                "binary_sha256": release.digest(b"raw")}
        url = "https://github.com/theLucius7/sinan/releases/download/agent-v0.3.0/agent-0.3.0-freebsd-arm64"
        with tempfile.TemporaryDirectory() as directory:
            for data, response_url in ((b"evil", url), (b"ra", url), (b"bad", url), (b"raw", "https://panel.example.com/agent")):
                target = Path(directory) / "agent"
                with self.subTest(data=data), patch.object(bootstrap, "github_opener") as opener, \
                        patch.object(bootstrap, "panel_opener") as panel:
                    opener.return_value.open.return_value = Response(data, response_url)
                    with self.assertRaises(ValueError):
                        bootstrap.download_agent(item, target)
                    self.assertFalse(target.exists())
                    panel.assert_not_called()
            target = Path(directory) / "valid"
            with patch.object(bootstrap, "github_opener") as opener:
                opener.return_value.open.return_value = Response(b"raw", url)
                bootstrap.download_agent(item, target)
                self.assertEqual(opener.return_value.open.call_args.args[0], url)
                self.assertNotIn("token", opener.return_value.open.call_args.args[0])
            self.assertEqual(target.read_bytes(), b"raw")
            mirror = "https://mirror.example.com"
            with patch.object(bootstrap, "github_opener") as opener:
                opener.return_value.open.return_value = Response(b"raw", mirror + "/" + url)
                bootstrap.download_agent(item, Path(directory) / "mirrored", mirror)
                self.assertEqual(opener.return_value.open.call_args.args[0], mirror + "/" + url)
                self.assertEqual(opener.call_args.args, (mirror,))
            offline = Path(directory) / "offline"
            offline.mkdir()
            (offline / item["asset_name"]).write_bytes(b"raw")
            with patch.object(bootstrap, "github_opener") as opener:
                bootstrap.download_agent(item, Path(directory) / "copied", release_dir=offline)
                opener.assert_not_called()
            (offline / item["asset_name"]).write_bytes(b"bad")
            with self.assertRaises(ValueError):
                bootstrap.download_agent(item, Path(directory) / "rejected", release_dir=offline)
            self.assertFalse((Path(directory) / "rejected").exists())

    def test_native_preflight_rejects_download_and_cached_state_before_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "0.3.0"
            bundle.mkdir()
            with patch.object(bootstrap, "download_agent", side_effect=ValueError("tampered")), \
                    patch.object(bootstrap, "checked_agent") as execute, self.assertRaises(ValueError):
                bootstrap.install_native(bundle, "https://panel.example.com", "fixture", {}, "macos-arm64")
            execute.assert_not_called()

    def test_failed_native_upgrade_restores_configuration_and_previous_service(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "0.3.0"
            bundle.mkdir()
            configuration = root / "config/agent.toml"
            configuration.parent.mkdir()
            previous = b'panel_url="https://old.example.com"\n'
            configuration.write_bytes(previous)
            command = root / "bin/sinan-agent"
            command.parent.mkdir()
            agent_root = root / "core"
            old = agent_root / "0.2.0"
            old.mkdir(parents=True)
            old_agent = old / "sinan-agent"
            old_agent.write_bytes(b"TEST ONLY old signed Agent")
            (agent_root / "current").symlink_to(old)
            calls = []

            def execute(agent, arguments):
                calls.append((Path(agent), arguments))
                if "enroll" in arguments:
                    configuration.write_bytes(b'panel_url="https://new.example.com"\n')
                if "install-service" in arguments and Path(agent) == bundle / "sinan-agent":
                    raise ValueError("TEST ONLY activation failure")

            def download(_item, target, _mirror, _release_dir):
                target.write_bytes(b"TEST ONLY already independently validated new Agent")

            with patch.object(bootstrap, "download_agent", side_effect=download), \
                    patch.object(bootstrap, "checked_agent", side_effect=execute), \
                    patch.object(bootstrap, "require_protected_file"), \
                    patch.object(bootstrap, "native_paths", return_value=(configuration, command, root / "var", agent_root)), \
                    self.assertRaisesRegex(ValueError, "activation failure"):
                bootstrap.install_native(bundle, "https://panel.example.com", "fixture", {}, "freebsd-amd64")
            self.assertEqual(configuration.read_bytes(), previous)
            self.assertEqual(calls[-1][0], old_agent.resolve(strict=True))
            self.assertIn("install-service", calls[-1][1])
            self.assertEqual(calls[0][1][0], "verify-installed")
            self.assertIn("verify-cache", calls[1][1])
            self.assertFalse(command.exists())

    def test_failed_first_enrollment_can_retry_with_the_same_private_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "0.3.0"
            bundle.mkdir()
            configuration = root / "config/agent.toml"
            configuration.parent.mkdir()
            identity = configuration.parent / "identity"
            command = root / "bin/sinan-agent"
            command.parent.mkdir()
            agent_root = root / "core"
            key = b"K" * 32
            attempts = []

            def execute(_agent, arguments):
                if "enroll" not in arguments:
                    return
                self.assertIn("--token=-TEST_ONLY_" + str(len(attempts) + 1), arguments)
                self.assertNotIn("--token", arguments)
                identity.mkdir(mode=0o700, exist_ok=True)
                key_path = identity / "device.key"
                if not key_path.exists():
                    key_path.write_bytes(key)
                    key_path.chmod(0o600)
                    (identity / "panel_origin").write_text("https://panel.example.com")
                attempts.append(key_path.read_bytes())
                if len(attempts) == 1:
                    raise ValueError("TEST ONLY enrollment HTTP failure")
                configuration.write_text('panel_url="https://panel.example.com"\n')

            def download(_item, target, _mirror, _release_dir):
                target.write_bytes(b"TEST ONLY already independently validated new Agent")

            with patch.object(bootstrap, "download_agent", side_effect=download), \
                    patch.object(bootstrap, "checked_agent", side_effect=execute), \
                    patch.object(bootstrap, "require_protected_file"), \
                    patch.object(bootstrap, "native_paths", return_value=(configuration, command, root / "var", agent_root)):
                with self.assertRaisesRegex(ValueError, "HTTP failure"):
                    bootstrap.install_native(bundle, "https://panel.example.com", "-TEST_ONLY_1", {}, "macos-arm64")
                self.assertFalse(configuration.exists())
                bootstrap.install_native(bundle, "https://panel.example.com", "-TEST_ONLY_2", {}, "macos-arm64")
            self.assertEqual(attempts, [key, key])
            self.assertTrue(configuration.exists())
            self.assertTrue(command.is_symlink())
            (identity / "panel_origin").write_text("https://other.example.com")
            with patch.object(bootstrap, "require_protected_file"), self.assertRaises(ValueError):
                bootstrap.validate_partial_identity(identity, "https://panel.example.com")
            (identity / "panel_origin").write_text("https://panel.example.com")
            (identity / "unknown").write_bytes(b"unexpected")
            with patch.object(bootstrap, "require_protected_file"), self.assertRaises(ValueError):
                bootstrap.validate_partial_identity(identity, "https://panel.example.com")
            (identity / "unknown").unlink()
            (identity / "device.key").unlink()
            with patch.object(bootstrap, "require_protected_file"):
                bootstrap.validate_partial_identity(identity, "https://panel.example.com")
            (identity / "server_id").write_text("1")
            with patch.object(bootstrap, "require_protected_file"), self.assertRaises(ValueError):
                bootstrap.validate_partial_identity(identity, "https://panel.example.com")

    def test_official_standalone_bootstrap_matches_all_sources_and_refuses_test_root(self):
        self.assertEqual((ROOT / "deploy/bootstrap.sh").read_text(), RENDER.render())
        with self.assertRaises(ValueError):
            RENDER.render(trusted_keys=FIXTURES / "public-keys.json")
        with self.assertRaises(ValueError):
            RENDER.render(test_installer="#!/bin/sh\nexit 0\n")

    @unittest.skipUnless(os.getuid() == 0, "unprivileged bootstrap entry test requires root to drop privileges")
    def test_direct_unprivileged_entry_refuses_before_sudo_or_installation(self):
        def unprivileged():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            script = root / "bootstrap.sh"
            script.write_text((ROOT / "deploy/bootstrap.sh").read_text())
            script.chmod(0o644)
            result = subprocess.run(["/bin/sh", "-x", str(script)], capture_output=True,
                                    check=False, timeout=10, preexec_fn=unprivileged)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("请以 root 执行此脚本".encode(), result.stderr)
            self.assertNotIn(b"sudo", result.stderr)
            self.assertNotIn(b"mktemp", result.stderr)
            self.assertEqual(result.stdout, b"")

    def test_actual_trusted_installer_requires_unique_preloaded_agent_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            installer = Path(directory) / "trusted-install.sh"
            installer.write_bytes(b"#!/bin/sh\n# Old trusted executor\n")
            with self.assertRaisesRegex(ValueError, "preloaded-GitHub Agent contract"):
                bootstrap.require_preloaded_installer(installer)
            marker = bootstrap.PRELOADED_INSTALLER_MARKER + b"\n"
            installer.write_bytes(b"#!/bin/sh\n" + marker)
            bootstrap.require_preloaded_installer(installer)
            installer.write_bytes(b"#!/bin/sh\n" + marker + marker)
            with self.assertRaises(ValueError):
                bootstrap.require_preloaded_installer(installer)

    def test_linux_enrollment_command_preserves_token_with_option_prefix(self):
        template = (ROOT / "deploy/install.sh.tmpl").read_text()
        command = next(line for line in template.splitlines() if '" enroll --panel ' in line)
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "fixture-agent"
            agent.write_text("#!" + sys.executable + "\n" +
                             "import argparse, json\n"
                             "parser = argparse.ArgumentParser()\n"
                             "parser.add_argument('command')\n"
                             "parser.add_argument('--panel')\n"
                             "parser.add_argument('--token')\n"
                             "print(json.dumps(vars(parser.parse_args())))\n")
            agent.chmod(0o755)
            code = "PANEL=$1\nTOKEN=$2\nVERSION=0.3.0\n" + command.replace(
                '"/opt/sinan/core/$VERSION/sinan-agent"', '"$3"')
            result = subprocess.run(["/bin/sh", "-c", code, "linux-enrollment-fixture",
                                     "https://panel.example.com", "-TEST_ONLY_token", str(agent)],
                                    capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["token"], "-TEST_ONLY_token")

    def test_slow_proof_and_agent_streams_have_total_budget_and_leave_no_partial_file(self):
        class SlowResponse(Response):
            def read1(self, size):
                return b"x"

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "agent"
            entry = {"version": "0.3.0", "archive_size": 1024, "binary_size": 1024,
                     "format": "raw", "asset_name": "agent-0.3.0-linux-musl-amd64",
                     "binary_sha256": release.digest(b"x" * 1024)}
            for agent in (False, True):
                with self.subTest(agent=agent), patch.object(bootstrap, "github_opener") as opener, \
                        patch.object(bootstrap.time, "monotonic", side_effect=[0, 0, 200, 200, 301]):
                    opener.return_value.open.return_value = SlowResponse(b"", "https://github.com/asset")
                    with self.assertRaisesRegex(ValueError, "total time budget"):
                        if agent:
                            bootstrap.download_agent(entry, target)
                        else:
                            bootstrap.download("https://github.com/allowed", "agent", target, 1024)
                    self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 20)
                self.assertFalse(target.exists())

    def test_proof_and_agent_socket_timeout_use_remaining_file_budget(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "agent"
            entry = {"version": "0.3.0", "archive_size": 6, "binary_size": 6,
                     "format": "raw", "asset_name": "agent-0.3.0-linux-musl-amd64",
                     "binary_sha256": release.digest(b"signed")}
            for agent in (False, True):
                response = Response(b"signed", "https://github.com/asset")
                sock = Mock()
                response.fp = SimpleNamespace(raw=SimpleNamespace(_sock=sock))
                with self.subTest(agent=agent), patch.object(bootstrap, "github_opener") as opener, \
                        patch.object(bootstrap.time, "monotonic", side_effect=[0, 295, 296, 297, 298]):
                    opener.return_value.open.return_value = response
                    if agent:
                        bootstrap.download_agent(entry, target)
                    else:
                        bootstrap.download("https://github.com/allowed", "agent", target, 1024)
                self.assertEqual([call.args for call in sock.settimeout.call_args_list], [(5,), (3,)])
                self.assertEqual(target.read_bytes(), b"signed")
                target.unlink()

    def test_mirror_is_explicit_https_prefix_without_panel_credentials(self):
        base = "https://github.com/theLucius7/sinan/releases/download/agent-v0.3.1"
        mirror = "https://mirror.example.com"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "agent"
            with patch.object(bootstrap, "github_opener") as opener:
                opener.return_value.open.return_value = Response(b"signed", mirror + "/" + base + "/agent")
                bootstrap.download(base, "agent", target, 1024, mirror)
                self.assertEqual(opener.call_args.args, (mirror,))
                self.assertEqual(opener.return_value.open.call_args.args, (mirror + "/" + base + "/agent",))
                self.assertEqual(target.read_bytes(), b"signed")
        for prefix in ("http://mirror.example.com", "https://secret@mirror.example.com", "https://127.0.0.1",
                       "https://[::1]", "https://mirror.example.com?token=secret", "https://mirror.example.com/#fragment",
                       "https://panel.example.com:443"):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                bootstrap.validate_mirror(prefix,"https://panel.example.com")
        request = urllib.request.Request(mirror + "/" + base + "/agent")
        with self.assertRaises(ValueError):
            bootstrap.GithubRedirect(mirror).redirect_request(request,None,302,"Found",{},"https://panel.example.com/agent")

    def test_http_panel_is_only_allowed_for_loopback(self):
        for value in ("http://127.0.0.1:8000", "http://[::1]:8000", "http://localhost:8000",
                      "http://[::ffff:127.0.0.1]:8000", "https://panel.example.com"):
            bootstrap.validate_panel_origin(value)
        for value in ("http://panel.example.com", "http://192.0.2.1", "http://10.0.0.1",
                      "https://user:pass@panel.example.com", "https://panel.example.com/path",
                      "https://panel.example.com?token=value", "http://localhost:0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bootstrap.validate_panel_origin(value)

    def test_only_fixed_github_https_hosts_are_allowed(self):
        for host in bootstrap.GITHUB_DOWNLOAD_HOSTS:
            bootstrap.validate_github_url(f"https://{host}:443/release?token=fixture")
        for url in ("http://github.com/a", "https://github.com:444/a",
                    "https://github.com.example.com/a", "https://example.com/a",
                    "https://127.0.0.1/a", "https://[::ffff:127.0.0.1]/a",
                    "https://user:pass@github.com/a", "https://github.com/a#fragment",
                    "https://github.com/a\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                bootstrap.validate_github_url(url)

    def test_redirect_is_rejected_before_unapproved_connection(self):
        request = urllib.request.Request("https://github.com/asset")
        for destination in ("https://example.com/asset", "http://github.com/asset",
                            "https://127.0.0.1/asset"):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                bootstrap.GithubRedirect().redirect_request(request, None, 302, "Found", {}, destination)
        next_request = bootstrap.GithubRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/asset")
        self.assertEqual(next_request.full_url, "https://release-assets.githubusercontent.com/asset")
        self.assertEqual(bootstrap.GithubRedirect.max_redirections, 5)

    def test_environment_proxy_is_never_loaded(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9",
                                    "ALL_PROXY": "socks5://127.0.0.1:9"}):
            with patch("urllib.request.build_opener") as build:
                bootstrap.github_opener()
                proxy = build.call_args.args[0]
                self.assertIsInstance(proxy, urllib.request.ProxyHandler)
                self.assertEqual(proxy.proxies, {})

    def test_download_checks_final_host_and_size_without_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "SHA256SUMS"
            for payload, url in ((b"12345", "https://github.com/asset"),
                                 (b"123", "https://example.com/asset")):
                with patch.object(bootstrap, "github_opener") as opener:
                    opener.return_value.open.return_value = Response(payload, url)
                    with self.assertRaises(ValueError):
                        bootstrap.download("https://github.com/allowed", "SHA256SUMS", target, 4)
                self.assertFalse(target.exists())

    def test_unprotected_operator_trust_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public-keys.json"
            path.write_text((FIXTURES / "public-keys.json").read_text())
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                release.load_roots(path, require_protected=True)

    @unittest.skipUnless(os.getuid() == 0, "root-owned trust file test requires container root")
    def test_protected_operator_root_is_accepted_and_symlink_refused(self):
        with tempfile.TemporaryDirectory(prefix="sinan-trust-test-", dir="/root") as directory:
            path = Path(directory) / "public-keys.json"
            path.write_text((FIXTURES / "public-keys.json").read_text())
            path.chmod(0o600)
            self.assertEqual(len(release.load_roots(path, require_protected=True)), 1)
            link = Path(directory) / "linked.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                release.load_roots(link, require_protected=True)


@unittest.skipUnless(shutil.which("minisign"), "standalone signed bootstrap requires minisign")
class StandaloneBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_command = [] if os.getuid() == 0 else ["sudo", "-n"]
        if cls.root_command:
            if not shutil.which("sudo"):
                raise unittest.SkipTest("standalone bootstrap requires privileged root access; sudo is unavailable")
            result = subprocess.run(cls.root_command + ["true"], capture_output=True, check=False)
            if result.returncode:
                raise unittest.SkipTest("standalone bootstrap needs root or passwordless sudo")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sinan-standalone-bootstrap-test-")
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory / "release"
        self.bundle.mkdir()
        installer = b"#!/bin/sh\nset -eu\nprintf '%s\\n' RELEASE_INSTALLER_MUST_NOT_EXECUTE\n"
        (self.bundle / "install.sh").write_bytes(installer)
        binary = b"TEST ONLY Agent never executed"
        architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
        metadata = dict(schema=1, source_repo=release.REPOSITORY, tag="agent-v0.3.0",
                        protocol_min=1, protocol_max=1, artifacts=[dict(
                            name="agent", version="0.3.0", arch=architecture, format="raw",
                            binary_name="sinan-agent", archive_size=len(binary),
                            binary_size=len(binary), binary_sha256=release.digest(binary),
                            asset_name="agent-0.3.0-linux-musl-" + architecture)])
        (self.bundle / metadata["artifacts"][0]["asset_name"]).write_bytes(binary)
        encoded = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (self.bundle / "release.json").write_bytes(encoded)
        checksums = {"agent/0.3.0/" + architecture: release.digest(binary),
                     "install.sh": release.digest(installer), "release.json": release.digest(encoded)}
        (self.bundle / "SHA256SUMS").write_text("".join(
            f"{checksums[name]}  {name}\n" for name in sorted(checksums)))
        result = subprocess.run(["minisign", "-S", "-m", str(self.bundle / "SHA256SUMS"),
                                 "-s", str(FIXTURES / "TEST_ONLY.key"), "-x",
                                 str(self.bundle / "SHA256SUMS.minisig"), "-t",
                                 "Sinan TEST ONLY standalone fixture"], capture_output=True)
        self.assertEqual(result.returncode, 0, "fixture signing failed")
        self.script = self.directory / "bootstrap.sh"
        self.script.write_text(RENDER.render(
            trusted_keys=FIXTURES / "public-keys.json", publication=False,
            test_installer="#!/bin/sh\n# SINAN_BOOTSTRAP_AGENT_SOURCE=preloaded-github-v1\nset -eu\nprintf '%s\\n' TRUSTED_INSTALLER_VERIFIED\n"))

    def tearDown(self):
        self.temporary.cleanup()

    def run_bootstrap(self, script=None):
        return subprocess.run(self.root_command + ["/bin/sh", str(script or self.script),
                              "--tag", "agent-v0.3.0", "--panel", "http://127.0.0.1:8000",
                              "--token=-TEST_ONLY_token", "--release-dir", str(self.bundle)],
                              capture_output=True, check=False, timeout=30)

    def test_standalone_bootstrap_provisions_its_own_trust_and_verifies_before_execution(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"TRUSTED_INSTALLER_VERIFIED", result.stdout)
        self.assertNotIn(b"RELEASE_INSTALLER_MUST_NOT_EXECUTE", result.stdout)

    def test_standalone_rejects_executor_without_contract_but_accepts_signed_legacy_proof(self):
        script = self.directory / "missing-contract-bootstrap.sh"
        script.write_text(RENDER.render(
            trusted_keys=FIXTURES / "public-keys.json", publication=False,
            test_installer="#!/bin/sh\nset -eu\nprintf '%s\\n' UNCONTRACTED_EXECUTOR_MUST_NOT_RUN\n"))
        result = self.run_bootstrap(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"preloaded-GitHub Agent contract", result.stderr)
        self.assertNotIn(b"UNCONTRACTED_EXECUTOR_MUST_NOT_RUN", result.stdout)
        self.assertNotIn(b"RELEASE_INSTALLER_MUST_NOT_EXECUTE", result.stdout)

    def test_standalone_rejects_writable_staging_before_writing_or_importing_helpers(self):
        unsafe = self.directory / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        script = self.directory / "unsafe-bootstrap.sh"
        script.write_text(self.script.read_text().replace(
            "STAGING_BASE=/opt/sinan", "STAGING_BASE=" + shlex.quote(str(unsafe))))
        result = self.run_bootstrap(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root 保护".encode(), result.stderr)
        self.assertNotIn(b"TRUSTED_INSTALLER_VERIFIED", result.stdout)
        self.assertEqual(list(unsafe.iterdir()), [])

    def test_tampered_installer_or_metadata_never_executes(self):
        for filename in ("install.sh", "release.json", next(self.bundle.glob("agent-*" )).name):
            path = self.bundle / filename
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            result = self.run_bootstrap()
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"TRUSTED_INSTALLER_VERIFIED", result.stdout)
            path.write_bytes(original)

    def test_official_roots_reject_a_release_signed_by_test_root(self):
        result = self.run_bootstrap(ROOT / "deploy/bootstrap.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"TRUSTED_INSTALLER_VERIFIED", result.stdout)
        self.assertIn(b"no trusted key verifies", result.stderr)

    def test_linux_static_preflight_allows_only_recoverable_same_origin_identity(self):
        template = (ROOT / "deploy/install.sh.tmpl").read_text()
        preflight = template.split('python3 -I - "$PANEL" <<\'PY\'\n', 1)[1].split("\nPY\n", 1)[0]
        # Run the production preflight in a protected disposable hierarchy, without activating services.
        harness = r'''
import os, pathlib, sys, tempfile
source = sys.argv[1]
with tempfile.TemporaryDirectory(prefix='sinan-partial-fixture-', dir='/root') as fixture:
    root = pathlib.Path(fixture)
    source = source.replace('/etc/sinan/identity', str(root / 'identity'))
    source = source.replace('/var/lib/sinan/core/state.db', str(root / 'state.db'))
    source = source.replace('/opt/sinan/core/current', str(root / 'current'))
    source = source.replace('/opt/sinan/plugins', str(root / 'plugins'))
    sys.argv = ['trusted-preflight', 'https://panel.example.com']
    identity = root / 'identity'
    identity.mkdir(mode=0o700)
    origin = identity / 'panel_origin'
    origin.write_text('https://PANEL.example.com:443/')
    key = identity / 'device.key'
    def preflight(refused=False):
        try:
            exec(compile(source, '<actual static Linux preflight>', 'exec'), {})
        except (SystemExit, ValueError, OSError):
            assert refused, 'recoverable identity was rejected'
        else:
            assert not refused, 'unsafe partial identity was accepted'
    preflight()
    key.write_bytes(b'K' * 32)
    key.chmod(0o600)
    preflight()  # An interrupted registration keeps its original device identity on retry.
    assert key.read_bytes() == b'K' * 32
    server = identity / 'server_id'
    server.write_text('123')
    preflight()
    key.unlink()
    preflight(True)
    key.write_bytes(b'K' * 32)
    key.chmod(0o600)
    origin.write_text('https://different.example.com')
    preflight(True)
    origin.write_text('https://panel.example.com')
    unknown = identity / 'unexpected'
    unknown.write_text('unknown state')
    preflight(True)
    unknown.unlink()
    key.chmod(0o644)
    preflight(True)
    key.chmod(0o600)
    state = root / 'state.db-wal'
    state.write_bytes(b'active state')
    preflight(True)
    state.unlink()
    preflight()
    assert key.read_bytes() == b'K' * 32
'''
        result = subprocess.run(self.root_command + ["python3", "-I", "-c", harness, preflight],
                                capture_output=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
