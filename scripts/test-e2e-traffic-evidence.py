#!/usr/bin/env python3
"""Keep failure evidence bounded, private, and separate from traffic acceptance."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("traffic_evidence", ROOT / "scripts/e2e-traffic-evidence.py")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
FIXTURE_SPEC = importlib.util.spec_from_file_location("http_fixture", ROOT / "scripts/e2e-http-fixture.py")
FIXTURE = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(FIXTURE)
SECRET = "PRIVATE-TOKEN-key@private-host.example.test/198.51.100.77"


class EvidenceContracts(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.scratch = Path(directory.name)
        self.path = self.scratch / EVIDENCE.EVIDENCE_NAME

    def test_transfer_timeout_preserves_exit_partial_metrics_and_fixed_budget(self):
        metrics = "200 1103168 0 0.001 0.02 90.0\n"
        process = subprocess.CompletedProcess([], 28, metrics, SECRET)
        with patch.object(EVIDENCE.subprocess, "run", return_value=process) as run, \
             contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(EVIDENCE.transfer(self.scratch, "resumed-traffic", "download"), 28)
        record = EVIDENCE.load(self.path)["transfers"][0]
        self.assertEqual(record["curl_exit"], 28)
        self.assertEqual(record["error_kind"], "timeout")
        self.assertEqual(record["download_bytes"], 1103168)
        self.assertEqual(record["elapsed_ms"], 90000)
        self.assertEqual(record["timeout_source"], "curl_deadline")
        self.assertEqual(EVIDENCE.load(self.path)["policy"]["request_ms"], 90000)
        self.assertEqual(EVIDENCE.load(self.path)["policy"]["target_scope"], "owned_loopback")
        self.assertEqual(EVIDENCE.load(self.path)["policy"]["retries"], 0)
        self.assertFalse(record["curl_succeeded"])
        arguments, options = run.call_args.args[0], run.call_args.kwargs
        self.assertEqual(arguments[arguments.index("--max-time") + 1], "90")
        self.assertEqual(options["timeout"], 92)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertNotIn("--retry", arguments)
        self.assertNotIn("--show-error", arguments)
        self.assertNotIn(SECRET, self.path.read_text() + error.getvalue())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_success_upload_command_is_fixed_and_body_remains_private(self):
        with patch.object(EVIDENCE.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, "200 8 1048576 0.001 0.02 0.03\n", SECRET)) as run:
            self.assertEqual(EVIDENCE.transfer(self.scratch, "first-traffic", "upload"), 0)
        arguments = run.call_args.args[0]
        self.assertIn("@" + str(self.scratch / "upload.bin"), arguments)
        self.assertIn("http://127.0.0.1:18081/upload", arguments)
        self.assertIn("socks5h://127.0.0.1:2080", arguments)
        record = EVIDENCE.load(self.path)["transfers"][0]
        self.assertTrue(record["curl_succeeded"])
        self.assertNotIn("passed", record)
        self.assertNotIn(str(self.scratch), self.path.read_text())
        self.assertNotIn("timeout_source", record)

    def test_process_guard_is_distinct_from_curl_deadline_and_preserves_failure(self):
        with patch.object(EVIDENCE.subprocess, "run", side_effect=subprocess.TimeoutExpired([SECRET], 92)), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(EVIDENCE.transfer(self.scratch, "first-traffic", "upload"), 28)
        record = EVIDENCE.load(self.path)["transfers"][0]
        self.assertEqual(record["timeout_source"], "process_guard")
        self.assertEqual(record["reached_stage"], "unknown")
        self.assertFalse(record["curl_succeeded"])
        self.assertEqual(EVIDENCE.load(self.path)["policy"]["process_guard_ms"], 92000)
        self.assertNotIn(SECRET, self.path.read_text())

    def test_policy_is_exact_allowlisted_and_never_inferred_for_historical_evidence(self):
        legacy = {"transfers": [{"phase": "first-traffic", "direction": "download", "curl_exit": 28,
                                 "error_kind": "timeout", "timeout_source": SECRET}]}
        summary = EVIDENCE.safe_summary(legacy)
        self.assertNotIn("policy", summary)
        self.assertNotIn("timeout_source", summary["transfers"][0])
        for key, replacement in (("request_ms", 15000), ("retries", False),
                                 ("target_scope", SECRET), ("process_guard_ms", 92001)):
            policy = dict(EVIDENCE.TRAFFIC_POLICY, **{key: replacement})
            self.assertNotIn("policy", EVIDENCE.safe_summary({"policy": policy}))
        policy = dict(EVIDENCE.TRAFFIC_POLICY, private_url=SECRET, token=SECRET)
        self.assertEqual(EVIDENCE.safe_summary({"policy": policy}), {"policy": EVIDENCE.TRAFFIC_POLICY})
        successful = dict(legacy["transfers"][0], curl_exit=0, error_kind="none", timeout_source="process_guard")
        self.assertNotIn("timeout_source", EVIDENCE.safe_record(successful, True))

    def test_timeout_stage_distinguishes_observed_progress_without_claiming_root_cause(self):
        cases = (
            ("000 0 0 0 0 0 0 90", "before_proxy_connect"),
            ("000 0 0 0 0.001 0 0 90", "proxy_or_transport"),
            ("000 0 1048576 0 0.001 0.02 0 90", "request_or_response"),
            ("200 1103168 0 0 0.001 0.02 0.04 90", "receiving_response"),
            ("", "unknown"),
        )
        for metrics, expected in cases:
            with self.subTest(expected=expected), patch.object(EVIDENCE.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 28, metrics, SECRET)), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(EVIDENCE.transfer(self.scratch, "first-traffic", "download"), 28)
            record = EVIDENCE.load(self.path)["transfers"][0]
            self.assertEqual(record["reached_stage"], expected)
            self.assertEqual(record["curl_exit"], 28)
            self.assertNotIn(SECRET, self.path.read_text())

    def test_extended_timing_fields_are_allowlisted_and_legacy_json_stays_readable(self):
        metrics = EVIDENCE.curl_metrics("200 8 1048576 0.001 0.002 0.03 0.04 0.05")
        self.assertEqual(metrics["local_dns_ms"], 1)
        self.assertEqual(metrics["pretransfer_ms"], 30)
        value = {"transfers": [{"phase": "first-traffic", "direction": "upload", **metrics,
                                "reached_stage": SECRET, "proxy_target": SECRET}]}
        EVIDENCE.save(self.path, value)
        self.assertNotIn(SECRET, self.path.read_text())
        self.assertNotIn("reached_stage", EVIDENCE.load(self.path)["transfers"][0])
        self.assertEqual(EVIDENCE.curl_metrics("200 8 1048576 0.002 0.04 0.05")["connect_ms"], 2)

    def test_launch_guard_and_evidence_write_failure_never_turn_timeout_into_success(self):
        for error, expected, kind in ((OSError(SECRET), 127, "launch"),
                                      (subprocess.TimeoutExpired([SECRET], 92, SECRET, SECRET), 28, "timeout")):
            with self.subTest(kind=kind), patch.object(EVIDENCE.subprocess, "run", side_effect=error), \
                 patch.object(EVIDENCE, "save", side_effect=OSError(SECRET)), \
                 contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(EVIDENCE.transfer(self.scratch, "first-traffic", "download"), expected)
                self.assertIn("error_kind=" + kind, output.getvalue())
                self.assertNotIn(SECRET, output.getvalue())

    def test_metrics_reject_free_form_nan_negative_oversized_and_fractional_counters(self):
        self.assertEqual(EVIDENCE.curl_metrics(SECRET), {})
        self.assertEqual(EVIDENCE.curl_metrics("0 " * 128), {})
        record = EVIDENCE.curl_metrics("SECRET 1.5 -2 NaN -0.1 9000000")
        self.assertEqual(record, {"elapsed_ms": None})
        record = EVIDENCE.curl_metrics("200 2097152 0 0.001234 0 0.1")
        self.assertEqual(record["connect_ms"], 1)
        self.assertEqual(record["download_bytes"], 2097152)
        for value in (-1, True, 2 ** 63, SECRET, float("nan")):
            self.assertIsNone(EVIDENCE.integer(value, 2 ** 63 - 1))

    def test_signalled_curl_preserves_shell_exit_without_claiming_http_failure(self):
        with patch.object(EVIDENCE.subprocess, "run", return_value=subprocess.CompletedProcess([], -9, "", "")), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(EVIDENCE.transfer(self.scratch, "first-traffic", "download"), 137)
        record = EVIDENCE.load(self.path)["transfers"][0]
        self.assertEqual(record["error_kind"], "signal")
        self.assertNotIn("http_status", record)

    def test_public_json_is_revalidated_and_cannot_carry_private_fields_or_invalid_enums(self):
        bad = {"phase": SECRET, "direction": "download", "error_kind": SECRET, "token": SECRET}
        good = {"phase": "first-traffic", "direction": "download", "curl_exit": 28,
                "error_kind": "timeout", "download_bytes": 0, "curl_succeeded": False,
                "command": SECRET, "stderr": SECRET}
        value = {"transfers": [bad, good, {"phase": {}, "direction": []}, SECRET] * 20,
                 "failure": {"fixture_http": {"passed": False, "error_kind": {}, "http_status": SECRET},
                             "fixture_tls": {"error_kind": "tls", "certificate": SECRET},
                             "host": {"cpu_count": 2, "load1_milli": True, "mem_available_kib": SECRET,
                                      "environment": SECRET}, "client_present": SECRET,
                             "http_fixture_present": True, "config": SECRET}, "identity": SECRET}
        self.path.write_text(json.dumps(value))
        summary = EVIDENCE.load(self.path)
        self.assertEqual(len(summary["transfers"]), 1)
        self.assertIsNone(summary["failure"]["fixture_http"]["http_status"])
        self.assertEqual(summary["failure"]["fixture_tls"], {"error_kind": "tls"})
        self.assertNotIn("client_present", summary["failure"])
        self.assertNotIn(SECRET, json.dumps(summary))
        self.path.write_text("x" * 16385)
        self.assertEqual(EVIDENCE.load(self.path), {})
        self.path.unlink()
        self.path.symlink_to(self.scratch / "private")
        self.assertEqual(EVIDENCE.load(self.path), {})
        with self.assertRaises(OSError):
            EVIDENCE.save(self.path, {})

    def test_each_phase_direction_is_bounded_without_resending(self):
        with patch.object(EVIDENCE.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, "200 2097152 1048576 0 0 0\n", "")) as run:
            for phase in sorted(EVIDENCE.PHASES):
                for direction in sorted(EVIDENCE.DIRECTIONS):
                    EVIDENCE.transfer(self.scratch, phase, direction)
            self.assertEqual(run.call_count, 4)
        self.assertEqual(len(EVIDENCE.load(self.path)["transfers"]), 4)

    def test_failure_probes_use_only_fixed_targets_and_reject_unrelated_networks(self):
        for networks in ({}, {"a": {}, "b": {}}, {"a": {"IPAddress": "127.0.0.1"}},
                         {"a": {"IPAddress": "198.51.100.1"}}, {"a": {"IPAddress": "::1"}}):
            (self.scratch / "tls-network.json").write_text(json.dumps(networks))
            with patch.object(EVIDENCE, "tcp_probe", return_value={}) as tcp, \
                 patch.object(EVIDENCE, "bounded_http_probe", return_value={"http_status": 200}), \
                 patch.object(EVIDENCE, "tls_probe") as tls:
                EVIDENCE.failure(self.scratch, 0, 0)
                self.assertEqual([call.args[0] for call in tcp.call_args_list], [18081, 2080, 443])
                tls.assert_not_called()
            self.assertEqual(EVIDENCE.load(self.path)["failure"]["fixture_tls"]["error_kind"], "not_configured")
        (self.scratch / "tls-network.json").write_text(json.dumps({"fixture": {"IPAddress": "10.0.0.2"}}))
        self.assertEqual(EVIDENCE.fixture_address(self.scratch), "10.0.0.2")

    def test_real_http_fixture_is_direct_bounded_and_counts_without_recording_payload(self):
        server = FIXTURE.ThreadingHTTPServer(("127.0.0.1", 18081), FIXTURE.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            record = EVIDENCE.probe(lambda: EVIDENCE.bounded_http_probe(self.scratch))
            self.assertTrue(record["passed"])
            self.assertEqual(record["http_status"], 200)
            self.assertEqual(record["download_bytes"], 2097152)
            self.assertLess(record["elapsed_ms"], 2000)
            self.assertNotIn("body", record)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_real_tls_fixture_handshake_and_plaintext_are_classified_without_certificate_output(self):
        certificate, key = self.scratch / "fixture.crt", self.scratch / "fixture.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "1", "-keyout", str(key), "-out", str(certificate),
                        "-subj", "/CN=sinan-e2e.example.test", "-addext", "subjectAltName=DNS:sinan-e2e.example.test"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ecdh_curve("X25519")
        context.load_cert_chain(certificate, key)
        for use_tls, kind in ((True, "none"), (False, "tls")):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                def serve():
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(2)
                        if use_tls:
                            with context.wrap_socket(stream, server_side=True):
                                pass
                        else:
                            stream.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                record = EVIDENCE.probe(lambda: EVIDENCE.tls_probe("127.0.0.1", certificate, listener.getsockname()[1]))
                thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(record["error_kind"], kind)
                self.assertEqual(record["passed"], use_tls)
                self.assertLess(record["elapsed_ms"], 2000)
                self.assertNotIn(str(key), json.dumps(record))

    def test_stalled_http_fixture_stops_at_two_second_probe_budget(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            def stall():
                connection, _ = listener.accept()
                with connection:
                    time.sleep(2.2)
            thread = threading.Thread(target=stall, daemon=True)
            thread.start()
            started = time.monotonic()
            record = EVIDENCE.probe(lambda: EVIDENCE.http_probe(listener.getsockname()[1]))
            self.assertEqual(record["error_kind"], "timeout")
            self.assertFalse(record["passed"])
            self.assertLess(time.monotonic() - started, 2.5)
            thread.join(3)

    def test_slow_drip_headers_and_body_are_killed_and_reaped_at_hard_deadline(self):
        for body in (False, True):
            with self.subTest(body=body), socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 18081))
                listener.listen(1)
                listener.settimeout(3)
                done = threading.Event()
                def drip():
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(1)
                        stream.recv(4096)
                        if body:
                            stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n")
                        try:
                            for _ in range(20):
                                stream.sendall(b"s" if body else b"H")
                                if done.wait(0.2):
                                    break
                        except OSError:
                            pass
                thread = threading.Thread(target=drip, daemon=True)
                thread.start()
                started = time.monotonic()
                children = []
                original_popen = subprocess.Popen
                def launch(*arguments, **options):
                    child = original_popen(*arguments, **options)
                    children.append(child)
                    return child
                with patch.object(EVIDENCE.subprocess, "Popen", side_effect=launch):
                    record = EVIDENCE.probe(lambda: EVIDENCE.bounded_http_probe(self.scratch))
                done.set()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(record["passed"])
                self.assertEqual(record["error_kind"], "timeout")
                self.assertLess(time.monotonic() - started, 2.5)
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].returncode, -9)
                with self.assertRaises(ProcessLookupError):
                    EVIDENCE.os.kill(children[0].pid, 0)

    def test_dripping_http_headers_and_body_share_the_absolute_two_second_budget(self):
        for stage in ("headers", "body"):
            with self.subTest(stage=stage), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                def drip():
                    try:
                        stream, _ = listener.accept()
                        with stream:
                            stream.settimeout(3)
                            stream.recv(4096)
                            headers = b"HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n"
                            if stage == "body":
                                stream.sendall(headers)
                            payload = headers if stage == "headers" else b"s" * 44
                            for byte in payload:
                                stream.sendall(bytes([byte]))
                                time.sleep(0.075)
                    except OSError:
                        # The bounded client closes before the fixture finishes.
                        pass
                thread = threading.Thread(target=drip, daemon=True)
                thread.start()
                started = time.monotonic()
                record = EVIDENCE.probe(lambda: EVIDENCE.http_probe(listener.getsockname()[1]))
                elapsed = time.monotonic() - started
                thread.join(4)
                self.assertFalse(thread.is_alive())
                self.assertLess(elapsed, 2.5)
                self.assertEqual(record["error_kind"], "timeout")
                self.assertFalse(record["passed"])


    def test_public_ci_summary_revalidates_evidence_without_probes_or_private_dump(self):
        source = (ROOT / "scripts/ci-real-e2e.sh").read_text().split("write_summary() {\n", 1)[1]
        source = source.split("<<'PY'\n", 1)[1].split("\nPY\n}", 1)[0]
        self.path.write_text(json.dumps({"policy": dict(EVIDENCE.TRAFFIC_POLICY, private_target=SECRET),
                    "transfers": [{"phase": "first-traffic", "direction": "download",
                    "curl_exit": 28, "error_kind": "timeout", "timeout_source": "curl_deadline",
                    "download_bytes": 0, "stderr": SECRET}],
                    "failure": {"fixture_tls": {"passed": False, "error_kind": "tls", "key": SECRET}}}))
        output = self.scratch / "summary.json"
        argv = ["summary", str(self.scratch / "state.json"), str(output), "0", "first-traffic", "28", "0", "278"]
        annotation = io.StringIO()
        with contextlib.chdir(ROOT), patch.object(EVIDENCE.sys, "argv", argv), \
             patch.dict(EVIDENCE.os.environ, {"GITHUB_ACTIONS": "true"}, clear=True), \
             contextlib.redirect_stdout(annotation), patch.object(EVIDENCE.subprocess, "run") as run:
            exec(compile(source, "ci-real-e2e.sh:write_summary", "exec"), {})
            run.assert_not_called()
        summary = json.loads(output.read_text())
        self.assertFalse(summary["passed"])
        self.assertEqual(summary["exit_code"], 28)
        self.assertEqual(summary["failure_line"], 278)
        self.assertEqual(summary["traffic"]["transfers"][0]["download_bytes"], 0)
        self.assertEqual(summary["traffic"]["transfers"][0]["timeout_source"], "curl_deadline")
        self.assertEqual(summary["traffic"]["policy"], EVIDENCE.TRAFFIC_POLICY)
        self.assertEqual(annotation.getvalue(), "::error title=Reality acceptance failed::"
                         + json.dumps(summary, ensure_ascii=True) + "\n")
        self.assertNotIn(SECRET, output.read_text() + annotation.getvalue())
        shell = (ROOT / "scripts/ci-real-e2e.sh").read_text()
        cleanup = shell.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
        self.assertLess(cleanup.index("failure \\\n"), cleanup.index("write_summary || true"))
        self.assertLess(cleanup.index("write_summary || true"), cleanup.index('kill "$client_pid"'))
        self.assertIn('exit "$result"', cleanup)

    def test_real_cleanup_preserves_exit_when_evidence_and_summary_both_fail(self):
        shell = (ROOT / "scripts/ci-real-e2e.sh").read_text()
        cleanup = "cleanup() {" + shell.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
        script = """set -euo pipefail
scratch=$E2E_TEST_SCRATCH
phase=resumed-traffic owned_installation=0 hosts_entry=0 client_pid= fixture_pid= tls_container= trust_directory=
python3() { printf 'probe_failed\\n'; return 7; }
write_summary() { printf 'summary_failed\\n'; return 8; }
sudo() { :; }
""" + cleanup + "\ntrap cleanup EXIT\nexit 28\n"
        process = subprocess.run(["bash"], input=script, capture_output=True, text=True, timeout=3,
                                 env={"E2E_TEST_SCRATCH": str(self.scratch)})
        self.assertEqual(process.returncode, 28)
        self.assertEqual(process.stdout, "probe_failed\nsummary_failed\n")
        self.assertIn("failed during resumed-traffic", process.stderr)


    def test_real_cleanup_failure_keeps_existing_error_and_success_still_rejects_cleanup_failure(self):
        shell = (ROOT / "scripts/ci-real-e2e.sh").read_text()
        cleanup = "cleanup() {" + shell.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
        for original, expected in ((28, 28), (0, 7)):
            with self.subTest(original=original):
                script = """set -euo pipefail
scratch=$E2E_TEST_SCRATCH
phase=first-traffic owned_installation=1 hosts_entry=0 client_pid= fixture_pid= tls_container= trust_directory=
python3() { return 0; }
write_summary() { return 0; }
sudo() { if [[ $1 == rm && ${!#} == "$scratch" ]]; then printf 'scratch_cleanup_attempt\n'; fi; return 7; }
getent() { return 1; }
""" + cleanup + "\ntrap cleanup EXIT\nexit " + str(original) + "\n"
                process = subprocess.run(["bash"], input=script, capture_output=True, text=True, timeout=3,
                                         env={"E2E_TEST_SCRATCH": str(self.scratch)})
                self.assertEqual(process.returncode, expected)
                if original:
                    self.assertIn("scratch_cleanup_attempt", process.stdout)
                    self.assertIn("failed during first-traffic", process.stderr)


if __name__ == "__main__":
    unittest.main()
